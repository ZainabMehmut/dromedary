//! PyO3 bindings for the russh-backed SSH vendor.
//!
//! The SSH logic lives in `dromedary::ssh::russh_vendor`. This module
//! gathers the inputs that need Python (username from the config, key
//! passphrases, the config directory, password prompts) while holding the
//! GIL, and releases it around the network round-trips.

use crate::sftp::{BoxedChannel, SFTPClient};
use dromedary::ssh::russh_vendor::{
    home_dir, system_known_hosts_path, AuthOutcome, BlockingChannel, ConnectParams, Error, Session,
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::import_exception;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

import_exception!(dromedary.errors, SocketConnectionError);
import_exception!(dromedary.errors, TransportError);

/// Synchronous helper that loads `~/.ssh/id_rsa` and `~/.ssh/id_dsa`,
/// prompting the user via `dromedary._ui.get_password` for a passphrase
/// when a key is encrypted. Missing files are silently skipped.
fn load_default_keyfiles(py: Python) -> Vec<russh::keys::PrivateKey> {
    let Some(home) = home_dir() else {
        log::debug!("no home directory; skipping key-file auth");
        return Vec::new();
    };

    let mut keys = Vec::new();
    for name in ["id_rsa", "id_dsa"] {
        let path = home.join(".ssh").join(name);
        if !path.exists() {
            continue;
        }
        match load_one_keyfile(py, &path) {
            Ok(Some(k)) => keys.push(k),
            Ok(None) => {}
            Err(e) => log::debug!("load key {}: {}", path.display(), e),
        }
    }
    keys
}

/// Load a single private key file, prompting once for a passphrase on
/// `KeyIsEncrypted`. Returns `Ok(None)` if the user cancels the prompt or
/// the second attempt also fails.
fn load_one_keyfile(
    py: Python,
    path: &Path,
) -> Result<Option<russh::keys::PrivateKey>, russh::keys::Error> {
    match russh::keys::load_secret_key(path, None) {
        Ok(k) => Ok(Some(k)),
        Err(russh::keys::Error::KeyIsEncrypted) => {
            let Some(pw) = prompt_key_password(py, path) else {
                log::debug!(
                    "encrypted key {} skipped (no passphrase provided)",
                    path.display()
                );
                return Ok(None);
            };
            match russh::keys::load_secret_key(path, Some(&pw)) {
                Ok(k) => Ok(Some(k)),
                Err(e) => {
                    log::debug!(
                        "decrypting {} with supplied passphrase failed: {}",
                        path.display(),
                        e
                    );
                    Ok(None)
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// Call `dromedary._ui.get_password(prompt, filename=<path>)`, matching
/// paramiko.py's prompt format. Returns `None` if the call fails or the
/// result is `None`.
fn prompt_key_password(py: Python, path: &Path) -> Option<String> {
    let ui = match py.import("dromedary._ui") {
        Ok(m) => m,
        Err(e) => {
            log::debug!("importing dromedary._ui failed: {e}");
            return None;
        }
    };
    let kwargs = PyDict::new(py);
    if let Err(e) = kwargs.set_item("filename", path.display().to_string()) {
        log::debug!("building get_password kwargs failed: {e}");
        return None;
    }
    let result = ui.call_method(
        "get_password",
        ("SSH %(filename)s password",),
        Some(&kwargs),
    );
    match result {
        Ok(v) if v.is_none() => None,
        Ok(v) => v.extract::<String>().ok(),
        Err(e) => {
            log::debug!("_ui.get_password raised: {e}");
            None
        }
    }
}

/// Resolve a default username via `dromedary._config.get_auth_user("ssh",
/// host, port=port, default=getpass.getuser())`, falling back to `$USER`
/// if the Python layer is unavailable. Mirrors paramiko.py:64-67.
fn resolve_username(py: Python, host: &str, port: Option<u16>) -> String {
    let fallback = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let cfg = match py.import("dromedary._config") {
        Ok(m) => m,
        Err(e) => {
            log::debug!("importing dromedary._config failed: {e}");
            return fallback;
        }
    };
    let kwargs = PyDict::new(py);
    if let Err(e) = kwargs.set_item("default", &fallback) {
        log::debug!("building get_auth_user kwargs failed: {e}");
        return fallback;
    }
    if let Some(p) = port {
        if let Err(e) = kwargs.set_item("port", p) {
            log::debug!("building get_auth_user kwargs failed: {e}");
            return fallback;
        }
    }
    match cfg.call_method("get_auth_user", ("ssh", host), Some(&kwargs)) {
        Ok(v) if v.is_none() => fallback,
        Ok(v) => v.extract::<String>().unwrap_or(fallback),
        Err(e) => {
            log::debug!("_config.get_auth_user raised: {e}");
            fallback
        }
    }
}

/// Prompt for an auth password via `dromedary._config.get_auth_password(
/// "ssh", host, user, port=port)`. Returns `None` if the call fails or
/// the user cancels.
fn prompt_auth_password(py: Python, host: &str, port: Option<u16>, user: &str) -> Option<String> {
    let cfg = match py.import("dromedary._config") {
        Ok(m) => m,
        Err(e) => {
            log::debug!("importing dromedary._config failed: {e}");
            return None;
        }
    };
    let kwargs = PyDict::new(py);
    if let Some(p) = port {
        if let Err(e) = kwargs.set_item("port", p) {
            log::debug!("building get_auth_password kwargs failed: {e}");
            return None;
        }
    }
    match cfg.call_method("get_auth_password", ("ssh", host, user), Some(&kwargs)) {
        Ok(v) if v.is_none() => None,
        Ok(v) => v.extract::<String>().ok(),
        Err(e) => {
            log::debug!("_config.get_auth_password raised: {e}");
            None
        }
    }
}

/// Resolve `<dromedary._bedding.config_dir()>/ssh_host_keys` via the
/// Python side so embedder overrides are honored. Also calls
/// `_bedding.ensure_config_dir_exists()` so the later `learn_*` write
/// doesn't fail on a missing parent directory.
fn dromedary_host_keys_path(py: Python) -> PathBuf {
    let fallback = || {
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|h| h.join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        xdg.join("breezy").join("ssh_host_keys")
    };
    let bedding = match py.import("dromedary._bedding") {
        Ok(m) => m,
        Err(e) => {
            log::debug!("importing dromedary._bedding failed: {e}");
            return fallback();
        }
    };
    if let Err(e) = bedding.call_method0("ensure_config_dir_exists") {
        log::debug!("ensure_config_dir_exists failed: {e}");
    }
    match bedding.call_method0("config_dir") {
        Ok(v) => match v.extract::<String>() {
            Ok(s) => PathBuf::from(s).join("ssh_host_keys"),
            Err(e) => {
                log::debug!("config_dir() returned non-string: {e}");
                fallback()
            }
        },
        Err(e) => {
            log::debug!("_bedding.config_dir() raised: {e}");
            fallback()
        }
    }
}

fn connect_err(host: &str, port: u16, e: Error) -> PyErr {
    match e {
        Error::HostKeyMismatch(m) => TransportError::new_err((
            m.to_string(),
            format!(
                "Try editing {} or {}",
                m.system_path.display(),
                m.dromedary_path.display()
            ),
        )),
        e => SocketConnectionError::new_err((
            host.to_string(),
            format!(":{port}"),
            "Failed to connect to",
            e.to_string(),
        )),
    }
}

/// Counterpart to `SSHSubprocessConnection` for the russh transport. Unlike
/// the subprocess variant it doesn't expose a raw fd: the remote command's
/// stdio is read/written through the same async runtime that performed the
/// handshake.
#[pyclass(module = "dromedary._transport_rs.ssh", name = "RusshSSHConnection")]
pub(crate) struct RusshSSHConnection {
    inner: Mutex<Option<BlockingChannel>>,
}

#[pymethods]
impl RusshSSHConnection {
    fn send(&self, py: Python, data: &[u8]) -> PyResult<usize> {
        use std::io::Write;
        py.detach(|| {
            let mut guard = self.inner.lock().unwrap();
            let ch = guard
                .as_mut()
                .ok_or_else(|| PyRuntimeError::new_err("connection closed"))?;
            ch.write(data)
                .map_err(|e| PyRuntimeError::new_err(format!("send failed: {e}")))
        })
    }

    fn recv(&self, py: Python, count: usize) -> PyResult<Vec<u8>> {
        use std::io::Read;
        py.detach(|| {
            let mut guard = self.inner.lock().unwrap();
            let ch = guard
                .as_mut()
                .ok_or_else(|| PyRuntimeError::new_err("connection closed"))?;
            let mut buf = vec![0u8; count];
            let n = ch
                .read(&mut buf)
                .map_err(|e| PyRuntimeError::new_err(format!("recv failed: {e}")))?;
            buf.truncate(n);
            Ok(buf)
        })
    }

    fn close(&self) -> PyResult<()> {
        // Drops the underlying stream; russh will send channel_close when
        // the Channel's write half is dropped.
        let _ = self.inner.lock().unwrap().take();
        Ok(())
    }
}

#[pyclass(module = "dromedary._transport_rs.ssh", name = "RusshVendor")]
pub(crate) struct RusshVendor;

impl RusshVendor {
    /// Connect and authenticate, prompting for a password if needed.
    ///
    /// Everything that calls into Python (username lookup, key passphrase
    /// prompts, config dir, password prompt) runs with the GIL held; the
    /// network round-trips run with it released.
    fn connect(
        py: Python,
        username: Option<&str>,
        password: Option<&str>,
        host: &str,
        port: Option<u16>,
    ) -> PyResult<Session> {
        let port_nr = port.unwrap_or(22);
        let user = match username {
            Some(u) => u.to_string(),
            None => resolve_username(py, host, port),
        };
        let key_files = load_default_keyfiles(py);
        let system_known_hosts = system_known_hosts_path();
        let dromedary_known_hosts = dromedary_host_keys_path(py);
        let params = ConnectParams {
            host,
            port: port_nr,
            user: &user,
            password,
            key_files: &key_files,
            use_agent: true,
            system_known_hosts: &system_known_hosts,
            dromedary_known_hosts: &dromedary_known_hosts,
        };

        let (mut session, outcome) = py
            .detach(|| Session::connect(&params))
            .map_err(|e| connect_err(host, port_nr, e))?;
        if outcome == AuthOutcome::Authenticated {
            return Ok(session);
        }

        // A cancelled prompt is a hard failure, as in paramiko.py:138.
        let Some(prompt_pw) = prompt_auth_password(py, host, port, &user) else {
            return Err(connect_err(host, port_nr, Error::NoMethodsSucceeded));
        };
        py.detach(|| session.authenticate_password(&user, &prompt_pw))
            .map_err(|e| connect_err(host, port_nr, e))?;
        Ok(session)
    }
}

#[pymethods]
impl RusshVendor {
    #[new]
    fn new() -> Self {
        Self
    }

    /// Open an SFTP session. Returns a fully-constructed `SFTPClient` that
    /// the caller can use directly (same object as `_transport_rs.sftp.
    /// SFTPClient`).
    #[pyo3(signature = (username, password, host, port=None))]
    fn connect_sftp(
        &self,
        py: Python,
        username: Option<&str>,
        password: Option<&str>,
        host: &str,
        port: Option<u16>,
    ) -> PyResult<SFTPClient> {
        let session = Self::connect(py, username, password, host, port)?;
        py.detach(move || {
            let channel: BoxedChannel = Box::new(
                session
                    .open_sftp()
                    .map_err(|e| PyRuntimeError::new_err(format!("open sftp channel: {e}")))?,
            );
            SFTPClient::from_channel(channel)
                .map_err(|e| PyRuntimeError::new_err(format!("sftp init: {e}")))
        })
    }

    /// Execute a remote command and return a connection whose `send` / `recv`
    /// drive the command's stdio. Parallels paramiko's
    /// `_ParamikoSSHConnection`.
    #[pyo3(signature = (username, password, host, command, port=None))]
    fn connect_ssh(
        &self,
        py: Python,
        username: Option<&str>,
        password: Option<&str>,
        host: &str,
        command: Vec<String>,
        port: Option<u16>,
    ) -> PyResult<RusshSSHConnection> {
        let session = Self::connect(py, username, password, host, port)?;
        let channel = py
            .detach(move || session.exec(&command.join(" ")))
            .map_err(|e| PyRuntimeError::new_err(format!("exec: {e}")))?;
        Ok(RusshSSHConnection {
            inner: Mutex::new(Some(channel)),
        })
    }
}

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<RusshVendor>()?;
    m.add_class::<RusshSSHConnection>()?;
    Ok(())
}
