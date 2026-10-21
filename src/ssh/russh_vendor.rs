//! russh-backed SSH client: host-key verification, authentication and a
//! blocking wrapper around russh's async channels.
//!
//! Nothing here calls into Python. The PyO3 wrappers in
//! `_transport_rs/src/ssh/russh_vendor.rs` resolve the username, load key
//! files (prompting for passphrases) and look up config paths, then hand
//! the results to [`Session::connect`].

use russh::keys::Algorithm;
use std::borrow::Cow;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Russh(russh::Error),
    /// The server key differs from the one recorded in a known_hosts file.
    HostKeyMismatch(Box<HostKeyMismatch>),
    /// A known_hosts file could not be read, so the host key can't be
    /// verified.
    KnownHosts {
        path: PathBuf,
        source: russh::keys::Error,
    },
    /// All authentication methods we tried were rejected by the server.
    NoMethodsSucceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Russh(e) => write!(f, "{e}"),
            Error::HostKeyMismatch(m) => write!(f, "{m}"),
            Error::KnownHosts { path, source } => {
                write!(f, "unable to read {}: {source}", path.display())
            }
            Error::NoMethodsSucceeded => f.write_str("no SSH authentication method succeeded"),
        }
    }
}

impl std::error::Error for Error {}

impl From<russh::Error> for Error {
    fn from(e: russh::Error) -> Self {
        Error::Russh(e)
    }
}

#[derive(Debug)]
pub struct HostKeyMismatch {
    pub host: String,
    pub expected_fp: String,
    pub actual_fp: String,
    pub system_path: PathBuf,
    pub dromedary_path: PathBuf,
}

impl fmt::Display for HostKeyMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Host keys for {} do not match!  {} != {}",
            self.host, self.expected_fp, self.actual_fp
        )
    }
}

/// Everything [`Session::connect`] needs, resolved up front by the caller.
pub struct ConnectParams<'a> {
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    /// Tried once agent and key-file authentication have failed.
    pub password: Option<&'a str>,
    pub key_files: &'a [russh::keys::PrivateKey],
    /// Whether to try keys from the SSH agent (`$SSH_AUTH_SOCK`, or Pageant
    /// on Windows).
    pub use_agent: bool,
    /// Normally `~/.ssh/known_hosts`; only read.
    pub system_known_hosts: &'a Path,
    /// Dromedary's own `ssh_host_keys`; unknown host keys are added here.
    pub dromedary_known_hosts: &'a Path,
}

/// Result of [`Session::connect`]. With `NeedsPassword` the server accepts
/// password-style authentication but none of the credentials we had
/// worked; the caller can prompt and call [`Session::authenticate_password`].
#[derive(Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    Authenticated,
    NeedsPassword,
}

/// An SSH connection together with the runtime that drives it.
pub struct Session {
    runtime: Runtime,
    handle: russh::client::Handle<VerifyingHandler>,
}

impl Session {
    /// Connect, verify the host key and try agent keys, key files and the
    /// supplied password, in that order. Mirrors paramiko.py:68-126.
    pub fn connect(params: &ConnectParams) -> Result<(Session, AuthOutcome), Error> {
        let lookup = |path| recorded_host_keys(path, params.host, params.port);
        let mut recorded = lookup(params.system_known_hosts)?;
        recorded.extend(lookup(params.dromedary_known_hosts)?);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(Error::Io)?;

        let config = Arc::new(russh::client::Config {
            inactivity_timeout: Some(Duration::from_secs(3600)),
            preferred: russh::Preferred {
                key: Cow::Owned(preferred_host_key_algorithms(&recorded)),
                ..Default::default()
            },
            ..Default::default()
        });
        let handler = VerifyingHandler {
            host: params.host.to_string(),
            port: params.port,
            system_path: params.system_known_hosts.to_path_buf(),
            dromedary_path: params.dromedary_known_hosts.to_path_buf(),
            recorded,
        };

        let (handle, outcome) = runtime.block_on(async {
            let mut handle =
                russh::client::connect(config, (params.host.to_string(), params.port), handler)
                    .await?;
            let outcome = authenticate_pre_prompt(&mut handle, params).await?;
            Ok::<_, Error>((handle, outcome))
        })?;
        Ok((Session { runtime, handle }, outcome))
    }

    /// Try a password obtained after [`Session::connect`] returned
    /// [`AuthOutcome::NeedsPassword`].
    pub fn authenticate_password(&mut self, user: &str, password: &str) -> Result<(), Error> {
        if self.runtime.block_on(try_password_or_interactive(
            &mut self.handle,
            user,
            password,
        ))? {
            Ok(())
        } else {
            Err(Error::NoMethodsSucceeded)
        }
    }

    /// Open a channel running the `sftp` subsystem.
    pub fn open_sftp(self) -> Result<BlockingChannel, Error> {
        let stream = self.runtime.block_on(async {
            let channel = self.handle.channel_open_session().await?;
            channel.request_subsystem(true, "sftp").await?;
            Ok::<_, Error>(channel.into_stream())
        })?;
        Ok(BlockingChannel::new(self.runtime, stream))
    }

    /// Run `command` on the remote host; the returned channel is connected
    /// to its stdin and stdout.
    pub fn exec(self, command: &str) -> Result<BlockingChannel, Error> {
        let stream = self.runtime.block_on(async {
            let channel = self.handle.channel_open_session().await?;
            channel.exec(true, command).await?;
            Ok::<_, Error>(channel.into_stream())
        })?;
        Ok(BlockingChannel::new(self.runtime, stream))
    }
}

/// Verifies the server key against the user's `~/.ssh/known_hosts` and
/// dromedary's `ssh_host_keys`, recording unknown keys in the latter
/// (trust on first use). Mirrors `ParamikoVendor._connect` at
/// paramiko.py:240 so both backends share the same stores.
struct VerifyingHandler {
    host: String,
    port: u16,
    system_path: PathBuf,
    dromedary_path: PathBuf,
    /// Keys recorded for this host in either file.
    recorded: Vec<russh::keys::PublicKey>,
}

impl russh::client::Handler for VerifyingHandler {
    type Error = Error;

    async fn check_server_key(
        &mut self,
        server_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let server_public_key = match server_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key,
            // We advertise no certificate algorithms, so a server sending a
            // certificate is misbehaving.
            russh::keys::PublicKeyOrCertificate::Certificate(_) => return Ok(false),
        };
        match check_host_key(server_public_key, &self.recorded) {
            HostKeyCheck::Match => Ok(true),
            HostKeyCheck::Unknown => {
                // Only written to dromedary's file, as paramiko's
                // `BRZ_HOSTKEYS.add` + `save_host_keys` did.
                log::warn!(
                    "Adding {} host key for {}: {}",
                    server_public_key.algorithm(),
                    self.host,
                    server_public_key.fingerprint(Default::default())
                );
                if let Err(e) = russh::keys::known_hosts::learn_known_hosts_path(
                    &self.host,
                    self.port,
                    server_public_key,
                    &self.dromedary_path,
                ) {
                    log::debug!(
                        "failed to save host key to {}: {}",
                        self.dromedary_path.display(),
                        e
                    );
                }
                Ok(true)
            }
            HostKeyCheck::Mismatch { expected_fp } => {
                Err(Error::HostKeyMismatch(Box::new(HostKeyMismatch {
                    host: self.host.clone(),
                    expected_fp,
                    actual_fp: server_public_key
                        .fingerprint(Default::default())
                        .to_string(),
                    system_path: self.system_path.clone(),
                    dromedary_path: self.dromedary_path.clone(),
                })))
            }
        }
    }
}

enum HostKeyCheck {
    Match,
    Unknown,
    Mismatch { expected_fp: String },
}

/// The keys recorded for `host` in the known_hosts file at `path`.
///
/// russh treats a file it can't open as having no entries, so check that
/// first: only a missing file may be skipped. Errors reading the file or
/// parsing an entry for the host abort the connection rather than letting
/// the host be treated as unknown.
fn recorded_host_keys(
    path: &Path,
    host: &str,
    port: u16,
) -> Result<Vec<russh::keys::PublicKey>, Error> {
    let error = |source| Error::KnownHosts {
        path: path.to_path_buf(),
        source,
    };
    match std::fs::File::open(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(error(e.into())),
    }
    let entries =
        russh::keys::known_hosts::known_host_keys_path(host, port, path).map_err(error)?;
    Ok(entries.into_iter().map(|(_, key)| key).collect())
}

/// Check the server key against the keys recorded in both files. A
/// different key in either file is fatal, even one of another type: an
/// attacker could otherwise present a key of a type we have no record of.
/// An entry only in the system file is acceptable without writing to the
/// dromedary file.
fn check_host_key(
    key: &russh::keys::PublicKey,
    recorded: &[russh::keys::PublicKey],
) -> HostKeyCheck {
    if recorded.iter().any(|r| r.key_data() == key.key_data()) {
        return HostKeyCheck::Match;
    }
    if recorded.is_empty() {
        return HostKeyCheck::Unknown;
    }
    // Show the recorded key of the same type if there is one, otherwise all
    // of them.
    let mut shown: Vec<_> = recorded
        .iter()
        .filter(|r| same_key_type(&r.algorithm(), &key.algorithm()))
        .collect();
    if shown.is_empty() {
        shown = recorded.iter().collect();
    }
    let expected_fp = shown
        .iter()
        .map(|r| r.fingerprint(Default::default()).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    HostKeyCheck::Mismatch { expected_fp }
}

/// RSA keys are the same type whichever signature hash is negotiated.
fn same_key_type(a: &Algorithm, b: &Algorithm) -> bool {
    matches!((a, b), (Algorithm::Rsa { .. }, Algorithm::Rsa { .. })) || a == b
}

/// russh's default host key algorithms, with the types we have recorded
/// for this host moved to the front, as OpenSSH does. Otherwise a server
/// with several host keys could present one we have no record of.
fn preferred_host_key_algorithms(recorded: &[russh::keys::PublicKey]) -> Vec<Algorithm> {
    let mut algorithms = russh::Preferred::DEFAULT.key.to_vec();
    algorithms.sort_by_key(|a| !recorded.iter().any(|r| same_key_type(&r.algorithm(), a)));
    algorithms
}

/// Wraps an async `ChannelStream` so it can be driven by synchronous SFTP
/// code. Each `read` / `write` call `block_on`s the owned runtime.
///
/// This must be the runtime that performed the SSH handshake, otherwise
/// the tasks russh spawned for the session would never be polled.
pub struct BlockingChannel {
    runtime: Runtime,
    /// Only `None` while being dropped.
    stream: Option<russh::ChannelStream<russh::client::Msg>>,
}

impl BlockingChannel {
    fn new(runtime: Runtime, stream: russh::ChannelStream<russh::client::Msg>) -> Self {
        Self {
            runtime,
            stream: Some(stream),
        }
    }
}

impl Drop for BlockingChannel {
    fn drop(&mut self) {
        // Dropping a ChannelStream calls `tokio::spawn` to send the channel
        // close, which panics outside a runtime context.
        let _guard = self.runtime.enter();
        self.stream.take();
    }
}

impl Read for BlockingChannel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let stream = self.stream.as_mut().unwrap();
        self.runtime.block_on(stream.read(buf))
    }
}

impl Write for BlockingChannel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let stream = self.stream.as_mut().unwrap();
        self.runtime.block_on(stream.write(buf))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let stream = self.stream.as_mut().unwrap();
        self.runtime.block_on(stream.flush())
    }
}

type ClientHandle = russh::client::Handle<VerifyingHandler>;

async fn authenticate_pre_prompt(
    handle: &mut ClientHandle,
    params: &ConnectParams<'_>,
) -> Result<AuthOutcome, Error> {
    if params.use_agent && try_agent_auth(handle, params.user).await? {
        return Ok(AuthOutcome::Authenticated);
    }

    if try_keyfile_auth(handle, params.user, params.key_files).await? {
        return Ok(AuthOutcome::Authenticated);
    }

    // auth_none probe: unlikely to succeed, but its `remaining_methods`
    // tells us whether password-style auth is even accepted. If it's not,
    // paramiko.py:116 raises ConnectionError.
    let remaining = match handle.authenticate_none(params.user.to_string()).await? {
        russh::client::AuthResult::Success => return Ok(AuthOutcome::Authenticated),
        russh::client::AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    };
    if !password_style_accepted(&remaining) {
        log::debug!(
            "server does not accept password or keyboard-interactive; remaining: {:?}",
            remaining
        );
        return Err(Error::NoMethodsSucceeded);
    }

    if let Some(pw) = params.password {
        if try_password_or_interactive(handle, params.user, pw).await? {
            return Ok(AuthOutcome::Authenticated);
        }
    }

    Ok(AuthOutcome::NeedsPassword)
}

fn password_style_accepted(methods: &russh::MethodSet) -> bool {
    methods.iter().any(|m| {
        matches!(
            m,
            russh::MethodKind::Password | russh::MethodKind::KeyboardInteractive
        )
    })
}

/// Try `authenticate_password`; on failure, fall back to
/// `keyboard-interactive` with the password as the sole response. This
/// mirrors paramiko's `auth_password` which transparently does the same.
async fn try_password_or_interactive(
    handle: &mut ClientHandle,
    user: &str,
    password: &str,
) -> Result<bool, Error> {
    if let russh::client::AuthResult::Success = handle
        .authenticate_password(user.to_string(), password)
        .await?
    {
        return Ok(true);
    }

    // We blindly respond to the first InfoRequest with one copy of the
    // password per prompt. Servers that ask anything beyond a password
    // aren't supported (paramiko has the same limitation, see the XXX at
    // paramiko.py:109).
    match handle
        .authenticate_keyboard_interactive_start(user.to_string(), None)
        .await?
    {
        russh::client::KeyboardInteractiveAuthResponse::Success => Ok(true),
        russh::client::KeyboardInteractiveAuthResponse::Failure { .. } => Ok(false),
        russh::client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
            let responses = vec![password.to_string(); prompts.len()];
            match handle
                .authenticate_keyboard_interactive_respond(responses)
                .await?
            {
                russh::client::KeyboardInteractiveAuthResponse::Success => Ok(true),
                _ => Ok(false),
            }
        }
    }
}

/// Enumerate keys from the SSH agent and try each in turn. An unreachable
/// agent is not an error, matching paramiko: agent failures never block
/// other auth methods.
#[cfg(unix)]
async fn try_agent_auth(handle: &mut ClientHandle, user: &str) -> Result<bool, Error> {
    let agent = match russh::keys::agent::client::AgentClient::connect_env().await {
        Ok(a) => a,
        Err(e) => {
            log::debug!("SSH agent unavailable: {e}");
            return Ok(false);
        }
    };
    try_agent_auth_with(handle, user, agent).await
}

#[cfg(windows)]
async fn try_agent_auth(handle: &mut ClientHandle, user: &str) -> Result<bool, Error> {
    let agent = match russh::keys::agent::client::AgentClient::connect_pageant().await {
        Ok(a) => a,
        Err(e) => {
            log::debug!("Pageant unavailable: {e}");
            return Ok(false);
        }
    };
    try_agent_auth_with(handle, user, agent).await
}

async fn try_agent_auth_with<S>(
    handle: &mut ClientHandle,
    user: &str,
    mut agent: russh::keys::agent::client::AgentClient<S>,
) -> Result<bool, Error>
where
    S: russh::keys::agent::client::AgentStream + Unpin + Send + 'static,
{
    let identities = match agent.request_identities().await {
        Ok(ids) => ids,
        Err(e) => {
            log::debug!("SSH agent request_identities failed: {e}");
            return Ok(false);
        }
    };

    for identity in identities {
        let key = identity.public_key().into_owned();
        log::debug!(
            "Trying SSH agent key {} ({})",
            key.fingerprint(Default::default()),
            key.algorithm()
        );
        match handle
            .authenticate_publickey_with(user.to_string(), key, None, &mut agent)
            .await
        {
            Ok(auth) if auth.success() => return Ok(true),
            Ok(_) => continue,
            Err(e) => {
                // Signer problems with one key don't rule out the others.
                log::debug!("agent key auth attempt failed: {e}");
                continue;
            }
        }
    }
    Ok(false)
}

/// Try each preloaded key file in turn. RSA keys negotiate the strongest
/// hash algorithm the server advertises (falling back to SHA-1 when the
/// server doesn't send `server-sig-algs`).
async fn try_keyfile_auth(
    handle: &mut ClientHandle,
    user: &str,
    key_files: &[russh::keys::PrivateKey],
) -> Result<bool, Error> {
    if key_files.is_empty() {
        return Ok(false);
    }

    // `Some(Some(alg))` = server wants this hash; `Some(None)` = server
    // only supports SHA-1; `None` = server didn't advertise, try SHA-1.
    let rsa_hash = handle
        .best_supported_rsa_hash()
        .await
        .ok()
        .flatten()
        .flatten();

    for key in key_files {
        let with_hash = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key.clone()), rsa_hash);
        log::debug!(
            "Trying key file ({}) fingerprint {}",
            key.algorithm(),
            key.fingerprint(Default::default())
        );
        match handle
            .authenticate_publickey(user.to_string(), with_hash)
            .await
        {
            Ok(auth) if auth.success() => return Ok(true),
            Ok(_) => continue,
            Err(e) => {
                log::debug!("key file auth attempt failed: {e}");
                continue;
            }
        }
    }
    Ok(false)
}

/// `~/.ssh/known_hosts` (on Windows: `~/ssh/known_hosts`, matching
/// russh's own `known_hosts_path`). Falls back to a path that doesn't
/// exist when `$HOME` is unset; `check_known_hosts_path` treats a missing
/// file as "no entries".
pub fn system_known_hosts_path() -> PathBuf {
    match home_dir() {
        Some(h) if cfg!(windows) => h.join("ssh").join("known_hosts"),
        Some(h) => h.join(".ssh").join("known_hosts"),
        None => PathBuf::from("/nonexistent/known_hosts"),
    }
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::server::{Auth, Msg, Server as _};
    use std::net::SocketAddr;

    const HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAjXNygcVylJHGyxhFFUAkNvqHd0OV5yQQdLaFKyOhPMQAAAIgn6RX5J+kV
+QAAAAtzc2gtZWQyNTUxOQAAACAjXNygcVylJHGyxhFFUAkNvqHd0OV5yQQdLaFKyOhPMQ
AAAEDcmyfW822twVPjYXoyl5kck3AEzqs9DQ6bJZnmOsor5SNc3KBxXKUkcbLGEUVQCQ2+
od3Q5XnJBB0toUrI6E8xAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
";
    const HOST_KEY_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICNc3KBxXKUkcbLGEUVQCQ2+od3Q5XnJBB0toUrI6E8x";

    const ECDSA_HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQNRImQBDExQP0XLQrof2hLHdjFYQaT
pylm+T93kLOzkA5TbCDHeKu7Osp/bB++NIwQ+0xAG1fjFTgtrbOr3mv1AAAAmIInrJ2CJ6
ydAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA1EiZAEMTFA/Rct
Cuh/aEsd2MVhBpOnKWb5P3eQs7OQDlNsIMd4q7s6yn9sH740jBD7TEAbV+MVOC2ts6vea/
UAAAAgcP59plQ809jMyiJ+SSnB4DZYAqqsKvHXy/72Zn61vtIAAAAA
-----END OPENSSH PRIVATE KEY-----
";
    const ECDSA_HOST_KEY_PUB: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA1EiZAEMTFA/RctCuh/aEsd2MVhBpOnKWb5P3eQs7OQDlNsIMd4q7s6yn9sH740jBD7TEAbV+MVOC2ts6vea/U=";

    const CLIENT_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAtDraz/I3X9mEAPOprNcRYFI/eXG6DMQJqDU/TsxsXsQAAAIg9nHUkPZx1
JAAAAAtzc2gtZWQyNTUxOQAAACAtDraz/I3X9mEAPOprNcRYFI/eXG6DMQJqDU/TsxsXsQ
AAAECs6o9oW7PLKo5Jnn6nEcP3c9+zOvPS+BZlH43bqrYXXy0OtrP8jdf2YQA86ms1xFgU
j95cboMxAmoNT9OzGxexAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
";
    const CLIENT_KEY_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC0OtrP8jdf2YQA86ms1xFgUj95cboMxAmoNT9OzGxex";

    fn private_key(s: &str) -> russh::keys::PrivateKey {
        russh::keys::PrivateKey::from_openssh(s).unwrap()
    }

    fn public_key(s: &str) -> russh::keys::PublicKey {
        russh::keys::PublicKey::from_openssh(s).unwrap()
    }

    /// Accepts the password "secret" and `CLIENT_KEY`; `exec` echoes the
    /// command line back and closes the channel.
    #[derive(Clone)]
    struct TestServer;

    impl russh::server::Server for TestServer {
        type Handler = Self;
        fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl russh::server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            password: &str,
        ) -> Result<Auth, Self::Error> {
            if password == "secret" {
                Ok(Auth::Accept)
            } else {
                // Keep password on offer, like OpenSSH; `Auth::reject()`
                // would remove it after the first failure.
                Ok(Auth::Reject {
                    proceed_with_methods: Some((&[russh::MethodKind::Password][..]).into()),
                    partial_success: false,
                })
            }
        }

        async fn auth_publickey(
            &mut self,
            _user: &str,
            key: &russh::keys::PublicKey,
        ) -> Result<Auth, Self::Error> {
            if key.key_data() == public_key(CLIENT_KEY_PUB).key_data() {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::reject())
            }
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            session.data(channel, data.to_vec())?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    /// Start `TestServer` on an ephemeral localhost port in a background
    /// thread. The thread is leaked; it exits with the test process.
    fn start_server(methods: &[russh::MethodKind]) -> u16 {
        start_server_with_host_keys(methods, &[HOST_KEY])
    }

    fn start_server_with_host_keys(methods: &[russh::MethodKind], host_keys: &[&str]) -> u16 {
        let config = Arc::new(russh::server::Config {
            methods: methods.into(),
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: host_keys.iter().map(|k| private_key(k)).collect(),
            ..Default::default()
        });
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap().port()).unwrap();
                TestServer.run_on_socket(config, &listener).await.unwrap();
            });
        });
        rx.recv().unwrap()
    }

    struct KnownHosts {
        _dir: tempfile::TempDir,
        system: PathBuf,
        dromedary: PathBuf,
    }

    fn known_hosts() -> KnownHosts {
        let dir = tempfile::tempdir().unwrap();
        KnownHosts {
            system: dir.path().join("known_hosts"),
            dromedary: dir.path().join("ssh_host_keys"),
            _dir: dir,
        }
    }

    fn params<'a>(
        port: u16,
        password: Option<&'a str>,
        key_files: &'a [russh::keys::PrivateKey],
        kh: &'a KnownHosts,
    ) -> ConnectParams<'a> {
        ConnectParams {
            host: "127.0.0.1",
            port,
            user: "alice",
            password,
            key_files,
            use_agent: false,
            system_known_hosts: &kh.system,
            dromedary_known_hosts: &kh.dromedary,
        }
    }

    fn read_to_end(mut ch: BlockingChannel) -> Vec<u8> {
        let mut out = Vec::new();
        ch.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn supplied_password_authenticates() {
        let port = start_server(&[russh::MethodKind::Password]);
        let kh = known_hosts();
        let (session, outcome) = Session::connect(&params(port, Some("secret"), &[], &kh)).unwrap();
        assert_eq!(outcome, AuthOutcome::Authenticated);
        assert_eq!(read_to_end(session.exec("echo hi").unwrap()), b"echo hi");
    }

    #[test]
    fn wrong_password_needs_prompt() {
        let port = start_server(&[russh::MethodKind::Password]);
        let kh = known_hosts();
        let (mut session, outcome) =
            Session::connect(&params(port, Some("wrong"), &[], &kh)).unwrap();
        assert_eq!(outcome, AuthOutcome::NeedsPassword);
        assert!(matches!(
            session.authenticate_password("alice", "also wrong"),
            Err(Error::NoMethodsSucceeded)
        ));
        session.authenticate_password("alice", "secret").unwrap();
        assert_eq!(read_to_end(session.exec("true").unwrap()), b"true");
    }

    #[test]
    fn no_password_needs_prompt() {
        let port = start_server(&[russh::MethodKind::Password]);
        let kh = known_hosts();
        let (_, outcome) = Session::connect(&params(port, None, &[], &kh)).unwrap();
        assert_eq!(outcome, AuthOutcome::NeedsPassword);
    }

    #[test]
    fn key_file_authenticates() {
        let port = start_server(&[russh::MethodKind::PublicKey]);
        let kh = known_hosts();
        let keys = [private_key(CLIENT_KEY)];
        let (_, outcome) = Session::connect(&params(port, None, &keys, &kh)).unwrap();
        assert_eq!(outcome, AuthOutcome::Authenticated);
    }

    #[test]
    fn password_not_accepted_by_server() {
        let port = start_server(&[russh::MethodKind::PublicKey]);
        let kh = known_hosts();
        assert!(matches!(
            Session::connect(&params(port, Some("secret"), &[], &kh)),
            Err(Error::NoMethodsSucceeded)
        ));
    }

    #[test]
    fn unknown_host_key_is_recorded() {
        let port = start_server(&[russh::MethodKind::Password]);
        let kh = known_hosts();
        Session::connect(&params(port, Some("secret"), &[], &kh)).unwrap();
        assert!(!kh.system.exists());
        assert_eq!(
            recorded_host_keys(&kh.dromedary, "127.0.0.1", port).unwrap(),
            vec![public_key(HOST_KEY_PUB)]
        );
    }

    #[test]
    fn missing_known_hosts_has_no_entries() {
        let kh = known_hosts();
        assert_eq!(
            recorded_host_keys(&kh.system, "127.0.0.1", 22).unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn unreadable_known_hosts_is_rejected() {
        let port = start_server(&[russh::MethodKind::Password]);
        let kh = known_hosts();
        // Reading a directory fails even when running as root.
        std::fs::create_dir(&kh.system).unwrap();
        match Session::connect(&params(port, Some("secret"), &[], &kh)) {
            Err(Error::KnownHosts { path, .. }) => assert_eq!(path, kh.system),
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("connected with unreadable known_hosts"),
        }
        assert!(!kh.dromedary.exists());
    }

    #[test]
    fn unparsable_entry_does_not_hide_mismatch() {
        let port = start_server(&[russh::MethodKind::Password]);
        let kh = known_hosts();
        std::fs::write(
            &kh.system,
            format!(
                "[127.0.0.1]:{port} {CLIENT_KEY_PUB}\n[127.0.0.1]:{port} ssh-ed25519 not-base64!\n"
            ),
        )
        .unwrap();
        match Session::connect(&params(port, Some("secret"), &[], &kh)) {
            Err(Error::KnownHosts { path, .. }) => assert_eq!(path, kh.system),
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("connected despite unparsable known_hosts entry"),
        }
        assert!(!kh.dromedary.exists());
    }

    #[test]
    fn host_key_mismatch_is_rejected() {
        let port = start_server(&[russh::MethodKind::Password]);
        let kh = known_hosts();
        let recorded = public_key(CLIENT_KEY_PUB);
        russh::keys::known_hosts::learn_known_hosts_path("127.0.0.1", port, &recorded, &kh.system)
            .unwrap();
        match Session::connect(&params(port, Some("secret"), &[], &kh)) {
            Err(Error::HostKeyMismatch(m)) => {
                assert_eq!(m.host, "127.0.0.1");
                assert_eq!(
                    m.expected_fp,
                    recorded.fingerprint(Default::default()).to_string()
                );
                assert_eq!(
                    m.actual_fp,
                    public_key(HOST_KEY_PUB)
                        .fingerprint(Default::default())
                        .to_string()
                );
            }
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("connected despite host key mismatch"),
        }
        assert!(!kh.dromedary.exists());
    }

    #[test]
    fn host_key_in_system_file_is_not_copied() {
        let port = start_server(&[russh::MethodKind::Password]);
        let kh = known_hosts();
        russh::keys::known_hosts::learn_known_hosts_path(
            "127.0.0.1",
            port,
            &public_key(HOST_KEY_PUB),
            &kh.system,
        )
        .unwrap();
        Session::connect(&params(port, Some("secret"), &[], &kh)).unwrap();
        assert!(!kh.dromedary.exists());
    }

    #[test]
    fn host_key_of_unrecorded_type_is_rejected() {
        let port = start_server(&[russh::MethodKind::Password]);
        let kh = known_hosts();
        let recorded = public_key(ECDSA_HOST_KEY_PUB);
        russh::keys::known_hosts::learn_known_hosts_path("127.0.0.1", port, &recorded, &kh.system)
            .unwrap();
        match Session::connect(&params(port, Some("secret"), &[], &kh)) {
            Err(Error::HostKeyMismatch(m)) => assert_eq!(
                m.expected_fp,
                recorded.fingerprint(Default::default()).to_string()
            ),
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("connected despite host key of unrecorded type"),
        }
        assert!(!kh.dromedary.exists());
    }

    #[test]
    fn recorded_host_key_type_is_preferred() {
        // The server offers Ed25519 first, which russh would otherwise pick.
        let port = start_server_with_host_keys(
            &[russh::MethodKind::Password],
            &[HOST_KEY, ECDSA_HOST_KEY],
        );
        let kh = known_hosts();
        russh::keys::known_hosts::learn_known_hosts_path(
            "127.0.0.1",
            port,
            &public_key(ECDSA_HOST_KEY_PUB),
            &kh.system,
        )
        .unwrap();
        Session::connect(&params(port, Some("secret"), &[], &kh)).unwrap();
        assert!(!kh.dromedary.exists());
    }

    #[test]
    fn preferred_algorithms_put_recorded_types_first() {
        let default = russh::Preferred::DEFAULT.key.to_vec();
        assert_eq!(preferred_host_key_algorithms(&[]), default);
        let algorithms = preferred_host_key_algorithms(&[public_key(ECDSA_HOST_KEY_PUB)]);
        assert_eq!(
            algorithms[0],
            Algorithm::Ecdsa {
                curve: russh::keys::EcdsaCurve::NistP256
            }
        );
        assert_eq!(algorithms.len(), default.len());
    }
}
