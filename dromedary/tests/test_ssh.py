# Copyright (C) 2026 Jelmer Vernooĳ <jelmer@jelmer.uk>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

"""Tests for errors raised by the Rust SSH and SFTP layers."""

import os
import socket
import sys
import tempfile
import unittest
from unittest import mock

from dromedary import tests as features
from dromedary._transport_rs import sftp as _sftp_rs
from dromedary._transport_rs import ssh as _ssh_rs
from dromedary.errors import SocketConnectionError, TransportError


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestConnectionErrors(unittest.TestCase):
    @unittest.skipIf(sys.platform == "win32", "spawn_sftp returns an fd")
    def test_loopback_refused(self):
        port = closed_port()
        with self.assertRaises(SocketConnectionError) as cm:
            _ssh_rs.LoopbackVendor().spawn_sftp("127.0.0.1", port)
        self.assertEqual(f":{port}", cm.exception.port)

    @unittest.skipIf(sys.platform == "win32", "spawn_sftp returns an fd")
    def test_subprocess_spawn_failure(self):
        vendor = _ssh_rs.OpenSSHSubprocessVendor()
        with tempfile.TemporaryDirectory() as d:
            vendor.executable_path = os.path.join(d, "no-such-ssh")
            with self.assertRaises(SocketConnectionError) as cm:
                vendor.spawn_sftp(None, "example.com", 2222)
        self.assertEqual(":2222", cm.exception.port)

    @unittest.skipIf(sys.platform == "win32", "spawn_sftp returns an fd")
    def test_subprocess_spawn_failure_without_port(self):
        vendor = _ssh_rs.OpenSSHSubprocessVendor()
        with tempfile.TemporaryDirectory() as d:
            vendor.executable_path = os.path.join(d, "no-such-ssh")
            with self.assertRaises(SocketConnectionError) as cm:
                vendor.spawn_sftp(None, "example.com")
        self.assertEqual("", cm.exception.port)

    @unittest.skipIf(sys.platform == "win32", "SFTPClient takes an fd")
    def test_sftp_peer_gone(self):
        ours, theirs = socket.socketpair()
        theirs.close()
        with self.assertRaises(SocketConnectionError) as cm:
            _sftp_rs.SFTPClient(ours.detach(), "example.com", 2222)
        self.assertEqual("example.com", cm.exception.host)
        self.assertEqual(":2222", cm.exception.port)


class TestRusshHostKeys(unittest.TestCase):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = tmp.name
        patcher = mock.patch.dict(
            os.environ,
            {
                "HOME": self.home,
                "XDG_CONFIG_HOME": os.path.join(self.home, ".config"),
                "SSH_AUTH_SOCK": "",
            },
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    @unittest.skipIf(sys.platform == "win32", "known_hosts lives elsewhere")
    def test_unreadable_known_hosts(self):
        # A directory can't be read as a file.
        os.makedirs(os.path.join(self.home, ".ssh", "known_hosts"))
        with self.assertRaises(TransportError) as cm:
            _ssh_rs.RusshVendor().connect_ssh(
                "alice", None, "127.0.0.1", ["true"], port=closed_port()
            )
        known_hosts = os.path.join(self.home, ".ssh", "known_hosts")
        self.assertEqual("Unable to verify host key for 127.0.0.1", cm.exception.msg)
        self.assertEqual(
            f"unable to read {known_hosts}: Is a directory (os error 21)",
            cm.exception.orig_error,
        )

    def start_sftp_server(self):
        if not features.paramiko.available():
            self.skipTest("paramiko is not available")
        from dromedary.tests import stub_sftp

        cwd = os.getcwd()
        os.chdir(self.home)
        self.addCleanup(os.chdir, cwd)
        server = stub_sftp.SFTPFullAbsoluteServer()
        server.start_server()
        self.addCleanup(server.stop_server)
        return server

    def test_new_host_key_is_logged(self):
        server = self.start_sftp_server()
        with self.assertLogs("dromedary.ssh.russh_vendor", "WARNING") as cm:
            client = _ssh_rs.RusshVendor().connect_sftp(
                "foo", "bar", server.host, port=server.port
            )
        client.close()
        fingerprint = server.get_host_key().fingerprint
        self.assertEqual(
            [
                "WARNING:dromedary.ssh.russh_vendor:"
                f"Adding ssh-rsa host key for 127.0.0.1: {fingerprint}"
            ],
            cm.output,
        )

    @unittest.skipIf(
        sys.platform == "win32" or os.geteuid() == 0,
        "needs directory permissions to apply",
    )
    def test_unsaved_host_key_is_logged(self):
        server = self.start_sftp_server()
        config_dir = os.path.join(self.home, ".config", "breezy")
        os.makedirs(config_dir)
        os.chmod(config_dir, 0o500)
        self.addCleanup(os.chmod, config_dir, 0o700)
        host_keys = os.path.join(config_dir, "ssh_host_keys")
        with self.assertLogs("dromedary.ssh.russh_vendor", "WARNING") as cm:
            client = _ssh_rs.RusshVendor().connect_sftp(
                "foo", "bar", server.host, port=server.port
            )
        client.close()
        fingerprint = server.get_host_key().fingerprint
        self.assertEqual(
            [
                "WARNING:dromedary.ssh.russh_vendor:"
                f"Adding ssh-rsa host key for 127.0.0.1: {fingerprint}",
                "WARNING:dromedary.ssh.russh_vendor:"
                f"Unable to save host key for 127.0.0.1 to {host_keys}: "
                "Permission denied (os error 13)",
            ],
            cm.output,
        )
