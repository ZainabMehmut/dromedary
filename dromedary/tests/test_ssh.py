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

from dromedary._transport_rs import sftp as _sftp_rs
from dromedary._transport_rs import ssh as _ssh_rs
from dromedary.errors import SocketConnectionError


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

    def test_subprocess_spawn_failure(self):
        vendor = _ssh_rs.OpenSSHSubprocessVendor()
        with tempfile.TemporaryDirectory() as d:
            vendor.executable_path = os.path.join(d, "no-such-ssh")
            with self.assertRaises(SocketConnectionError) as cm:
                vendor.spawn_sftp(None, "example.com", 2222)
        self.assertEqual(":2222", cm.exception.port)

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
            _sftp_rs.SFTPClient(ours.detach())
        self.assertEqual("", cm.exception.port)
