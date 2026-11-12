# Copyright (C) 2026  Paramiko open source project
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Unit tests for SSHClient host-key verification semantics.

These tests deliberately avoid real sockets: a fake Transport stands in for
the network layer, keys are generated/fixed locally, and known_hosts files
are real temporary files.  They cover StrictHostKeyChecking-style policies,
key rotation (same type and cross-algorithm), port aliases, deterministic
ordering when several key algorithms are stored, and concurrent connections
sharing one client's key stores.
"""

import os
import tempfile
import threading
import unittest

import paramiko
from paramiko import SSHClient
from paramiko.client import AcceptNewPolicy
from paramiko.ssh_exception import BadHostKeyException, SSHException


class FakeSecurityOptions:
    def __init__(self, key_types):
        self.key_types = list(key_types)


class FakeTransport:
    """
    Minimal Transport double exercising only what SSHClient.connect touches
    before authentication.
    """

    DEFAULT_KEY_TYPES = (
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "rsa-sha2-256",
    )

    def __init__(self, sock, disabled_algorithms=None, server_key=None):
        self._sock = sock
        self.disabled_algorithms = disabled_algorithms or {}
        self._server_key = server_key
        self._sec = FakeSecurityOptions(self.DEFAULT_KEY_TYPES)
        self.started = False
        self.closed = False

    def use_compression(self, compress=False):
        pass

    def set_log_channel(self, name):
        pass

    def get_security_options(self):
        return self._sec

    def start_client(self, timeout=None):
        self.started = True

    def get_remote_server_key(self):
        return self._server_key

    def _log(self, level, msg):
        pass

    # The host-key stage ends successfully; these stub out the legacy auth
    # flow so connect() returns cleanly instead of dying on auth.
    def auth_publickey(self, username, key):
        return []

    def auth_password(self, username, password):
        return []

    def auth_interactive_dumb(self, username):
        return []

    def is_authenticated(self):
        return True

    def close(self):
        self.closed = True


class ClientHostKeyPolicyTest(unittest.TestCase):
    def setUp(self):
        self.rsa = paramiko.RSAKey.generate(2048)
        self.rsa_rotated = paramiko.RSAKey.generate(2048)
        self.ecdsa = paramiko.ECDSAKey.generate()
        self.ed25519 = paramiko.Ed25519Key.from_private_key_file(
            os.path.join(os.path.dirname(__file__), "_support", "ed25519.key")
        )
        self.hostname = "unit-test.example.com"
        fd, self.known_hosts_path = tempfile.mkstemp()
        os.close(fd)

    def tearDown(self):
        if os.path.exists(self.known_hosts_path):
            os.unlink(self.known_hosts_path)

    def _factory(self, server_key=None, transport_class=FakeTransport):
        key = server_key if server_key is not None else self.rsa

        def factory(sock, disabled_algorithms=None):
            return transport_class(
                sock,
                disabled_algorithms=disabled_algorithms,
                server_key=key,
            )

        return factory

    def _client(self, policy=None, server_key=None):
        client = SSHClient()
        if policy is not None:
            client.set_missing_host_key_policy(policy)
        return client, self._factory(server_key)

    def _connect(self, client, factory, port=22):
        # sock=... bypasses all real socket code
        client.connect(
            hostname=self.hostname,
            port=port,
            username="tester",
            password="test-password",
            sock=object(),
            transport_factory=factory,
            look_for_keys=False,
            allow_agent=False,
        )

    # ---- StrictHostKeyChecking semantics --------------------------------

    def test_default_reject_policy_refuses_unknown_host(self):
        client, factory = self._client(server_key=self.rsa)
        with self.assertRaises(SSHException):
            self._connect(client, factory)

    def test_auto_add_policy_records_unknown_host(self):
        client, factory = self._client(
            paramiko.AutoAddPolicy(), server_key=self.rsa
        )
        client.load_host_keys(self.known_hosts_path)
        self._connect(client, factory)
        self.assertIn(self.hostname, client.get_host_keys())
        # And it was persisted to the backing file
        with open(self.known_hosts_path) as f:
            self.assertIn(self.hostname, f.read())
        # A fresh client loading the file now sees the host as known
        reloaded = SSHClient()
        reloaded.load_host_keys(self.known_hosts_path)
        self.assertIn(self.hostname, reloaded.get_host_keys())

    def test_accept_new_policy_adds_only_when_fully_unknown(self):
        client = SSHClient()
        client.set_missing_host_key_policy(AcceptNewPolicy())
        client.load_host_keys(self.known_hosts_path)
        factory = self._factory(self.rsa)
        self._connect(client, factory)
        self.assertIn(self.hostname, client.get_host_keys())

    def test_accept_new_policy_refuses_rotation_to_new_type(self):
        # Known via RSA, server presents ECDSA: accept-new must not append
        client = SSHClient()
        client.set_missing_host_key_policy(AcceptNewPolicy())
        client.get_host_keys().add(self.hostname, "ssh-rsa", self.rsa)
        factory = self._factory(self.ecdsa)
        with self.assertRaises(BadHostKeyException):
            self._connect(client, factory)
        # Nothing for the new type was written
        self.assertNotIn(
            "ecdsa-sha2-nistp256", client.get_host_keys()[self.hostname]
        )

    def test_auto_add_policy_also_refuses_known_host_mismatch(self):
        # AutoAdd's "add" only runs for genuinely unknown hosts; a known host
        # presenting a different key must still raise.
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.get_host_keys().add(self.hostname, "ssh-rsa", self.rsa)
        factory = self._factory(self.rsa_rotated)
        with self.assertRaises(BadHostKeyException):
            self._connect(client, factory)

    # ---- Rotation --------------------------------------------------------

    def test_same_type_rotation_is_bad_host_key(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.get_host_keys().add(self.hostname, "ssh-rsa", self.rsa)
        factory = self._factory(self.rsa_rotated)
        with self.assertRaises(BadHostKeyException) as cm:
            self._connect(client, factory)
        self.assertEqual(cm.exception.key, self.rsa_rotated)
        self.assertEqual(cm.exception.expected_key, self.rsa)

    def test_known_host_new_algorithm_is_bad_host_key_not_missing(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.get_host_keys().add(self.hostname, "ssh-rsa", self.rsa)
        factory = self._factory(self.ecdsa)
        with self.assertRaises(BadHostKeyException):
            self._connect(client, factory)

    def test_matching_key_succeeds_under_reject_policy(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.get_host_keys().add(self.hostname, "ssh-rsa", self.rsa)
        factory = self._factory(self.rsa)
        # Would proceed to auth (which fails on the fake) but host-key
        # verification itself passes; assert no BadHostKeyException.
        try:
            self._connect(client, factory)
        except BadHostKeyException:
            self.fail("Matching key must not raise BadHostKeyException")
        except SSHException:
            # Auth stage on the fake transport -- host key stage already won
            pass

    # ---- Deterministic multi-algorithm handling --------------------------

    def test_known_key_types_reorder_transport_preferences(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.get_host_keys().add(
            self.hostname, "ecdsa-sha2-nistp256", self.ecdsa
        )
        client.get_host_keys().add(self.hostname, "ssh-ed25519", self.ed25519)
        captured = {}

        class CapturingTransport(FakeTransport):
            def get_security_options(self_inner):
                sec = super().get_security_options()
                captured["sec"] = sec
                return sec

        factory = self._factory(self.ecdsa, CapturingTransport)
        try:
            self._connect(client, factory)
        except (SSHException, BadHostKeyException):
            pass
        # Both known types come first, deterministically, in known_hosts order
        self.assertEqual(
            captured["sec"].key_types[:2],
            ["ecdsa-sha2-nistp256", "ssh-ed25519"],
        )
        # The remaining supported algorithms trail after them
        self.assertEqual(
            captured["sec"].key_types[2:],
            [
                "rsa-sha2-512",
                "rsa-sha2-256",
            ],
        )

    def test_rsa_known_host_maps_to_sha2_algorithm(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.get_host_keys().add(self.hostname, "ssh-rsa", self.rsa)
        captured = {}

        class CapturingTransport(FakeTransport):
            def get_security_options(self_inner):
                sec = super().get_security_options()
                captured["sec"] = sec
                return sec

        factory = self._factory(self.rsa, CapturingTransport)
        try:
            self._connect(client, factory)
        except (SSHException, BadHostKeyException):
            pass
        self.assertEqual(captured["sec"].key_types[0], "rsa-sha2-512")

    # ---- Port aliases ----------------------------------------------------

    def test_port_alias_requires_bracket_form(self):
        port = 2222
        alias = "[{}]:{}".format(self.hostname, port)
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.get_host_keys().add(alias, "ssh-rsa", self.rsa)
        good_factory = self._factory(self.rsa)
        try:
            self._connect(client, good_factory, port=port)
        except BadHostKeyException:
            self.fail("Bracketed port alias must match")
        except SSHException:
            pass
        # The same key on the default port must still be unknown (rejected)
        client2 = SSHClient()
        client2.set_missing_host_key_policy(paramiko.RejectPolicy())
        client2.get_host_keys().add(alias, "ssh-rsa", self.rsa)
        with self.assertRaises(SSHException):
            self._connect(client2, good_factory, port=22)

    # ---- Wildcard / negation patterns ------------------------------------

    def test_wildcard_known_hosts_entry_matches(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.get_host_keys().add("*.suffix.example.com", "ssh-rsa", self.rsa)
        # The wildcard host verifies successfully
        self.hostname = "host.suffix.example.com"
        factory = self._factory(self.rsa)
        try:
            self._connect(client, factory)
        except BadHostKeyException:
            self.fail("Wildcard known_hosts entry must verify")
        except SSHException:
            pass

    def test_negated_wildcard_host_is_treated_as_unknown(self):
        client = SSHClient()
        # RejectPolicy + negation: the wildcard is vetoed, host becomes
        # unknown and the reject policy fires
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.get_host_keys().add("*.neg.example.com", "ssh-rsa", self.rsa)
        client.get_host_keys().add(
            "!host.neg.example.com", "ssh-rsa", self.rsa
        )
        self.hostname = "host.neg.example.com"
        factory = self._factory(self.rsa)
        with self.assertRaises(SSHException):
            self._connect(client, factory)
        # A non-negated sibling still verifies
        self.hostname = "other.neg.example.com"
        try:
            self._connect(client, factory)
        except BadHostKeyException:
            self.fail("Non-negated wildcard host must verify")
        except SSHException:
            pass

    def test_revoked_entry_rejects_connection_even_with_matching_key(self):
        from paramiko.hostkeys import REVOKED_MARKER, HostKeyEntry

        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client._host_keys._entries.append(
            HostKeyEntry(
                [self.hostname], self.rsa, marker=REVOKED_MARKER
            )
        )
        factory = self._factory(self.rsa)
        with self.assertRaises(SSHException):
            self._connect(client, factory)

    # ---- Malformed lines don't loosen policy ------------------------------

    def test_malformed_known_hosts_line_keeps_policy_strict(self):
        good_line = "{} ssh-rsa {}\n".format(
            self.hostname, self.rsa.get_base64()
        )
        with open(self.known_hosts_path, "w") as f:
            f.write(good_line)
            f.write("{} ssh-rsa !!!not-base64!!!\n".format(self.hostname))
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.load_host_keys(self.known_hosts_path)
        # A rotated key must still be rejected despite the broken second line
        factory = self._factory(self.rsa_rotated)
        with self.assertRaises(BadHostKeyException):
            self._connect(client, factory)

    # ---- System + local store merge --------------------------------------

    def test_system_and_local_keys_merge_by_type(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client._system_host_keys.add(
            self.hostname, "ecdsa-sha2-nistp256", self.ecdsa
        )
        client.get_host_keys().add(self.hostname, "ssh-rsa", self.rsa)
        # ECDSA server key verifies via the system store even though local
        # only has RSA
        factory = self._factory(self.ecdsa)
        try:
            self._connect(client, factory)
        except BadHostKeyException:
            self.fail("System host key must verify")
        except SSHException:
            pass

    # ---- Certificates end-to-end -----------------------------------------

    def test_certificate_host_key_accepted_via_cert_authority(self):
        from paramiko.hostkeys import CERT_AUTHORITY_MARKER, HostKeyEntry
        from tests.test_hostkeys_security import _make_host_cert

        ca = paramiko.RSAKey.generate(2048)
        cert_key = _make_host_cert(
            self.rsa, ca, [self.hostname]
        )
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client._system_host_keys._entries.append(
            HostKeyEntry(
                [self.hostname], ca, marker=CERT_AUTHORITY_MARKER
            )
        )
        factory = self._factory(cert_key)
        try:
            self._connect(client, factory)
        except BadHostKeyException:
            self.fail("Cert-authority-backed host cert must verify")
        except SSHException:
            pass

    def test_certificate_signed_by_unknown_ca_rejected_at_connect(self):
        from paramiko.hostkeys import CERT_AUTHORITY_MARKER, HostKeyEntry
        from tests.test_hostkeys_security import _make_host_cert

        trusted_ca = paramiko.RSAKey.generate(2048)
        rogue_ca = paramiko.RSAKey.generate(2048)
        cert_key = _make_host_cert(
            self.rsa, rogue_ca, [self.hostname]
        )
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client._host_keys._entries.append(
            HostKeyEntry(
                [self.hostname], trusted_ca, marker=CERT_AUTHORITY_MARKER
            )
        )
        factory = self._factory(cert_key)
        with self.assertRaises(SSHException):
            self._connect(client, factory)
        # AutoAdd must not have recorded the rogue key as a plain host key
        result = client.get_host_keys().lookup(self.hostname)
        self.assertEqual(len(result.keys()), 0)
        self.assertEqual(
            len(result.cert_authority_entries), 1
        )

    # ---- Concurrency ------------------------------------------------------

    def test_save_preserves_marker_and_hashed_entries(self):
        from paramiko.hostkeys import REVOKED_MARKER, HostKeyEntry

        client = SSHClient()
        client.load_host_keys(self.known_hosts_path)
        # A revoked line and a hashed-hostname line must round-trip, not be
        # flattened or dropped by save_host_keys.
        client._host_keys._entries.append(
            HostKeyEntry(
                ["dead.example.com"], self.rsa, marker=REVOKED_MARKER
            )
        )
        hashed = paramiko.HostKeys.hash_host("hidden.example.com")
        client.get_host_keys().add(hashed, "ssh-rsa", self.rsa)
        client.save_host_keys(self.known_hosts_path)

        with open(self.known_hosts_path) as f:
            contents = f.read()
        self.assertIn("@revoked dead.example.com", contents)
        self.assertIn(hashed, contents)
        # And the reloaded file still behaves correctly
        reloaded = SSHClient()
        reloaded.load_host_keys(self.known_hosts_path)
        self.assertTrue(
            reloaded.get_host_keys().lookup("dead.example.com").is_revoked
        )
        self.assertIsNotNone(
            reloaded.get_host_keys().lookup("hidden.example.com")
        )

    def test_concurrent_connections_share_key_stores_safely(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.load_host_keys(self.known_hosts_path)
        errors = []

        def worker():
            try:
                factory = self._factory(self.rsa)
                c = SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                # Share the exact same HostKeys stores, as a pool of clients
                # would in real usage
                c._host_keys = client._host_keys
                c._host_keys_filename = self.known_hosts_path
                c.connect(
                    hostname=self.hostname,
                    password="test-password",
                    sock=object(),
                    transport_factory=factory,
                    look_for_keys=False,
                    allow_agent=False,
                )
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
            self.assertFalse(t.is_alive(), "worker thread hung")
        self.assertEqual(errors, [])
        # The host ends up with exactly one key entry, not eight duplicates
        keys = client._host_keys.lookup(self.hostname)
        self.assertEqual(len(keys), 1)
        self.assertTrue(client._host_keys.check(self.hostname, self.rsa))


if __name__ == "__main__":
    unittest.main()
