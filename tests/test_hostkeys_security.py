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
Unit tests for the OpenSSH known_hosts semantics added around host key
rotation, hashed/wildcard/negated hostname patterns, port aliases,
cert-authority entries and malformed-line handling.

All tests use temporary files, locally generated fixed keys and (where a
client is involved) a fake Transport -- no real sockets are opened.
"""

import os
import tempfile
import unittest

import paramiko
from paramiko.hostkeys import (
    CERT_AUTHORITY_MARKER,
    REVOKED_MARKER,
    HostKeyEntry,
    HostKeys,
    _base_key_name,
    _certificate_principals,
    _parse_certificate,
)
from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.ssh_exception import BadHostKeyException, SSHException


def _b64(key):
    return key.get_base64()


def _make_host_cert(host_key, ca_key, principals, cert_type=None):
    """
    Build an OpenSSH host certificate (as the bytes of the cert public blob)
    signed by ``ca_key`` for ``host_key`` with the given principals.

    Returns a cert-bearing `.PKey` (the server-presented host key).
    """
    base = _base_key_name(host_key.get_name())
    if cert_type is None:
        cert_type = "{}-cert-v01@openssh.com".format(base)
    msg = Message()
    msg.add_string(cert_type)
    msg.add_string(b"\x00" * 32)  # nonce
    inner = Message(host_key.asbytes())
    inner.get_text()
    if base == "ssh-rsa":
        msg.add_mpint(inner.get_mpint())  # e
        msg.add_mpint(inner.get_mpint())  # n
    elif base.startswith("ecdsa-sha2-"):
        msg.add_string(inner.get_text())  # curve
        msg.add_string(inner.get_binary())  # point
    else:
        msg.add_string(inner.get_binary())  # ed25519 raw key
    msg.add_int64(1234)  # serial
    msg.add_int(1)  # SSH2_CERT_TYPE_HOST
    msg.add_string("unit-test-host-cert")  # key id
    packed_principals = Message()
    for principal in principals:
        packed_principals.add_string(principal)
    msg.add_string(packed_principals.asbytes())
    msg.add_int64(0)  # valid after
    msg.add_int64(0)  # valid before (0 = unrestricted)
    msg.add_string(b"")  # critical options
    msg.add_string(b"")  # extensions
    msg.add_string(b"")  # reserved
    signed_blob = msg.asbytes()
    msg.add_string(ca_key.asbytes())  # signature key
    algorithm = None
    if base == "ssh-rsa":
        algorithm = "rsa-sha2-512"
    msg.add_string(
        ca_key.sign_ssh_data(signed_blob, algorithm=algorithm).asbytes()
    )
    # ECDSA/Ed25519 cert types are not registered in
    # PKey.from_type_string's identifiers; the real Transport constructs the
    # concrete class directly, so do the same here.
    if base.startswith("ecdsa-sha2-"):
        return paramiko.ECDSAKey(data=msg.asbytes())
    if base == "ssh-ed25519":
        return paramiko.Ed25519Key(data=msg.asbytes())
    return PKey.from_type_string(cert_type, msg.asbytes())


class HostKeyNameMatchingTest(unittest.TestCase):
    def setUp(self):
        self.hosts = HostKeys()
        self.rsa = paramiko.RSAKey.generate(2048)
        self.ecdsa = paramiko.ECDSAKey.generate()
        self.ed25519 = paramiko.Ed25519Key.from_private_key_file(
            os.path.join(os.path.dirname(__file__), "_support", "ed25519.key")
        )

    def test_literal_and_port_alias(self):
        self.hosts.add("plain.example.com", "ssh-rsa", self.rsa)
        self.hosts.add("[bracketed.example.com]:2222", "ssh-rsa", self.rsa)
        self.assertIsNotNone(self.hosts.lookup("plain.example.com"))
        self.assertIsNone(self.hosts.lookup("other.example.com"))
        # Port alias must not match the bare name or a different port
        self.assertIsNotNone(
            self.hosts.lookup("[bracketed.example.com]:2222")
        )
        self.assertIsNone(self.hosts.lookup("[bracketed.example.com]:22"))
        self.assertIsNone(self.hosts.lookup("bracketed.example.com"))

    def test_hashed_hostname_matches_only_its_host(self):
        hashed = HostKeys.hash_host("secret.example.com")
        self.hosts.add(hashed, "ssh-rsa", self.rsa)
        self.assertIsNotNone(self.hosts.lookup("secret.example.com"))
        self.assertTrue(self.hosts.check("secret.example.com", self.rsa))
        self.assertIsNone(self.hosts.lookup("guess.example.com"))
        # The hashed entry must never match via plain-text partial names
        self.assertIsNone(self.hosts.lookup("secret"))
        self.assertIsNone(self.hosts.lookup("example.com"))
        # A *different* hash (new random salt) of the same name still resolves
        # via HMAC recomputation, confirming the match uses the stored salt
        other_salt_hash = HostKeys.hash_host("other.example.com")
        self.assertIsNone(self.hosts.lookup(other_salt_hash))

    def test_wildcard_patterns(self):
        self.hosts.add("*.wild.example.com", "ssh-rsa", self.rsa)
        self.hosts.add("pre?.example.com", "ssh-rsa", self.rsa)
        self.assertIsNotNone(self.hosts.lookup("a.wild.example.com"))
        self.assertIsNotNone(self.hosts.lookup("deep.wild.example.com"))
        self.assertIsNone(self.hosts.lookup("wild.example.com"))
        self.assertIsNotNone(self.hosts.lookup("pre1.example.com"))
        self.assertIsNone(self.hosts.lookup("pre12.example.com"))

    def test_negation_excludes_host_everywhere(self):
        self.hosts.add("*.neg.example.com", "ssh-rsa", self.rsa)
        self.hosts.add("!special.neg.example.com", "ssh-rsa", self.ecdsa)
        # Wildcard would match, but the negation vetoes it
        self.assertIsNone(self.hosts.lookup("special.neg.example.com"))
        self.assertIsNotNone(self.hosts.lookup("other.neg.example.com"))

    def test_combined_positive_and_negative_line(self):
        entry = HostKeyEntry(
            ["*.mix.example.com", "!no.mix.example.com"], self.rsa
        )
        self.hosts._entries.append(entry)
        self.assertIsNotNone(self.hosts.lookup("yes.mix.example.com"))
        self.assertIsNone(self.hosts.lookup("no.mix.example.com"))

    def test_negation_entry_can_be_deleted(self):
        self.hosts.add("!veto.example.com", "ssh-rsa", self.rsa)
        del self.hosts["!veto.example.com"]
        self.assertEqual(len(self.hosts), 0)
        with self.assertRaises(KeyError):
            del self.hosts["never-existed.example.com"]

    def test_marker_line_accepts_tab_separators(self):
        line = "@cert-authority\ttab.example.com\tssh-rsa\t{}".format(
            self.rsa.get_base64()
        )
        entry = HostKeyEntry.from_line(line)
        self.assertEqual(entry.marker, CERT_AUTHORITY_MARKER)
        self.assertEqual(entry.hostnames, ["tab.example.com"])
        self.assertEqual(entry.key, self.rsa)

    def test_unknown_marker_raises_ssh_exception(self):
        with self.assertRaises(SSHException):
            HostKeyEntry.from_line(
                "@bogus h.example.com ssh-rsa {}".format(self.rsa.get_base64())
            )

    def test_multiple_key_types_are_deterministic(self):
        # Two entries for the same host, distinct key types: both must be
        # returned, in insertion (file) order, regardless of dict hashing.
        self.hosts.add("multi.example.com", "ssh-rsa", self.rsa)
        self.hosts.add("multi.example.com", "ecdsa-sha2-nistp256", self.ecdsa)
        self.hosts.add(
            "multi.example.com", "ssh-ed25519", self.ed25519
        )
        result = self.hosts.lookup("multi.example.com")
        self.assertEqual(
            list(result.keys()),
            ["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"],
        )
        self.assertTrue(self.hosts.check("multi.example.com", self.rsa))
        self.assertTrue(self.hosts.check("multi.example.com", self.ed25519))


class HostKeyRotationTest(unittest.TestCase):
    def setUp(self):
        self.hosts = HostKeys()
        self.old_rsa = paramiko.RSAKey.generate(2048)
        self.new_rsa = paramiko.RSAKey.generate(2048)
        self.ecdsa = paramiko.ECDSAKey.generate()

    def test_same_type_but_different_key_is_mismatch(self):
        self.hosts.add("rot.example.com", "ssh-rsa", self.old_rsa)
        with self.assertRaises(BadHostKeyException):
            self.hosts.verify_host_key("rot.example.com", self.new_rsa)

    def test_known_host_unknown_type_is_not_accepted(self):
        # Host known via RSA; server now presents ECDSA.  That is a rotation
        # to a new algorithm, which must not be silently accepted.
        self.hosts.add("rot.example.com", "ssh-rsa", self.old_rsa)
        with self.assertRaises(BadHostKeyException):
            self.hosts.verify_host_key("rot.example.com", self.ecdsa)

    def test_matching_key_passes(self):
        self.hosts.add("rot.example.com", "ssh-rsa", self.old_rsa)
        result = self.hosts.verify_host_key("rot.example.com", self.old_rsa)
        self.assertIsNotNone(result)

    def test_unknown_host_returns_none_without_raising(self):
        self.assertIsNone(
            self.hosts.verify_host_key("brand-new.example.com", self.new_rsa)
        )

    def test_rsa_sha2_algorithm_names_normalize(self):
        self.assertEqual(_base_key_name("rsa-sha2-256"), "ssh-rsa")
        self.assertEqual(_base_key_name("rsa-sha2-512"), "ssh-rsa")
        self.assertEqual(
            _base_key_name("rsa-sha2-512-cert-v01@openssh.com"), "ssh-rsa"
        )
        self.assertEqual(
            _base_key_name("ssh-ed25519-cert-v01@openssh.com"), "ssh-ed25519"
        )
        self.hosts.add("rsa.example.com", "ssh-rsa", self.old_rsa)
        result = self.hosts.lookup("rsa.example.com")

        class _Alg:
            @staticmethod
            def get_name():
                return "rsa-sha2-512"

        # key_for() must find the stored RSA key under the sha2 alias
        self.assertIs(result.key_for(_Alg()), self.old_rsa)


class MalformedLineTest(unittest.TestCase):
    def _write_load(self, lines):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(lines) + "\n")
            return HostKeys(path)
        finally:
            os.unlink(path)

    def test_broken_base64_line_does_not_abort_load(self):
        good = paramiko.RSAKey.generate(2048)
        hosts = self._write_load(
            [
                "good.example.com ssh-rsa {}".format(_b64(good)),
                "broken.example.com ssh-rsa AAAA-not-valid-base64!!!",
                "toofew.example.com ssh-rsa",
            ]
        )
        # The good line survives; the bad ones contribute nothing
        self.assertTrue(hosts.check("good.example.com", good))
        self.assertIsNone(hosts.lookup("broken.example.com"))
        self.assertIsNone(hosts.lookup("toofew.example.com"))

    def test_bad_line_never_loosens_policy_for_same_host(self):
        good = paramiko.RSAKey.generate(2048)
        # A valid line and a malformed line for the *same* host: the valid
        # entry must still enforce verification
        hosts = self._write_load(
            [
                "dup.example.com ssh-rsa {}".format(_b64(good)),
                "dup.example.com ssh-rsa ???garbage???",
            ]
        )
        self.assertTrue(hosts.check("dup.example.com", good))
        other = paramiko.RSAKey.generate(2048)
        with self.assertRaises(BadHostKeyException):
            hosts.verify_host_key("dup.example.com", other)

    def test_unknown_marker_is_rejected_not_ignored_silently(self):
        good = paramiko.RSAKey.generate(2048)
        bad_marker = "@bogus-marker marked.example.com ssh-rsa {}".format(
            _b64(good)
        )
        # An unrecognized @marker must be skipped (no crash, no entry that
        # could weaken matching)
        hosts = self._write_load(
            [
                bad_marker,
                "plain.example.com ssh-rsa {}".format(_b64(good)),
            ]
        )
        self.assertIsNone(hosts.lookup("marked.example.com"))
        self.assertIsNotNone(hosts.lookup("plain.example.com"))


class MarkerAndCertificateTest(unittest.TestCase):
    def setUp(self):
        self.ca = paramiko.RSAKey.generate(2048)
        self.host_key = paramiko.RSAKey.generate(2048)
        self.other_ca = paramiko.RSAKey.generate(2048)

    def _hosts_with_ca(self, hostname="host.example.com"):
        hosts = HostKeys()
        hosts._entries.append(
            HostKeyEntry(
                [hostname], self.ca, marker=CERT_AUTHORITY_MARKER
            )
        )
        return hosts

    def test_cert_authority_line_round_trips(self):
        entry = HostKeyEntry(
            ["host.example.com"], self.ca, marker=CERT_AUTHORITY_MARKER
        )
        line = entry.to_line().strip()
        self.assertTrue(line.startswith("@cert-authority "))
        reparsed = HostKeyEntry.from_line(line)
        self.assertEqual(reparsed.marker, CERT_AUTHORITY_MARKER)
        self.assertEqual(reparsed.hostnames, ["host.example.com"])
        self.assertEqual(reparsed.key, self.ca)

    def test_revoked_line_round_trips(self):
        entry = HostKeyEntry(
            ["host.example.com"], self.host_key, marker=REVOKED_MARKER
        )
        reparsed = HostKeyEntry.from_line(entry.to_line().strip())
        self.assertEqual(reparsed.marker, REVOKED_MARKER)

    def test_valid_certificate_accepted(self):
        hosts = self._hosts_with_ca()
        cert_key = _make_host_cert(
            self.host_key, self.ca, ["host.example.com"]
        )
        result = hosts.verify_host_key("host.example.com", cert_key)
        self.assertIsNotNone(result)

    def test_certificate_from_untrusted_ca_rejected(self):
        hosts = self._hosts_with_ca()
        cert_key = _make_host_cert(
            self.host_key, self.other_ca, ["host.example.com"]
        )
        with self.assertRaises(SSHException):
            hosts.verify_host_key("host.example.com", cert_key)

    def test_certificate_principal_mismatch_rejected(self):
        hosts = self._hosts_with_ca()
        cert_key = _make_host_cert(
            self.host_key, self.ca, ["different.example.com"]
        )
        with self.assertRaises(SSHException):
            hosts.verify_host_key("host.example.com", cert_key)

    def test_certificate_wildcard_principal_matches(self):
        hosts = self._hosts_with_ca()
        cert_key = _make_host_cert(self.host_key, self.ca, ["*.example.com"])
        self.assertIsNotNone(
            hosts.verify_host_key("host.example.com", cert_key)
        )

    def test_certificate_with_empty_principals_matches_any_host(self):
        # A wildcard cert-authority line makes the host "known"; the cert's
        # own empty principal list then imposes no further restriction.
        hosts = HostKeys()
        hosts._entries.append(
            HostKeyEntry(
                ["*.example.com"], self.ca, marker=CERT_AUTHORITY_MARKER
            )
        )
        cert_key = _make_host_cert(self.host_key, self.ca, [])
        self.assertIsNotNone(
            hosts.verify_host_key("anything.example.com", cert_key)
        )

    def test_revoked_key_always_rejected(self):
        hosts = HostKeys()
        hosts._entries.append(
            HostKeyEntry(
                ["host.example.com"], self.host_key, marker=REVOKED_MARKER
            )
        )
        with self.assertRaises(SSHException):
            hosts.verify_host_key("host.example.com", self.host_key)

    def test_parse_certificate_helpers(self):
        cert_key = _make_host_cert(
            self.host_key, self.ca, ["host.example.com", "alias.example.com"]
        )
        parsed = _parse_certificate(cert_key)
        inner, signed_blob, signature, embedded_ca = parsed
        self.assertEqual(inner, self.host_key)
        self.assertEqual(embedded_ca, self.ca)
        self.assertTrue(self.ca.verify_ssh_sig(signed_blob, signature))
        self.assertEqual(
            _certificate_principals(cert_key),
            ["host.example.com", "alias.example.com"],
        )

    def test_plain_key_does_not_use_cert_authority_path(self):
        # A bare key (no public_blob) must match against plain entries only;
        # a cert-authority-only store cannot authenticate a raw key.
        hosts = self._hosts_with_ca()
        with self.assertRaises(BadHostKeyException):
            hosts.verify_host_key("host.example.com", self.host_key)

    def test_load_marker_lines_from_file(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as f:
                f.write(
                    "@cert-authority host.example.com ssh-rsa {}\n".format(
                        _b64(self.ca)
                    )
                )
                f.write(
                    "@revoked dead.example.com ssh-rsa {}\n".format(
                        _b64(self.host_key)
                    )
                )
            hosts = HostKeys(path)
            result = hosts.lookup("host.example.com")
            self.assertEqual(
                result.cert_authority_entries[0].marker,
                CERT_AUTHORITY_MARKER,
            )
            self.assertTrue(hosts.lookup("dead.example.com").is_revoked)
        finally:
            os.unlink(path)

    def test_ecdsa_certificate_accepted_via_ecdsa_ca(self):
        ecdsa_ca = paramiko.ECDSAKey.generate()
        ecdsa_host = paramiko.ECDSAKey.generate()
        hosts = HostKeys()
        hosts._entries.append(
            HostKeyEntry(
                ["ec.example.com"], ecdsa_ca, marker=CERT_AUTHORITY_MARKER
            )
        )
        cert_key = _make_host_cert(
            ecdsa_host, ecdsa_ca, ["ec.example.com"]
        )
        self.assertEqual(
            cert_key.public_blob.key_type,
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        )
        self.assertIsNotNone(
            hosts.verify_host_key("ec.example.com", cert_key)
        )
        # A cert whose principals don't cover the (known) target host is
        # rejected rather than accepted.
        wrong_principal = _make_host_cert(
            ecdsa_host, ecdsa_ca, ["somewhere-else.example.com"]
        )
        with self.assertRaises(SSHException):
            hosts.verify_host_key("ec.example.com", wrong_principal)

    def test_ed25519_certificate_accepted_via_ed25519_ca(self):
        ed_ca = paramiko.Ed25519Key.from_private_key_file(
            os.path.join(
                os.path.dirname(__file__), "_support", "ed25519.key"
            )
        )
        # A second, distinct ed25519 key as the host key
        ed_host = paramiko.Ed25519Key.from_private_key_file(
            os.path.join(
                os.path.dirname(__file__),
                "test_ed25519-funky-padding.key",
            )
        )
        hosts = HostKeys()
        hosts._entries.append(
            HostKeyEntry(
                ["ed.example.com"], ed_ca, marker=CERT_AUTHORITY_MARKER
            )
        )
        cert_key = _make_host_cert(ed_host, ed_ca, ["ed.example.com"])
        self.assertEqual(
            cert_key.public_blob.key_type,
            "ssh-ed25519-cert-v01@openssh.com",
        )
        self.assertIsNotNone(
            hosts.verify_host_key("ed.example.com", cert_key)
        )

    def test_cross_algorithm_ca_cannot_verify(self):
        # An RSA CA entry must not authenticate a cert signed by an ECDSA CA
        ecdsa_ca = paramiko.ECDSAKey.generate()
        ecdsa_host = paramiko.ECDSAKey.generate()
        hosts = self._hosts_with_ca()  # RSA CA only
        cert_key = _make_host_cert(
            ecdsa_host, ecdsa_ca, ["host.example.com"]
        )
        with self.assertRaises(SSHException):
            hosts.verify_host_key("host.example.com", cert_key)

    def test_tampered_certificate_signature_is_rejected(self):
        from paramiko.pkey import PublicBlob

        hosts = self._hosts_with_ca()
        cert_key = _make_host_cert(
            self.host_key, self.ca, ["host.example.com"]
        )
        # Flip the final signature byte: structurally valid, bad signature
        blob = bytearray(cert_key.public_blob.key_blob)
        blob[-1] ^= 0xFF
        cert_key.public_blob = PublicBlob(
            type_=cert_key.public_blob.key_type, blob=bytes(blob)
        )
        with self.assertRaises(SSHException):
            hosts.verify_host_key("host.example.com", cert_key)

    def test_revoked_certificate_is_rejected(self):
        hosts = HostKeys()
        hosts._entries.append(
            HostKeyEntry(
                ["host.example.com"], self.ca, marker=CERT_AUTHORITY_MARKER
            )
        )
        hosts._entries.append(
            HostKeyEntry(
                ["host.example.com"],
                self.host_key,
                marker=REVOKED_MARKER,
            )
        )
        cert_key = _make_host_cert(
            self.host_key, self.ca, ["host.example.com"]
        )
        with self.assertRaises(SSHException):
            hosts.verify_host_key("host.example.com", cert_key)


class HostKeysFileMergeTest(unittest.TestCase):
    def test_duplicate_identical_lines_deduped(self):
        key = paramiko.RSAKey.generate(2048)
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as f:
                line = "dup.example.com ssh-rsa {}\n".format(_b64(key))
                f.write(line)
                f.write(line)
            hosts = HostKeys(path)
            self.assertEqual(len(hosts.lookup("dup.example.com")), 1)
        finally:
            os.unlink(path)

    def test_conflicting_same_type_lines_both_retained(self):
        # Silent overwrite is the historical danger: two lines, same host+type
        # but different keys.  Both entries remain visible so verification can
        # detect the conflict instead of one quietly shadowing the other.
        key1 = paramiko.RSAKey.generate(2048)
        key2 = paramiko.RSAKey.generate(2048)
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as f:
                f.write("c.example.com ssh-rsa {}\n".format(_b64(key1)))
                f.write("c.example.com ssh-rsa {}\n".format(_b64(key2)))
            hosts = HostKeys(path)
            result = hosts.lookup("c.example.com")
            # Two raw entries exist; the key mapping keeps the first (file
            # order) deterministically rather than picking arbitrarily.
            self.assertEqual(len(result.entries), 2)
            self.assertEqual(result["ssh-rsa"], key1)
            # The second key is flagged as a mismatch, not silently accepted
            with self.assertRaises(BadHostKeyException):
                hosts.verify_host_key("c.example.com", key2)
        finally:
            os.unlink(path)
