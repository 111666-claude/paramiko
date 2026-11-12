# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
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
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Some unit tests for HostKeys.
"""

from base64 import decodebytes, encodebytes
from binascii import hexlify
from hashlib import sha1
import os
import shutil
import tempfile
import unittest
from unittest.mock import Mock

import paramiko
from paramiko import ECDSAKey, HostKeyConflictError, HostKeys
from paramiko import PKey, RSAKey, SSHClient, SSHException
from paramiko.hostkeys import HostKeyEntry
from paramiko.ssh_exception import BadHostKeyException

from ._util import _support


test_hosts_file = """\
secure.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
broken.example.com ssh-rsa AAAA
happy.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz\
dHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv9\
T9iRZjQzvJd5s+kBAZtpk=
"""

test_hosts_file_tabs = """\
secure.example.com\tssh-rsa\tAAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
happy.example.com\tssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com\tssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com\tecdsa-sha2-nistp256\tAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbml\
zdHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv\
9T9iRZjQzvJd5s+kBAZtpk=
"""

keyblob = b"""\
AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3GQ/Fc7SX6gkpXkwcZryoi4k\
NFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgK\
oc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M="""


class HostKeysTest(unittest.TestCase):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file)

    def tearDown(self):
        os.unlink("hostfile.temp")

    def test_load(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        assert len(hostdict) == 4
        self.assertEqual(1, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)

    def test_add(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        hh = "|1|BMsIC6cUIP2zBuXR3t2LRcJYjzM=|hpkJMysjTk/+zzUUzxQEa2ieq6c="
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        hostdict.add(hh, "ssh-rsa", key)
        assert len(hostdict) == 5
        x = hostdict["foo.example.com"]
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        self.assertTrue(hostdict.check("foo.example.com", key))

    def test_dict(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        x = hostdict.get("secure.example.com", None)
        self.assertTrue(x is not None)
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)
        assert list(hostdict) == hostdict.keys()
        assert len(list(hostdict)) == len(hostdict.keys()) == 4

    def test_dict_set(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        key_ed25519 = paramiko.Ed25519Key.from_private_key_file(
            _support("ed25519.key")
        )
        hostdict["secure.example.com"] = {
            "ssh-rsa": key,
            "ssh-ed25519": key_ed25519,
        }
        hostdict["fake.example.com"] = {}
        hostdict["fake.example.com"]["ssh-rsa"] = key

        assert len(hostdict) == 5
        self.assertEqual(2, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        self.assertEqual(1, len(list(hostdict.values())[2]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-ed25519"].get_fingerprint()
        ).upper()
        self.assertEqual(b"B3D522AAF9755EE8CD0EEA02B929A280", fp)

    def test_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        hostdict[target]  # will KeyError if not present
        del hostdict[target]
        try:
            hostdict[target]
        except KeyError:
            pass  # Good
        else:
            assert False, "Entry was not deleted from HostKeys on delitem!"

    def test_entry_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        entry = hostdict[target]
        key_type_list = [key_type for key_type in entry]
        for key_type in key_type_list:
            del entry[key_type]

        # will KeyError if not present
        for key_type in key_type_list:
            try:
                del entry[key_type]
            except KeyError:
                pass  # Good
            else:
                assert False, "Key was not deleted from Entry on delitem!"


class HostKeysTabsTest(HostKeysTest):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file_tabs)


def _known_hosts_line(hostnames, key):
    return "{} {} {}\n".format(
        ",".join(hostnames), key.get_name(), key.get_base64()
    )


# Name of the key type produced by ECDSAKey.generate() (the tests use
# ECDSA keys because Ed25519Key has no generate() classmethod).
ECDSA_TYPE = "ecdsa-sha2-nistp256"


class FakePKey(PKey):
    """
    A minimal hand-rolled `.PKey`, used to stand in for server host keys
    without generating real cryptographic key material.
    """

    def __init__(self, name, blob, fingerprint=None):
        self._name = name
        self._blob = blob
        self._fingerprint = fingerprint or sha1(blob).digest()

    def get_name(self):
        return self._name

    def asbytes(self):
        return self._blob

    def get_base64(self):
        return encodebytes(self._blob).decode().strip()

    def get_fingerprint(self):
        return self._fingerprint

    @property
    def _fields(self):
        return (self._name, self._blob)


class PatternAndHashedHostKeysTest(unittest.TestCase):
    """
    Cover hashed hostnames, [host]:port names, wildcards and negation
    patterns, plus duplicate/conflicting entries.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="paramiko-known-hosts-")
        self.hostfile = os.path.join(self.tmpdir, "known_hosts")
        self.key1 = ECDSAKey.generate()
        self.key2 = ECDSAKey.generate()
        self.rsa_key = RSAKey.generate(2048)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write(self, text):
        with open(self.hostfile, "w") as f:
            f.write(text)

    def _load(self):
        return HostKeys(self.hostfile)

    def test_hashed_hostname_matches_bare_name(self):
        # An entry stored under the hashed form of the hostname must be
        # found when looking up the plain hostname.
        hashed = HostKeys.hash_host("secret.example.com")
        self._write(_known_hosts_line([hashed], self.key1))
        hostdict = self._load()
        ktype = self.key1.get_name()
        self.assertEqual(
            hostdict.lookup("secret.example.com")[ktype], self.key1
        )
        self.assertTrue(hostdict.check("secret.example.com", self.key1))
        # And some other host must not match.
        self.assertIsNone(hostdict.lookup("other.example.com"))

    def test_hashed_hostname_matches_bracketed_port(self):
        # A hash stored for the OpenSSH [host]:port form must be found by
        # the corresponding bracketed lookup (and vice versa).
        bracketed = "[secret.example.com]:2200"
        hashed = HostKeys.hash_host(bracketed)
        self._write(_known_hosts_line([hashed], self.key1))
        hostdict = self._load()
        self.assertEqual(
            hostdict.lookup(bracketed)[ECDSA_TYPE], self.key1
        )
        # Default port: hash for bare name matches both lookup forms.
        hashed_bare = HostKeys.hash_host("plain.example.com")
        self._write(_known_hosts_line([hashed_bare], self.key2))
        hostdict = self._load()
        self.assertEqual(
            hostdict.lookup("plain.example.com")[ECDSA_TYPE], self.key2
        )
        self.assertEqual(
            hostdict.lookup("[plain.example.com]:22")[ECDSA_TYPE],
            self.key2,
        )

    def test_literal_bracketed_host_port(self):
        # [host]:port entries (unhashed) match literally and are distinct
        # from the bare host.
        self._write(
            _known_hosts_line(["[web.example.com]:2222"], self.key1)
        )
        hostdict = self._load()
        self.assertEqual(
            hostdict.lookup("[web.example.com]:2222")[ECDSA_TYPE],
            self.key1,
        )
        self.assertIsNone(hostdict.lookup("web.example.com"))
        self.assertIsNone(hostdict.lookup("[web.example.com]:22"))

    def test_wildcard_pattern(self):
        self._write(_known_hosts_line(["*.example.com"], self.key1))
        hostdict = self._load()
        for host in ("foo.example.com", "a.b.example.com"):
            self.assertEqual(
                hostdict.lookup(host)[ECDSA_TYPE], self.key1, host
            )
        # The wildcard must not eat the boundary dot.
        self.assertIsNone(hostdict.lookup("example.com"))
        self.assertIsNone(hostdict.lookup("foo.example.org"))

    def test_question_mark_pattern(self):
        self._write(_known_hosts_line(["host?.example.com"], self.key1))
        hostdict = self._load()
        self.assertEqual(
            hostdict.lookup("host1.example.com")[ECDSA_TYPE], self.key1
        )
        self.assertIsNone(hostdict.lookup("host12.example.com"))

    def test_wildcard_pattern_covers_bracketed_non_default_port(self):
        # The wildcard applies to the host part even when the lookup uses
        # the OpenSSH [host]:port form.
        self._write(_known_hosts_line(["*.example.com"], self.key1))
        hostdict = self._load()
        self.assertEqual(
            hostdict.lookup("[host.example.com]:2222")[
                ECDSA_TYPE
            ],
            self.key1,
        )
        self.assertIsNone(hostdict.lookup("[host.example.org]:2222"))

    def test_negation_pattern_excludes_host(self):
        self._write(
            _known_hosts_line(
                ["*.example.com", "!bad.example.com"], self.key1
            )
        )
        hostdict = self._load()
        self.assertEqual(
            hostdict.lookup("good.example.com")[ECDSA_TYPE], self.key1
        )
        # Negation takes precedence over the positive wildcard.
        self.assertIsNone(hostdict.lookup("bad.example.com"))

    def test_negation_only_never_matches(self):
        self._write(_known_hosts_line(["!whatever.example.com"], self.key1))
        hostdict = self._load()
        self.assertIsNone(hostdict.lookup("whatever.example.com"))

    def test_negation_pattern_covers_bracketed_lookup(self):
        self._write(
            _known_hosts_line(
                ["*.example.com", "!bad.example.com"], self.key1
            )
        )
        hostdict = self._load()
        # Negation applies to the host part of a [host]:port lookup too.
        self.assertIsNone(hostdict.lookup("[bad.example.com]:2222"))
        self.assertEqual(
            hostdict.lookup("[good.example.com]:2222")[ECDSA_TYPE],
            self.key1,
        )

    def test_hashed_hostname_does_not_match_other_host(self):
        # The hash must not behave like a wildcard: a different hostname
        # hashes differently and must not be accepted.
        hashed = HostKeys.hash_host("real.example.com")
        self._write(_known_hosts_line([hashed], self.key1))
        hostdict = self._load()
        self.assertIsNone(hostdict.lookup("fake.example.com"))
        self.assertFalse(hostdict.check("fake.example.com", self.key1))
        # Looking the hash string itself up must not match.
        self.assertIsNone(hostdict.lookup(hashed))

    def test_add_conflicting_key_is_not_silently_overwritten(self):
        hostdict = HostKeys()
        hostdict.add("rotating.example.com", ECDSA_TYPE, self.key1)
        # Same key again: idempotent, no error, no duplicate.
        hostdict.add("rotating.example.com", ECDSA_TYPE, self.key1)
        self.assertEqual(len(hostdict), 1)
        # Different key of the same type: refuse to overwrite.
        with self.assertRaises(HostKeyConflictError):
            hostdict.add("rotating.example.com", ECDSA_TYPE, self.key2)
        # The original key is still in place.
        self.assertEqual(
            hostdict.lookup("rotating.example.com")[ECDSA_TYPE],
            self.key1,
        )

    def test_key_rotation_after_explicit_removal(self):
        # The supported rotation workflow: delete, then add the new key.
        hostdict = HostKeys()
        hostdict.add("rotating.example.com", ECDSA_TYPE, self.key1)
        del hostdict["rotating.example.com"]
        hostdict.add("rotating.example.com", ECDSA_TYPE, self.key2)
        self.assertEqual(
            hostdict.lookup("rotating.example.com")[ECDSA_TYPE],
            self.key2,
        )

    def test_load_conflicting_line_keeps_first_key(self):
        # A second line carrying a different key for the same
        # (host, keytype) must be ignored instead of replacing the first.
        self._write(
            _known_hosts_line(["dup.example.com"], self.key1)
            + _known_hosts_line(["dup.example.com"], self.key2)
        )
        with self.assertLogs("paramiko.hostkeys", level="WARNING"):
            hostdict = self._load()
        self.assertEqual(
            hostdict.lookup("dup.example.com")[ECDSA_TYPE], self.key1
        )
        # Still a single entry for the host.
        self.assertEqual(len(hostdict), 1)

    def test_load_identical_duplicate_line_is_ignored(self):
        line = _known_hosts_line(["dup.example.com"], self.key1)
        self._write(line + line)
        hostdict = self._load()
        self.assertEqual(len(hostdict), 1)
        self.assertEqual(
            hostdict.lookup("dup.example.com")[ECDSA_TYPE], self.key1
        )

    def test_subdict_deduplicates_repeated_key_type(self):
        # Even if two matching entries claim the same keytype, the
        # per-host view must list the type only once.
        hostdict = HostKeys()
        hostdict._entries.append(
            HostKeyEntry(["shared.example.com"], self.key1)
        )
        hostdict._entries.append(
            HostKeyEntry(["*.example.com"], self.key2)
        )
        subdict = hostdict.lookup("shared.example.com")
        self.assertEqual(sorted(subdict.keys()), [ECDSA_TYPE])
        self.assertEqual(len(subdict), 1)

    def test_same_host_may_hold_multiple_key_types(self):
        # Key rotation commonly means two different algorithms coexisting
        # for one host; that must remain allowed.
        self._write(
            _known_hosts_line(["multi.example.com"], self.key1)
            + _known_hosts_line(["multi.example.com"], self.rsa_key)
        )
        hostdict = self._load()
        subdict = hostdict.lookup("multi.example.com")
        self.assertEqual(
            sorted(subdict.keys()), [ECDSA_TYPE, "ssh-rsa"]
        )
        self.assertTrue(hostdict.check("multi.example.com", self.key1))
        self.assertTrue(hostdict.check("multi.example.com", self.rsa_key))

    def test_bad_lines_are_skipped(self):
        good = _known_hosts_line(["good.example.com"], self.key1)
        self._write(
            "# a comment\n"
            "\n"
            "only-two-fields ssh-rsa\n"
            "broken.example.com ssh-rsa AAAA\n"  # invalid base64
            "ssh-bogus-type "
            + encodebytes(b"not-a-real-key").decode().strip()
            + "\n"
            + good
        )
        hostdict = self._load()
        self.assertEqual(len(hostdict), 1)
        self.assertIn("good.example.com", hostdict)

    def test_alias_line_loads_all_names(self):
        # A comma-separated list of names on one line applies the key to
        # every alias.
        self._write(
            _known_hosts_line(
                ["alias1.example.com", "alias2.example.com"], self.key1
            )
        )
        hostdict = self._load()
        self.assertEqual(
            hostdict.lookup("alias1.example.com")[ECDSA_TYPE],
            self.key1,
        )
        self.assertEqual(
            hostdict.lookup("alias2.example.com")[ECDSA_TYPE],
            self.key1,
        )

    def test_alias_line_conflict_does_not_poison_other_aliases(self):
        # If one alias of a multi-name line already has a conflicting key,
        # the remaining aliases must still be registered.
        self._write(
            _known_hosts_line(["taken.example.com"], self.key1)
            + _known_hosts_line(
                ["taken.example.com", "fresh.example.com"], self.key2
            )
        )
        with self.assertLogs("paramiko.hostkeys", level="WARNING"):
            hostdict = self._load()
        self.assertEqual(
            hostdict.lookup("taken.example.com")[ECDSA_TYPE],
            self.key1,
        )
        self.assertEqual(
            hostdict.lookup("fresh.example.com")[ECDSA_TYPE],
            self.key2,
        )

    def test_from_line_handles_extra_whitespace_and_comments(self):
        raw = (
            "spaced.example.com\t\tecdsa-sha2-nistp256   "
            + self.key1.get_base64()
            + "   free-form comment"
        )
        entry = HostKeyEntry.from_line(raw, lineno=1)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.hostnames, ["spaced.example.com"])
        self.assertEqual(entry.key, self.key1)

    def test_from_line_rejects_empty_fields(self):
        # Trailing comma -> empty hostname field.
        raw = "host, ecdsa-sha2-nistp256 " + self.key1.get_base64()
        self.assertIsNone(HostKeyEntry.from_line(raw, lineno=1))


class FakeTransport:
    """
    Stand-in for `.Transport` used to exercise SSHClient's host-key
    verification logic without a real connection.
    """

    def __init__(self, sock, disabled_algorithms=None):
        self.sock = sock
        self.disabled_algorithms = disabled_algorithms or {}
        self.remote_key = None
        self.security_options = Mock()
        self.security_options.key_types = ["ssh-ed25519"]

    def use_compression(self, compress=False):
        pass

    def set_log_channel(self, name):
        pass

    def _log(self, level, message):
        pass

    def start_client(self, timeout=None):
        pass

    def get_remote_server_key(self):
        return self.remote_key

    def get_security_options(self):
        return self.security_options

    def auth_publickey(self, username, key):
        # Pretend public-key auth succeeded outright.
        return []

    def close(self):
        pass


class SSHClientHostKeyVerificationTest(unittest.TestCase):
    """
    End-to-end (but connection-less) checks of how SSHClient combines
    HostKeys with the missing-host-key policy.

    Keys written to the known_hosts file are real `.ECDSAKey` objects so
    they survive `HostKeyEntry.from_line`; the "network" side is a
    `.FakeTransport` handing back whichever key the test configures.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="paramiko-client-kh-")
        self.hostfile = os.path.join(self.tmpdir, "known_hosts")
        # Real key material for anything that must round-trip through the
        # known_hosts file parser.
        self.server_key = ECDSAKey.from_private_key_file(
            _support("ecdsa-256.key")
        )
        self.other_key = ECDSAKey.generate()
        # A lightweight stand-in used only where the key never gets parsed
        # back from a file (unknown-host policy callbacks).
        self.fake_key = FakePKey("ssh-ed25519", b"server-host-key-blob")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _client(self, transport, policy=None):
        client = SSHClient()
        client.load_host_keys(self.hostfile)
        if policy is not None:
            client.set_missing_host_key_policy(policy)
        return client

    def _connect(self, client, transport, remote_key=None):
        transport.remote_key = remote_key or self.server_key
        client.connect(
            "host.example.com",
            port=2200,
            username="user",
            pkey=self.server_key,
            allow_agent=False,
            look_for_keys=False,
            sock=object(),
            transport_factory=lambda *a, **k: transport,
        )

    def test_unknown_host_is_handed_to_missing_host_key_policy(self):
        with open(self.hostfile, "w") as f:
            f.write("")
        transport = FakeTransport(object())
        client = self._client(transport, policy=paramiko.RejectPolicy())
        with self.assertRaises(SSHException):
            self._connect(client, transport, remote_key=self.fake_key)

    def test_unknown_host_custom_policy_receives_arguments(self):
        with open(self.hostfile, "w") as f:
            f.write("")
        seen = {}

        class RecordingPolicy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                seen["client"] = client
                seen["hostname"] = hostname
                seen["key"] = key

        transport = FakeTransport(object())
        client = self._client(transport, policy=RecordingPolicy())
        self._connect(client, transport, remote_key=self.fake_key)
        self.assertIs(seen["client"], client)
        self.assertEqual(seen["hostname"], "[host.example.com]:2200")
        self.assertIs(seen["key"], self.fake_key)

    def test_known_matching_key_connects(self):
        with open(self.hostfile, "w") as f:
            f.write(
                _known_hosts_line(
                    ["[host.example.com]:2200"], self.server_key
                )
            )
        transport = FakeTransport(object())
        # RejectPolicy must never be called for a known, matching key.
        client = self._client(transport, policy=paramiko.RejectPolicy())
        self._connect(client, transport)

    def test_conflicting_known_key_raises_bad_host_key(self):
        with open(self.hostfile, "w") as f:
            f.write(
                _known_hosts_line(
                    ["[host.example.com]:2200"], self.other_key
                )
            )
        transport = FakeTransport(object())
        client = self._client(transport, policy=paramiko.AutoAddPolicy())
        with self.assertRaises(BadHostKeyException) as ctx:
            self._connect(client, transport)
        self.assertEqual(ctx.exception.key, self.server_key)
        self.assertEqual(ctx.exception.expected_key, self.other_key)
        # AutoAddPolicy must not have been used to paper over the clash:
        # the originally stored key remains untouched.
        stored = client.get_host_keys().lookup("[host.example.com]:2200")
        self.assertEqual(
            stored[self.other_key.get_name()], self.other_key
        )

    def test_wildcard_known_host_covers_connection(self):
        with open(self.hostfile, "w") as f:
            f.write(_known_hosts_line(["*.example.com"], self.server_key))
        transport = FakeTransport(object())
        client = self._client(transport, policy=paramiko.RejectPolicy())
        self._connect(client, transport)
