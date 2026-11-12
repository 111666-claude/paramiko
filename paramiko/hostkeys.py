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


import binascii
import fnmatch
import os
import re
from base64 import decodebytes, encodebytes
from collections.abc import MutableMapping
from hashlib import sha1
from hmac import HMAC

from paramiko.message import Message
from paramiko.pkey import PKey, UnknownKeyType
from paramiko.ssh_exception import SSHException
from paramiko.util import b, constant_time_bytes_eq, get_logger, u


# Known markers that may prefix the hostname list of an OpenSSH known_hosts
# line.  See the ``KNOWN_HOSTS`` section of ``man sshd``.
CERT_AUTHORITY_MARKER = "@cert-authority"
REVOKED_MARKER = "@revoked"
_KNOWN_MARKERS = (CERT_AUTHORITY_MARKER, REVOKED_MARKER)
_CERT_SUFFIX = "-cert-v01@openssh.com"
_NOT_ENOUGH_FIELDS = (
    "Not enough fields found in known_hosts in line {} ({!r})"
)


class HostKeyResult:
    """
    Outcome of verifying a server-presented host key against the entries
    stored in a `.HostKeys` instance.

    Instances behave like the legacy keytype->`.PKey` mapping returned by
    `.HostKeys.lookup` (so existing callers such as `.SSHClient` keep
    working), while additionally recording *why* a lookup did or did not
    produce a match -- in particular, whether the host was genuinely unknown
    versus merely having entries of a different key type, and whether a
    matching ``@revoked`` line was encountered.

    .. versionadded:: 5.1
    """

    def __init__(self, hostname, entries, hostkeys=None):
        self.hostname = hostname
        # All entries whose hostnames pattern-match the queried host, in file
        # order.  Includes revoked and cert-authority entries.
        self.entries = list(entries)
        # Back-reference to the owning HostKeys for mutating operations,
        # preserving the legacy writable-SubDict behavior of lookup().
        self._hostkeys = hostkeys
        # Keytype -> key for the plain (non-marker) matching entries; this is
        # the historical SubDict payload.
        self._keys = {}
        for entry in self.entries:
            if entry.marker is None and entry.key is not None:
                # First occurrence wins so file order stays deterministic and
                # later duplicate lines cannot silently shadow earlier ones.
                self._keys.setdefault(entry.key.get_name(), entry.key)

    def __contains__(self, keytype):
        return keytype in self._keys

    def __iter__(self):
        return iter(self._keys)

    def __len__(self):
        return len(self._keys)

    def __getitem__(self, keytype):
        return self._keys[keytype]

    def __setitem__(self, keytype, key):
        for entry in self.entries:
            if entry.key is None:
                continue
            if entry.key.get_name() == keytype:
                entry.key = key
                self._keys[keytype] = key
                break
        else:
            entry = HostKeyEntry([self.hostname], key)
            self.entries.append(entry)
            self._keys[keytype] = key
            if self._hostkeys is not None:
                self._hostkeys._entries.append(entry)

    def __delitem__(self, keytype):
        for entry in list(self.entries):
            if entry.key is not None and entry.key.get_name() == keytype:
                self.entries.remove(entry)
                self._keys.pop(keytype, None)
                if (
                    self._hostkeys is not None
                    and entry in self._hostkeys._entries
                ):
                    self._hostkeys._entries.remove(entry)
                break
        else:
            raise KeyError(keytype)

    def get(self, keytype, default=None):
        return self._keys.get(keytype, default)

    def keys(self):
        return list(self._keys.keys())

    def values(self):
        return list(self._keys.values())

    def items(self):
        return list(self._keys.items())

    @property
    def matched(self):
        """Whether at least one line pattern-matched the hostname."""
        return bool(self.entries)

    @property
    def revoked_entries(self):
        return [e for e in self.entries if e.marker == REVOKED_MARKER]

    @property
    def is_revoked(self):
        """Whether a matching ``@revoked`` line exists."""
        return bool(self.revoked_entries)

    @property
    def cert_authority_entries(self):
        return [e for e in self.entries if e.marker == CERT_AUTHORITY_MARKER]

    def key_for(self, key):
        """
        Return the stored plain key expected for the key type of ``key``,
        or ``None`` if no plain entry of that type exists.

        RSA keys are matched on underlying key material rather than the
        negotiated signature algorithm name (``rsa-sha2-*`` vs
        ``ssh-rsa``).
        """
        name = _base_key_name(key.get_name())
        for keytype, candidate in self._keys.items():
            if _base_key_name(keytype) == name:
                return candidate
        return None


def _base_key_name(name):
    """
    Normalize an algorithm/key name to the underlying host key type.

    Strips the OpenSSH certificate suffix and maps the RSA SHA-2 signature
    algorithm names back to the ``ssh-rsa`` host key type.
    """
    if name.endswith(_CERT_SUFFIX):
        name = name[: -len(_CERT_SUFFIX)]
    if name in ("rsa-sha2-256", "rsa-sha2-512"):
        return "ssh-rsa"
    return name


def _is_cert_name(name):
    return name.endswith(_CERT_SUFFIX)


def _parse_certificate(key):
    """
    Parse the OpenSSH certificate carried by a cert-bearing `.PKey`.

    Returns a tuple ``(inner_key, signed_blob, signature_message, ca_key)``
    where ``inner_key`` is a `.PKey` of the certificate's base key type built
    from the certified public key, and ``ca_key`` is the embedded CA public
    key (also a `.PKey`).

    :raises SSHException: if the key carries no certificate or the blob is
        malformed.
    """
    if key.public_blob is None:
        raise SSHException("Host key is not an OpenSSH certificate")
    blob = key.public_blob.key_blob
    msg = Message(blob)
    cert_type = msg.get_text()
    if not _is_cert_name(cert_type):
        raise SSHException("Invalid certificate type {!r}".format(cert_type))
    msg.get_binary()  # nonce
    # The fields following the nonce are exactly those of the base key's
    # plain public key blob; re-wrap them under the base name so the regular
    # PKey constructors can parse them.
    base_type = _base_key_name(cert_type)
    inner_msg = Message()
    inner_msg.add_string(base_type)
    if base_type.startswith("ecdsa-sha2-"):
        # ECDSA: curve name string + point string
        inner_msg.add_string(msg.get_text())  # curve name
        inner_msg.add_string(msg.get_binary())  # public point
    elif base_type == "ssh-rsa":
        # RSA: mpint e, mpint n
        inner_msg.add_mpint(msg.get_mpint())  # e
        inner_msg.add_mpint(msg.get_mpint())  # n
    else:
        # Ed25519: raw public key string
        inner_msg.add_string(msg.get_binary())
    inner_key = PKey.from_type_string(base_type, inner_msg.asbytes())
    msg.get_int64()  # serial
    msg.get_int()  # cert type (user/host)
    msg.get_string()  # key id
    msg.get_string()  # packed principals
    msg.get_int64()  # valid after
    msg.get_int64()  # valid before
    msg.get_string()  # critical options
    msg.get_string()  # extensions
    msg.get_string()  # reserved
    # Everything preceding the signature-key field is what the CA signed.
    signed_blob = blob[: msg.packet.tell()]
    ca_blob = msg.get_string()
    signature = Message(msg.get_binary())
    ca_key = PKey.from_type_string(Message(ca_blob).get_text(), ca_blob)
    return inner_key, signed_blob, signature, ca_key


def _certificate_principals(key):
    """Return the list of principals embedded in a cert-bearing `.PKey`."""
    blob = key.public_blob.key_blob
    msg = Message(blob)
    msg.get_text()  # cert type
    msg.get_binary()  # nonce
    base_type = _base_key_name(key.public_blob.key_type)
    if base_type.startswith("ecdsa-sha2-"):
        msg.get_text()
        msg.get_binary()
    elif base_type == "ssh-rsa":
        msg.get_mpint()
        msg.get_mpint()
    else:
        msg.get_binary()
    msg.get_int64()  # serial
    msg.get_int()  # cert type
    msg.get_string()  # key id
    packed = msg.get_binary()  # packed principals
    principals = []
    sub = Message(packed)
    remainder = sub.get_remainder()
    while remainder:
        principals.append(sub.get_text())
        remainder = sub.get_remainder()
    return principals


class HostKeys(MutableMapping):
    """
    Representation of an OpenSSH-style "known hosts" file.  Host keys can be
    read from one or more files, and then individual hosts can be looked up to
    verify server keys during SSH negotiation.

    A `.HostKeys` object can be treated like a dict; any dict lookup is
    equivalent to calling `lookup`.

    .. versionadded:: 1.5.3
    """

    def __init__(self, filename=None):
        """
        Create a new HostKeys object, optionally loading keys from an OpenSSH
        style host-key file.

        :param str filename: filename to load host keys from, or ``None``
        """
        # emulate a dict of { hostname: { keytype: PKey } }
        self._entries = []
        if filename is not None:
            self.load(filename)

    @classmethod
    def from_stores(cls, *stores):
        """
        Build a transient `.HostKeys` containing every entry of the given
        stores (e.g. the system and local known-hosts sets), in order.

        Used to verify a server key against the union of the configured
        stores without mutating either of them.
        """
        merged = cls()
        for store in stores:
            merged._entries.extend(store._entries)
        return merged

    def add(self, hostname, keytype, key):
        """
        Add a host key entry to the table.  Any existing entry for a
        ``(hostname, keytype)`` pair will be replaced.

        :param str hostname: the hostname (or IP) to add
        :param str keytype: key type (in ``"ssh-<type>"`` format)
        :param .PKey key: the key to add
        """
        for e in self._entries:
            if (hostname in e.hostnames) and (e.key.get_name() == keytype):
                e.key = key
                return
        self._entries.append(HostKeyEntry([hostname], key))

    def load(self, filename):
        """
        Read a file of known SSH host keys, in the format used by OpenSSH.
        This type of file unfortunately doesn't exist on Windows, but on
        posix, it will usually be stored in
        ``os.path.expanduser("~/.ssh/known_hosts")``.

        If this method is called multiple times, the host keys are merged,
        not cleared.  So multiple calls to `load` will just call `add`,
        replacing any existing entries and adding new ones.

        Malformed lines (including lines whose key blob cannot be decoded or
        whose key type is unknown) are skipped with a log message instead of
        aborting the whole load; a broken line never causes a host to be
        treated as unknown or to fall through to a missing-host-key policy.

        :param str filename: name of the file to read host keys from

        :raises: ``IOError`` -- if there was an error reading the file
        """
        with open(filename, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if (len(line) == 0) or (line[0] == "#"):
                    continue
                try:
                    entry = HostKeyEntry.from_line(line, lineno)
                except (SSHException, InvalidHostKey, binascii.Error) as e:
                    # An unparseable line must not take down loading of the
                    # rest of the file, and must never loosen verification:
                    # it simply contributes no entry.
                    get_logger("paramiko.hostkeys").info(
                        "Ignoring invalid known_hosts line {} "
                        "({}): {!r}".format(lineno, e, line)
                    )
                    continue
                if entry is None:
                    continue
                # Marker lines (@cert-authority/@revoked) always participate
                # in matching/revocation; plain lines drop hostnames whose key
                # is already present (the historical duplicate-suppression).
                if entry.marker is None:
                    for h in list(entry.hostnames):
                        if self.check(h, entry.key):
                            entry.hostnames.remove(h)
                if len(entry.hostnames):
                    self._entries.append(entry)

    def save(self, filename):
        """
        Save host keys into a file, in the format used by OpenSSH.  The order
        of keys in the file will be preserved when possible (if these keys were
        loaded from a file originally).  The single exception is that combined
        lines will be split into individual key lines, which is arguably a bug.

        :param str filename: name of the file to write

        :raises: ``IOError`` -- if there was an error writing the file

        .. versionadded:: 1.6.1
        """
        with open(filename, "w") as f:
            for e in self._entries:
                line = e.to_line()
                if line:
                    f.write(line)

    def lookup(self, hostname):
        """
        Find a hostkey entry for a given hostname or IP.  If no entry is found,
        ``None`` is returned.  Otherwise a dictionary of keytype to key is
        returned.

        Hostname matching follows the OpenSSH known_hosts rules: literal
        names (including ``[host]:port`` aliases), hashed ``|1|...`` names,
        ``*``/``?`` wildcard patterns, and ``!`` negation patterns are all
        honored, and negated patterns exclude a host even when another line
        would otherwise match.

        :param str hostname: the hostname (or IP) to lookup
        :return: dict-like `.HostKeyResult` of `str` -> `.PKey` keys
            associated with this host (or ``None``)
        """
        # OpenSSH: a negated pattern (anywhere in known_hosts) excludes the
        # host from *every* other matching line.
        if self._is_negated(hostname):
            return None
        matched = [
            e
            for e in self._entries
            if self._hostname_matches(hostname, e)
        ]
        if not matched:
            return None
        return HostKeyResult(hostname, matched, hostkeys=self)

    def _is_negated(self, hostname):
        """
        Whether any entry carries a ``!pattern`` matching ``hostname``.

        OpenSSH treats negated patterns as global exclusions: once a host is
        negated, no other line can match it (so the host behaves as unknown
        rather than falling back to a wildcard key).
        """
        for entry in self._entries:
            for pattern in entry.hostnames:
                if pattern.startswith("!") and self._pattern_matches(
                    hostname, pattern[1:]
                ):
                    return True
        return False

    def _hostname_matches(self, hostname, entry):
        """
        Tests whether ``hostname`` string matches given ``entry``.

        :returns bool:
        """
        return any(
            not pattern.startswith("!")
            and self._pattern_matches(hostname, pattern)
            for pattern in entry.hostnames
        )

    def _pattern_matches(self, hostname, pattern):
        """
        Match a single known_hosts hostname pattern against ``hostname``.

        Supports hashed (``|1|salt|hash``) entries, ``[host]:port`` aliases,
        and shell-style wildcard (``*``/``?``) patterns.
        """
        if pattern == hostname:
            return True
        if pattern.startswith("|1|"):
            if hostname.startswith("|1|"):
                # Two hashed forms only match on exact equality (handled
                # above); a hash can never be re-derived from another hash.
                return False
            return constant_time_bytes_eq(
                self.hash_host(hostname, pattern), pattern
            )
        if _has_wildcard(pattern):
            # Bracketed port aliases and wildcard patterns share the same
            # lexical space, so match the whole string (brackets included).
            return fnmatch.fnmatchcase(hostname, pattern)
        return False

    def check(self, hostname, key):
        """
        Return True if the given key is associated with the given hostname
        in this dictionary.

        :param str hostname: hostname (or IP) of the SSH server
        :param .PKey key: the key to check
        :return:
            ``True`` if the key is associated with the hostname; else ``False``
        """
        k = self.lookup(hostname)
        if k is None:
            return False
        host_key = k.get(_base_key_name(key.get_name()), None)
        if host_key is None:
            # Preserve historical behavior for non-normalized lookups.
            host_key = k.get(key.get_name(), None)
        if host_key is None:
            return False
        return host_key.asbytes() == key.asbytes()

    def verify_host_key(self, hostname, key):
        """
        Verify a server-presented host (or host certificate) key against the
        entries stored for ``hostname``.

        :param str hostname: the ``[host]:port`` style lookup name
        :param .PKey key: the key presented by the server (may carry an
            OpenSSH certificate in ``.public_blob``)
        :return: a `.HostKeyResult` describing the matching entries
        :raises SSHException: if the key is revoked, the certificate is
            invalid/untrusted, or a matching entry holds a different key
        """
        from paramiko.ssh_exception import BadHostKeyException

        result = self.lookup(hostname)
        if result is None:
            return result
        if result.is_revoked:
            raise SSHException(
                "Host key for {!r} has been revoked in known_hosts".format(
                    hostname
                )
            )
        if key.public_blob is not None and _is_cert_name(
            key.public_blob.key_type
        ):
            # Certificates may only be vouched for by @cert-authority lines;
            # ordinary entries cannot accidentally authenticate a cert.
            if not result.cert_authority_entries:
                raise SSHException(
                    "No cert-authority key found for {!r}".format(hostname)
                )
            self._verify_certificate(hostname, result, key)
            return result
        # A bare host key can never match a cert-authority-only store.
        our_key = result.key_for(key)
        if our_key is None:
            # The host has entries but none of this key type: either a
            # rotation to a new algorithm or a cert-authority-only store.
            # Both are mismatches, not missing keys -- never silently accept.
            expected = result._keys and list(result.values())[0] or None
            if expected is None:
                # cert-authority/revoked-only store: use the first entry key
                for entry in result.entries:
                    if entry.key is not None:
                        expected = entry.key
                        break
            raise BadHostKeyException(hostname, key, expected)
        if our_key != key:
            raise BadHostKeyException(hostname, key, our_key)
        return result

    def _verify_certificate(self, hostname, result, key):
        """
        Verify an OpenSSH host certificate against ``@cert-authority``
        entries (and reject plain-key conflicts for the same host).
        """
        try:
            inner_key, signed_blob, signature, ca_key = _parse_certificate(key)
        except SSHException as e:
            raise SSHException(
                "Malformed host certificate presented by {!r}: {}".format(
                    hostname, e
                )
            )
        # The certified public key must be the key the server actually used.
        if inner_key.asbytes() != key.asbytes():
            raise SSHException(
                "Host certificate for {!r} does not certify the presented "
                "key".format(hostname)
            )
        # OpenSSH rejects certs whose principals don't cover the host.  An
        # empty principal list means "valid for any host".
        principals = _certificate_principals(key)
        bare_name = hostname
        if hostname.startswith("[") and "]:" in hostname:
            bare_name = hostname[1:].split("]:", 1)[0]
        if principals and not any(
            fnmatch.fnmatchcase(bare_name, p)
            or fnmatch.fnmatchcase(hostname, p)
            for p in principals
        ):
            raise SSHException(
                "Host certificate for {!r} is not valid for this host "
                "(principals: {!r})".format(hostname, principals)
            )
        trusted = False
        for entry in result.cert_authority_entries:
            if entry.key is None:
                continue
            if _base_key_name(entry.key.get_name()) != _base_key_name(
                ca_key.get_name()
            ):
                continue
            if entry.key.asbytes() != ca_key.asbytes():
                continue
            # Re-instantiate as a public-only key.  Some PKey subclasses
            # (notably Ed25519Key) cannot verify signatures while holding a
            # private key with no public-part counterpart loaded, whereas the
            # data-constructed form always can; known_hosts entries are public
            # keys by definition anyway.
            verifier = PKey.from_type_string(
                entry.key.get_name(), entry.key.asbytes()
            )
            if verifier.verify_ssh_sig(signed_blob, signature):
                trusted = True
                break
        if not trusted:
            raise SSHException(
                "Host certificate presented by {!r} was not signed by a "
                "trusted cert-authority key".format(hostname)
            )

    def clear(self):
        """
        Remove all host keys from the dictionary.
        """
        self._entries = []

    def __iter__(self):
        for k in self.keys():
            yield k

    def __len__(self):
        return len(self.keys())

    def __getitem__(self, key):
        ret = self.lookup(key)
        if ret is None:
            raise KeyError(key)
        return ret

    def __delitem__(self, key):
        index = None
        for i, entry in enumerate(self._entries):
            # Match via pattern semantics, but also allow deleting entries
            # that only carry negated/literal names (which lookup() hides).
            if self._hostname_matches(key, entry) or key in entry.hostnames:
                index = i
                break
        if index is None:
            raise KeyError(key)
        self._entries.pop(index)

    def __setitem__(self, hostname, entry):
        # don't use this please.
        if len(entry) == 0:
            self._entries.append(HostKeyEntry([hostname], None))
            return
        for key_type in entry.keys():
            found = False
            for e in self._entries:
                if (hostname in e.hostnames) and e.key.get_name() == key_type:
                    # replace
                    e.key = entry[key_type]
                    found = True
            if not found:
                self._entries.append(HostKeyEntry([hostname], entry[key_type]))

    def keys(self):
        ret = []
        for e in self._entries:
            for h in e.hostnames:
                if h not in ret:
                    ret.append(h)
        return ret

    def values(self):
        ret = []
        for k in self.keys():
            ret.append(self.lookup(k))
        return ret

    @staticmethod
    def hash_host(hostname, salt=None):
        """
        Return a "hashed" form of the hostname, as used by OpenSSH when storing
        hashed hostnames in the known_hosts file.

        :param str hostname: the hostname to hash
        :param str salt: optional salt to use when hashing
            (must be 20 bytes long)
        :return: the hashed hostname as a `str`
        """
        if salt is None:
            salt = os.urandom(sha1().digest_size)
        else:
            if salt.startswith("|1|"):
                salt = salt.split("|")[2]
            salt = decodebytes(b(salt))
        assert len(salt) == sha1().digest_size
        hmac = HMAC(salt, b(hostname), sha1).digest()
        hostkey = "|1|{}|{}".format(u(encodebytes(salt)), u(encodebytes(hmac)))
        return hostkey.replace("\n", "")


def _has_wildcard(pattern):
    return any(char in pattern for char in ("*", "?"))


class InvalidHostKey(Exception):
    def __init__(self, line, exc):
        self.line = line
        self.exc = exc
        self.args = (line, exc)


class HostKeyEntry:
    """
    Representation of a line in an OpenSSH-style "known hosts" file.
    """

    def __init__(self, hostnames=None, key=None, marker=None):
        self.valid = (hostnames is not None) and (key is not None)
        self.hostnames = hostnames
        self.key = key
        # ``None`` for plain lines, otherwise one of
        # ``@cert-authority`` / ``@revoked``.
        self.marker = marker

    @classmethod
    def from_line(cls, line, lineno=None):
        """
        Parses the given line of text to find the names for the host,
        the type of key, and the key data. The line is expected to be in the
        format used by the OpenSSH known_hosts file. Fields are separated by a
        single space or tab.

        Lines may begin with an OpenSSH marker (``@cert-authority`` or
        ``@revoked``) between the start of the line and the hostname list.

        Lines are expected to not have leading or trailing whitespace.
        We don't bother to check for comments or empty lines.  All of
        that should be taken care of before sending the line to us.

        :param str line: a line from an OpenSSH known_hosts file
        """
        log = get_logger("paramiko.hostkeys")
        fields = re.split(" |\t", line)
        if len(fields) < 3:
            # Bad number of fields
            log.info(_NOT_ENOUGH_FIELDS.format(lineno, line))
            return None
        marker = None
        if fields[0].startswith("@"):
            marker = fields.pop(0)
            if marker not in _KNOWN_MARKERS:
                raise SSHException(
                    "Unknown known_hosts marker {!r} in line {}".format(
                        marker, lineno
                    )
                )
            if len(fields) < 3:
                log.info(_NOT_ENOUGH_FIELDS.format(lineno, line))
                return None
        fields = fields[:3]

        names, key_type, key = fields
        names = names.split(",")

        # Decide what kind of key we're looking at and create an object
        # to hold it accordingly.
        try:
            # TODO: this grew organically and doesn't seem /wrong/ per se (file
            # read -> unicode str -> bytes for base64 decode -> decoded bytes);
            # but in Python 3 forever land, can we simply use
            # `base64.b64decode(str-from-file)` here?
            key_bytes = decodebytes(b(key))
        except binascii.Error as e:
            raise InvalidHostKey(line, e)

        try:
            return cls(
                names,
                PKey.from_type_string(key_type, key_bytes),
                marker,
            )
        except UnknownKeyType:
            # TODO (backwards incompat): consider changing HostKeys API so this
            # just raises naturally and the exception is muted higher up in the
            # stack?
            log.info("Unable to handle key of type {}".format(key_type))
            return None

    def to_line(self):
        """
        Returns a string in OpenSSH known_hosts file format, or None if
        the object is not in a valid state.  A trailing newline is
        included.
        """
        if self.valid:
            prefix = "{} ".format(self.marker) if self.marker else ""
            return "{}{} {} {}\n".format(
                prefix,
                ",".join(self.hostnames),
                self.key.get_name(),
                self.key.get_base64(),
            )
        return None

    def __repr__(self):
        return "<HostKeyEntry {!r}: {!r}>".format(self.hostnames, self.key)
