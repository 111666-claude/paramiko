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

from paramiko.pkey import PKey, UnknownKeyType
from paramiko.ssh_exception import SSHException
from paramiko.util import b, constant_time_bytes_eq, get_logger, u


class HostKeyConflictError(SSHException):
    """
    Raised when a host key entry already exists for a given
    ``(hostname, keytype)`` pair but carries a *different* key, and the
    caller tried to replace it through an API that refuses to overwrite
    conflicting keys silently.

    OpenSSH treats such a conflict as a possible host-key compromise and
    refuses to update ``known_hosts`` on its own; the stale entry has to be
    removed explicitly first.  Paramiko now follows the same rule.

    .. versionadded:: 5.1
    """


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

    def add(self, hostname, keytype, key):
        """
        Add a host key entry to the table.

        If an entry for the ``(hostname, keytype)`` pair already exists:

        * an entry holding the *same* key is left untouched (this makes
          `add` idempotent, which `load` relies on when the same host line
          appears more than once);
        * an entry holding a *different* key is a conflict.  The existing
          key is never silently overwritten; instead `.HostKeyConflictError`
          is raised, mirroring OpenSSH's refusal to replace a changed host
          key without explicit user action.  Remove the stale entry first
          (e.g. with ``del hostkeys[hostname]``) and then add the new key.

        :param str hostname: the hostname (or IP) to add
        :param str keytype: key type (in ``"ssh-<type>"`` format)
        :param .PKey key: the key to add

        :raises .HostKeyConflictError: if a different key of the same type
            is already stored for ``hostname``
        """
        for e in self._entries:
            if (hostname in e.hostnames) and (e.key.get_name() == keytype):
                if e.key.asbytes() == key.asbytes():
                    # Same key stored twice; nothing to do.
                    return
                raise HostKeyConflictError(
                    "Refusing to overwrite existing {!r} host key for {!r} "
                    "with a different key; remove the old entry first "
                    "(possible host key change/rotation)".format(
                        keytype, hostname
                    )
                )
        self._entries.append(HostKeyEntry([hostname], key))

    def load(self, filename):
        """
        Read a file of known SSH host keys, in the format used by OpenSSH.
        This type of file unfortunately doesn't exist on Windows, but on
        posix, it will usually be stored in
        ``os.path.expanduser("~/.ssh/known_hosts")``.

        If this method is called multiple times, the host keys are merged,
        not cleared.  Entries for hosts (or host/key-type pairs) not yet
        present are added; identical entries are ignored.  A line carrying a
        *different* key for a ``(hostname, keytype)`` pair that already has a
        key stored is a conflict and is skipped (with a warning) instead of
        silently replacing the known key -- remove the stale entry yourself
        if the key really did change.

        :param str filename: name of the file to read host keys from

        :raises: ``IOError`` -- if there was an error reading the file
        """
        log = get_logger("paramiko.hostkeys")
        with open(filename, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if (len(line) == 0) or (line[0] == "#"):
                    continue
                try:
                    entry = HostKeyEntry.from_line(line, lineno)
                except (SSHException, InvalidHostKey):
                    # Unparsable line: log (inside from_line) and skip it,
                    # like OpenSSH does, instead of taking the whole file
                    # down.
                    continue
                if entry is None:
                    continue
                # Only keep hostnames that are not already known with the
                # same key; note that we must not mutate entry.hostnames
                # while iterating over it.
                new_hostnames = []
                for h in entry.hostnames:
                    known = self.lookup(h)
                    if known is None:
                        new_hostnames.append(h)
                        continue
                    known_key = known.get(entry.key.get_name())
                    if known_key is None:
                        # Host is known, but not for this key type: keep the
                        # new (host, keytype) pair.
                        new_hostnames.append(h)
                    elif known_key.asbytes() != entry.key.asbytes():
                        # Conflict: a *different* key of the same type is
                        # already stored for this host.  OpenSSH rejects
                        # such lines rather than silently replacing the
                        # stored key, so do the same.
                        log.warning(
                            "Ignoring conflicting %s host key for %r in "
                            "line %d of %s (key differs from the one "
                            "already stored)",
                            entry.key.get_name(),
                            h,
                            lineno,
                            filename,
                        )
                    # else: identical key already known -> skip hostname
                if new_hostnames:
                    entry.hostnames = new_hostnames
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

        :param str hostname: the hostname (or IP) to lookup
        :return: dict of `str` -> `.PKey` keys associated with this host
            (or ``None``)
        """

        class SubDict(MutableMapping):
            def __init__(self, hostname, entries, hostkeys):
                self._hostname = hostname
                self._entries = entries
                self._hostkeys = hostkeys

            def __iter__(self):
                for k in self.keys():
                    yield k

            def __len__(self):
                return len(self.keys())

            def __delitem__(self, key):
                for e in list(self._entries):
                    if e.key.get_name() == key:
                        self._entries.remove(e)
                        break
                else:
                    raise KeyError(key)

            def __getitem__(self, key):
                for e in self._entries:
                    if e.key is not None and e.key.get_name() == key:
                        return e.key
                raise KeyError(key)

            def __setitem__(self, key, val):
                for e in self._entries:
                    if e.key is None:
                        continue
                    if e.key.get_name() == key:
                        # replace
                        e.key = val
                        break
                else:
                    # add a new one
                    e = HostKeyEntry([hostname], val)
                    self._entries.append(e)
                    self._hostkeys._entries.append(e)

            def keys(self):
                ret = []
                for e in self._entries:
                    if e.key is not None:
                        name = e.key.get_name()
                        if name not in ret:
                            ret.append(name)
                return ret

        entries = []
        for e in self._entries:
            if self._hostname_matches(hostname, e):
                entries.append(e)
        if len(entries) == 0:
            return None
        return SubDict(hostname, entries, self)

    def _hostname_matches(self, hostname, entry):
        """
        Tests whether ``hostname`` string matches given SubDict ``entry``.

        Hostname patterns follow the OpenSSH ``known_hosts`` rules:

        * plain names and ``[host]:port`` names match literally;
        * ``|1|salt|hash`` entries are hashed hostnames (see
          `hash_host`) and are checked by hashing the looked-up name with
          the entry's salt; the bracketed ``[host]:port`` form of the
          looked-up name is tried as well, since hashed entries may have
          been stored for a non-default port;
        * patterns may contain ``*`` and ``?`` glob characters, matched
          shell-style against the whole host name (so ``*.example.com``
          matches ``foo.example.com`` but not ``example.com``);
        * a pattern prefixed with ``!`` negates the match.  Negated
          patterns take precedence: if any negated pattern matches, the
          whole entry does not match, regardless of positive patterns.

        :returns bool:
        """
        matched = False
        for pattern in entry.hostnames:
            negated = pattern.startswith("!")
            bare = pattern[1:] if negated else pattern
            # A negation pattern names a host (or host pattern) without a
            # port, so it is evaluated against the host portion of a
            # bracketed [host]:port lookup as well.
            if self._pattern_matches(hostname, bare, strip_port=negated):
                if negated:
                    # Negation always wins for the whole entry.
                    return False
                matched = True
        return matched

    def _pattern_matches(self, hostname, pattern, strip_port=False):
        """
        Check a single (non-negated) known-hosts ``pattern`` against
        ``hostname``.

        :param bool strip_port:
            when true (used for negation patterns, which never carry a
            port), the host portion of a bracketed ``[host]:port`` lookup
            is tested in addition to the full name.

        :returns bool:
        """
        if pattern.startswith("|1|"):
            # Hashed hostname: compare HMAC hashes instead of strings.
            if hostname.startswith("|1|"):
                return False
            for candidate in self._hostname_variants(hostname):
                if constant_time_bytes_eq(
                    self.hash_host(candidate, pattern), pattern
                ):
                    return True
            return False
        # OpenSSH pattern matching only knows '*' and '?'; a '[' in a
        # bracketed [host]:port name is literal, not a glob character set.
        is_glob = "*" in pattern or "?" in pattern
        if not is_glob and not strip_port:
            # Literal names (including explicit [host]:port entries) match
            # exactly; the port is a distinct dimension from the host name.
            return pattern == hostname
        # Globs and negations name a host without a port, so test the host
        # portion of a bracketed [host]:port lookup as well.
        for candidate in self._hostname_variants(hostname):
            if is_glob:
                if fnmatch.fnmatchcase(candidate, pattern):
                    return True
            elif pattern == candidate:
                return True
        return False

    @staticmethod
    def _hostname_variants(hostname):
        """
        Yield the names to try when matching a hashed known-hosts entry.

        A hashed entry may have been stored for either the bare hostname
        or the OpenSSH bracketed ``[host]:port`` form, so both are tried
        when applicable.
        """
        yield hostname
        if hostname.startswith("[") and "]:" in hostname:
            # [host]:port -> also try the bare host
            yield hostname[1:].split("]:", 1)[0]
        else:
            # bare host -> also try its bracketed form on the default port
            yield "[{}]:22".format(hostname)

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
        host_key = k.get(key.get_name(), None)
        if host_key is None:
            return False
        return host_key.asbytes() == key.asbytes()

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
            if self._hostname_matches(key, entry):
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


class InvalidHostKey(SSHException):
    def __init__(self, line, exc):
        self.line = line
        self.exc = exc
        self.args = (line, exc)


class HostKeyEntry:
    """
    Representation of a line in an OpenSSH-style "known hosts" file.
    """

    def __init__(self, hostnames=None, key=None):
        self.valid = (hostnames is not None) and (key is not None)
        self.hostnames = hostnames
        self.key = key

    @classmethod
    def from_line(cls, line, lineno=None):
        """
        Parses the given line of text to find the names for the host,
        the type of key, and the key data. The line is expected to be in the
        format used by the OpenSSH known_hosts file. Fields are separated by
        one or more spaces or tabs; any content after the key data (such as
        a comment) is ignored.

        Lines are expected to not have leading or trailing whitespace.
        We don't bother to check for comments or empty lines.  All of
        that should be taken care of before sending the line to us.

        :param str line: a line from an OpenSSH known_hosts file
        """
        log = get_logger("paramiko.hostkeys")
        # OpenSSH splits on runs of whitespace and treats the first three
        # fields as hostnames, key type and key; anything afterwards is a
        # comment.
        fields = re.split(r"[ \t]+", line, maxsplit=2)
        if len(fields) < 3:
            # Bad number of fields
            msg = "Not enough fields found in known_hosts in line {} ({!r})"
            log.info(msg.format(lineno, line))
            return None

        names, key_type, key = fields
        # Strip any trailing comment (OpenSSH allows free text after the
        # base64 key).
        key = key.split()[0]
        names = names.split(",")
        if not all(names) or not key_type or not key:
            msg = "Empty field found in known_hosts in line {} ({!r})"
            log.info(msg.format(lineno, line))
            return None

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
            return cls(names, PKey.from_type_string(key_type, key_bytes))
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
            return "{} {} {}\n".format(
                ",".join(self.hostnames),
                self.key.get_name(),
                self.key.get_base64(),
            )
        return None

    def __repr__(self):
        return "<HostKeyEntry {!r}: {!r}>".format(self.hostnames, self.key)
