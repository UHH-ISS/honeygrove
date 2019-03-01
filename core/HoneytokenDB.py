from honeygrove import log
from honeygrove.config import Config

import twisted.conch.error as concherror
from twisted.conch.ssh import keys
from twisted.cred import credentials, error
from twisted.cred.checkers import ICredentialsChecker
from twisted.internet import defer
from twisted.python import failure
from zope.interface import implementer

import hashlib
import os
import random
import shutil
import tempfile


@implementer(ICredentialsChecker)
class HoneytokenDataBase():
    """
        Honeytoken Database.
        Chredchecker used by all Services.
    """

    allServices = 'SSH,HTTP,FTP'

    scopeField = 0
    usernameField = 1
    passwordField = 2
    publicKeyField = 3

    filepath = Config.honeytoken.database_file
    sep = ':'

    credentialInterfaces = (credentials.IUsernamePassword,
                            credentials.IUsernameHashedPassword,
                            credentials.ISSHPrivateKey)

    def __init__(self, servicename):
        """
        @type servicename: str
        @param servicename: The name of the service which is using this instance of HoneytokenDB.

        """
        self.servicename = servicename
        self.temp_copy_path = self.create_temporary_copy(self.filepath)

    def create_temporary_copy(self, path):
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, 'temp_file_name')
        shutil.copy2(path, temp_path)
        return temp_path

    def try_decode_key(self, raw_key):
        key_str = raw_key.decode(errors='ignore')
        # These keys are unsupported by twisted and Key.fromString fails if we call it, so return None
        if "ed25519" in key_str or "ecdsa" in key_str:
            return None
        return keys.Key.fromString(data=raw_key).toString("OPENSSH").decode()

    def try_get_tokens(self, user, data, is_key=False):
        res = []

        if is_key:
            # login via ssh key
            key = self.try_decode_key(data)
            if key is None:
                # Key type is unsupported
                return res
        elif isinstance(data, bytes):
            # login via password (which might be bytes)
            pw = data.decode()
        else:
            pw = data

        # Parse the credentials
        try:
            lines = self.load_credentials()
        except error.UnauthorizedLogin:
            return res

        # Look for matching credentials
        for line in lines:
            if is_key:
                if line[1] == user and line[3] == key:
                    res.extend(line[0])
            else:
                if line[1] == user and line[2] == pw:
                    res.extend(line[0])

        return list(set(res))

    def load_credentials(self):
        """
        Loads the credentials from the Configured file.

        @return: A list of (scope, username, password) tuples.
        @rtype: iterable

        @raise UnauthorizedLogin: when failing to read the credentials from the file.
        """
        res = ''

        # try to read from original database-file
        try:
            with open(self.filepath, "r+") as fp:
                res = self.parse_lines(fp)
                self.temp_copy_path = self.create_temporary_copy(self.filepath)  # update copy
                return res
        except IOError:
            # original database-file is blocked, go on
            pass

        # read from copied database-file
        try:
            with open(self.temp_copy_path, "r") as fp:
                res = self.parse_lines(fp)
                return res
        except IOError as e:  # noqa
            raise error.UnauthorizedLogin()

    def parse_lines(self, lines):
        res = []
        for line in lines:
            line = line.rstrip()
            parts = line.split(self.sep)

            if len(parts) == 4:
                res.append((parts[self.scopeField].split(','),
                            parts[self.usernameField],
                            parts[self.passwordField],
                            parts[self.publicKeyField]))
            if len(parts) == 3:
                res.append((parts[self.scopeField].split(','),
                            parts[self.usernameField],
                            parts[self.passwordField],
                            ''))
        return res

    def write_to_database(self, user, pw, services):

        if type(user) is bytes:
            user = user.decode()
        if type(pw) is bytes:
            pw = pw.decode()

        try:
            with open(self.filepath, "a") as fp:
                log.info("Begin Honeytoken creation: {} : {}".format(user, pw))  # TODO make this a proper log type
                fp.write("\n" + services + self.sep + user + self.sep + pw + self.sep)
        except Exception as e:
            log.err("Honeytoken DB write exception: {}".format(e))

    def get_user(self, username):

        by = type(username) is bytes
        for (s, u, p, k) in self.load_credentials():
            if by:
                u = bytes(u, 'utf-8')
                p = bytes(p, 'utf-8')
            if u == username and self.servicename in s:
                return u, p, k
        raise KeyError(username)

    def password_match(self, matched, username):
        if matched:
            return username
        else:
            return failure.Failure(error.UnauthorizedLogin())

    def accept(self, username, password, randomAcceptProbability):
        if (Config.honeytoken.username_min <= len(username) <= Config.honeytoken.username_max
                and Config.honeytoken.password_min <= len(password) <= Config.honeytoken.password_max
                and b":" not in username and b":" not in password):

            if Config.accept_via_hash:
                hashbau = username + Config.hash_seed + password
                hash1 = hashlib.sha1(hashbau).hexdigest()
                i = 0
                for x in range(0, 39):
                    i = i+(int(hash1[x], 16))
                if (i % 10 <= randomAcceptProbability * 10 - 1):
                    return True
                else:
                    return False
            elif random.random() <= randomAcceptProbability:
                return True
            else:
                return False
        else:
            return False

    def requestAvatarId(self, c):

        try:
            # try user authentification
            u, p, k = self.get_user(c.username)

        except error.UnauthorizedLogin:
            return defer.fail(error.UnauthorizedLogin())

        except KeyError:
            # user not in database -> accept probabilistic
            randomAcceptProbability = 0
            if self.servicename in Config.honeytoken.probabilities.keys():
                randomAcceptProbability = Config.honeytoken.probabilities[self.servicename]

            if hasattr(c, 'password') and self.accept(c.username, c.password, randomAcceptProbability):
                if self.servicename in Config.honeytoken.generating.keys():
                    self.write_to_database(c.username, c.password, ",".join(Config.honeytoken.generating[self.servicename]))
                    return defer.succeed(c.username)

            # TODO: Handle unknown keys
            return defer.fail(error.UnauthorizedLogin("Invalid Password or Signature"))

        if hasattr(c, 'blob'):
            userkey = keys.Key.fromString(data=k)
            if not c.blob == userkey.blob():
                return failure.Failure(error.ConchError("Unknown key."))
            if not c.signature:
                # tell the cient to sign his authentication (else the public key is kind of pointless)
                return defer.fail(concherror.ValidPublicKey())
            if userkey.verify(c.signature, c.sigData):
                return defer.succeed(c.username)
            else:
                return failure.Failure(error.ConchError("Invalid Signature"))

        if not p:
            return defer.fail(error.UnauthorizedLogin())  # don't allow login with empty passwords

        return defer.maybeDeferred(c.checkPassword, p).addCallback(self.password_match, u)
