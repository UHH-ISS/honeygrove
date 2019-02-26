from honeygrove import config, log

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

    filepath = config.tokenDatabase
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

    def getActual(self, user, pw, iskey=False):
        res = []
        try:
            lines = self.load_credentials()
        except error.UnauthorizedLogin:
            return res

        for line in lines:
            if iskey:
                # login via ssh key
                pw = keys.Key.fromString(data=pw).toString("OPENSSH").decode()
                if line[1] == user and line[3] == pw:
                    res.extend(line[0])
            else:
                # login without ssh key
                if isinstance(pw, bytes):
                    pw = pw.decode()
                if line[1] == user and line[2] == pw:
                    res.extend(line[0])

        return list(set(res))

    def load_credentials(self):
        """
        Loads the credentials from the configured file.

        @return: A list of (scope, username, password) tuples.
        @rtype: iterable

        @raise UnauthorizedLogin: when failing to read the credentials from the file.
        """
        res = ''

        # try to read from original database-file
        try:
            with open(self.filepath, "r+") as file:
                res = self.readLinesFromFile(file)
                self.temp_copy_path = self.create_temporary_copy(self.filepath)  # update copy
                return res
        except IOError:
            # original database-file is blocked, go on
            pass

        # read from copied database-file
        try:
            with open(self.temp_copy_path, "r") as file:
                res = self.readLinesFromFile(file)
                return res
        except IOError as e:  # noqa
            raise error.UnauthorizedLogin()

    def readLinesFromFile(self, file):
        res = []
        for line in file:
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
            else:
                continue
        return res

    def writeToDatabase(self, user, pw, services):

        if type(user) is bytes:
            user = user.decode()
        if type(pw) is bytes:
            pw = pw.decode()

        try:
            with open(self.filepath, "a") as file:
                log.info("Begin Honeytoken creation: {} : {}".format(user, pw))  # TODO make this a proper log type
                file.write("\n" + services + self.sep + user + self.sep + pw + self.sep)
        except Exception as e:
            log.err("Honeytoken DB write exception: {}".format(e))

    def getUser(self, username):

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

    def randomAccept(self, username, password, randomAcceptProbability):
        if (len(password) <= config.pc_maxLength) and (len(password) >= config.pc_minLength) and (len(username) <= config.nc_maxLength) and (len(username) >= config.nc_minLength) and b":" not in username and b":" not in password:
            if config.hashAccept:
                hashbau = username + config.hashSeed + password
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
            u, p, k = self.getUser(c.username)

        except error.UnauthorizedLogin:
            return defer.fail(error.UnauthorizedLogin())

        except KeyError:

            # accept random
            if self.servicename in config.honeytokendbProbabilities.keys():
                randomAcceptProbability = config.honeytokendbProbabilities[self.servicename]

            if self.randomAccept(c.username, c.password, randomAcceptProbability) and hasattr(c, 'password'):
                if self.servicename in config.honeytokendbGenerating.keys():
                    self.writeToDatabase(c.username, c.password, ",".join(config.honeytokendbGenerating[self.servicename]))
                    return defer.succeed(c.username)

            return defer.fail(error.UnauthorizedLogin())

        else:

            if hasattr(c, 'blob'):
                userkey = keys.Key.fromString(data=k)
                if not c.blob == userkey.blob():
                    return failure.Failure(error.ConchError("Unknown key."))
                if not c.signature:
                    return defer.fail(
                        # telling the cient to sign his authentication (else the public key is kind of pointless)
                        concherror.ValidPublicKey())
                if userkey.verify(c.signature, c.sigData):
                    return defer.succeed(c.username)
                else:
                    return failure.Failure(error.ConchError("Invalid Signature"))

            if not p:
                return defer.fail(error.UnauthorizedLogin())  # don't allow login with empty passwords

            return defer.maybeDeferred(c.checkPassword, p).addCallback(self.password_match, u)
