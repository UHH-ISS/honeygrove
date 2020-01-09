from honeygrove import log
from honeygrove.config import Config
from honeygrove.core.Credential import Credential
from honeygrove.core.SessionDatabase import SessionDatabase

from twisted.conch.ssh import keys
from twisted.cred import credentials, error
from twisted.cred.checkers import ICredentialsChecker, FilePasswordDB
from twisted.internet import defer
from zope.interface import implementer

import hashlib
import random


@implementer(ICredentialsChecker)
class HoneytokenDatabase():
    """
        Honeytoken Database.
        Credchecker used by all Services.
    """

    delimiter = '\t'

    credentialInterfaces = (credentials.IUsernamePassword,
                            credentials.IUsernameHashedPassword)

    def __init__(self, servicename):
        """
        @type servicename: str
        @param servicename: The name of the service which is using this database instance.

        """
        self.servicename = servicename
        self.filepath = str(Config.honeytoken.database_folder / "database-{}.txt".format(servicename))
        self.token_db = FilePasswordDB(self.filepath, delim=self.delimiter, cache=True)
        self.session_db = SessionDatabase()

        self.strategy = Config.honeytoken.strategy

    # FIXME: This should be moved to SSHService
    def try_decode_key(self, raw_key):
        key_str = raw_key.decode(errors='ignore')
        # These keys are unsupported by twisted and Key.fromString fails if we call it, so return None
        if "ed25519" in key_str or "ecdsa" in key_str:
            return None
        return keys.Key.fromString(data=raw_key).toString("OPENSSH").decode()

    def add_token(user, secret):
        pass

    def try_get_token(self, user, secret):
        if isinstance(secret, bytes):
            # login via password (which might be bytes)
            secret = secret.decode()

        try:
            u, s = self.token_db.getUser(user)
            return (u, s)
        except KeyError:
            return None

    def hash_accept(self, username, password, randomAcceptProbability):
        if (Config.honeytoken.username_min <= len(username) <= Config.honeytoken.username_max
                and Config.honeytoken.password_min <= len(password) <= Config.honeytoken.password_max
                and ":" not in username and ":" not in password):

            if Config.honeytoken.accept_via_hash:
                # Need to encode to be able to hash it via hashlib
                hashbau = (username + Config.honeytoken.hash_seed + password).encode()
                hash1 = hashlib.sha1(hashbau).hexdigest()
                i = 0
                for x in range(0, 39):
                    i = i + int(hash1[x], 16)
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

    def strategy_hash(self, creds):
        randomAcceptProbability = 0
        if self.servicename in Config.honeytoken.probabilities.keys():
            randomAcceptProbability = Config.honeytoken.probabilities[self.servicename]

        if hasattr(creds, 'password') and self.hash_accept(creds.username, creds.password, randomAcceptProbability):
            if self.servicename in Config.honeytoken.generating.keys():
                # FIXME: Do we need to know the IP here?
                self.add_token(creds.username, creds.password)
                return defer.succeed(creds.username)

        # Keys should not reach the database, as we abort before this, but better make sure
        return defer.fail(error.UnauthorizedLogin("Invalid Password or Public Key"))

    def on_login(self, c):
        # Always suceed for now
        print("HoneytokenDatabase.requestAvatarId: returning succeed for {}".format(c))
        session_result = None

        if isinstance(c, Credential):
            session_result = self.session_db.on_login(c)
            return defer.succeed(c.username)

        if session_result:
            pass
        try:
            # Does this credential match a honeytoken?
            user, secret = self.try_get_token(c.username)
            return defer.maybeDeferred(c.checkPassword, secret).addCallback(self.password_match, user)

        except KeyError:
            # If not, react according to self.strategy
            if self.strategy == 'hash':
                return self.strategy_hash(c)
            elif self.strategy == 'v1':
                pass

    # Rebind methods for twisted
    requestAvatarId = on_login
