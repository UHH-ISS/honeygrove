import unittest

from honeygrove.core.HoneytokenDB import HoneytokenDataBase
import twisted.cred.credentials as credentials
from twisted.cred.error import UnauthorizedLogin


class HoneyTokenDBTest(unittest.TestCase):

    databasefile = 'testresources/testdatabase.txt'
    servicename = 'MyServiceName'
    sep = ':'

    def addCredentials(self, credstring):
        with open(self.databasefile, 'w') as file:
            file.write(credstring)

    def clearCredentials(self):
        with open(self.databasefile, 'w') as file:
            file.seek(0)

    def setUp(self):
        HoneytokenDataBase.filepath = self.databasefile
        self.db = HoneytokenDataBase(self.servicename)

    def test_validCreds(self):
        username = 'usermcuserface'
        pw = 'pass'
        c = credentials.UsernamePassword(username, pw)

        # Write them to Database
        credstring = self.servicename + self.sep + username + self.sep + pw + self.sep
        self.addCredentials(credstring)

        # Make sure you got UserName back ==> creds are valid
        actual = self.db.requestAvatarId(c).result
        self.assertEqual(username, actual)

        # Delete creds from file
        self.clearCredentials()

    def test_inValidCreds(self):
        c = credentials.UsernamePassword('idontexist', 'hahahahah')
        actual = self.db.requestAvatarId(c).result.value
        self.assertTrue(isinstance(actual, UnauthorizedLogin))
