from honeygrove.core.FilesystemParser import FilesystemParser
from honeygrove.services.FTPService import FTPProtocol
from honeygrove.tests.testresources import TestLogging as fakelogging, testconfig as config

import mock
from twisted.protocols.ftp import *

import os
from os.path import join
import unittest


def add_file(dir, name):
    path = join(dir, name)
    with open(path, 'w+') as file:
        file.write("")


def remove_file(dir, name):
    os.remove(join(dir, name))


class FTP_Test(unittest.TestCase):

    def setUp(self):
        self.ftp = FTPProtocol()
        FilesystemParser.honeytoken_directory = config.tokendir
        self.ftp._parser = FilesystemParser(config.resources + "/test_dir_sys.xml")
        self.ftp.factory = FactoryMock()
        self.ftp.transport = TransportMock()
        self.ftp.l = fakelogging

    def test_PWD(self):

        actual = self.ftp.ftp_PWD()
        expected = ('257.1', ' C:\\Benutzer\\TestUser')
        self.assertEqual(expected, actual)

    def test_CWD(self):

        # Case 1: Valid Path
        actual = self.ftp.ftp_CWD("Desktop")
        expected = ('250',)
        # 1.1 Get The Correct Response
        self.assertEqual(expected, actual)
        # 1.2 Be In The Wanted Directory
        actual_directory = self.ftp.ftp_PWD()
        expected_directory = ('257.1', ' C:\\Benutzer\\TestUser\\Desktop')
        self.assertEqual(expected_directory, actual_directory)

        # Case 2: Invalid Path
        actual = self.ftp.ftp_CWD("non-existent").result.value
        self.assertTrue(isinstance(actual, FileNotFoundError))

    def test_LS(self):

        patch_sendLine = mock.patch.object(DTPMock, 'sendLine')
        patched_sendline = patch_sendLine.start()
        self.ftp.dtpInstance = DTPMock()

        # Case 1: From Current Directory
        # 1.1 Get Correct Response
        actual = self.ftp.ftp_LIST()
        expected = ('226.2',)
        self.assertEqual(expected, actual)
        # 1.2 Response Sent Via DTP
        self.assertTrue(patched_sendline.call_count == 7)

        # Case 2: From Child-Directory
        # 2.1 Get Correct Response
        actual = self.ftp.ftp_LIST("Desktop")
        self.assertEqual(expected, actual)
        # 2.2 Response Sent Via DTP
        self.assertTrue(patched_sendline.call_count == 7+1)

        # Case 3: No DTP-Connection
        self.ftp.dtpInstance = DTPMock_Unconnected()
        actual = self.ftp.ftp_LIST().result.value
        # 3.1 Get The Expected Error
        self.assertTrue(isinstance(actual, BadCmdSequenceError))

    def test_DELE(self):

        # Case 1: Valid Path to Directory
        # 1.1 Get Correct Response
        actual = self.ftp.ftp_DELE("Desktop")
        expected = "250"
        self.assertEqual(expected, actual)
        # 1.2 Directory is Deleted
        self.assertFalse(self.ftp._parser.valid_directory("Desktop"))

        # Case 2: Valid Path to File
        self.ftp.ftp_CWD("Dokumente")
        # 2.1 Get Correct Response
        actual = self.ftp.ftp_DELE("brief.doc")
        self.assertEqual(expected, actual)
        # 2.2 File is Deleted
        self.assertFalse(self.ftp._parser.valid_directory("brief.doc"))

        # Case 3: Invalid Path
        actual = self.ftp.ftp_DELE("non-existent").result.value
        # Get The Expected Error
        self.assertTrue(isinstance(actual, FileNotFoundError))

    def test_MDTM(self):

        # Case 1: Valid Path to Directory
        actual = self.ftp.ftp_MDTM("Desktop")
        expected = ('213', self.ftp.lastmodified.strftime('%Y%m%d%H%M%S'))
        self.assertEqual(expected, actual)

        # Case 2: Valid Path to File
        self.ftp.ftp_CWD("Dokumente")
        actual = self.ftp.ftp_MDTM("brief.doc")
        self.assertEqual(expected, actual)

        # Case 3: Invalid Path
        actual = self.ftp.ftp_MDTM("non-existent").result.value
        # Get The Expected Error
        self.assertTrue(isinstance(actual, FileNotFoundError))

    def test_RMD(self):

        # Case 1: Valid Path to Directory
        actual = self.ftp.ftp_RMD("Desktop")
        expected = ('250',)
        # 1.1 Directory Removed
        self.assertFalse(self.ftp._parser.valid_directory("Desktop"))
        # 1.2 Correct Response Received
        self.assertEqual(expected, actual)

        # Case 2: Invalid Path
        actual = self.ftp.ftp_RMD("non-existent").result.value
        # 2.1 Get The Expected Error
        self.assertTrue(isinstance(actual, FileNotFoundError))

        # Case 3: Valid Path to File
        self.ftp.ftp_CWD("Dokumente")
        actual = self.ftp.ftp_RMD("brief.doc").result.value
        # 3.1 Get Expected Error
        self.assertTrue(isinstance(actual, FileNotFoundError))
        # 3.2 File Not Removed
        self.assertTrue(self.ftp._parser.valid_file("brief.doc"))

    def test_MKD(self):

        # Case 1: Directory At Path Already Exists
        actual = self.ftp.ftp_MKD("Desktop").result.value
        # 1.1 Get Expected Error
        self.assertTrue(isinstance(actual, FileNotFoundError))

        # Case 2: Directory Does Not Exist And Name Is Valid
        actual = self.ftp.ftp_MKD("validfilename")
        expected = ('257.2', 'validfilename')
        # 2.1 Correct Response Received
        self.assertEqual(expected, actual)
        # 2.2 Directory Created
        self.assertTrue(self.ftp._parser.valid_directory("validfilename"))

        # Case 3: Directory Does Not Exist And Name Is Invalid
        actual = self.ftp.ftp_MKD("$$$$invalidfilename$$$$").result.value
        # 3.1 Get Expected Error
        self.assertTrue(isinstance(actual, FileNotFoundError))
        # 3.2 No Such File Created
        self.assertFalse(self.ftp._parser.valid_directory("$$$$invalidfilename$$$$"))

    def test_RNFR_RNTO(self):

        # Case 1: FromName Not Valid (aka. Dir/File Doesnt Exist)
        self.ftp.ftp_RNFR("non-existent")
        actual = self.ftp.ftp_RNTO("somename").result.value
        # 1.1 Get Expected Error
        self.assertTrue(isinstance(actual, FileNotFoundError))

        # Case 2: ToName Not Valid
        self.ftp.ftp_RNFR("Desktop")
        actual = self.ftp.ftp_RNTO("De$ktop").result.value
        # 2.1 Get Expected Error
        self.assertTrue(isinstance(actual, FileNotFoundError))
        # 2.2 No Names Have Changed
        self.assertTrue(self.ftp._parser.valid_directory("Desktop"))
        self.assertFalse(self.ftp._parser.valid_directory("De$ktop"))

        # Case 3: Both Names Valid + Directory To Rename
        self.ftp.ftp_RNFR("Desktop")
        actual = self.ftp.ftp_RNTO("ValidToName")
        expected = ('250',)
        # 3.1 Correct Response Received
        self.assertEqual(expected, actual)
        # 3.2 Directory Renamed
        self.assertTrue(self.ftp._parser.valid_directory("ValidToName"))
        self.assertFalse(self.ftp._parser.valid_directory("Desktop"))

        # Case 4: Both Names Valid + File To Rename
        self.ftp.ftp_CWD("Dokumente")
        self.ftp.ftp_RNFR("brief.doc")
        actual = self.ftp.ftp_RNTO("ValidToName")
        # 3.1 Correct Response Received
        self.assertEqual(expected, actual)
        # 3.2 File Renamed
        self.assertTrue(self.ftp._parser.valid_file("ValidToName"))
        self.assertFalse(self.ftp._parser.valid_file("brief.doc"))

    def test_SIZE(self):

        # Case 1: Invalid Path
        actual = self.ftp.ftp_SIZE("non-existent").result.value
        # 1.1 Get Expected Error
        self.assertTrue(isinstance(actual, FileNotFoundError))

        # Case 2: Valid Path to Directory
        (response, size) = self.ftp.ftp_SIZE("Desktop")
        # 2.1 Get Correct Response
        self.assertEqual('213', response)
        # 2.2 Get Appropriate Size
        self.assertTrue(size <= 5000000 and size >= 20000)

        # Case 3: Valid Path to File
        self.ftp.ftp_CWD("Dokumente")
        (response, size) = self.ftp.ftp_SIZE("brief.doc")
        # 3.1 Get Correct Response
        self.assertEqual('213', response)
        # 3.2 Get Appropriate Size
        self.assertTrue(size <= 30000 and size >= 100)

    def test_STOR(self):

        patch = mock.patch.object(DTPMock, 'registerConsumer')
        patched = patch.start()
        self.ftp.dtpInstance = DTPMock()
        self.ftp.receivedDataDirectory = './testresources/ftptest'

        # Case 1: File With Given Path Already Exists
        self.ftp.ftp_CWD("Dokumente")
        self.ftp.ftp_STOR("brief.doc")
        # 1.1 DTP Waited For Input
        self.assertTrue(patched.call_count == 1)
        # 1.2 File Exists In Parser
        self.assertTrue(self.ftp._parser.valid_file("brief.doc"))

        # Case 2: File With Given Path Doesnt Exist
        self.ftp.ftp_STOR("stortest")
        # 2.1 Make Sure That DTP Waited For Input
        self.assertTrue(patched.call_count == 1+1)
        # 2.2 File Exists In Parser
        self.assertTrue(self.ftp._parser.valid_file("stortest"))

        # Case 3: DTP-Instance is None
        self.ftp.dtpInstance = None
        # 3.1 Get Expected Error
        self.assertRaises(BadCmdSequenceError, self.ftp.ftp_STOR, "No DTP Instance")

        # Delete
        remove_file(self.ftp.receivedDataDirectory, "brief.doc")
        remove_file(self.ftp.receivedDataDirectory, "stortest")

    def test_RETR(self):

        patch = mock.patch.object(DTPMock, 'registerProducer')
        patched = patch.start()
        mydtpmock = DTPMock()
        self.ftp.dtpInstance = mydtpmock
        honeytokentestdir = './testresources'
        self.ftp.honeytokenDirectory = honeytokentestdir

        # Case 1: Invalid Path
        actual = self.ftp.ftp_RETR("non-existent")
        expected = ('550.1', 'non-existent')
        # 1.1 Get Expected Response
        self.assertEqual(expected, actual)
        # 1.2 Nothing Was Send
        self.assertTrue(patched.call_count == 0)

        # Case 2: Valid Path to Directory
        actual = self.ftp.ftp_RETR("Desktop")
        expected = ('550.1', 'Desktop')
        # 2.1 Get Expected Response
        self.assertEqual(expected, actual)
        # 2.2 Nothing Was Tried To Send
        self.assertTrue(patched.call_count == 0)

        # Case 3: Valid Path to File Not In Honeytokendirectory
        self.ftp.ftp_CWD("Dokumente")
        actual = self.ftp.ftp_RETR("brief.doc")
        expected = ('550.1', 'brief.doc')
        # 3.1 Nothing Was Tried To Send
        self.assertTrue(patched.call_count == 0)
        # 3.2 Get Expected Response
        self.assertEqual(expected, actual)
        self.ftp.ftp_CWD("..")

        # Case 4: Valid Path to File In Honeytokendirectory
        # Create File For FTP To 'Send' in Test-Folder And Parser
        honeytokenfilename = 'honeytokenfile'
        add_file(honeytokentestdir, honeytokenfilename)
        self.ftp._parser.touch(honeytokenfilename)
        actual = self.ftp.ftp_RETR(honeytokenfilename)
        # 4.1 DTP Registered Producer (aka. Something Was Decided To Send)
        self.assertTrue(patched.call_count == 1)
        remove_file(honeytokentestdir, honeytokenfilename)

        # Case 5: DTP-Instance is None
        self.ftp.dtpInstance = None
        # 5.1 Get Expected Error
        self.assertRaises(BadCmdSequenceError, self.ftp.ftp_RETR, "No DTP Instance")

    def test_Login(self):

        patch = mock.patch.object(PortalMock, 'login')
        patched = patch.start()
        self.ftp.portal = PortalMock()

        self.ftp.ftp_USER("some")
        actual = self.ftp.ftp_PASS("some")

        # Login Method of PortalMock has been Called.
        self.assertTrue(patched.call_count == 1)

    def test_InheritedCommands(self):
        supported_commands = self.ftp.inherited_commands_whitelist
        supported_commands.remove('RNFR')  # Was already tested
        for com in supported_commands:
            patch = mock.patch.object(FTPProtocol, "ftp_" + com)
            ftp = FTPProtocol()
            ftp.state = self.ftp.AUTHED
            ftp.transport = TransportMock()
            ftp.l = fakelogging
            patched = patch.start()
            actual = ftp.processCommand(com)
            # Make Sure Method is Called
            self.assertTrue(patched.call_count == 1)


# The following classes are needed to mock
# the behaviour of various classes of the twisted
# framework, which are beeing used in the implementation.

class TransportMock():
    def getPeer(self):
        return PeerMock()

    def getHost(self):
        return PeerMock()

    def write(self, text):
        pass

    def loseConnection(self):
        pass


class PeerMock():
    host = "AttackerIP"


class DTPMock():
    isConnected = True
    transport = TransportMock()

    def sendLine(self, line):
        pass

    def registerConsumer(self, consumer):
        pass

    def registerProducer(self, producer, smth):
        pass


class DTPMock_Unconnected():
    isConnected = False
    transport = TransportMock()


class PortalMock():
    def login(self, one, two, three):
        print(one, two, three)
        return SomeMock()


class SomeMock():
    def addCallbacks(self, one, two):
        pass


class FactoryMock():
    timeOut = None
    allowAnonymous = False
    pass

