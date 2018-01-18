import unittest

from twisted.conch.insults.helper import TerminalBuffer

from honeygrove.core.FilesystemParser import FilesystemParser
from honeygrove.services.SSHService import SSHProtocol
from honeygrove.tests.FTP_Test import TransportMock
from honeygrove.tests.testresources import TestLogging
from honeygrove.tests.testresources import testconfig as config


class SSHTest(unittest.TestCase):

    def setUp(self):
        self.ssh = SSHProtocol()
        self.ssh.transport = TransportMock()
        self.ssh.terminal = TerminalBuffer()
        self.ssh.userName = "Test"
        self.ssh.name = config.sshName
        self.ssh.port = config.sshPort
        FilesystemParser.honeytoken_directory = config.tokendir
        self.ssh._parser = FilesystemParser(config.resources + "/test_unix.xml")
        self.ssh.userIP = "TestIP"
        self.ssh.l = TestLogging

    def test_ssh_help(self):
        self.assertEqual(self.ssh.ssh_help("help"), self.ssh.get_help("help"))

    def test_handle_arguments(self):
        self.assertEqual(("", ["l","a"]), self.ssh.handle_arguments(["-la"]))
        self.assertEqual(("/",["l", "a"]), self.ssh.handle_arguments(["/", "-la"]))

    def test_ssh_pwd(self):
        self.assertEqual(self.ssh._parser.get_current_path(), self.ssh.ssh_pwd())

    def test_ssh_cd(self):
        self.ssh.ssh_cd("/")
        self.assertEqual("/", self.ssh.ssh_pwd())
        self.ssh.ssh_cd("~")
        self.assertEqual("/home/root", self.ssh.ssh_pwd())
        self.ssh.ssh_cd("/..")
        self.assertEqual("/", self.ssh.ssh_pwd())
        self.ssh.ssh_cd("/.././bin")
        self.assertEqual("/bin", self.ssh.ssh_pwd())
        self.ssh.ssh_cd("")
        self.assertEqual("/bin", self.ssh.ssh_pwd())
        self.ssh.ssh_cd("ungültigerpfad")
        self.assertEqual("/bin", self.ssh.ssh_pwd())

    def test_ssh_echo(self):
        self.assertEqual("123", self.ssh.ssh_echo("123"))
        self.assertEqual("/?§$%&§$%/!", self.ssh.ssh_echo("/?§$%&§$%/!"))
        self.assertEqual("&&|/)", self.ssh.ssh_echo("&&|/)"))

    def test_ssh_whoami(self):
        self.assertEqual("Test", self.ssh.ssh_whoami())

    def test_ssh_mkdir(self):
        self.assertEqual(None, self.ssh.ssh_mkdir("Test"))
        self.assertEqual("mkdir: cannot create directory 'Test': File exists", self.ssh.ssh_mkdir("Test"))

    def test_ssh_touch(self):
        self.assertEqual(None, self.ssh.ssh_touch("Test2"))
        self.assertEqual(None, self.ssh.ssh_touch("Test2"))

    def test_ssh_rm(self):
        self.ssh.ssh_touch("Test3")
        self.assertEqual(None, self.ssh.ssh_rm("Test3"))
        self.ssh.ssh_mkdir("Test4")
        self.assertEqual("rm: Test4: is a directory", self.ssh.ssh_rm("Test4"))
        self.assertTrue("Test4" in self.ssh._parser.ls())
        self.assertEqual(None, self.ssh.ssh_rm("Test4", "-rf"))
        self.assertTrue("Test4" not in self.ssh._parser.ls())

    def test_ssh_cat(self):
        self.assertEqual("user1:password1\na:b\n", self.ssh.ssh_cat("suspicious_data.txt"))

