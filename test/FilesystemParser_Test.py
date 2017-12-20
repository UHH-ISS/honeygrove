import unittest

from honeygrove.core.FilesystemParser import FilesystemParser
from honeygrove.tests.testresources import __path__ as resources
from honeygrove.tests.testresources import testconfig as config


class FilesystemParserUnixTest(unittest.TestCase):
    def setUp(self):
        FilesystemParser.honeytoken_directory = config.tokendir
        self.fp = FilesystemParser(resources._path[0] + '/test_unix.xml')

    def test_get_absolute_path(self):
        self.assertEqual("/home/root", self.fp.get_absolute_path("../../bin/../home/root"))
        self.assertEqual("/bin", self.fp.get_absolute_path("/../home/../bin"))

    def test_tree_contains(self):
        self.assertTrue(self.fp.tree_contains("id_rsa.pub"))
        self.assertFalse(self.fp.tree_contains("michgibtsnicht"))

    def test_add_honeytoken_files(self):
        self.assertTrue(self.fp.tree_contains("id_rsa"))
        self.assertTrue(self.fp.tree_contains("id_rsa.pub"))
        self.assertTrue(self.fp.tree_contains("suspicious_data.txt"))

    def test_get_element(self):
        self.assertEqual(self.fp.get_element([]).attrib['name'], "/")

    def test_get_current_path(self):
        self.fp.cd("/home/root")
        self.assertEqual(self.fp.get_current_path(), "/home/root")
        self.fp.cd("..")
        self.assertEqual(self.fp.get_current_path(), "/home")
        self.fp.cd("/")
        self.assertEqual(self.fp.get_current_path(), "/")

    def test_get_formatted_path(self):
        self.fp.cd("/home/root")
        self.assertEqual(self.fp.get_formatted_path(), "~")
        self.fp.cd("/home")
        self.assertFalse(self.fp.get_formatted_path() == "~")

    def test_mkdir(self):
        self.fp.mkdir("new_folder_01")
        self.assertTrue(self.fp.tree_contains("new_folder_01"))
        self.assertEqual(self.fp.ls().count("new_folder_01"), 1)  # pruefen, dass nicht mehrfach erzeugt

        self.fp.mkdir("~/new_folder_02")
        self.assertTrue(self.fp.tree_contains("new_folder_02"))
        self.fp.mkdir("../new_folder_03")
        self.assertTrue(self.fp.tree_contains("new_folder_03"))

        response = self.fp.mkdir("~/new_folder_02")
        self.assertEqual(response, "mkdir: cannot create directory 'new_folder_02': File exists")

    def test_touch(self):
        self.fp.mkdir("new_file_01")
        self.assertTrue(self.fp.tree_contains("new_file_01"))
        self.assertEqual(self.fp.ls().count("new_file_01"), 1)  # pruefen, dass nicht mehrfach erzeugt
        self.fp.mkdir("~/new_file_02")
        self.assertTrue(self.fp.tree_contains("new_file_02"))
        self.fp.mkdir("../new_file_03")
        self.assertTrue(self.fp.tree_contains("new_file_03"))

    def test_ls(self):
        self.assertEqual(self.fp.ls("/var"), "log\nmail\nspool\ntmp\n")
        self.assertEqual(self.fp.ls("/var/log"), "")
        self.fp.cd("~")
        self.assertEqual(self.fp.ls(".ssh"), "id_rsa\nid_rsa.pub\n")

    def test_change_dir(self):
        path = self.fp.get_current_path()  # alten Pfad merken
        self.fp.cd("./..")
        self.assertEqual(self.fp.get_current_path().split("/")[-1],
                         path.split("/")[-2])  # neuer Pfad = alter Pfad ohne letzten /

        self.fp.cd("~")
        path = self.fp.get_current_path()  # alten Pfad merken
        self.fp.cd("../.")
        self.assertEqual(self.fp.get_current_path().split("/")[-1],
                         path.split("/")[-2])  # neuer Pfad = alter Pfad ohne letzten /

        self.fp.cd("/")
        self.assertEqual(self.fp.get_current_path(), "/")

        self.fp.cd("~")
        self.assertEqual(self.fp.get_formatted_path(), "~")

        self.fp.cd("../..")
        self.fp.cd("../../..")
        self.assertEqual(self.fp.get_current_path(), "/")

        path = "mich/gibtsnicht"
        self.assertEqual(self.fp.cd(path), path + ": No such file or directory")

        path = "~~"
        self.assertEqual(self.fp.cd(path), path + ": No such file or directory")

    def test_get_absoulte_path(self):
        self.fp.cd("/home/root")
        self.assertEqual(self.fp.get_absolute_path("~"), "/home/root")
        self.assertEqual(self.fp.get_absolute_path("./."), "/home/root")
        self.assertEqual(self.fp.get_absolute_path("./"), "/home/root")
        self.assertEqual(self.fp.get_absolute_path("."), "/home/root")
        self.assertEqual(self.fp.get_absolute_path("/"), "/")
        self.assertEqual(self.fp.get_absolute_path("/home"), "/home")
        self.assertEqual(self.fp.get_absolute_path("/home/../bin"), "/bin")
        self.assertEqual(self.fp.get_absolute_path(""), "")
        self.fp.cd("/")
        self.assertEqual(self.fp.get_absolute_path("C:\\Benutzer"), "/C:\\Benutzer")
        self.assertEqual(self.fp.get_absolute_path("/#wasistdaßfür1Verzeichnis,_vong_Name_her?\\\n"),
                         "/#wasistdaßfür1Verzeichnis,_vong_Name_her?\\\n")
        self.assertEqual(self.fp.get_absolute_path("/PfadDarfMitSlashEnden/"), "/PfadDarfMitSlashEnden")

    def test_valid_dir(self):
        self.assertTrue(self.fp.valid_directory("/home/root"))
        self.assertTrue(self.fp.valid_directory("/home/root/"))
        self.assertTrue(self.fp.valid_directory("/"))
        self.assertTrue(self.fp.valid_directory("~"))
        self.assertTrue(self.fp.valid_directory(".."))
        self.assertTrue(self.fp.valid_directory("./.."))
        self.assertTrue(self.fp.valid_directory("../.."))
        self.assertTrue(self.fp.valid_directory("."))
        self.assertTrue(self.fp.valid_directory("./."))
        self.assertTrue(self.fp.valid_directory("../."))

        self.assertFalse(self.fp.valid_directory("..."))

    def test_valid_file(self):
        self.assertTrue(self.fp.valid_file("~/.ssh/id_rsa"))
        self.assertTrue(self.fp.valid_file("~/.ssh/id_rsa.pub"))

        self.assertFalse(self.fp.valid_file("michgibtsnicht!1!"))

    def test_delete(self):
        self.fp.cd("/")
        self.fp.mkdir("testdir")
        self.fp.cd("testdir")
        self.fp.cd("..")

        self.assertTrue("testdir" in self.fp.ls())
        self.assertEqual(self.fp.ls().count("testdir"), 1)

        self.fp.delete("testdir")
        self.assertFalse("testdir" in self.fp.ls())

        self.fp.touch("testfile")
        self.assertTrue("testfile" in self.fp.ls())
        self.assertEqual(self.fp.ls().count("testfile"), 1)

        response = self.fp.delete(".")
        self.assertEqual(response, "rm: refusing to remove '.' or '..' directory: skipping '.'")

        response = self.fp.delete("..")
        self.assertEqual(response, "rm: refusing to remove '.' or '..' directory: skipping '..'")

    def test_rename(self):
        self.fp.cd("/")
        self.fp.touch("old_name")
        self.fp.rename("old_name", "new_name")

        self.assertFalse("old_name" in self.fp.ls())

        self.assertTrue("new_name" in self.fp.ls())
        self.assertEqual(self.fp.ls().count("new_name"), 1)

    def test_move(self):
        self.fp.cd("/")
        self.fp.mkdir("testdir")
        self.fp.touch("testfile")
        response = self.fp.move("testfile", "testdir")
        self.assertEqual(response, "Not possible")

        self.fp.mkdir("testdir/testrecursive")
        self.fp.move("testdir", "/bin/testdir")
        self.assertFalse("testdir" in self.fp.ls())

        self.assertTrue("testdir" in self.fp.ls("/bin"))
        self.assertEqual(self.fp.ls("/bin").count("testdir"), 1)

        self.assertTrue("testrecursive" in self.fp.ls("/bin/testdir"))
        self.assertEqual(self.fp.ls("/bin/testdir").count("testrecursive"), 1)

    def test_cat(self):
        self.fp.cd("~")
        self.assertTrue("-----BEGIN RSA PRIVATE KEY-----" in self.fp.cat(".ssh/id_rsa"))
        self.assertFalse(self.fp.cat("~/suspicious_data.txt") == "")

class FilesystemParserWindowsTest(unittest.TestCase):
    def setUp(self):
        FilesystemParser.honeytoken_directory = config.tokendir
        self.fp = FilesystemParser(resources._path[0] + '/test_dir_sys.xml')

    def test_get_absolute_path(self):
        self.assertEqual(self.fp.get_absolute_path("~"), "/Benutzer/TestUser")

    def test_tree_contains(self):
        self.assertTrue(self.fp.tree_contains("scan_01.jpg"))
        self.assertTrue(self.fp.tree_contains("Firefox"))
        self.assertTrue(self.fp.tree_contains("id_rsa"))
        self.assertFalse(self.fp.tree_contains("michgibtsnicht"))

    def test_add_honeytoken_files(self):
        print(self.fp.ls())
        self.assertTrue(self.fp.tree_contains("id_rsa"))
        self.assertTrue(self.fp.tree_contains("suspicious_data.txt"))

    def test_get_element(self):
        self.assertEqual(self.fp.get_element([]).attrib['name'], "C:")

    def test_get_current_path(self):
        self.fp.cd("\Programme\Firefox")
        self.assertEqual(self.fp.get_current_path(), "/Programme/Firefox")
        self.fp.cd("..")
        self.assertEqual(self.fp.get_current_path(), "/Programme")
        self.fp.cd("\\")
        self.assertEqual(self.fp.get_current_path(), "/")

    def test_mkdir(self):
        self.fp.mkdir("new_folder_01")
        self.assertTrue(self.fp.tree_contains("new_folder_01"))
        self.assertEqual(self.fp.ls().count("new_folder_01"), 1)  # pruefen, dass nicht mehrfach erzeugt

        self.fp.mkdir("~/new_folder_02")
        self.assertTrue(self.fp.tree_contains("new_folder_02"))
        self.fp.mkdir("../new_folder_03")
        self.assertTrue(self.fp.tree_contains("new_folder_03"))

        response = self.fp.mkdir("~/new_folder_02")
        self.assertEqual(response, "mkdir: cannot create directory 'new_folder_02': File exists")

    def test_touch(self):
        self.fp.mkdir("new_file_01")
        self.assertTrue(self.fp.tree_contains("new_file_01"))
        self.assertEqual(self.fp.ls().count("new_file_01"), 1)  # pruefen, dass nicht mehrfach erzeugt
        self.fp.mkdir("~/new_file_02")
        self.assertTrue(self.fp.tree_contains("new_file_02"))
        self.fp.mkdir("../new_file_03")
        self.assertTrue(self.fp.tree_contains("new_file_03"))

    def test_ls(self):
        self.assertEqual(self.fp.ls("\Benutzer\TestUser\Musik"), "asdf.mp3\n")
        self.assertEqual(self.fp.ls("~/Downloads/"), "")

    def test_change_dir(self):
        path = self.fp.get_current_path()  # alten Pfad merken
        self.fp.cd("./..")
        self.assertEqual(self.fp.get_current_path().split("/")[-1],
                         path.split("/")[-2])  # neuer Pfad = alter Pfad ohne letzten /

        self.fp.cd("~")
        path = self.fp.get_current_path()  # alten Pfad merken
        self.fp.cd("../.")
        self.assertEqual(self.fp.get_current_path().split("/")[-1],
                         path.split("/")[-2])  # neuer Pfad = alter Pfad ohne letzten /

        self.fp.cd("/")
        self.assertEqual(self.fp.get_current_path(), "/")

        self.fp.cd("~")
        self.assertEqual(self.fp.get_formatted_path(), "C:\\Benutzer\\TestUser")

        self.fp.cd("../..")
        self.fp.cd("../../..")
        self.assertEqual(self.fp.get_current_path(), "/")

        path = "mich/gibtsnicht"
        self.assertEqual(self.fp.cd(path), path + ": No such file or directory")

        path = "~~"
        self.assertEqual(self.fp.cd(path), path + ": No such file or directory")

    def test_valid_dir(self):
        self.fp.cd("~")
        self.assertTrue(self.fp.valid_directory("..\..\Programme\Firefox"))
        self.assertTrue(self.fp.valid_directory("/"))
        self.assertTrue(self.fp.valid_directory("~"))
        self.assertTrue(self.fp.valid_directory(".."))
        self.assertTrue(self.fp.valid_directory("./.."))
        self.assertTrue(self.fp.valid_directory("../.."))
        self.assertTrue(self.fp.valid_directory("."))
        self.assertTrue(self.fp.valid_directory("./."))
        self.assertTrue(self.fp.valid_directory("../."))

        self.assertFalse(self.fp.valid_directory("..."))

    def test_valid_file(self):
        self.assertFalse(self.fp.valid_file("michgibtsnicht!1!"))

    def test_delete(self):
        self.fp.cd("/")
        self.fp.mkdir("testdir")
        self.fp.cd("testdir")
        self.fp.cd("..")

        self.assertTrue("testdir" in self.fp.ls())
        self.assertEqual(self.fp.ls().count("testdir"), 1)

        self.fp.delete("testdir")
        self.assertFalse("testdir" in self.fp.ls())

        self.fp.touch("testfile")
        self.assertTrue("testfile" in self.fp.ls())
        self.assertEqual(self.fp.ls().count("testfile"), 1)

        response = self.fp.delete(".")
        self.assertEqual(response, "rm: refusing to remove '.' or '..' directory: skipping '.'")

        response = self.fp.delete("..")
        self.assertEqual(response, "rm: refusing to remove '.' or '..' directory: skipping '..'")

    def test_rename(self):
        self.fp.cd("/")
        self.fp.touch("old_name")
        self.fp.rename("old_name", "new_name")

        self.assertFalse("old_name" in self.fp.ls())

        self.assertTrue("new_name" in self.fp.ls())
        self.assertEqual(self.fp.ls().count("new_name"), 1)

    def test_move(self):
        self.fp.cd("/")
        self.fp.mkdir("testdir")
        self.fp.touch("testfile")
        response = self.fp.move("testfile", "testdir")
        self.assertEqual(response, "Not possible")

        # self.fp.mkdir("testdir/testrecursive")
        # self.fp.move("testdir", "/bin/testdir")
        # self.assertFalse("testdir" in self.fp.ls())

        # self.assertTrue("testdir" in self.fp.ls("/bin"))
        # self.assertEqual(self.fp.ls("/bin").count("testdir"), 1)

        # self.assertTrue("testrecursive" in self.fp.ls("/bin/testdir"))
        # self.assertEqual(self.fp.ls("/bin/testdir").count("testrecursive"), 1)

    def test_cat(self):
        # self.assertTrue("-----BEGIN RSA PRIVATE KEY-----" in self.fp.cat("~/.ssh/id_rsa"))
        # self.assertTrue("ssh-rsa " in self.fp.cat("~/.ssh/id_rsa.pub"))
        self.assertFalse(self.fp.cat("~/suspicious_data.txt") == "")
