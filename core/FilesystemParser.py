from honeygrove.config import Config

import os
import re
import xml.etree.ElementTree as ET


class FilesystemParser:
    honeytoken_directory = Config.tokendir
    cd_pattern = "^cd \S+$"
    mkdir_pattern = "^mkdir \S+$"
    touch_pattern = "^touch \S+$"
    ls_pattern = "^ls \S+$"

    def __init__(self, xml_path=Config.path_to_filesys):

        with open(xml_path) as f:
            try:
                self.start_path = f.readline().split("--")[1].split(",")  # read first line and parse
                self.start_path = list(map(int, self.start_path))  # letters-numbers to list
            except Exception:
                self.start_path = []  # if nothing given, the "/" is the root-/user directory

        # The current position in the tree as list
        self.current_pos = self.start_path
        self.xml_path = xml_path
        self.tree = ET.parse(self.xml_path)
        self.root = self.tree.getroot()

        if self.root.attrib['name'] != "/":
            self.mode = "DOS"
        else:
            self.mode = "UNIX"

        # Saves the user directory path (to show it as "-")
        self.user_path = self.get_current_path()
        self.add_honeytoken_files()

    def get_position(self, path):
        """
        Specifies the position to a given path
        :param path: the path which position shall be determined
        :return:
        """
        path = self.get_absolute_path(path)
        if not self.valid_path(path):
            raise Exception("Invalid path")
        position = []
        if path == "/":
            return position
        for element in path.split("/")[1:]:  # da wir mit absoluten Pfaden arbeiten, ist das erste Element ""
            children = [c.attrib['name'] for c in self.get_element(position)]
            position.append(children.index(element))
        return position

    def get_path(self, position):
        """
        Gives path for a position
        :param position: The position, the path has to be determined for
        :return:
        """
        path = ""
        current = self.root
        if position == []:
            return "/"
        for i in position:
            current = current[i]
            if current.attrib['name'] != "/":  # "root-/" brauchen wir nicht, ist schon da
                path += "/" + current.attrib['name']
        return path

    def get_element(self, position):
        """
        Gives the element from the XML-tree
        :param position: Position of the element
        :return:
        """
        current = self.root
        for i in position:
            current = current[i]
        return current

    def get_absolute_path(self, rel_path: str):
        """
        Changes a (absolute or relevant) path into a absolute Path and converts commands like ".."
        :param rel_path: The path to be converted
        :return: the absolute path to path
        """

        if not rel_path:
            return ""

        if self.mode == "DOS":
            if re.match(r"\w:\\", rel_path[0:2]):
                rel_path = rel_path[3:]
            rel_path = rel_path.replace("\\", "/")

        if rel_path == "/":
            return rel_path

        if rel_path[0] == "~":
            rel_path = rel_path.replace("~", self.user_path)

        if rel_path[0] != "/":  # if its a absolute path, we don't have to add a prefix
            rel_path = self.get_current_path() + "/" + rel_path

        # Deletes stuff like ///, /./, ./ or /.
        rel_path = re.sub(r"([^\.]|^)(\./)", r"/",
                          rel_path)  # "beginning of the line" or " not .", followed by any amount of "./"
        rel_path = re.sub(r"(/\.)$", r"/", rel_path)  # the same for the end of the line
        rel_path = re.sub(r"/{2,}", r"/", rel_path)  # ///// goes to /

        folders = rel_path.split("/")
        folders = list(filter(None, folders))

        i = 0
        while i < len(folders):
            f = folders[i]
            if f == "..":
                if i > 0:
                    folders.pop(i - 1)
                    folders.pop(i - 1)  # same index because the list slipped by 1
                else:
                    folders.pop(i)
                i = 0

            else:
                i += 1
        return "/" + "/".join(folders)

    def tree_contains(self, file_name):
        """
        Checks if a name exists somewhere in the tree
        :param file_name:
        :return:
        """
        found = False
        for child in self.root.findall('.//'):
            if child.attrib['name'] == file_name:
                found = True
                break
        return found

    def add_honeytoken_files(self):
        """
        Adds the file names from the honeytokenfiles folder if files with given names not already exist
        """

        for file in os.listdir(self.honeytoken_directory):
            if not self.tree_contains(str(file)):
                self.touch(self.user_path + "/" + file)

    def get_current_path(self):
        """returns the current path as String"""
        return self.get_path(self.current_pos)

    def get_formatted_path(self):
        """
        Returns the current path as platform adjusted, returnable String
        :return:
        """
        path = self.get_current_path()
        if self.user_path == "/":
            return path  # if / is configured as user directory, nothing shall be replaced

        if self.mode == "DOS":
            return "C:" + path.replace("/", "\\")

        if self.user_path in path:
            path = path.replace(self.user_path, '~')

        return path

    def mkdir(self, path):
        """Creates a new folder at the given path"""
        return self.create(path, "dir")

    def touch(self, path):
        """
        Creates a new file at the given path
        """
        try:
            return self.create(path, "file")
        except Exception as e:
            return e

    def create(self, path, tag):
        """
        Creates a new node
        :param path: Path (with filename) to the ne node
        :param tag: Type (file or directory)
        :return:
        """

        path = self.get_absolute_path(path)
        split = path.split("/")
        file_path = "/".join(split[:-1])
        file_name = split[-1]

        if file_name in self.ls(file_path) or file_name == ".":
            if tag == "dir":
                return "mkdir: cannot create directory '" + file_name + "': File exists"
            else:
                return  # hall not be created again

        file_position = self.get_position(file_path)
        ET.SubElement(self.get_element(file_position), tag, {"name": file_name})

    def ls(self, path=''):
        """Lists all children"""
        if path:
            path = self.get_absolute_path(path)
            pos = self.get_position(path)
        else:
            pos = self.current_pos
        element = self.get_element(pos)
        response = ""
        for child in element:
            response += child.attrib['name'] + '\n'
        return response

    def cd(self, path):
        """
        Changes the position in the data tree
        :param path (absolute or relative path)
        :return None or a error message
        """
        if not path:
            return

        input = path
        path = self.get_absolute_path(path)

        if not self.valid_path(path):
            return input + ": No such file or directory"

        self.current_pos = self.get_position(path)
        return

    def valid_path(self, path, tag=''):
        """
        Determines if a given path exists

        :param path: the path to be checked
        :param tag: if tag is given, it'll be checked if the tag of the element is at the position path =tag
        """
        path = self.get_absolute_path(path)  # just in case

        if tag != 'file' and path == "/":
            return True

        pos = []

        res = True
        for p in path.split("/")[1:]:
            children = [c.attrib['name'] for c in self.get_element(pos)]
            if p in children:
                pos.append(children.index(p))
            else:
                res = False
        if not (tag == '' or self.get_element(pos).tag == tag):  # not valid if the tag is not the desired
            res = False

        return res

    def valid_directory(self, path):
        """Determines if the given path of current_pos leads to a folder"""
        return self.valid_path(path, 'dir')

    def valid_file(self, path):
        """Determines if the given path of current_pos leads to a file"""
        return self.valid_path(path, 'file')

    def delete(self, path):
        """
        Searches for a given file and deletes it if it exists
        :param path: the path to the file to be deleted
        :return:
        """
        if path == ".." or path == ".":
            return "rm: refusing to remove '.' or '..' directory: skipping '" + path + "'"

        path = self.get_absolute_path(path)
        if not self.valid_path(path):
            return

        child_name = path.split("/")[-1]
        parent_path = "/".join(path.split("/")[:-1])

        parent = self.get_element(self.get_position(parent_path))
        for child in parent:
            if child.attrib.get('name') == child_name:
                parent.remove(child)

    def rename(self, from_path, to_name):
        """
        Changes the name of a given file
        :param from_path: path to the file to be renamedPfad zur umzubenennenden Datei
        :param to_name: new name
        :return:
        """
        self.move(from_path, to_name)  # rename is actually just a special case of move

    def move(self, sourcepath, targetpath):
        """
        Moves a file from one position to another
        :param sourcepath: the path to the file to be moved
        :param targetpath: the destination path (with new filename)
        :return:
        """

        sourcepath = self.get_absolute_path(sourcepath)
        targetpath = self.get_absolute_path(targetpath)

        split = targetpath.split("/")
        parentpath = "/" + "/".join(split[1:-1])

        element = self.get_element(self.get_position(sourcepath))
        sourcetype = element.tag

        if not self.valid_directory(parentpath):
            return "Directory not found."
        else:
            if self.valid_path(targetpath):
                targettype = self.get_element(self.get_position(targetpath)).tag
                if targettype != sourcetype:
                    return "Not possible"

        parent = self.get_element(self.get_position(parentpath))

        self.delete(sourcepath)

        element.attrib['name'] = targetpath.split("/")[-1]
        parent.append(element)

    def cat(self, path):
        """
        Returns the content of the file as String
        :param path: the path to the file
        :return:
        """
        path = self.get_absolute_path(path)
        if not self.valid_path(path):
            raise Exception("File not found")
        if not self.valid_file(path):
            raise Exception("Is a directory")
        filename = path.split("/")[-1]
        for file in os.listdir(self.honeytoken_directory):
            if file == filename:
                with open(self.honeytoken_directory + "/" + file, "r") as myfile:
                    data = myfile.read()
                return data
