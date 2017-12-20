from parser.ui import Ui
from parser.functions import *
from parser.functions import NO_SELECT
from parser.functions import ALL_FUNCTIONS
import traceback


class Parser(object):


    def __init__(self,logic,logging):
        """ Parse input and call parser/functions """
        self.logic = logic
        self.logging = logging
        self.is_select = False
        self.selected_group = "default"
        self.select_dict = {self.selected_group:[]}
        self.ui = None
        self.map_dict = {}

    def print(self,string=None):
        """ Print to ui or stdout """
        if self.ui:
            if not string:
                self.ui.print(" ")
                return
            for line in string.split("\n"):
                self.ui.print(line)
        else:
            print(string)

    def input(self,string):
        """ Get input from ui or stdin """
        if self.ui:
            return self.ui.input(string)
        else:
            return input(string)

    def select(self,args):
        """ Manipulate selected Honeypotids """
        if not args:
            self.print("Select is activ: "+str(self.is_select))
            self.print("Selected group: "+str(self.selected_group))
            self.print("Selected Honeypot Ids "+str(self.select_dict[self.selected_group]))
            self.print()
            self.print("All groups")
            for g in self.select_dict.keys():
                self.print("Group:"+g)
                self.print("    Honeypots:")
                for h in self.select_dict[g]:
                    self.print("    - "+h)
            return
        if "g"in args.keys():  # group
            if not args["g"]:
                self.selected_group = "default"
            elif len(args["g"]) == 1:
                self.selected_group = args["g"][0]
                if not args["g"][0] in self.select_dict.keys():  # group does not exost yet
                    self.select_dict[self.selected_group] = []
            else:
                self.print("You can only select one group at a time")
                return
        for option in args.keys():
            if option == "g":  # group selection already done
                self.is_select = True
                continue
            para = args[option]
            if option == "d":  # delete group
                for g in para:
                    if g == "default":
                        self.print("The default group can not be deleted")
                    else:
                        try:
                            del(self.select_dict[g])
                        except:
                            self.print(g+":group could not be deleted")
                self.selected_group = "default"
            if option == "c":#clear
                self.select_dict[self.selected_group] = []
                self.is_select = False
            elif option == "a":#add
                for h in para: 
                    if h in self.select_dict.keys():
                        for i in self.select_dict[h]:
                            if i not in self.select_dict[self.selected_group]:
                                self.select_dict[self.selected_group].append(i)
                    else:
                        self.select_dict[self.selected_group].append(h)
                self.is_select = True
            elif option == "r":#remove honeypot from group
                for i in para:
                    if i in self.select_dict[self.selected_group]:
                        self.select_dict[self.selected_group].remove(i)
                    else:
                        self.print(i+ " not in the selected list")
                self.is_select =True 
            elif option == "on":
                self.is_select = True
            elif option == "off":
                self.is_select = False
            elif option == "all":
                hlist = self.logic.list_honeypots()
                self.select_dict[self.selected_group] = hlist
                self.is_select = True
        if self.ui:
            self.ui.draw_select()

    def map(self,args):
        """ Manage the mapping of names to Honeypotids """
        if args:
            options = args.keys()
            if "auto" in options: #automatic
                answer = self.logic.get_info(["ALL"])
                for h in answer.keys():
                    if "Name" in answer[h].keys():
                        #self.map_dict[h] = answer[h]["Name"]
                        self.map_dict[answer[h]["Name"]] = h
            if "r" in options: #remove
                for i in args["r"]:
                    if i in self.map_dict.keys():
                        del(self.map_dict[i])
                    else:
                        self.print(i+": could not be deleted")
            if "c" in options: #clear
                self.map_dict = {}
            if "hid" in options and "n" in options and len(args["hid"])>0 and len(args["n"])>0: #add
                self.map_dict[args["n"][0]] = args["hid"][0]
                self.print("Mapped:"+args["n"][0]+" to:"+args["hid"][0])
        else:
            self.print("Active mappings")
            for n in self.map_dict.keys():
                self.print("Name: "+n+" Id: "+self.map_dict[n])


    def script(self,args):
        """ Exectute a script """
        run = True
        for f in args[0]:
            try:
                with open(f) as s:
                    lines = s.readlines()
                    for line in lines:
                        if line == "\n" or line.startswith("#"):
                            continue
                        self.print(">>"+line[:len(line)-1])
                        run = self.parse(line)
            except IOError as e:
                self.print(f+":file not found")
        return run

    def default_script(self):
        """ Execute the default script """
        return self.parse("script default.conf")


    def list_to_dict(self,l):
        """ Helpermethod of parse """
        if not l:
            return
        result = {}
        key = 0
        params = []
        for word in l:
            if word.startswith("-"):
                result[key] = params
                if key:
                    result[key] = params
                key = word[1:]
                params = []
            else:
                params.append(word)
        result[key] = params
        return result


    def parse(self, command):
        """ Parse and execute a command """
        command = command.split()
        if not command:
            return True
        function = command[0]
        args = self.list_to_dict(command[1:])
        if self.is_select and function not in NO_SELECT:
            if not args:
                args = {}
                args["hid"] = self.select_dict[self.selected_group]
            elif "hid" not in args.keys():
                    args["hid"] = self.select_dict[self.selected_group]
        if function == "map":
            self.map(args)
        elif function == "script":
            return self.script(args)
        elif function == "select":
            self.select(args)
        elif function == "quit":
            return False
        elif function in ALL_FUNCTIONS:
            if args and "hid" in args.keys():
                mapped_ids = []
                for h in args["hid"]:
                    if h in self.map_dict.keys():
                        mapped_ids.append(self.map_dict[h])
                    else:
                        mapped_ids.append(h)
                args["hid"] = mapped_ids
            try:
                getattr(globals()[function], function)(self, self.logic, self.logging, args)
            except:
                self.print(traceback.format_exc())
        else:
            self.print(function + ": command not found")
        return True
