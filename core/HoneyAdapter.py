from honeygrove import log
from honeygrove.config import Config
from honeygrove.core.ServiceController import ServiceController
from honeygrove.resources.http_resources import HTMLLoader

import json
import os
from os.path import isfile, join
import threading
import time
from xml.etree import ElementTree as ET

if Config.use_broker:
    from honeygrove.broker.BrokerEndpoint import BrokerEndpoint


class HoneyAdapter:
    controller = None
    start = Config.honeygrove_start
    lock = threading.Lock()

    @staticmethod
    def init():
        HoneyAdapter.controller = ServiceController()

        if HoneyAdapter.start == 'active':
            for service in Config.startupList:
                HoneyAdapter.controller.startService(service)

        if Config.use_broker:
            BrokerEndpoint.startListening()

            if Config.broker.peer:
                BrokerEndpoint.peerTo(Config.broker.peer_ip, Config.broker.peer_port)

    @staticmethod
    def command_message_loop():
        while Config.use_broker:
            time.sleep(0.1)
            msg = BrokerEndpoint.getCommandMessage()
            if msg:
                with HoneyAdapter.lock:
                    HoneyAdapter.handle_messages(msg)

    @staticmethod
    def heartbeat():
        while True:
            log.heartbeat()
            time.sleep(60)

    @staticmethod
    def handle_messages(msgs):
        """
        Processes the commands sent by the management-console.

        :param msgs: List of list of JSON-formatted command [['{"type": "ping"}']]
        :return: Honeypot's answer as JSON
        """
        print("[!] In Message: ", msgs[0][0])
        hp_id = str(Config.HPID)

        for msg in msgs[0]:  # zweifach-geschachtelte Liste aus Strings im JSON Format: [['{"type": "ping"}']]
            jsonDict = json.loads(str(msg))

            answer = hp_id + ": COULD NOT HANDLE " + str(msg)  # Wichtig, damit answer nie None ist

            # Ping
            if jsonDict["type"] == "ping":
                answer = json.dumps(
                    {"type": "pong", "from": hp_id, "to": jsonDict["from"]}, sort_keys=True)

            # Get names of all services
            elif jsonDict["type"] == "get_all_services" and hp_id in jsonDict["to"]:
                # XXX: What does this do?
                services = list(HoneyAdapter.controller.runningServicesDict.keys())
                nservices = list(HoneyAdapter.controller.serviceDict.keys())
                aService = []

                for service in nservices:
                    aService.append(str(service))

                answer = json.dumps({"type": "send_all_services", "from": hp_id, "to": jsonDict["from"],
                                     "services": aService}, sort_keys=True)

            # Start serveral services (key = servicename)
            elif jsonDict["type"] == "start_services" and hp_id in jsonDict["to"]:
                started = []
                for service in jsonDict["services"]:
                    try:
                        if HoneyAdapter.controller.startService(service):
                            started.append(service)
                        else:
                            started = "service schon gestartet!"
                        answer = json.dumps(
                                {"type": "started_services", "to": jsonDict["from"], "from": hp_id,
                                 "services": started},
                                sort_keys=True)
                    except Exception:
                        answer = json.dumps({"type": "started_services", "to": jsonDict["from"], "from": hp_id,
                                             "services": "port already used!"}, sort_keys=True)

            # Stop serveral services (key = servicename)
            elif jsonDict["type"] == "stop_services" and hp_id in jsonDict["to"]:
                stopped = []
                for service in jsonDict["services"]:
                    if HoneyAdapter.controller.stopService(service):
                        stopped.append(service)
                    else:
                        stopped = ["Already stopped"]
                answer = json.dumps(
                    {"type": "stopped_services", "to": jsonDict["from"], "from": hp_id, "services": stopped},
                    sort_keys=True)

            # Get all changeable settings
            elif jsonDict["type"] == "get_settings" and hp_id in jsonDict["to"]:
                service_name = jsonDict["service"]
                service = HoneyAdapter.controller.serviceDict[service_name]

                ports = [service._port]
                # Case service == ListenService
                if service_name == 'LISTEN':
                    ports = ports[0]

                running = not service._stop

                if service_name in Config.honeytokendbProbabilities:
                    token_prob = Config.honeytokendbProbabilities[service_name]
                else:
                    token_prob = 0

                answer = json.dumps(
                    {"type": "hp_settings", "from": hp_id, "to": str(jsonDict["from"]), "settings": {
                        "service": service_name, "ports": ports, "running": running,
                        "token_probabilty": token_prob}}, sort_keys=True)

            # Set received settings
            elif jsonDict["type"] == "set_settings" and hp_id in jsonDict["to"]:
                settings = jsonDict["settings"]
                service_name = settings["service"]
                print(jsonDict)
                print(settings)
                if settings["token_probability"] != "":
                    token_prob = settings["token_probability"]
                else:
                    token_prob = "unchanged"
                service = HoneyAdapter.controller.serviceDict[service_name]
                running = not service._stop

                # Change port
                if settings["ports"] != "":
                    port = settings["ports"]
                    if service_name != 'LISTEN':
                        port = port[0]
                    if running:
                        service.changePort(port)
                    else:
                        service._port = port

                # Set new token_probability
                if token_prob != "unchanged":
                    Config.honeytokendbProbabilities[service_name] = token_prob

                returnport = [service._port]
                if service_name == 'LISTEN':
                    returnport = returnport[0]

                answer = json.dumps(
                    {"type": "hp_settings", "to": str(jsonDict["from"]), "from": hp_id, "settings": {
                        "service": service_name, "ports": returnport, "running": running,
                        "token_probability": token_prob}}, sort_keys=True)

            # Get file of credentials of honeytokendb
            elif jsonDict["type"] == "get_credentials" and hp_id == jsonDict["to"]:
                with open(Config.tokenDatabase, "r") as myfile:
                    data = myfile.read()
                    answer = json.dumps({"type": "send_credentials", "from": hp_id, "to": jsonDict["from"],
                                         "file": data}, sort_keys=True)

            # Set file of credentials of honeytokendb
            elif jsonDict["type"] == "set_credentials" and hp_id == jsonDict["to"]:
                valid = True

                # Check if every line contains 2 or 3 colons
                # with the string before the first colon not being empty
                for line in jsonDict["file"].split("\n")[:-1]:
                    colons = len(line.split(":")) - 1
                    split = line.split(":")
                    valid = colons >= 2 and colons <= 3 and split[0] != ""
                    # In case there are 3 colons, the string behind the
                    # third colon has to start with 'ssh-rsa '
                    if colons == 3:
                        valid = split[3].startswith("ssh-rsa ")

                if valid:
                    with open(Config.tokenDatabase, "w") as myfile:
                        myfile.write(jsonDict["file"])
                answer = json.dumps({"type": "update", "from": hp_id, "to": jsonDict["from"],
                                     "response": "set_credentials", "successful": valid}, sort_keys=True)

            # Get the current filesystem_xml
            elif jsonDict["type"] == "get_filesystem_xml" and hp_id in jsonDict["to"]:
                with open(Config.path_to_filesys, "r") as myfile:
                    data = myfile.read()
                    answer = json.dumps(
                        {"type": "respond_filesystem_xml", "from": hp_id, "to": jsonDict["from"],
                         "file": data}, sort_keys=True)

            # Set a new filesstem_xml
            elif jsonDict["type"] == "set_filesystem_xml" and hp_id in jsonDict["to"]:

                try:
                    # Tries to interpret the file as XML-tree
                    tree = ET.fromstring(jsonDict["file"])

                    # Create set of tags
                    tags = set()
                    for elem in tree.iter():
                        tags.add(elem.tag)

                    length = len(tags)
                    # Case only one sort of tag: has to be dir!
                    if length == 1:
                        valid = 'dir' in tags
                    # Case two sorts of tag: dir + file
                    elif length == 2:
                        valid = 'dir' in tags and 'file' in tags
                    # More the two sorts of tags: invalid
                    else:
                        valid = False
                except ET.ParseError:
                    valid = False

                if valid:
                    file_name = "custom_file_system.xml"

                    new_path = "/".join(Config.path_to_filesys.split("/")[:-1]) + "/" + file_name
                    with open(new_path, "w") as myfile:
                        myfile.write(jsonDict["file"])

                    Config.path_to_filesys = new_path

                answer = json.dumps({"type": "update", "from": hp_id, "to": jsonDict["from"],
                                     "response": "set_filesystem_xml", "successful": valid}, sort_keys=True)

            # Get name and content of all tokenfiles
            elif jsonDict["type"] == 'get_token_files' and hp_id == jsonDict["to"]:
                tokenfiles = []
                for filename in os.listdir(Config.tokendir):
                    path = join(Config.tokendir, filename)
                    if isfile(path):
                        try:
                            with open(path, 'r') as file:
                                data = file.read()
                                tokenfiles.append({"name": filename, "file": data})
                        except EnvironmentError:
                            pass

                answer = json.dumps({"type": "send_token_files", "from": hp_id, "to": jsonDict["from"],
                                     "tokenfiles": tokenfiles}, sort_keys=True)

            # Add a tokenfile
            elif jsonDict["type"] == 'add_token_file' and hp_id == jsonDict["to"]:
                succ = 'true'
                filename = jsonDict["file"]["name"]
                path = join(Config.tokendir, filename)
                content = jsonDict["file"]["file"]

                # If tokenfile with same name exists: overwrite content
                # Else: create new file
                try:
                    with open(path, 'w+') as file:
                        file.write(content)
                except EnvironmentError:
                    succ = 'false'

                answer = json.dumps(
                    {"type": "update", "from": hp_id, "to": jsonDict["from"], "successful": succ,
                     "response": "add_token_file"}, sort_keys=True)

            # Remove tokenfile (key = name)
            elif jsonDict["type"] == 'remove_token_files' and hp_id == jsonDict["to"]:
                succ = 'true'
                names = jsonDict["names"]

                # Case ALL
                if "ALL" in names:
                    try:
                        files = os.listdir(Config.tokendir)
                        for f in files:
                            os.remove(join(Config.tokendir, f))

                    except EnvironmentError:
                        succ = 'false'

                # Case specific names
                else:
                    try:
                        for name in names:
                            path = join(Config.tokendir, name)
                            if isfile(path):  # In case name is not valid
                                os.remove(path)
                    except EnvironmentError:
                        succ = 'false'

                answer = json.dumps(
                    {"type": "update", "from": hp_id, "to": jsonDict["from"], "successful": succ,
                     "response": "remove_token_files"}, sort_keys=True)

            # Get HTML-pages
            elif jsonDict["type"] == "get_html_pages" and jsonDict["to"] == hp_id:
                print("get html pages")
                data = []
                sites = []
                for key in Config.http.html_dictionary:
                    sites.append(key)
                for i in range(0, sites.__len__()):
                    login = Config.http.html_dictionary[sites[i]][0]
                    content = "None"
                    if Config.http.html_dictionary[sites[i]].__len__() > 1:
                        content = Config.http.html_dictionary[sites[i]][1]
                        file = open(Config.httpResources + content, encoding='utf8')
                        content = file.read()
                        file.close()
                    file = open(Config.httpResources + login, encoding='utf8')
                    login = file.read()
                    file.close()
                    data.append({"url": sites[i],
                                 "html": login,
                                 "dashboard": content})
                answer = json.dumps(
                    {"type": "send_html_pages", "from": hp_id, "to": jsonDict["from"],
                     "pages": data})

            # Remove one or more HTML-pages
            elif jsonDict["type"] == "remove_html" and jsonDict["to"] == hp_id:
                pages = jsonDict["urls"]
                data = False
                sites = []
                for key in Config.http.html_dictionary:
                    sites.append(key)
                if pages == ["ALL"]:
                    Config.http.html_dictionary.clear()
                    Config.http.html_dictionary["404"] = ["404_login.html"]

                    for currentFile in os.listdir(Config.httpResources):
                        ext = ('.html')
                        if currentFile.endswith(ext) and not currentFile.__eq__("404_login.html"):
                            os.remove(Config.httpResources + currentFile)
                    HTMLLoader.save_HTMLDictionary(Config.http.html_dictionary)
                    Config.http.html_dictionary = HTMLLoader.load_HTMLDictionary()
                    data = True  # data = "Removing of all pages was succesful!"
                else:
                    for page in pages:
                        if page in Config.http.html_dictionary:
                            if Config.http.html_dictionary[page].__len__() > 1:
                                os.remove(Config.httpResources + Config.http.html_dictionary[page][1])
                            os.remove(Config.httpResources + Config.http.html_dictionary[page][0])
                            del Config.http.html_dictionary[page]
                            HTMLLoader.save_HTMLDictionary(Config.http.html_dictionary)
                            Config.http.html_dictionary = HTMLLoader.load_HTMLDictionary()
                    if set(pages) < set(sites):
                        data = True
                    else:
                        data = False

                answer = json.dumps(
                    {"type": "update", "from": hp_id, "to": jsonDict["from"],
                     "successful": data, "response": "remove_html"})

            # Add HTML-page
            elif jsonDict["type"] == "add_html" and jsonDict["to"] == hp_id:
                path = jsonDict["page"]["url"]
                page = jsonDict["page"]["html"]
                page2 = jsonDict["page"]["dashboard"]
                data = False  # data = "Something went wrong!"
                sites = []
                for key in Config.http.html_dictionary:
                    sites.append(key)
                if path in sites:
                    data = False  # data = "Page does exist already!"
                else:
                    data = True  # data = "Adding of " + path + " was succesful!"
                    with open(Config.resources + "/http_resources" + path + "_login.html", "a+") as f:
                        f.write(page)
                    if page2 != "":
                        with open(Config.resources + "/http_resources" + path + "_content.html", "a+") as f:
                            f.write(page2)
                        Config.http.html_dictionary[path] = [path[1:] + "_login.html", path[1:] + "_content.html"]
                    else:
                        Config.http.html_dictionary[path] = [path[1:] + "_login.html"]
                    HoneyAdapter.controller.stopService(Config.httpName)
                    HoneyAdapter.controller.startService(Config.httpName)
                HTMLLoader.save_HTMLDictionary(Config.http.html_dictionary)
                answer = json.dumps(
                    {"type": "update", "from": hp_id, "to": jsonDict["from"],
                     "successful": data, "response": "add_html"})

            # Get description
            elif jsonDict["type"] == "getDescription" and jsonDict["to"] == hp_id:
                answer = json.dumps({"type": "responseDescription", "to": jsonDict["from"], "from": hp_id,
                                     "data": Config.hp_description})

            # Get peering
            elif jsonDict["type"] == "get_peering" and jsonDict["to"] == [hp_id]:
                answer = json.dumps({"type": "send_peering", "to": jsonDict["from"], "from": hp_id,
                                     "ip": BrokerEndpoint.peerings[0], "port": int(BrokerEndpoint.peerings[1])})
            # Set peer
            elif jsonDict["type"] == "set_peer" and jsonDict["to"] == [hp_id]:
                BrokerEndpoint.peerTo(jsonDict["ip"], int(jsonDict["port"]))
                answer = json.dumps({"type": "peer_set", "to": jsonDict["from"], "from": hp_id,
                                     "ip": BrokerEndpoint.peerings[0], "port": int(BrokerEndpoint.peerings[1])})

            # Unpeer honeypot with its peering-partner
            elif jsonDict["type"] == "unpeer" and jsonDict["to"] == [hp_id]:
                BrokerEndpoint.unPeer()
                answer = json.dumps({"type": "unpeered", "to": jsonDict["from"], "from": hp_id})

            # Get info
            elif jsonDict["type"] == "get_info" and jsonDict["to"] == [hp_id]:
                answer = json.dumps({"type": "send_info", "to": jsonDict["from"], "from": hp_id,
                                     "info": Config.hp_description})

            BrokerEndpoint.sendMessageToTopic("answer", answer)
            print("[!] Antwort: ", answer, "Antwort Ende!")
            return answer
