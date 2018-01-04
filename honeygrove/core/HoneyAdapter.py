# Honey Adapter
import json
import os
import threading
import time
from os.path import isfile, join
from xml.etree import ElementTree as ET

import honeygrove.config as config
import honeygrove.logging.log as log
from honeygrove.broker.BrokerEndpoint import BrokerEndpoint
from honeygrove.core.ServiceController import ServiceController
from honeygrove.resources.http_resources import HTMLLoader


class HoneyAdapter(object):
    controller = None
    start = config.honeygrove_start
    lock = threading.Lock()

    @staticmethod
    def init():
        HoneyAdapter.controller = ServiceController()

        if HoneyAdapter.start == 'active':
            for service in config.startupList:
                HoneyAdapter.controller.startService(service)

        BrokerEndpoint.startListening()

        if config.init_peer:
            BrokerEndpoint.peerTo(config.init_peer_ip, config.init_peer_port)

    @staticmethod
    def command_message_loop():
        while (True):
            time.sleep(0.1)
            msg = BrokerEndpoint.getCommandMessage()
            if msg:
                with HoneyAdapter.lock:
                    HoneyAdapter.handle_messages(msg)

    @staticmethod
    def hearbeat():
        while (True):
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

        for msg in msgs[0]:  # zweifach-geschachtelte Liste aus Strings im JSON Format: [['{"type": "ping"}']]
            jsonDict = json.loads(str(msg))

            answer = str(config.HPID) + ": COULD NOT HANDLE " + str(msg)  # Wichtig, damit answer nie None ist

            # Ping
            if jsonDict["type"] == "ping":
                answer = json.dumps(
                    {"type": "pong", "from": str(config.HPID), "to": jsonDict["from"]}, sort_keys=True)

            # Get names of all services
            elif jsonDict["type"] == "get_all_services" and str(config.HPID) in jsonDict["to"]:
                services = list(HoneyAdapter.controller.runningServicesDict.keys())
                nservices = list(HoneyAdapter.controller.serviceDict.keys())
                aService = []

                for service in nservices:
                    aService.append(str(service))

                answer = json.dumps({"type": "send_all_services", "from": str(config.HPID), "to": jsonDict["from"],
                                     "services": aService}, sort_keys=True)

            # Start serveral services (key = servicename)
            elif jsonDict["type"] == "start_services" and str(config.HPID) in jsonDict["to"]:
                started = []
                for service in jsonDict["services"]:
                    try:
                        if HoneyAdapter.controller.startService(service):
                            started.append(service)
                        else:
                            started = "service schon gestartet!"
                        answer = json.dumps(
                                {"type": "started_services", "to": jsonDict["from"], "from": str(config.HPID),
                                 "services": started},
                                sort_keys=True)
                    except:
                        answer = json.dumps({"type": "started_services", "to": jsonDict["from"], "from": str(config.HPID),
                                             "services": "port already used!"}, sort_keys=True)

            # Stop serveral services (key = servicename)
            elif jsonDict["type"] == "stop_services" and str(config.HPID) in jsonDict["to"]:
                stopped = []
                for service in jsonDict["services"]:
                    if HoneyAdapter.controller.stopService(service):
                        stopped.append(service)
                    else:
                        stopped = ["Already stopped"]
                answer = json.dumps(
                    {"type": "stopped_services", "to": jsonDict["from"], "from": str(config.HPID), "services": stopped},
                    sort_keys=True)

            # Get all changeable settings
            elif jsonDict["type"] == "get_settings" and str(config.HPID) in jsonDict["to"]:
                service_name = jsonDict["service"]
                service = HoneyAdapter.controller.serviceDict[service_name]

                ports = [service._port]
                # Case service == ListenService
                if service_name == 'LISTEN':
                    ports = ports[0]

                running = not service._stop

                if service_name in config.honeytokendbProbabilities:
                    token_prob = config.honeytokendbProbabilities[service_name]
                else:
                    token_prob = 0

                answer = json.dumps(
                    {"type": "hp_settings", "from": str(config.HPID), "to": str(jsonDict["from"]), "settings": {
                        "service": service_name, "ports": ports, "running": running,
                        "token_probabilty": token_prob}}, sort_keys=True)

            # Set received settings
            elif jsonDict["type"] == "set_settings" and str(config.HPID) in jsonDict["to"]:
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
                    config.honeytokendbProbabilities[service_name] = token_prob

                returnport = [service._port]
                if service_name == 'LISTEN':
                    returnport = returnport[0]

                answer = json.dumps(
                    {"type": "hp_settings", "to": str(jsonDict["from"]), "from": str(config.HPID), "settings": {
                        "service": service_name, "ports": returnport, "running": running,
                        "token_probability": token_prob}}, sort_keys=True)

            # Get file of credentials of honeytokendb
            elif jsonDict["type"] == "get_credentials" and str(config.HPID) == jsonDict["to"]:
                with open(config.tokenDatabase, "r") as myfile:
                    data = myfile.read()
                    answer = json.dumps({"type": "send_credentials", "from": str(config.HPID), "to": jsonDict["from"],
                                         "file": data}, sort_keys=True)

            # Set file of credentials of honeytokendb
            elif jsonDict["type"] == "set_credentials" and str(config.HPID) == jsonDict["to"]:
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
                    with open(config.tokenDatabase, "w") as myfile:
                        myfile.write(jsonDict["file"])
                answer = json.dumps({"type": "update", "from": str(config.HPID), "to": jsonDict["from"],
                                     "response": "set_credentials", "successful": valid}, sort_keys=True)

            # Get the current filesystem_xml
            elif jsonDict["type"] == "get_filesystem_xml" and str(config.HPID) in jsonDict["to"]:
                with open(config.path_to_filesys, "r") as myfile:
                    data = myfile.read()
                    answer = json.dumps(
                        {"type": "respond_filesystem_xml", "from": str(config.HPID), "to": jsonDict["from"],
                         "file": data}, sort_keys=True)

            # Set a new filesstem_xml
            elif jsonDict["type"] == "set_filesystem_xml" and str(config.HPID) in jsonDict["to"]:

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

                    new_path = "/".join(config.path_to_filesys.split("/")[:-1]) + "/" + file_name
                    with open(new_path, "w") as myfile:
                        myfile.write(jsonDict["file"])

                    config.path_to_filesys = new_path

                answer = json.dumps({"type": "update", "from": str(config.HPID), "to": jsonDict["from"],
                                     "response": "set_filesystem_xml", "successful": valid}, sort_keys=True)

            # Get name and content of all tokenfiles
            elif jsonDict["type"] == 'get_token_files' and str(config.HPID) == jsonDict["to"]:
                tokenfiles = []
                for filename in os.listdir(config.tokendir):
                    path = join(config.tokendir, filename)
                    if isfile(path):
                        try:
                            with open(path, 'r') as file:
                                data = file.read()
                                tokenfiles.append({"name": filename, "file": data})
                        except EnvironmentError:
                            pass

                answer = json.dumps({"type": "send_token_files", "from": str(config.HPID), "to": jsonDict["from"],
                                     "tokenfiles": tokenfiles}, sort_keys=True)

            # Add a tokenfile
            elif jsonDict["type"] == 'add_token_file' and str(config.HPID) == jsonDict["to"]:
                succ = 'true'
                filename = jsonDict["file"]["name"]
                path = join(config.tokendir, filename)
                content = jsonDict["file"]["file"]

                # If tokenfile with same name exists: overwrite content
                # Else: create new file
                try:
                    with open(path, 'w+') as file:
                        file.write(content)
                except EnvironmentError:
                    succ = 'false'

                answer = json.dumps(
                    {"type": "update", "from": str(config.HPID), "to": jsonDict["from"], "successful": succ,
                     "response": "add_token_file"}, sort_keys=True)

            # Remove tokenfile (key = name)
            elif jsonDict["type"] == 'remove_token_files' and str(config.HPID) == jsonDict["to"]:
                succ = 'true'
                names = jsonDict["names"]

                # Case ALL
                if "ALL" in names:
                    try:
                        files = os.listdir(config.tokendir)
                        for f in files:
                            os.remove(join(config.tokendir, f))

                    except EnvironmentError:
                        succ = 'false'

                # Case specific names
                else:
                    try:
                        for name in names:
                            path = join(config.tokendir, name)
                            if isfile(path):  # In case name is not valid
                                os.remove(path)
                    except EnvironmentError:
                        succ = 'false'

                answer = json.dumps(
                    {"type": "update", "from": str(config.HPID), "to": jsonDict["from"], "successful": succ,
                     "response": "remove_token_files"}, sort_keys=True)

            # Get HTML-pages
            elif jsonDict["type"] == "get_html_pages" and jsonDict["to"] == str(config.HPID):
                print("get html pages")
                data = []
                sites = []
                for key in config.httpHTMLDictionary:
                    sites.append(key)
                for i in range(0, sites.__len__()):
                    login = config.httpHTMLDictionary[sites[i]][0]
                    content = "None"
                    if config.httpHTMLDictionary[sites[i]].__len__() > 1:
                        content = config.httpHTMLDictionary[sites[i]][1]
                        file = open(config.httpResources + content, encoding='utf8')
                        content = file.read()
                        file.close()
                    file = open(config.httpResources + login, encoding='utf8')
                    login = file.read()
                    file.close()
                    data.append({"url": sites[i],
                                 "html": login,
                                 "dashboard": content})
                answer = json.dumps(
                    {"type": "send_html_pages", "from": str(config.HPID), "to": jsonDict["from"],
                     "pages": data})

            # Remove one or more HTML-pages
            elif jsonDict["type"] == "remove_html" and jsonDict["to"] == str(config.HPID):
                pages = jsonDict["urls"]
                data = False
                sites = []
                for key in config.httpHTMLDictionary:
                    sites.append(key)
                if pages == ["ALL"]:
                    config.httpHTMLDictionary.clear()
                    config.httpHTMLDictionary["404"] = ["404_login.html"]

                    for currentFile in os.listdir(config.httpResources):
                        ext = ('.html')
                        if currentFile.endswith(ext) and not currentFile.__eq__("404_login.html"):
                            os.remove(config.httpResources + currentFile)
                    HTMLLoader.save_HTMLDictionary(config.httpHTMLDictionary)
                    config.httpHTMLDictionary = HTMLLoader.load_HTMLDictionary()
                    data = True # data = "Removing of all pages was succesful!"
                else:
                    for page in pages:
                        if page in config.httpHTMLDictionary:
                            if config.httpHTMLDictionary[page].__len__() > 1:
                                os.remove(config.httpResources + config.httpHTMLDictionary[page][1])
                            os.remove(config.httpResources + config.httpHTMLDictionary[page][0])
                            del config.httpHTMLDictionary[page]
                            HTMLLoader.save_HTMLDictionary(config.httpHTMLDictionary)
                            config.httpHTMLDictionary = HTMLLoader.load_HTMLDictionary()
                    if set(pages) < set(sites):
                        data = True
                    else:
                        data = False

                answer = json.dumps(
                    {"type": "update", "from": str(config.HPID), "to": jsonDict["from"],
                     "successful": data, "response": "remove_html"})

            # Add HTML-page
            elif jsonDict["type"] == "add_html" and jsonDict["to"] == str(config.HPID):
                path = jsonDict["page"]["url"]
                page = jsonDict["page"]["html"]
                page2 = jsonDict["page"]["dashboard"]
                data = False #data = "Something went wrong!"
                sites = []
                for key in config.httpHTMLDictionary:
                    sites.append(key)
                if path in sites:
                    data = False #data = "Page does exist already!"
                else:
                    data = True #data = "Adding of " + path + " was succesful!"
                    with open(config.resources + "/http_resources" + path + "_login.html", "a+") as f:
                        f.write(page)
                    if page2 != "":
                        with open(config.resources + "/http_resources" + path + "_content.html", "a+") as f:
                            f.write(page2)
                        config.httpHTMLDictionary[path] = [path[1:] + "_login.html", path[1:] + "_content.html"]
                    else:
                        config.httpHTMLDictionary[path] = [path[1:] + "_login.html"]
                    HoneyAdapter.controller.stopService(config.httpName)
                    HoneyAdapter.controller.startService(config.httpName)
                HTMLLoader.save_HTMLDictionary(config.httpHTMLDictionary)
                answer = json.dumps(
                    {"type": "update", "from": str(config.HPID), "to": jsonDict["from"],
                     "successful": data, "response": "add_html"})

            # Get description
            elif jsonDict["type"] == "getDescription" and jsonDict["to"] == str(config.HPID):
                answer = json.dumps({"type": "responseDescription", "to": jsonDict["from"], "from": str(config.HPID),
                                     "data": config.hp_description})

            # Get peering
            elif jsonDict["type"] == "get_peering" and jsonDict["to"] == [str(config.HPID)]:
                answer = json.dumps({"type": "send_peering", "to": jsonDict["from"], "from": str(config.HPID),
                                     "ip": BrokerEndpoint.peerings[0], "port": int(BrokerEndpoint.peerings[1])})
            # Set peer
            elif jsonDict["type"] == "set_peer" and jsonDict["to"] == [str(config.HPID)]:
                BrokerEndpoint.peerTo(jsonDict["ip"], int(jsonDict["port"]))
                answer = json.dumps({"type": "peer_set", "to": jsonDict["from"], "from": str(config.HPID),
                                     "ip": BrokerEndpoint.peerings[0], "port": int(BrokerEndpoint.peerings[1])})

            # Unpeer honeypot with its peering-partner
            elif jsonDict["type"] == "unpeer" and jsonDict["to"] == [str(config.HPID)]:
                BrokerEndpoint.unPeer()
                answer = json.dumps({"type": "unpeered", "to": jsonDict["from"], "from": str(config.HPID)})

            # Get info
            elif jsonDict["type"] == "get_info" and jsonDict["to"] == [str(config.HPID)]:
                answer = json.dumps({"type": "send_info", "to": jsonDict["from"], "from": str(config.HPID),
                                     "info": config.hp_description})

            BrokerEndpoint.sendMessageToTopic("answer", answer)
            print("[!] Antwort: ", answer, "Antwort Ende!")
            return answer
