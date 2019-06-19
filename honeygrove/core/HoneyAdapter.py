from honeygrove import log
from honeygrove.config import Config

import json
import os
from os.path import isfile, join
import select
import time
from xml.etree import ElementTree as ET

if Config.use_broker:
    from honeygrove.broker.BrokerEndpoint import BrokerEndpoint


class BrokerWatcher():

    @staticmethod
    def broker_status_loop(controller):
        # Only if broker is enabled
        if not Config.use_broker:
            return

        # Initialize
        # - Listen for commands from management console
        if Config.broker.listen:
            BrokerEndpoint.listen(Config.broker.listen_ip, Config.broker.listen_port)
        # - Peer to database for log messages
        if Config.broker.peer:
            BrokerEndpoint.peer(Config.broker.peer_ip, Config.broker.peer_port)

        heartbeat_interval = 60
        next_heartbeat = time.time()

        # Watch endpoints
        # - Loop Status
        # - Print Status/Error
        fds = [BrokerEndpoint.status_queue.fd(),
               BrokerEndpoint.command_queue.fd()]
        while True:
            # Wait for something to do
            t = time.time()
            timeout = next_heartbeat - t if next_heartbeat > t else 0
            result = select.select(fds, [], [], timeout)

            # Heartbeat Time
            if len(result[0]) == 0:
                log.heartbeat()
                next_heartbeat += heartbeat_interval
                continue

            # - Status
            if fds[0] in result[0]:
                for status in BrokerEndpoint.getStatusMessages():
                    log.info(status)

            # - Command
            if fds[1] in result[0]:
                cmds = BrokerEndpoint.getCommandMessages()
                for cmd in cmds:
                    ManagementHandler.handle_messages(cmd, controller)


class ManagementHandler:

    @staticmethod
    def handle_messages(msg, controller):
        """
        Processes the commands sent by the management-console.

        :param msgs: List of list of JSON-formatted command [['{"type": "ping"}']]
        :return: Honeypot's answer as JSON
        """
        topic, datagrams = msg
        hp_id = str(Config.HPID)

        for data in datagrams:  # zweifach-geschachtelte Liste aus Strings im JSON Format: [['{"type": "ping"}']]
            print("[!] In Message: ", data)
            jsonDict = json.loads(str(data))

            answer = hp_id + ": COULD NOT HANDLE " + str(data)  # Wichtig, damit answer nie None ist

            # Ping
            if jsonDict["type"] == "ping":
                answer = json.dumps(
                    {"type": "pong", "from": hp_id, "to": jsonDict["from"]}, sort_keys=True)

            # Get names of all services
            elif jsonDict["type"] == "get_all_services" and hp_id in jsonDict["to"]:
                # XXX: What does this do?
                services = list(controller.runningServicesDict.keys())
                nservices = list(controller.serviceDict.keys())
                aService = []

                for service in nservices:
                    aService.append(str(service))

                answer = json.dumps({"type": "send_all_services", "from": hp_id, "to": jsonDict["from"],
                                     "services": aService}, sort_keys=True)

            # Start several services (key = servicename)
            elif jsonDict["type"] == "start_services" and hp_id in jsonDict["to"]:
                started = []
                for service in jsonDict["services"]:
                    try:
                        if controller.startService(service):
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
                    if controller.stopService(service):
                        stopped.append(service)
                    else:
                        stopped = ["Already stopped"]
                answer = json.dumps(
                    {"type": "stopped_services", "to": jsonDict["from"], "from": hp_id, "services": stopped},
                    sort_keys=True)

            # Get all changeable settings
            elif jsonDict["type"] == "get_settings" and hp_id in jsonDict["to"]:
                service_name = jsonDict["service"]
                service = controller.serviceDict[service_name]

                ports = [service._port]
                # Case service == ListenService
                if service_name == 'LISTEN':
                    ports = ports[0]

                running = not service._stop

                if service_name in Config.honeytoken.probabilities:
                    token_prob = Config.honeytoken.probabilities[service_name]
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
                service = controller.serviceDict[service_name]
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
                    Config.honeytoken.probabilities[service_name] = token_prob

                returnport = [service._port]
                if service_name == 'LISTEN':
                    returnport = returnport[0]

                answer = json.dumps(
                    {"type": "hp_settings", "to": str(jsonDict["from"]), "from": hp_id, "settings": {
                        "service": service_name, "ports": returnport, "running": running,
                        "token_probability": token_prob}}, sort_keys=True)

            # Get file of credentials of honeytokendb
            elif jsonDict["type"] == "get_credentials" and hp_id == jsonDict["to"]:
                # XXX: Is this the correct file?
                with open(str(Config.folder.honeytoken_files), "r") as myfile:
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
                    # XXX: Is this the correct file?
                    with open(str(Config.folder.honeytoken_files), "w") as myfile:
                        myfile.write(jsonDict["file"])
                answer = json.dumps({"type": "update", "from": hp_id, "to": jsonDict["from"],
                                     "response": "set_credentials", "successful": valid}, sort_keys=True)

            # Get the current filesystem_xml
            elif jsonDict["type"] == "get_filesystem_xml" and hp_id in jsonDict["to"]:
                with open(str(Config.folder.filesystem), "r") as myfile:
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

                    new_path = str(Config.folder.filesystem.with_name(file_name))
                    with open(new_path, "w") as myfile:
                        myfile.write(jsonDict["file"])

                    Config.folder.filesystem = new_path

                answer = json.dumps({"type": "update", "from": hp_id, "to": jsonDict["from"],
                                     "response": "set_filesystem_xml", "successful": valid}, sort_keys=True)

            # Get name and content of all tokenfiles
            elif jsonDict["type"] == 'get_token_files' and hp_id == jsonDict["to"]:
                tokenfiles = []
                for filename in os.listdir(Config.folder.honeytoken_files):
                    path = str(Config.folder.honeytoken_files / filename)
                    if isfile(path):
                        try:
                            with open(path, 'r') as fp:
                                data = fp.read()
                                tokenfiles.append({"name": filename, "file": data})
                        except EnvironmentError:
                            pass

                answer = json.dumps({"type": "send_token_files", "from": hp_id, "to": jsonDict["from"],
                                     "tokenfiles": tokenfiles}, sort_keys=True)

            # Add a tokenfile
            elif jsonDict["type"] == 'add_token_file' and hp_id == jsonDict["to"]:
                succ = 'true'
                filename = jsonDict["file"]["name"]
                path = join(Config.folder.honeytoken_files, filename)
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
                        files = os.listdir(Config.folder.honeytoken_files)
                        for f in files:
                            os.remove(Config.folder.honeytoken_files / f)

                    except EnvironmentError:
                        succ = 'false'

                # Case specific names
                else:
                    try:
                        for name in names:
                            path = join(Config.folder.honeytoken_files, name)
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
                        with open(str(Config.http.resource_folder / content, encoding='utf8')) as fp:
                            content = fp.read()
                    with open(str(Config.http.resource_folder / login, encoding='utf8')) as fp:
                        login = fp.read()
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

                    for currentFile in os.listdir(Config.http.resource_folder):
                        ext = ('.html')
                        if currentFile.endswith(ext) and not currentFile.__eq__("404_login.html"):
                            os.remove(Config.http.resource_folder / currentFile)
                    Config.save_html_dictionary()
                    data = True  # data = "Removing of all pages was succesful!"
                else:
                    for page in pages:
                        if page in Config.http.html_dictionary:
                            if len(Config.http.html_dictionary[page]) > 1:
                                os.remove(Config.http.resource_folder / Config.http.html_dictionary[page][1])
                            os.remove(Config.http.resource_folder / Config.http.html_dictionary[page][0])
                            del Config.http.html_dictionary[page]
                            Config.save_html_dictionary()

                    data = len(set(pages)) < len(set(sites))

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
                    with open(str(Config.http.resource_folder / path / "_login.html"), "a+") as f:
                        f.write(page)
                    if page2:
                        with open(str(Config.http.resource_folder / path / "_content.html"), "a+") as f:
                            f.write(page2)
                        Config.http.html_dictionary[path] = [path[1:] + "_login.html", path[1:] + "_content.html"]
                    else:
                        Config.http.html_dictionary[path] = [path[1:] + "_login.html"]
                    controller.stopService(Config.http.name)
                    controller.startService(Config.http.name)
                Config.save_html_dictionary()
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
