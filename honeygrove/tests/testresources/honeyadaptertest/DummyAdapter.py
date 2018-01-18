import json
import honeygrove.tests.testresources.testconfig as config
from honeygrove.resources import __path__ as resources
from xml.etree import ElementTree as ET

import os
from os.path import isfile, join


# Mock Classes needed for the Testing

class ServiceA():
    _name = 'TESTSERVICEA'
    _stop = True
    _port = 1

    def changePort(self, port):
        # Eigentlich + Start/Stop
        self._port = port


class ServiceB():
    _name = 'TESTSERVICEB'
    _stop = False
    _port = 2

    def changePort(self, port):
        # Eigentlich + Start/Stop
        self._port = port


class ListenService():
    _name = 'LISTEN'
    _stop = True
    _port = [1, 2, 3, 4, 5]

    def changePort(self, port):
        # Eigentlich + Start/Stop
        self._port = port


class ServiceController():
    def __init__(self):
        self.serviceList = [ServiceA(), ServiceB(), ListenService()]
        self.serviceDict = dict([(service._name, service) for service in self.serviceList])

    def get_serviceDict(self):
        return self.serviceDict

    def startAllServices(self):
        pass

    def stopAllServices(self):
        pass

    def startService(self, name):
        self.serviceDict[name]._stop = False

    def stopService(self, name):
        self.serviceDict[name]._stop = True

    def safeStartService(self, name):
        if self.serviceDict[name]._stop:
            self.serviceDict[name]._stop = True
        return self.serviceDict[name]._stop

    def safeStopService(self, name):
        if not self.serviceDict[name]._stop:
            self.serviceDict[name]._stop = False
        return not self.serviceDict[name]._stop


class BrokerEndpoint():
    @staticmethod
    def sendMessageToTopic(topic, message):
        # print("BrokerEndpoint.sendMessageToTopic", (topic, message))
        pass


# TESTING OBJECT:
class DummyAdapter():
    controller = ServiceController()

    @staticmethod
    def handle_messages(msgs):
        """
        Verarbeitet die Befehle der Managementkonsole.
        :param msgs: Erwartet von Broker einer zweifach-geschachtelte Liste aus Strings im JSON Format: [['{"type": "ping"}']]
        :return: die Antwort des HP als JSON (dict)
        """
        for msg in msgs[0]:  # zweifach-geschachtelte Liste aus Strings im JSON Format: [['{"type": "ping"}']]
            jsonDict = json.loads(str(msg))

            answer = "Couldn't handle " + msg  # Wichtig, damit answer nie None ist

            # Ping
            if jsonDict["type"] == "ping":
                answer = json.dumps(
                    {"type": "pong", "from": str(config.HPID), "to": jsonDict["from"]}, sort_keys=True)

            # Hole alle Services
            elif jsonDict["type"] == "get_all_services" and not set(jsonDict["to"]).isdisjoint(
                    ["ALL", str(config.HPID)]):
                services = list(DummyAdapter.controller.serviceDict.keys())
                answer = json.dumps({"type": "send_all_services", "from": str(config.HPID), "to": jsonDict["from"],
                                     "services": services}, sort_keys=True)

            # Starte mehrere Services (via Name) an mehreren HPs
            elif jsonDict["type"] == "start_services" and str(config.HPID) in jsonDict["to"]:
                started = []
                for service in jsonDict["services"]:
                    if DummyAdapter.controller.safeStartService(service):
                        started.append(service)
                answer = json.dumps(
                    {"type": "started_services", "to": jsonDict["from"], "from": str(config.HPID), "services": started},
                    sort_keys=True)

            # Stoppe mehrere Services (via Name) an mehreren HP
            elif jsonDict["type"] == "stop_services" and str(config.HPID) in jsonDict["to"]:
                stopped = []
                for service in jsonDict["services"]:
                    if DummyAdapter.controller.safeStopService(service):
                        stopped.append(service)
                answer = json.dumps(
                    {"type": "stopped_services", "to": jsonDict["from"], "from": str(config.HPID), "services": stopped},
                    sort_keys=True)

            # Hole aktuelles FileySystem eines HPs
            elif jsonDict["type"] == "get_filesystem_xml" and jsonDict["to"] == str(
                    config.HPID):
                with open(config.path_to_filesys, "r") as myfile:
                    data = myfile.read()
                    answer = json.dumps(
                        {"type": "respond_filesystem_xml", "from": str(config.HPID), "to": jsonDict["from"],
                         "file": data}, sort_keys=True)

            # Hole alle Settings EINES Services VIELER HPs
            elif jsonDict["type"] == "get_settings" and str(config.HPID) in jsonDict["to"]:
                service_name = jsonDict["service"]
                service = DummyAdapter.controller.serviceDict[service_name]

                ports = [service._port]
                # Case Service is ListenService
                if service_name == 'LISTEN':
                    ports = ports[0]

                running = not service._stop
                token_prob = config.honeytokendbProbabilities[service_name]

                answer = json.dumps(
                    {"type": "hp_settings", "from": str(config.HPID), "to": str(jsonDict["from"]), "settings": {
                        "service": service_name, "ports": ports, "running": running,
                        "token_probabilty": token_prob}}, sort_keys=True)

            # Setze alle Settings EINES Services MEHRERER HPs
            elif jsonDict["type"] == "set_settings" and str(config.HPID) in jsonDict["to"]:
                settings = jsonDict["settings"]
                service_name = settings["service"]
                token_prob = settings["token_probability"]
                service = DummyAdapter.controller.serviceDict[service_name]
                running = not service._stop

                port = settings["ports"]
                if service_name != 'LISTEN':
                    port = port[0]

                # Change Port
                if running:
                    service.changePort(port)
                else:
                    service._port = port

                # Set new TokenProbability
                config.honeytokendbProbabilities[service_name] = token_prob

                returnport = [service._port]
                if service_name == 'LISTEN':
                    returnport = returnport[0]

                answer = json.dumps(
                    {"type": "hp_settings", "to": str(jsonDict["from"]), "from": str(config.HPID), "settings": {
                        "service": service_name, "ports": returnport, "running": running,
                        "token_probability": token_prob}}, sort_keys=True)


            elif jsonDict["type"] == "get_credentials" and str(config.HPID) == jsonDict["to"]:
                with open(resources._path[0] + "/database.txt", "r") as myfile:
                    data = myfile.read()
                    answer = json.dumps({"type": "send_credentials", "from": str(config.HPID), "to": jsonDict["from"],
                                         "file": data}, sort_keys=True)

            elif jsonDict["type"] == "set_credentials" and str(config.HPID) == jsonDict["to"]:
                valid = True

                # Prüfen, dass jede Zeile genau 2 oder 3 Doppelpunkte enthält
                # und vor dem ersten Doppelpunkt irgendwas steht (ServiceName)
                for line in jsonDict["file"].split("\n")[:-1]:
                    colons = len(line.split(":")) - 1
                    split = line.split(":")
                    valid = colons >= 2 and colons <= 3 and split[0] != ""
                    # Fall es 3 Doppelpunkte gibt, muss der Inhalt dahinter mit 'ssh-rsa ' beginnen
                    if colons == 3:
                        valid = split[3].startswith("ssh-rsa ")

                if valid:
                    with open(resources._path[0] + "/database.txt", "w") as myfile:
                        myfile.write(jsonDict["file"])
                answer = json.dumps({"type": "update", "from": str(config.HPID), "to": jsonDict["from"],
                                     "response": "set_credentials", "successful": valid}, sort_keys=True)

            elif jsonDict["type"] == "set_filesystem_xml" and str(config.HPID) == jsonDict["to"]:

                # muss mit <! beginnen: die Zahlen dahinter zeigen das home Verzeichnis fuer den Service an
                # muss mit </dir> enden: die äußerste Schale eines jeden Systems ist immer ein Ordner
                valid = jsonDict["file"].startswith("<!") and jsonDict["file"].endswith("\n</dir>")
                try:
                    # Versuch die Datei als XML Baum einzulesen: Test ob diese XML wohlgeformt ist
                    tree = ET.fromstring(jsonDict["file"])

                    # Gehe alle Tags durch und lege sie in ein Set (keine Doppelten)
                    tags = set()
                    for elem in tree.iter():
                        tags.add(elem.tag)

                    length = len(tags)
                    # Falls es nur eine Sorte Tags gibt MUSS es dir sein
                    if length == 1:
                        valid = valid and 'dir' in tags
                    # Falls es genau zwei Sorten Tags gibt muessen es dir und file sein
                    elif length == 2:
                        valid = valid and 'dir' in tags and 'file' in tags
                    # Mehr als zwei Tags sind ungueltig
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

            # Erhalte Namen und Inhalt aller Token-Files EINES Honeypots
            elif jsonDict["type"] == 'get_token_files' and str(config.HPID) == jsonDict["to"]:
                tokenfiles = []
                for filename in os.listdir(config.tokendir_adapter):
                    path = join(config.tokendir_adapter, filename)
                    if isfile(path):
                        try:
                            with open(path, 'r') as file:
                                data = file.read()
                                tokenfiles.append({"name": filename, "file": data})
                        except EnvironmentError:
                            pass

                answer = json.dumps({"type": "send_token_files", "from": str(config.HPID), "to": jsonDict["from"],
                                     "tokenfiles": tokenfiles}, sort_keys=True)

            # Füge eine Token-File bei EINEM Honeypot hinzu
            elif jsonDict["type"] == 'add_token_file' and str(config.HPID) == jsonDict["to"]:
                succ = 'true'
                filename = jsonDict["file"]["name"]
                path = join(config.tokendir_adapter, filename)
                content = jsonDict["file"]["file"]

                # Case: Token mit gleichem Filenamen existiert: Inhalt überschreiben
                # Sonst: Neue Datei erstellen
                try:
                    with open(path, 'w+') as file:
                        file.write(content)
                except EnvironmentError:
                    succ = 'false'

                answer = json.dumps(
                    {"type": "update", "from": str(config.HPID), "to": jsonDict["from"], "successful": succ,
                     "response": "add_token_file"}, sort_keys=True)

            # Entfernt eine Token-File eines Honeypots
            elif jsonDict["type"] == 'remove_token_files' and str(config.HPID) == jsonDict["to"]:
                succ = 'true'
                names = jsonDict["names"]

                # Case ALL
                if "ALL" in names:
                    try:
                        files = os.listdir(config.tokendir_adapter)
                        for f in files:
                            os.remove(join(config.tokendir_adapter, f))

                    except EnvironmentError:
                        succ = 'false'

                # Case Specific Names
                else:
                    try:
                        for name in names:
                            path = join(config.tokendir_adapter, name)
                            if isfile(path):  # In Case Name is not valid
                                os.remove(path)
                    except EnvironmentError:
                        succ = 'false'

                answer = json.dumps(
                    {"type": "update", "from": str(config.HPID), "to": jsonDict["from"], "successful": succ,
                     "response": "remove_token_files"}, sort_keys=True)

        BrokerEndpoint.sendMessageToTopic("answer", answer)
        print(answer)
        return answer
