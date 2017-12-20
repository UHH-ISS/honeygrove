import time
import json
import os
from network.network import Network
from pathlib import Path

class Logic(object):

    def __init__(self):
        """ Implemantation of the pybroker messages """
        self.network = Network()
        self.home_dir = os.path.expanduser('~')

    def connect(self,ip,port):
        """
        Peer this console to a broker endpoint

        :param ip:
        :param port: type integer
        :return: peering successfully created
        """
        return self.network.connect(ip,port)

    def disconnect(self,connection_name):
        """
        Terminate one peering connection of this console 

        :param connection_name: id of the connection can be obtained by list_connections
        """
        return self.network.disconnect(connection_name)

    #return: [[ip,port],[ip2,port2]]
    def list_connections(self):
        """
        List peering connections of this console

        :return: {connection_id1:[[ip,port],
                    connection_id2:[ip2,port2]]}
        """
        return self.network.list_connections()

    def get_logs(self):
        """
        Get a list of all arrived logs since the last call of get_logs

        :return: 
        """
        return self.network.get_logs()

    def extract_messages(self,msg_list):
        """
        Helpermethod of check_answer
        Converts a list of json encodes messages to a list of dictionaries
        """
        msgs = []
        for m in msg_list:
            msgs.append(json.loads(str(m)))
        return msgs

    def check_answer(self,msg_list,honeypotids,expect_dict):
        """
        Helpermethod of get_messages
        Check which of the recieved messages are wanted
        
        :param msg_list: recieved messages
        :param honeypotids: 
        :param expect_dict: key value pairs to identify if a response is wanted
        """
        filtered_msgs = []
        for msg in msg_list:
            if "ALL" in honeypotids or msg["from"] in honeypotids:
                for k in expect_dict.keys():
                    if k in msg.keys():
                        if msg[k] == expect_dict[k]:
                            filtered_msgs.append(msg)
        return filtered_msgs


    def get_messages(self,honeypotids,expect_dict):
        """ 
        Helpermethod of send_receive
        Waits for messages from honeypots and check them

        :param honeypotids: list of honeypots responses are expected from
        :param expect_dict: 
        :return: list of expected responses, may be empty
        """
        if type(honeypotids) == str:
            honeypotids = [honeypotids]
        if "ALL" in honeypotids:
            msg_list = self.network.wait_for_messages()
            if msg_list:
                msg_list = self.extract_messages(msg_list)
                msg_list = self.check_answer(msg_list,honeypotids,expect_dict)
        else:
            msg_count = len(honeypotids)
            msg_list = []
            while(msg_count > 0):
                msgs = self.network.get_message()
                if msgs:
                    msgs = self.extract_messages(msgs)
                    msgs = self.check_answer(msgs,honeypotids,expect_dict)
                    if msgs:
                        msg_list = msg_list + msgs
                        msg_count -= len(msgs)
                else:
                    msg_count = 0
        return msg_list

    def send_receive(self, req, honeypotids, expect_dict):
        """
        Helpermethod
        Send a request to the specified honeypots, wait for messages and filter them for the wanted responses

        :param req: dictionary with the request
        :param honeypotids: honeypots, from which a response is expected
        :param expect_dict: if a message contains all these key value pairs, it is a wanted response
        :return: all wanted responses as a list of dictionaries
        """
        self.network.sendMessageToTopic(json.dumps(req))
        return self.get_messages(honeypotids,expect_dict)


    def get_info(self,honeypotids):
        """
        Get the infos of honeypots

        :param honeypotids:
        :return: 
        """
        req = {"type":"get_info",
                "from":self.network.mc_id,
                "to": honeypotids}
        expect_dict = {"type":"send_info"}
        msg_list = self.send_receive(req,honeypotids,expect_dict)
        answer = {}
        for msg in msg_list:
            answer[msg["from"]] = msg["info"]
        return answer

    def honeypot_peer(self,honeypotids,ip,port):
        """
        Peer honeypots to an endpoint

        :param honeypotids:
        :param ip:
        :param port: type:integer
        :return:
        """
        req = {"type":"set_peer",
                "from":self.network.mc_id,
                "to":honeypotids,
                "ip":ip,
                "port":port}
        expect_dict = {"type":"peer_set"}
        msg_list = self.send_receive(req,honeypotids,expect_dict)
        answer = {}
        for msg in msg_list:
            answer[msg["from"]] = [msg["ip"],msg["port"]]
        return answer

    def honeypot_get_peering(self,honeypotids):
        """
        Get info, to which endpoints the honeypots are peered to

        :param honeypotids:
        :return:
        """
        req = {"type":"get_peering",
                "from":self.network.mc_id,
                "to":honeypotids}
        expect_dict = {"type":"send_peering"}
        msg_list = self.send_receive(req,honeypotids,expect_dict)
        answer = {}
        for msg in msg_list:
            answer[msg["from"]] = [msg["ip"],msg["port"]]
        return answer

    def honeypot_unpeer(self,honeypotids):
        """
        Terminate the peerings of honeypots

        :param honeypotids:
        :return:
        """
        req = {"type":"unpeer",
                "from":self.network.mc_id,
                "to":honeypotids}
        expect_dict = {"type":"unpeered"}
        msg_list = self.send_receive(req,honeypotids,expect_dict)
        answer = []
        for msg in msg_list:
            answer.append(msg["from"])
        return answer

    def list_honeypots(self):
        """
        Get a list of all honeypots this console can reach

        :return:
        """
        req = {"type": "ping",
                "to":["ALL"],
                "from": self.network.mc_id}
        expect_dict = {"type":"pong"}
        msg_list = self.send_receive(req, "ALL", expect_dict)
        answer = []
        for msg in msg_list:
            answer.append(msg["from"])
        return answer


    def list_services(self,honeypotids):
        """
        Get all services (by their id, and sorted by honeypots) that are currently running on the honeypots

        :param honeypotids:
        :return:
        """
        req = {"type":"get_all_services",
                "to":honeypotids,
                "from":self.network.mc_id}
        expect_dict = {"type":"send_all_services"}
        msg_list = self.send_receive(req,honeypotids,expect_dict)
        answer = {}
        for msg in msg_list:
            answer[msg["from"]] = msg["services"]
        return answer


    def get_service_config(self, honeypotids, serviceid):
        """
        Get the configurations of one service from multiple honeypots

        :param honeypotids:
        :param serviceid:
        :return:
        """
        req = {"type": "get_settings", 
               "from": self.network.mc_id,
               "to": honeypotids,
               "service": serviceid}
        expect_dict = {"type": "hp_settings"}
        msg_list = self.send_receive(req, honeypotids, expect_dict)
        answer = {}
        for msg in msg_list:
            answer[msg["from"]] = msg["settings"]
        return answer


    def send_service_config(self, honeypotids, config):
        """
        Send configirations to honeypots

        :param honeypotids:
        :param config: contains the information which service this is addressed to
        :return: how the configuration is after the changes
        """
        req = {"type": "set_settings", 
                "from": self.network.mc_id,
                "to": honeypotids,
                "settings": config}
        expect_dict = {"type": "hp_settings"}
        msg_list = self.send_receive(req, honeypotids, expect_dict)
        answer = {}
        for msg in msg_list:
            answer[msg["from"]] = msg["settings"]
        return answer



    def start_service(self,honeypotids,serviceids):
        """
        Start services on honeypots

        :param honeypotids:
        :param serviceids:
        :return:
        """
        req = {"type": "start_services",
                "services": serviceids, 
                "to": honeypotids, 
                "from": self.network.mc_id}
        expect_dict = {"type":"started_services"}
        msg_list = self.send_receive(req, honeypotids, expect_dict)
        answer = {}
        for msg in msg_list:
            answer[msg["from"]] = msg["services"]
        return answer


    def stop_service(self,honeypotids,serviceids):
        """
        Stop services on honeypots

        :param honeypotids:
        :param serviceids:
        :return:
        """
        req = {"type": "stop_services",
                "services": serviceids, 
                "to": honeypotids, 
                "from": self.network.mc_id}
        expect_dict = {"type":"stopped_services"}
        msg_list = self.send_receive(req, honeypotids, expect_dict)
        answer = {}
        for msg in msg_list:
            answer[msg["from"]] = msg["services"]
        return answer


    # honeypotid: type string
    # return: bool: wurde eine Datei empfangen und geschrieben
    def get_filesystem(self, honeypotid, directory=[]):
        req = {"type": "get_filesystem_xml",
               "to": honeypotid,
               "from": self.network.mc_id}
        expect_dict = {"type": "respond_filesystem_xml"}
        msg_list = self.send_receive(req, honeypotid, expect_dict)
        if msg_list:
            iterator = 0
            while True:
                iterator_string = "" if iterator == 0 else "-" + str(iterator)

                if len(directory) > 0 and directory[0] != "":
                    filename = directory[0] + str("" if directory[0].endswith("/") else "/") + msg_list[0]["from"] + iterator_string + ".xml"
                else:
                    filename = self.home_dir + "/" + msg_list[0]["from"] + iterator_string + ".xml"

                iterator += 1
                if not(Path(filename).is_file()):
                    break
            with open(filename, 'x') as f:
                f.write(msg_list[0]["file"])
            return filename
        else:
            return False

    def send_filesystem(self, honeypotids, xml_file):
        # eine XML fuer alle Honeypots
        with open(xml_file, "r") as myfile:
            data = myfile.read()
            req = {"type": "set_filesystem_xml",
                   "to": honeypotids,
                   "from": self.network.mc_id,
                   "file": data}
            expect_dict = {"type": "update", "response": "set_filesystem_xml"}
            msg_list = self.send_receive(req, honeypotids, expect_dict)
            answer = {}
            for msg in msg_list:
                answer[msg["from"]] = msg["successful"]
        return answer

    def get_token_files(self, honeypotid, directory=[]):

        """
        Get all Tokenfile From one honeypot

        :param honeypotid:
        :param directory: not used yet
        :return:
        """

        req = {"type": "get_token_files",
               "to": honeypotid,
               "from": self.network.mc_id}
        expect_dict = {"type": "send_token_files"}
        msg_list = self.send_receive(req, honeypotid, expect_dict)
        answer = ""
        for msg in msg_list[0]['tokenfiles']:
            filename = self.home_dir + "/" + msg['name']
            answer = answer + "Tokenfile at: " + filename + "\n"
            # mode w will overwrite already existent files
            with open(filename, 'w') as f:
                f.write(msg["file"])
        return answer


    def add_token_files(self, honeypotid, filepath):
        """
        Add a Tokenfile From to honeypot

        :param honeypotid:
        :param filepath:
        :return:
        """

        expect_dict = {"type": "update"}
        with open(filepath, 'r') as file:
            data = file.read()
            filename = os.path.basename(filepath)
            filejson = {"name": filename, "file": data}
            req = {"type": "add_token_file",
                   "to": honeypotid,
                   "from": self.network.mc_id,
                   "file": filejson}
            msg_list = self.send_receive(req, honeypotid, expect_dict)
            try:
                return msg_list[0]['successful']
            except IndexError:
                return False


    def remove_token_files(self, honeypotid, filenames):
        """
        Remove Token Files honeypot

        :param honeypotid:
        :param filenames:
        :return: true/false
        """
        expect_dict = {"type": "update"}
        req = {"type": "remove_token_files",
               "to": honeypotid,
               "from": self.network.mc_id,
               "names": filenames}
        msg_list = self.send_receive(req, honeypotid, expect_dict)
        try:
            return msg_list[0]['successful']
        except IndexError:
            return False


    def get_html_pages(self, honeypotid):
        """
        Get all HTML pages from one honeypot

        :param honeypotid:
        :return: Msg
        """
        req = {"type": "get_html_pages",
               "to": honeypotid,
               "from": self.network.mc_id}
        expect_dict = {"type": "send_html_pages"}
        msg_list = self.send_receive(req, honeypotid, expect_dict)
        answer = ""
        i = 0;
        for msg in msg_list[0]['pages']:
            mainHTMLfilename = self.home_dir + "/" + msg_list[0]["from"] + "_" + str(i) + "_" + msg['url'].replace("/",
                                                                                                                   "_") + "_login.html"
            dashboardHTMLfilename = self.home_dir + "/" + msg_list[0]["from"] + "_" + str(i) + "_" + msg['url'].replace("/",
                                                                                                                        "_") + "_dashboard.html"
            answer = answer + "Main HTML at: " + mainHTMLfilename + "\n"

            # mode w will overwrite already existent files
            with open(mainHTMLfilename, 'w') as f:
                f.write(msg["html"])
            if  not msg["dashboard"] == "None":
                answer = answer + "Dashboard HTML at: " + dashboardHTMLfilename + "\n"
                with open(dashboardHTMLfilename, 'w') as f:
                    f.write(msg["dashboard"])
            i = i + 1
        return answer  # json.dumps(req) + "\n" + msg_list[0]["pages"][0]["url"]


    def add_html_page(self, honeypotid, url, dir, dashdir):
        """
        Add a HTML page to one honeypot

        :param honeypotid:
        :param url:
        :param dir:
        :param dashdir:
        :return: Msg
        """
        expect_dict = {"type": "update"}
        with open(dir, 'r') as file:
            maindata = file.read()
            if (dashdir != ""):
                with open(dashdir, 'r') as dashfile:
                    dashdata = dashfile.read()
                    page = {"url": url, "html": maindata, "dashboard": dashdata}
                    req = {"type": "add_html",
                           "to": honeypotid,
                           "from": self.network.mc_id,
                           "page": page}
                    msg_list = self.send_receive(req, honeypotid, expect_dict)
                    try:
                        return msg_list[0]['successful']
                    except IndexError:
                        return False
            else:
                page = {"url": url, "html": maindata, "dashboard": ""}
                req = {"type": "add_html",
                       "to": honeypotid,
                       "from": self.network.mc_id,
                       "page": page}
                msg_list = self.send_receive(req, honeypotid, expect_dict)
                try:
                    return msg_list[0]['successful']
                except IndexError:
                    return False



    def remove_html_pages(self, honeypotid, urls):
        """
        remove HTML page

        :param honeypotid:
        :param urls:
        :return: true/false:
        """
        expect_dict = {"type": "update"}
        req = {"type": "remove_html",
               "to": honeypotid,
               "from": self.network.mc_id,
               "urls": urls}
        msg_list = self.send_receive(req, honeypotid, expect_dict)
        try:
            return msg_list[0]['successful']
        except IndexError:
            return False

#TODO werden die noch gebraucht?
#
#    #wenn die tokens nicht abgerufen werden konnten: return -1
#    #wenn nichts zurueckgegeben wird, wird davon ausgegangen, dass der honeygrove existiert, aber die token datei leer ist
#    def get_tokens(self,honeypotid):
#        #name : passwort
#        t = {   "root" : "root123",
#                "myaccount" : "password",
#                "admin" : "12345"}
#        return t

#    def send_tokens(self,honeypotid,tokens):
#        print(tokens)
#        print(honeypotid,"Tokens gesendet")
#
#    #wofuer ist diese methode?
#    def py(self, arg):
#        print("x")
