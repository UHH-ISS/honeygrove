import pybroker
import time
import random

class Network(object):
    def __init__(self):
        """ Manage the connection the broker network """
        self.mc_id = "mc-" + str(random.randint(100000,9999999))
        flags = pybroker.AUTO_ADVERTISE | pybroker.AUTO_PUBLISH | pybroker.AUTO_ROUTING
        self.endpoint = pybroker.endpoint(self.mc_id,flags)
        self.answerQueue = pybroker.message_queue("answer", self.endpoint,pybroker.GLOBAL_SCOPE)
        self.logsQueue = pybroker.message_queue("logs", self.endpoint,pybroker.GLOBAL_SCOPE)

        #increments if new peering is created
        #used to identify peerings
        self.connection_counter = 0
        
        #dictionary of active peerings
        self.conncection_dic = {}
        

    def connect(self, IP, PORT):
        """
        Create a new peering

        :param IP:
        :param PORT:
        :return: peering created successfully
        """
        peering = self.endpoint.peer(IP,PORT)
        if peering:
            self.conncection_dic[self.connection_counter]=[IP,PORT,peering]
            self.connection_counter += 1
            return True
        else:
            return False
        
    def disconnect(self, connectionName):
        """
        Terminate one peering

        :param connectionName: id of the connection
        :return:
        """
        if connectionName in self.conncection_dic.keys():
            value = self.endpoint.unpeer(self.conncection_dic[connectionName][2])
            del self.conncection_dic[connectionName]
            return value
        else:
            return False

    def list_connections(self):
        """
        List the current peerings
        :return:
        """
        dic = {}
        for i in self.conncection_dic.keys():
            dic[i] = self.conncection_dic[i][:2]
        return dic


    def get_logs(self):
        """
        Get the logs that arrived since the last call of get_logs
        :return:
        """
        msg_list = self.empty_queue(self.logsQueue)
        return msg_list

    def empty_queue(self,queue):
        """
        Helpermethod of get_message, get_logs and wait_for_messages
        :param queue:
        :return: all messages in the queue
        """
        answer = []
        while True:
            msg = queue.want_pop()
            if msg:
                for x in msg:
                    for y in x:
                        if queue == self.answerQueue:
                            if str("to\": \""+self.mc_id+"\"") in str(y):
                                answer.append(y)
                        elif queue == self.logsQueue:
                            answer.append(y)
            else:
                return answer

    def get_message(self,timeout=10):
        """
        Get the first message that is addressed to this console 
        :param timeout:
        :return:
        """
        msgs = self.empty_queue(self.answerQueue)
        if msgs:
            return msgs
        else:
            for t in range(timeout):
                time.sleep(0.5)
                msgs = self.empty_queue(self.answerQueue)
                if msgs:
                    return msgs
        return []

    def wait_for_messages(self,sec=5):
        """
        Wait a few sconds, then get all arrived messages, that are addressed to this console
        :param sec:
        :return:
        """
        time.sleep(sec)
        return self.empty_queue(self.answerQueue)
        
    def sendMessageToTopic(self, msg):
        """
        Send a message to the commands topic
        :param msg:
        """
        self.endpoint.send("commands", pybroker.message([pybroker.data(msg)]))

