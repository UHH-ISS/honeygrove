from honeygrove.config import Config

import broker

import base64


class BrokerEndpoint:
    """
    The BrokerEndpoint is for the transmission of Broker messages.
    You can send and retrieve messages here.
    """

    # Broker Endpoint
    endpoint = broker.Endpoint()
    # Status Subscriber
    status_queue = endpoint.make_status_subscriber(True)
    # Subscribe to management commands
    command_queue = endpoint.make_subscriber("commands")

    # peering objects. needed for unpeering
    peerings = [0, 0, None]
    
    @staticmethod
    def getStatusMessages():
        for st in BrokerEndpoint.status_queue.poll():
            # Error
            if type(st) == broker.Error:
                yield "[Broker Error] {}". format(st)
            # Status
            elif type(st) == broker.Status:
                yield "[Broker Status] {}". format(st)
            else:
                raise RuntimeError("Unknown Broker Status Type")

    @staticmethod
    def getCommandMessages():
        """
        Gets a message from the command message_queue
        :return: Broker Message
        """
        return BrokerEndpoint.command_queue.poll()

    @staticmethod
    def sendLogs(jsonString):
        """
        Sends a Broker message containing a JSON string.
        :param jsonString: Json string.
        """
        BrokerEndpoint.endpoint.publish("logs", jsonString)

    @staticmethod
    def listen(ip, port):
        """
        Listen on ip:port
        :param ip: string
        :param port: int
        """
        p = BrokerEndpoint.endpoint.listen(ip, port)
        if p == 0:
            raise RuntimeError(
                "Unable to listen on Broker port {}".format(port))
        return p

    @staticmethod
    def peer(ip, port):
        """
        Peer to given ip:port
        :param ip: string
        :param port: int
        """
        if [ip, port] != BrokerEndpoint.peerings[0:2]:
            if BrokerEndpoint.peerings[0] != 0:
                BrokerEndpoint.unPeer(BrokerEndpoint.peerings[2])

            obj = BrokerEndpoint.endpoint.peer_nosync(ip, port)
            BrokerEndpoint.peerings = [ip, port, obj]

    @staticmethod
    def unPeer(peeringObj=None):
        """
        unpeering to given port/ip
        :param peeringObj: peering objekt
        """
        if peeringObj is None:
            BrokerEndpoint.endpoint.unpeer(BrokerEndpoint.peerings[2])
        else:
            BrokerEndpoint.endpoint.unpeer(peeringObj)

    @staticmethod
    def sendMessageToTopic(topic, msg):
        """
        Sends a Broker Message to a given topic
        :param topic: string with topic
        :param msg: can be str, int, double
        """
        BrokerEndpoint.endpoint.publish(topic, msg)

    @staticmethod
    def sendFile(filepath):
        """
        Sends a file to the file topic
        :param filepath: path to the file
        """
        with open(str(filepath), "rb") as file:
            content = file.read()
            b64content = base64.b64encode(content)
            BrokerEndpoint.endpoint.publish("files", b64content.decode(encoding="utf-8"))

