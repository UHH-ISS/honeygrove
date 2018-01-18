import unittest
from pybroker import *
from select import select
import time
from honeygrove.broker.BrokerEndpoint import BrokerEndpoint

class BrokerEndpointTest(unittest.TestCase):
    testEndpoint = None
    testQueue = None


    @classmethod
    def setUpClass(cls):
        BrokerEndpointTest.peeringObj = None

        flags = AUTO_ADVERTISE | AUTO_PUBLISH | AUTO_ROUTING
        BrokerEndpointTest.testEndpoint = endpoint("testEndpoint", flags)

        BrokerEndpoint.startListening()

    def peerToBrokerEndpoint(self):
        BrokerEndpointTest.peeringObj = BrokerEndpointTest.testEndpoint.peer("127.0.0.1", 8888)

    def setUp(self):
        BrokerEndpointTest.testQueue = message_queue("test", BrokerEndpointTest.testEndpoint, GLOBAL_SCOPE)

    def tearDown(self):
        try:
            BrokerEndpointTest.testEndpoint.unpeer(BrokerEndpointTest.peeringObj)
        except ValueError:
            pass


    def testConnectToBrokerEndpoint(self):
        """
        Tests the if we are able to build a connection to the BrokerEndpoint
        :return: 
        """
        self.peerToBrokerEndpoint()
        outStatus = BrokerEndpointTest.testEndpoint.outgoing_connection_status()

        select([outStatus.fd()], [], [])
        msgs = outStatus.want_pop()

        for msg in msgs:
            print(msg.peer_name)
            assert (msg.peer_name == "listenEndpoint")
        assert (msg.status == incoming_connection_status.tag_established)


    def testReceiveMessage(self):
        """
        Tests if we are able to receive a message from an Endpoint
        """
        self.peerToBrokerEndpoint()
        BrokerEndpointTest.testEndpoint.send("commands", message([data("Test")]))

        msgs = BrokerEndpoint.getCommandMessage()
        for msg in msgs:
            for entry in msg:
                print(entry)

                assert (entry == "Test")

    def testSendMessage(self):
        """
        Tests if we are able to send a Message with BrokerEndpoint.sendToTopic
        :return:
        """
        self.peerToBrokerEndpoint()
        BrokerEndpoint.sendMessageToTopic("test", "TestHallo")

        msgs = BrokerEndpointTest.testQueue.want_pop()
        for msg in msgs:
            for entry in msg:
                print(entry)
                assert (entry == "TestHallo")


    def testSendToWrongTopic(self):
        """
        When we send a mesage to a topic we dont listen. We dont get the message
        """
        self.peerToBrokerEndpoint()
        BrokerEndpoint.sendMessageToTopic("WrongTopic", "KommtNichtAn")
        msgs = BrokerEndpointTest.testQueue.want_pop()
        for msg in msgs:
            for entry in msg:
                print(entry)
                assert (entry == "[]")

    def testBrokerEndpointPeerTo(self):
        BrokerEndpointTest.testEndpoint.listen(9988,"127.0.0.1")
        BrokerEndpoint.peerTo("127.0.0.1", 9988)

        BrokerEndpoint.sendMessageToTopic("test", "kommtAn")
        msgs = BrokerEndpointTest.testQueue.want_pop()

        for msg in msgs:
            for entry in msg:
                print(entry)
                assert (entry == "kommtAn")