import unittest
from honeygrove.services.TCPFlagService import TCPFlagSniffer
import honeygrove.services.TCPFlagService as TCPInfo
import time


class TCPFlagTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Setup Class for reading the ACK and SYN packets
        """
        with open("testresources/TCPSnifferTest/ackPacket.txt", 'rb') as inFile:
            TCPFlagTest.ACKPacket = inFile.read()

        with open("testresources/TCPSnifferTest/synPacket.txt", 'rb') as inFile:
            TCPFlagTest.SYNPacket = inFile.read()

    def setUp(self):
        TCPFlagTest.sniffer = TCPFlagSniffer()
        TCPFlagTest.sniffer.rSock = testSocket(TCPFlagTest.SYNPacket, TCPFlagTest.ACKPacket)

    def tearDown(self):
        TCPFlagTest.sniffer.synConnections = dict([])

    def testParseTCPACKPacket(self):
        """
        Tests if the parsing of a package containing ACK Flag is correct
        """

        flag, destPort, sourceIP = TCPFlagTest.sniffer.getTCPPacketInformation(TCPFlagTest.ACKPacket)

        self.assertEqual(flag,TCPInfo.ACK_FLAG)
        self.assertEqual(destPort, 57092)
        self.assertEqual(sourceIP, "173.194.69.138")

    def testParseTCPSYNPacket(self):
        """
        Tests if the parsing of a package containing SYN Flag is correct
        """
        flag, destPort, sourceIP = TCPFlagTest.sniffer.getTCPPacketInformation(TCPFlagTest.SYNPacket)

        self.assertEqual(flag, TCPInfo.SYN_FLAG)
        self.assertEqual(destPort, 8888)
        self.assertEqual(sourceIP, "127.0.0.1")

    def testDataAccessSynPacket(self):
        """
        Tests if the Threads can access the dict
        """
        TCPFlagTest.sniffer.rSock.isSyn = True
        TCPFlagTest.sniffer.rootStatus = True

        self.assertEqual(TCPFlagTest.sniffer.synConnections, dict([]))

        TCPFlagTest.sniffer.startService()
        time.sleep(1)
        TCPFlagTest.sniffer.stopService()

        self.assertNotEqual(TCPFlagTest.sniffer.synConnections, dict([]))

    def testACKAfterSyn(self):
        """
        Tests if the Threads can access the dict and keys are removed.
        Removed if (syn(ip,port) = ack(ip,port))
        """
        TCPFlagTest.sniffer.rSock.isSyn = True
        TCPFlagTest.sniffer.rootStatus = True

        TCPFlagTest.sniffer.synConnections["173.194.69.13857092"] = "SYN-PACKET"

        self.assertNotEqual(TCPFlagTest.sniffer.synConnections, dict([]))
        TCPFlagTest.sniffer.rSock.isSyn = False

        TCPFlagTest.sniffer.startService()
        time.sleep(1)
        TCPFlagTest.sniffer.stopService()

        self.assertEqual(TCPFlagTest.sniffer.synConnections, dict([]))


class testSocket():
    def __init__(self, synPacket, ackPacket):
        """
        Simulates the RAW socket
        """
        self.synPacket = [synPacket]
        self.ackPacket = [ackPacket]
        self.isSyn = None

    def recvfrom(self, _):
        """
        Simulates the RAW socket function
        :return: A specify TCP/IP packet
        """
        time.sleep(0.5)
        if self.isSyn:
            return self.synPacket
        else:
            return self.ackPacket
