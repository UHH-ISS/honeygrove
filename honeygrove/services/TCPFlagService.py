import socket
import threading
import time
from datetime import datetime
from struct import *

import honeygrove.config as config
from honeygrove.logging import log
from honeygrove.services.ServiceBaseModel import ServiceBaseModel

SYN_FLAG = 0b10
ACK_FLAG = 0b10000
NULL_FLAG = 0b0
FIN_FLAG = 0b1
XMAS_FLAG = 0b101001


class TCPDataStruct():
    def __init__(self, sourceIP, destPort):
        """
        Holds information about a TCP/IP connection
        """
        self.sourceIP = sourceIP
        self.destPort = destPort
        self.inTime = time.time()
        self.timeStamp = log.get_time()


class TCPFlagSniffer(ServiceBaseModel):
    def __init__(self):
        """
        Opens a RAW socket which is able to monitor all TCP/IP Traffic within the machine.
        Root priv. are needed!
        """
        super(TCPFlagSniffer, self).__init__()
        self._name = config.tcpFlagSnifferName
        self.synConnections = dict([])
        self.finConnections = dict([])
        self.xmasConnections = dict([])

        self.reInstanceThreads()

        self.synConnectionsLock = threading.Lock()
        self.rootStatus = True

        try:
            self.rSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error:
            log.info("RAW Socket could not be created. You are root?")
            log.err("TCPFlagSniffer wird nicht ordnungsgemäß ausgeführt werden!")
            self.rootStatus = False


    def reInstanceThreads(self):
        """
        Python threads needs to be re-instanciated
        """
        self.startThread = threading.Thread(target=self.startTCPSniffer, args=())
        self.startThread.name = "START-TCPFlagSniffer-Thread"

        self.synScannThread = threading.Thread(target=self.scanOpenSynConnections, args=())
        self.synScannThread.name = "SynScan-Thread"

    def startService(self):
        """
        Starts the Service in a new Thread
        """

        if self.rootStatus == True:
            self._stop = False
            self.startThread.start()
            self.synScannThread.start()

    def startTCPSniffer(self):
        """
        Starts the Service which is blocking.
        unpacks the IP and TCP Header. The Data in TCP is not touched.
        """
        while not self._stop:
            packet = self.rSock.recvfrom(65565)
            packet = packet[0]

            flags, destPort, sourceAddress = self.getTCPPacketInformation(packet=packet)
            #print(flags, destPort, sourceAddress)

            if flags == SYN_FLAG:
                with self.synConnectionsLock:
                    self.synConnections[str(sourceAddress) + str(destPort)] = TCPDataStruct(sourceIP=sourceAddress,
                                                                                            destPort=destPort)

            elif flags == FIN_FLAG:
                    self.finConnections[str(sourceAddress) + str(destPort)] = TCPDataStruct(sourceIP=sourceAddress,
                                                                                            destPort=destPort)

            elif flags == XMAS_FLAG:
                    self.xmasConnections[str(sourceAddress) + str(destPort)] = TCPDataStruct(sourceIP=sourceAddress,
                                                                                            destPort=destPort)

            elif flags == ACK_FLAG:
                with self.synConnectionsLock:
                    self.synConnections.pop(str(sourceAddress) + str(destPort), None)
                    self.finConnections.pop(str(sourceAddress) + str(destPort), None)
                    self.xmasConnections.pop(str(sourceAddress) + str(destPort), None)

            elif flags == NULL_FLAG:
                with self.synConnectionsLock:
                    log.tcp_scan(sourceAddress, destPort, log.get_time(), 'null')
					
					

    def getTCPPacketInformation(self, packet):
        """
        Packs the TCP/IP packet and extracts information
        :param packet: TCP/IP packet
        :return: TCP packet flags, destination port, source ip address
        """

        # Ip Header entpacken
        ipHeaderRaw = packet[0:20]
        ipHeader = unpack('!BBHHHBBH4s4s', ipHeaderRaw)

        # Ip Header informationen
        ipHeaderVersion = ipHeader[0]
        ipVersion = ipHeaderVersion >> 4
        ipHeaderLength = ipHeaderVersion & 0xF
        ipHeaderBounds = ipHeaderLength * 4
        timeToLive = ipHeader[5]
        protocol = ipHeader[6]
        sourceAddress = socket.inet_ntoa(ipHeader[8]);
        destinationAddress = socket.inet_ntoa(ipHeader[9]);

        # Tcp Header entpacken
        tcpHeaderRaw = packet[ipHeaderBounds:ipHeaderBounds + 20]
        tcpHeader = unpack('!HHLLBBHHH', tcpHeaderRaw)

        sourcePort = tcpHeader[0]
        destPort = tcpHeader[1]
        flags = tcpHeader[5]

        return flags, destPort, sourceAddress

    def stopService(self):
        """Stops the Service with a Death flag"""
        self._stop = True
        self.reInstanceThreads()

    def scanOpenSynConnections(self):
        """
        Scans the Dict which is holding TCPDataStructs for timestaps which are older then a specific time defined in config
        """
        while not self._stop:
            with self.synConnectionsLock:
                for _, item in self.synConnections.copy().items():
                    if (time.time() - item.inTime) > config.tcpTimeout:
                        log.tcp_scan(item.sourceIP, item.destPort, item.timeStamp, 'syn')
                        self.synConnections.pop(str(item.sourceIP) + str(item.destPort), None)

                for _, item in self.finConnections.copy().items():
                    if (time.time() - item.inTime) > config.tcpTimeout:
                        log.tcp_scan(item.sourceIP, item.destPort, item.timeStamp, 'fin')
                        self.finConnections.pop(str(item.sourceIP) + str(item.destPort), None)

                for _, item in self.xmasConnections.copy().items():
                    if (time.time() - item.inTime) > config.tcpTimeout:
                        log.tcp_scan(item.sourceIP, item.destPort, item.timeStamp, 'xmas')
                        self.xmasConnections.pop(str(item.sourceIP) + str(item.destPort), None)

            time.sleep(0.5)

