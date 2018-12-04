# coding=utf-8
# "Prototype" for all Services.
from abc import ABC, abstractmethod

from twisted.internet.protocol import Factory
from twisted.protocols.policies import WrappingFactory
from twisted.internet.address import IPv4Address

from honeygrove.logging import log

class ServiceBaseModel(ABC):
    def __init__(self):
        """
        Initializeses some needed service parts.
        Only add variables here if they are needet in all services.
        """
        self._fService = Factory()
        self._fService.clients = dict([])

        # Only these variables should be changeable

        self._name = None
        self._port = None
        self._stop = True
        # _status wird anscheinend bisher nicht verwendet!
        self._status = None
        self._transport = None

    @abstractmethod
    def startService(self):
        """
        Starts the specific service
        """
        pass

    @abstractmethod
    def stopService(self):
        """
        Stops the specific service
        :return:
        """
        pass

    def changePort(self, port):
        """
        changes the port. If it is not possible the service will be terminatet.
        Eg. port is already in use.
        :param port: int
        """
        self.stopService()
        self._port = port
        self.startService()


class Limiter(WrappingFactory):

    # name = freier Name des Services
    # config = maxConnection
    def __init__(self, service, name, config):
        super(Limiter, self).__init__(service)
        self._maxConnectionsPerPeer = config
        self._name = name

    def startFactory(self):
        self.peerConnections = {}

    def buildProtocol(self, addr):
        peerHost = addr.host
        connectionCount = self.peerConnections.get(peerHost, 0)
        if connectionCount >= self._maxConnectionsPerPeer:
            log.limit_reached(self._name, peerHost)
            return None
        self.peerConnections[peerHost] = connectionCount + 1
        return WrappingFactory.buildProtocol(self, addr)

    # p = "protocol"?
    def unregisterProtocol(self, p):
        peerHost = p.getPeer().host
        self.peerConnections[peerHost] -= 1
        if self.peerConnections[peerHost] == 0:
           del self.peerConnections[peerHost]

