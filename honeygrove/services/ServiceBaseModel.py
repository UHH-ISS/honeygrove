from honeygrove import log
from honeygrove.config import Config

from abc import ABC, abstractmethod

from twisted.internet import reactor
from twisted.internet.protocol import Factory
from twisted.protocols.policies import WrappingFactory


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
        self._address = Config.address
        self._port = None

        self._stop = True
        # XXX: Not used currently?

        self._status = None
        self._limiter = None
        self._transport = None

    def startService(self):
        """
        Starts the specific service
        """
        self._stop = False
        self._transport = reactor.listenTCP(self._port, self._limiter, interface=self._address)

    def stopService(self):
        """
        Stops the specific service
        :return:
        """
        self._stop = True
        self._transport.stopListening()

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

    # name = Name of the service
    # max_conns = Maximum number of connections per host
    def __init__(self, service, name, max_conns):
        super(Limiter, self).__init__(service)
        self._maxConnectionsPerPeer = max_conns
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

