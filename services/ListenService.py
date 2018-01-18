# Listen-Service

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import Factory, Protocol

from honeygrove import config
from honeygrove.logging import log as l
from honeygrove.services.ServiceBaseModel import ServiceBaseModel


class ListenService(ServiceBaseModel):
    def __init__(self):
        """
        This service can open a lot of ports and starts listening and loggin on them.
        """
        super(ListenService, self).__init__()

        self._fService = Factory()
        self.protocol = ListenProtocol
        self._fService.protocol = self.protocol

        self._name = config.listenServiceName
        self._port = config.listenServicePorts
        self._transport = dict([])
        self._stop = True
        self._active = False

    def startService(self):
        """
        Start service on all ports defined in config.py. 
        Ignores ports where it can't listen.
        :return:
        """
        try:
            self._stop = False
            for port in self._port:
                try:
                    self._transport[port] = reactor.listenTCP(port, self._fService)
                except CannotListenError:
                    pass

            self._active = True

        except Exception as e:
            l.err(e)
            self._stop = True

    def startOnPort(self, port):
        """
        Start service on a specific port if it doesn't already run there.
        Ignores this call when it can't listen.
        :param port: the port on which the service shall start
        :return:
        """
        if self._stop:
            self._stop = False

        if port not in self._transport and self._active:
            try:
                self._transport[port] = reactor.listenTCP(port, self._fService)
            except CannotListenError:
                pass

    def stopOnPort(self, port):
        """
        Stop service on a specific port.
        :param port: the port where the service should stop listening
        """

        if port in self._transport and self._active:
            self._transport[port].stopListening()
            try:
                self._transport[port].connectionLost("Force close/cleanup due to next service scheduling")
            except AttributeError:
                l.err("ListenService connectionLost wirft AttributeError!", port)
            self._transport.pop(port, None)
            # Dict is Empty
            if self._transport == False:
                self._stop = True

    def stopService(self):
        """
        Closes all open ports and stops the Service
        """
        if not self._stop:
            for key, _ in self._transport.items():
                self._transport[key].stopListening()
                try:
                    self._transport[key].connectionLost("Force close/cleanup due to next service scheduling")
                except AttributeError:
                    l.err("ListenService connectionLost wirft AttributeError!", key)

        self._stop = True
        self._active = False


class ListenProtocol(Protocol):
    def dataReceived(self, data):
        """
        Called when the attacker sends data.
        :param data: The received data
        """
        l.request(config.listenServiceName, self.transport.getPeer().host, self.transport.getHost().port, data.decode())
