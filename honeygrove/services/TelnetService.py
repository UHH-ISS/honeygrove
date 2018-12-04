# Telnet-Service
from twisted.internet import reactor

from honeygrove.services.ServiceBaseModel import ServiceBaseModel, Limiter
from honeygrove import config

from twisted.conch.telnet import TelnetTransport, StatefulTelnetProtocol
from twisted.internet import protocol

from honeygrove.logging import log

import time

class TelnetService(ServiceBaseModel):
    def __init__(self):
        super(TelnetService, self).__init__()
        
        self._name = config.telnetName
        self._port = config.telnetPort

        self._fService = TelnetFactory()

        self._limiter = Limiter(self._fService, config.telnetName, config.Telnet_conn_per_host)

    def startService(self):
        self._stop = False
        self._transport = reactor.listenTCP(self._port, self._limiter)

    def stopService(self):
        self._stop = True
        self._transport.stopListening()

class TelnetProtocol(StatefulTelnetProtocol):
    state = "User"

    def telnet_Password(self, line):
        self.password = line.decode("UTF-8")

        log.login(config.telnetName, self.peerOfAttacker, config.telnetPort, False, self.username, self.password, "")

        time.sleep(2.0)

        response = "\nAuthentication failed\nUsername: "
        self.transport.write(response.encode("UTF-8"))

        self.state = "User"
        return "Discard"

    def connectionMade(self):
        response = "Username: "
        self.transport.write(response.encode("UTF-8"))
        self.peerOfAttacker = self.transport.getPeer().host

    def telnet_User(self, line):
        self.username = line.decode("UTF-8")
        response = "Password: "
        self.transport.write(response.encode("UTF-8"))
        return "Password"

class TelnetFactory(protocol.ServerFactory):
    protocol = lambda a: TelnetTransport(TelnetProtocol)
