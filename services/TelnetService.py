from honeygrove import log
from honeygrove.config import Config
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel

from twisted.conch.telnet import TelnetTransport, StatefulTelnetProtocol
from twisted.internet import reactor, protocol

import time


class TelnetService(ServiceBaseModel):
    def __init__(self):
        super(TelnetService, self).__init__()

        self._name = Config.telnetName
        self._port = Config.telnetPort

        self._fService = TelnetFactory()

        self._limiter = Limiter(self._fService, Config.telnetName, Config.Telnet_conn_per_host)

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

        log.login(Config.telnetName, self.peerOfAttacker, Config.telnetPort, False, self.username, self.password, "")

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
    def protocol(_):
        return TelnetTransport(TelnetProtocol)
