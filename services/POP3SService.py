# POP3S-Service

from twisted.internet import ssl, reactor
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import Factory, Protocol

from honeygrove import config
from honeygrove.services.POP3Service import POP3Protocol
from honeygrove.services.ServiceBaseModel import ServiceBaseModel
from honeygrove.services.ServiceBaseModel import Limiter

from enum import Enum
import re, hashlib, time

class POP3SService(ServiceBaseModel):
    def __init__(self):
        super(POP3SService, self).__init__()

        self._name = config.pop3sName
        self._port = config.pop3sPort
        self._limiter = Limiter(self._fService, config.pop3sName, config.POP3S_conn_per_host)

        self.protocol = POP3Protocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenSSL(self._port, self._limiter, ssl.DefaultOpenSSLContextFactory(config.TLSeMailKey, config.TLSeMailCrt))

    def stopService(self):
        self._stop = True
        self._transport.stopListening()