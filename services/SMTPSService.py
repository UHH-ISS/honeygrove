# SMTPS-Service

from twisted.internet import ssl, reactor
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import Factory, Protocol

from honeygrove import config
from honeygrove.services.SMTPService import SMTPProtocol
from honeygrove.services.ServiceBaseModel import ServiceBaseModel
from honeygrove.services.ServiceBaseModel import Limiter

class SMTPSService(ServiceBaseModel):
    def __init__(self):
        super(SMTPSService, self).__init__()

        self._name = config.smtpsName
        self._port = config.smtpsPort
        self._limiter = Limiter(self._fService, config.smtpsName, config.SMTPS_conn_per_host)

        self.protocol = SMTPProtocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenSSL(self._port, self._limiter, ssl.DefaultOpenSSLContextFactory(config.TLSeMailKey, config.TLSeMailCrt))

    def stopService(self):
        self._stop = True
        self._transport.stopListening()