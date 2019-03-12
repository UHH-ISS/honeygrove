from honeygrove.config import Config
from honeygrove.services.SMTPService import SMTPProtocol
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel

from twisted.internet import ssl, reactor


class SMTPSService(ServiceBaseModel):
    def __init__(self):
        super(SMTPSService, self).__init__()

        self._name = Config.smtps.name
        self._port = Config.smtps.port
        self._limiter = Limiter(self._fService, Config.smtps.name, Config.smtps.connections_per_host)

        self.protocol = SMTPProtocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenSSL(self._port, self._limiter, ssl.DefaultOpenSSLContextFactory(str(Config.email.tls_key), str(Config.email.tls_cert)))

    def stopService(self):
        self._stop = True
        self._transport.stopListening()
