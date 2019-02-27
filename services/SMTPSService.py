from honeygrove.config import Config
from honeygrove.services.SMTPService import SMTPProtocol
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel

from twisted.internet import ssl, reactor


class SMTPSService(ServiceBaseModel):
    def __init__(self):
        super(SMTPSService, self).__init__()

        self._name = Config.smtpsName
        self._port = Config.smtpsPort
        self._limiter = Limiter(self._fService, Config.smtpsName, Config.SMTPS_conn_per_host)

        self.protocol = SMTPProtocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenSSL(self._port, self._limiter, ssl.DefaultOpenSSLContextFactory(Config.TLSeMailKey, Config.TLSeMailCrt))

    def stopService(self):
        self._stop = True
        self._transport.stopListening()
