from honeygrove.config import Config
from honeygrove.services.IMAPService import IMAPProtocol
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel

from twisted.internet import ssl, reactor


class IMAPSService(ServiceBaseModel):
    def __init__(self):
        super(IMAPSService, self).__init__()

        self._name = Config.imaps.name
        self._port = Config.imaps.port
        self._limiter = Limiter(self._fService, Config.imaps.name, Config.imaps.connections_per_host)

        self.protocol = IMAPProtocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenSSL(self._port, self._limiter, ssl.DefaultOpenSSLContextFactory(str(Config.email.tls_key), str(Config.email.tls_cert)), interface=self._address)
