from honeygrove.config import Config
from honeygrove.services.HTTPService import HTTPProtocol
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel

from twisted.internet import ssl, reactor


class HTTPSService(ServiceBaseModel):
    def __init__(self):
        super(HTTPSService, self).__init__()

        self._name = Config.https.name
        self._port = Config.https.port
        self._limiter = Limiter(self._fService, Config.https.name, Config.https.connections_per_host)

        self.protocol = HTTPProtocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenSSL(self._port, self._limiter, ssl.DefaultOpenSSLContextFactory(str(Config.https.tls_key), str(Config.https.tls_cert)), interface=self._address)
