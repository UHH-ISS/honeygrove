from honeygrove import config
from honeygrove.services.IMAPService import IMAPProtocol
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel

from twisted.internet import ssl, reactor


class IMAPSService(ServiceBaseModel):
    def __init__(self):
        super(IMAPSService, self).__init__()

        self._name = config.imapsName
        self._port = config.imapsPort
        self._limiter = Limiter(self._fService, config.imapsName, config.IMAPS_conn_per_host)

        self.protocol = IMAPProtocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenSSL(self._port, self._limiter, ssl.DefaultOpenSSLContextFactory(config.TLSeMailKey, config.TLSeMailCrt))

    def stopService(self):
        self._stop = True
        self._transport.stopListening()
