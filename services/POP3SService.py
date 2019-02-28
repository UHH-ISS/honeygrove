from honeygrove.config import Config
from honeygrove.services.POP3Service import POP3Protocol
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel

from twisted.internet import ssl, reactor


class POP3SService(ServiceBaseModel):
    def __init__(self):
        super(POP3SService, self).__init__()

        self._name = Config.pop3sName
        self._port = Config.pop3sPort
        self._limiter = Limiter(self._fService, Config.pop3sName, Config.POP3S_conn_per_host)

        self.protocol = POP3Protocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenSSL(self._port, self._limiter, ssl.DefaultOpenSSLContextFactory(Config.email.tls_key, Config.email.tls_cert))

    def stopService(self):
        self._stop = True
        self._transport.stopListening()
