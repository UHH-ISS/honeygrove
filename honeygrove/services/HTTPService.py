from honeygrove import log
from honeygrove.config import Config
from honeygrove.core.HoneytokenDB import HoneytokenDataBase
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel

from twisted.conch import avatar
from twisted.cred import error
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol
from twisted.python import failure

from datetime import datetime
import time
from wsgiref.handlers import format_date_time


class HTTPService(ServiceBaseModel):
    now = datetime.now()
    timeNow = time.mktime(now.timetuple())

    responseHeadersOkStatus = Config.http.response_headers
    responseHeadersForbidden = {'Date': format_date_time(timeNow)}
    responseHeadersNotFound = {'Date': format_date_time(timeNow),
                               'Content-Type': 'text/html; charset=UTF-8'}
    okStatus = "HTTP/1.1 200 OK"
    forbiddenStatus = "HTTP/1.1 403 Forbidden"
    notFoundStatus = "HTTP/1.1 404 Not Found"
    htdb = HoneytokenDataBase("HTTP")
    port = ""
    html_dictionary = Config.http.html_dictionary_content
    supportedSites = []

    def __init__(self):
        super(HTTPService, self).__init__()

        self._name = Config.http.name
        self._port = Config.http.port
        self._limiter = Limiter(self._fService, Config.http.name, Config.http.connections_per_host)

        self.protocol = HTTPProtocol
        self._fService.protocol = self.protocol


    def startService(self):
        try:
            self._stop = False
            self._transport = reactor.listenTCP(self._port, self._fService, interface=self._address)

            sites = []
            for key in HTTPService.html_dictionary:
                sites.append(key)
            HTTPService.supportedSites = sites

        except Exception as e:
            self._stop = True

            raise e

    def stopService(self):
        self._stop = True
        self._transport.stopListening()
        try:
            self._transport.connectionLost("Force close/cleanup due to next service scheduling")
        except AttributeError as err:
            log.err("HTTPService.connectionLost threw AttributeError: " + err)

    def parseHeaderLine(self, line):
        pdata = line.split(':', 1)[0]
        if (pdata == "Host"):
            return pdata
        elif (pdata == "Accept"):
            return pdata


class HTTPProtocol(Protocol):

    def __init__(self):
        self.state = None

        self.peerOfAttacker = ""
        self.page = ""
        self.path = Config.http.resource_folder
        self.attackingSite = ""
        self.loginSuccessfulSite = ""
        self.notFoundSite = ""
        self.requestType = ""
        self.short = ""

    def connectionMade(self):
        # Add connection to dictionary
        self.factory.clients[self] = ("<" + str(self.transport.getPeer().host) + ":"
                                      + str(self.transport.getPeer().port) + ">")
        self.peerOfAttacker = self.transport.getPeer().host

    def dataReceived(self, data):

        data = data.decode('utf-8')

        self.requestType = data.split(' ', 1)[0]

        if self.requestType == "GET":
            self.page = data[data.find("GET ") + 4: data.find(" HTTP/1.1")]
        elif self.requestType == "POST":
            self.page = data[data.find("POST ") + 5: data.find(" HTTP/1.1")]

        pageNotFound = True

        for serviceLink in HTTPService.supportedSites:
            if self.page == serviceLink:
                pageNotFound = False
                self.attackingSite = str(self.path / HTTPService.html_dictionary[serviceLink][0])
                if len(HTTPService.html_dictionary[serviceLink]) > 1:
                    self.loginSuccessfulSite = str(self.path / HTTPService.html_dictionary[serviceLink][1])
                else:
                    self.loginSuccessfulSite = str(self.path / HTTPService.html_dictionary['404'][0])
                self.short = serviceLink
                break

        if pageNotFound:
            self.notFoundSite = str(self.path / HTTPService.html_dictionary['404'][0])

        # Handle GETs
        if self.requestType == "GET" and ('.gif' in self.page or '.png' in self.page or '/dashboard_files/' in self.page or '.jpg' in self.page or '.woff' in self.page or '.ttf' in self.page or '.svg' in self.page):
            message = HTTPService.notFoundStatus + "\n"
            for k in HTTPService.responseHeadersNotFound.keys():
                message = message + k + ": " + HTTPService.responseHeadersNotFound[k] + "\n"
            self.transport.write(message.encode('UTF-8'))
            self.transport.loseConnection()

        elif self.requestType == "GET" and self.page in HTTPService.supportedSites:

            log.request("HTTP", self.peerOfAttacker, HTTPService.port, self.page, "", "GET")

            message = HTTPService.okStatus + "\n"
            for k in HTTPService.responseHeadersOkStatus.keys():
                message = message + k + ": " + HTTPService.responseHeadersOkStatus[k] + "\n"

            with open(self.attackingSite, encoding='utf8') as file:
                message = message + "\n" + file.read()

            self.transport.write(message.encode('UTF-8'))
            if self.page in HTTPService.supportedSites:
                log.response("HTTP", self.peerOfAttacker, HTTPService.port, self.page, "", "200 OK")

            self.transport.loseConnection()

        # Handle POSTs
        elif (self.requestType == "POST" and self.page in HTTPService.supportedSites):
            self.page = data[data.find("POST ") + 5: data.find(" HTTP/1.1")]
            login_string = ""
            password_string = ""
            login_index = data.find("log=") + 4
            if login_index == 3:
                login_string = "fritz.box"
            else:
                login_string = data[login_index:data.find("&")]
            password_index = data.find("pwd=") + 4
            if data[password_index:data.find("&")] != -1:
                password_string = data[password_index:len(data)]
            else:
                password_string = data[password_index:data.find("&")]

            log.request("HTTP", self.peerOfAttacker, HTTPService.port, self.page, login_string, "POST")
            result = HTTPService.htdb.requestAvatarId(HTTPAvatar(login_string, password_string))
            if isinstance(result, Deferred):
                if isinstance(result.result, failure.Failure):  # Failure
                    result.addErrback(self.errorBack)
                    log.response("HTTP", self.peerOfAttacker, HTTPService.port, "", login_string, "403 FORBIDDEN")
                    log.login("HTTP", self.peerOfAttacker, HTTPService.port, False, login_string, password_string,
                              str(HTTPService.htdb.getActual(login_string, password_string)))
                else:  # Success
                    message = HTTPService.okStatus + "\n"
                    for k in HTTPService.responseHeadersOkStatus.keys():
                        message = message + k + ": " + HTTPService.responseHeadersOkStatus[k] + "\n"

                    with open(self.loginSuccessfulSite, encoding='utf8') as file:
                        message = message + "\n" + file.read()

                    self.transport.write(message.encode('UTF-8'))
                    self.page = "wp-admin_content.html"
                    log.response("HTTP", self.peerOfAttacker, HTTPService.port, self.page, login_string, "200 OK")
                    log.login("HTTP", self.peerOfAttacker, HTTPService.port, True, login_string, password_string,
                              str(HTTPService.htdb.getActual(login_string, password_string)))
                    self.transport.loseConnection()
        else:
            message = HTTPService.notFoundStatus + "\n"
            for k in HTTPService.responseHeadersNotFound.keys():
                message = message + k + ": " + HTTPService.responseHeadersNotFound[k] + "\n"

            with open(self.notFoundSite, encoding='utf8') as file:
                message = message + "\n" + file.read()

            self.transport.write(message.encode('UTF-8'))
            log.request("HTTP", self.peerOfAttacker, HTTPService.port, self.page, "", "GET")
            self.page = "404_login.html"
            log.response("HTTP", self.peerOfAttacker, HTTPService.port, self.page, "", "404 Not Found")
            self.transport.loseConnection()

    def connectionLost(self, reason):
        # Delete client from dict.
        del self.factory.clients[self]

    def errorBack(self, f):
        f.trap(error.UnauthorizedLogin)

        message = HTTPService.forbiddenStatus + "\n"
        for k in HTTPService.responseHeadersForbidden.keys():
            message = message + k + ": " + HTTPService.responseHeadersForbidden[k] + "\n"

        with open(self.attackingSite, encoding='utf8') as file:
            message = message + "\n" + file.read()

        self.transport.write(message.encode('UTF-8'))
        self.transport.loseConnection()


class HTTPAvatar(avatar.ConchUser):
    def __init__(self, avatarUsername, avatarPassword):
        super(HTTPAvatar, self).__init__()
        self.service = "HTTP"
        self.username = avatarUsername
        self.password = avatarPassword

    def checkPassword(self, password):
        if self.password == password:
            return True
        else:
            return False


if __name__ == '__main__':
    service = HTTPService()
    service.startService()
