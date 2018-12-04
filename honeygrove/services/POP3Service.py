# POP3-Service

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import Factory, Protocol

from twisted.protocols import policies

from honeygrove import config
from honeygrove.services.ServiceBaseModel import ServiceBaseModel
from honeygrove.services.ServiceBaseModel import Limiter

from honeygrove.logging import log

from honeygrove.resources.email_resources import database

from enum import Enum
import re, hashlib, time

class POP3Service(ServiceBaseModel):
    def __init__(self):
        super(POP3Service, self).__init__()

        self._name = config.pop3Name
        self._port = config.pop3Port
        self._limiter = Limiter(self._fService, config.pop3Name, config.POP3_conn_per_host)

        self.protocol = POP3Protocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenTCP(self._port, self._limiter)

    def stopService(self):
        self._stop = True
        self._transport.stopListening()

class POP3Protocol(Protocol, policies.TimeoutMixin):
    
    def savedMails(self):
        self.mailcount = 0
        self.mailsize = 0
        for mail in self.emails:
            self.mailcount += 1
            self.mailsize  += len(mail[1])

    def __init__(self):
        self.username = ""
        self.password = ""

        self.timeoutPreAuth = 60 
        self.timeoutPostAuth = 300

        self.mailcount = 0
        self.mailsize = 0
        
        # flags indicating different states to verify correct sequence of commands
        self.state = {"connected": False, "user": False, "auth": False}

        self.emails = list()
        for mail in database.mails:
            # POP3 offers only download function for received mails
            if (mail[0] == "INBOX"):
                header = ""
                for i in mail[1]:
                    header += i+": "+mail[1][i]+"\r\n"
                self.emails.append([header, mail[2], hashlib.md5((header+mail[2]).encode("UTF-8")).hexdigest()])
                # self.emails = [[header,body,UID], [header,body,UID], [header,body,UID], ...]
        
        # refresh mail stats
        self.savedMails()

    def connectionMade(self):
        if (self.transport.getHost().port == config.pop3Port):
            self.name = config.pop3Name
        elif (self.transport.getHost().port == config.pop3sPort):
            self.name = config.pop3sName
        else:
            log.err("Please check POP3/POP3S port configuration!")
            self.name = "POP3/POP3S"

        self.setTimeout(self.timeoutPreAuth)

        log.info(self.name+" established connection to "+str(self.transport.getPeer().host)+":"+str(self.transport.getPeer().port))

        # add connection to dictionary
        self.factory.clients[self] = (str(self.transport.getPeer().host) + ":" + str(self.transport.getPeer().port))
        
        # protocol state
        self.state["connected"] = True
        self.peerOfAttacker = self.transport.getPeer().host

        # TODO: modify server name
        response = "+OK example.com POP3 server\r\n"
        self.transport.write(response.encode("UTF-8"))

    def connectionLost(self, reason):
        self.setTimeout(None)
        log.info(self.name+" lost connection to "+str(self.transport.getPeer().host)+":"+str(self.transport.getPeer().port))
        # remove connection from dictionary
        del self.factory.clients[self]
    
    def timeoutConnection(self):
        response = "-ERR Timeout waiting for client input\r\n"
        log.info(self.name+" ("+self.peerOfAttacker+"): Timeout waiting for client input")
        self.transport.write(response.encode("UTF-8"))
        # close connection gently (nonblocking, send buffers before closing, client is able to receive error message)
        self.transport.loseConnection()
        time.sleep(5)
        # force close connection after waiting duration
        self.transport.abortConnection()
        # connectionLost() gets called automatically

    def dataReceived(self, rawData):
        self.resetTimeout()

        # TODO: Verifizieren, dass möglichst alle 503-Fälle ("Bad sequence of commands") abgedeckt sind
        if(rawData.startswith(b'\xff') or rawData.startswith(b'\x04')):
            #ignore Ctrl+C/D/Z etc.
            pass
        else:
            # binary data like b"\xff\x..." causes trouble when decoding (simply ignore it)
            try:
                # decode raw data
                data = rawData.decode("UTF-8")
            except Exception as e:
                data = ""
            
            # get first line
            line = data[:data.find("\r\n")]
            # restrict maximum input lenght (doesn't affect mail transmission)
            line = line[:4094]
            log.request(self.name, self.peerOfAttacker, config.pop3Port, line, self.username)

            if(re.match("^USER( \S+)?$", line, re.IGNORECASE)):
                if(re.match("^USER \S+$", line, re.IGNORECASE)):
                    arguments = re.match("^USER (?P<username>.+)$", line, re.IGNORECASE)
                    self.username = arguments.group("username")
                    self.state["user"] = True
                    response = "+OK Please enter password\r\n"
                    log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "+OK")
                else:
                    response = "-ERR Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match("^PASS( .*)?$", line, re.IGNORECASE)):
                if(re.match("^PASS \S+$", line, re.IGNORECASE)):
                    if(self.state["user"]):
                        arguments = re.match("^PASS (?P<password>\S+)$", line, re.IGNORECASE)
                        self.password = arguments.group("password")
                        # TODO: implement honeytokendb check
                        if (True):
                            log.login(self.name, self.peerOfAttacker, config.pop3Port, True, self.username, self.password, "")
                            self.state["auth"] = True
                            self.setTimeout(self.timeoutPostAuth)
                            response = "+OK mailbox locked and ready\r\n"
                            log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "+OK")
                        else:
                            log.login(self.name, self.peerOfAttacker, config.pop3Port, False, self.username, self.password, "")
                            response = "-ERR POP3 Authentication unsuccessful/Bad username or password\r\n"
                            log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (credentials)")
                    else:
                        response = "-ERR Bad sequence of commands\r\n"
                        log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (sequence of commands)")
                else:
                    response = "-ERR Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (syntax)")
#                print("POP3Service sent: \""+response+"\"")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match("^STAT( .*)?$", line, re.IGNORECASE)):
                if(line == "STAT"):
                    if (self.state["auth"]):
                        response = "+OK "+str(self.mailcount)+" "+str(self.mailsize)+"\r\n"
                        log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "+OK")
                    else:
                        response = "-ERR POP3 Authentication unsuccessful/Bad username or password\r\n"
                        log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (credentials)")
                else:
                    response = "-ERR Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (syntax)")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match("^LIST( .*)?$", line, re.IGNORECASE)):
                if(re.match("^LIST( \d+)?$", line, re.IGNORECASE)):
                    if (self.state["auth"]):
                        if(line == "LIST"):
                            response = "+OK mailbox has "+str(self.mailcount)+" messages ("+str(self.mailsize)+" octets)\r\n"
                            for i, mail in enumerate(self.emails):
                                response += str(i+1)+" "+str(len(mail[1]))+"\r\n"
                            response += ".\r\n"
                            log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "+OK")
                        else:
                            # n-th mail requested
                            n = int(re.match("^LIST( (\d+))$", line, re.IGNORECASE).groups()[1])
                            if (0 <= (n-1) < len(self.emails)):
                                response = "+OK "+str(n)+" "+str(len(self.emails[n-1][1]))+"\r\n"
                                log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "+OK")
                            else:
                                response = "-ERR Email "+str(n)+" not available\r\n"
                                log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (mail not found)")
                        self.transport.write(response.encode("UTF-8"))
                    else:
                        response = "-ERR POP3 Authentication unsuccessful/Bad username or password\r\n"
                        log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (credentials)")
                        self.transport.write(response.encode("UTF-8"))
                else:
                    response = "-ERR Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (syntax)")
                    self.transport.write(response.encode("UTF-8"))

            elif(re.match("^UIDL( .*)?$", line, re.IGNORECASE)):
                if(re.match("^UIDL( \d+)?$", line, re.IGNORECASE)):
                    if (self.state["auth"]):
                        if(line == "UIDL"):
                            response = "+OK\r\n"
                            for i, mail in enumerate(self.emails):
                                response += str(i+1)+" "+mail[2]+"\r\n"
                            response += ".\r\n"
                            log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "+OK")
                        else:
                            # n-th mail requested
                            n = int(re.match("^UIDL( (\d+))$", line).groups()[1])
                            if (0 <= (n-1) < len(self.emails)):
                                response = "+OK "+str(n)+" "+hashlib.md5(self.emails[n-1][1].encode("UTF-8")).hexdigest()+"\r\n"
                                log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "+OK")
                            else:
                                response = "-ERR Email "+str(n)+" not available\r\n"
                                log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (mail not found)")
                        self.transport.write(response.encode("UTF-8"))
                    else:
                        response = "-ERR POP3 Authentication unsuccessful/Bad username or password\r\n"
                        log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (credentials)")
                        self.transport.write(response.encode("UTF-8"))
                else:
                    response = "-ERR Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (syntax)")
                    self.transport.write(response.encode("UTF-8"))


            elif(re.match("^RETR( .*)?$", line, re.IGNORECASE)):
                if(re.match("^RETR( \d+)$", line, re.IGNORECASE)):
                    if (self.state["auth"]):
                        # n-th mail requested
                        n = int(re.match("^RETR( (\d+))$", line, re.IGNORECASE).groups()[1])
                        if (0 <= (n-1) < len(self.emails)):
                            response = "+OK "+str(len(self.emails[n-1][1]))+" octets\r\n"+self.emails[n-1][0]+"\r\n"+self.emails[n-1][1]+"\r\n.\r\n"
                            log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "+OK")
                        else:
                            response = "-ERR message "+str(n)+" not available\r\n"
                            log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (mail not found)")
                        self.transport.write(response.encode("UTF-8"))
                    else:
                        response = "-ERR POP3 Authentication unsuccessful/Bad username or password\r\n"
                        log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (credentials)")
                        self.transport.write(response.encode("UTF-8"))
                else:
                    response = "-ERR Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (syntax)")
                    self.transport.write(response.encode("UTF-8"))

            elif(re.match("^DELE( .*)?$", line, re.IGNORECASE)):
                if(re.match("^DELE( \d+)?$", line, re.IGNORECASE)):
                    if (self.state["auth"]):
                        # n-th mail requested
                        n = int(re.match("^DELE( (\d+))$", line, re.IGNORECASE).groups()[1])
                        if (0 <= (n-1) < len(self.emails)):
                            response = "+OK message "+str(n)+" deleted\r\n"
                            log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "+OK")
                        else:
                            response = "-ERR message "+str(n)+" not available\r\n"
                            log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (mail not found)")
                        self.transport.write(response.encode("UTF-8"))
                    else:
                        response = "-ERR POP3 Authentication unsuccessful/Bad username or password\r\n"
                        log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (credentials)")
                        self.transport.write(response.encode("UTF-8"))
                else:
                    response = "-ERR Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (syntax)")
                    self.transport.write(response.encode("UTF-8"))

            elif(re.match("^QUIT( .*)?$", line, re.IGNORECASE)):
                # make sure QUIT doesn't have parameters (unimportant for correct functioning but good for concealment)
                if (line == "QUIT"):
                    self.state["connected"] = False
                    response = "+OK bye\r\n"
                    log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "+OK")
                    self.transport.write(response.encode("UTF-8"))
                    # close connection
                    self.transport.loseConnection()
                else:
                    response = "-ERR Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (syntax")
                    self.transport.write(response.encode("UTF-8"))

            else:
                response = "-ERR Unrecognized command \'"+line+"\'\r\n"
                log.response(self.name, self.peerOfAttacker, config.pop3Port, "", self.username, "-ERR (command)")
                self.transport.write(response.encode("UTF-8"))