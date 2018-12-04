# SMTP-Service

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import Factory, Protocol

from twisted.protocols import policies

from honeygrove import config
from honeygrove.services.ServiceBaseModel import ServiceBaseModel
from honeygrove.services.ServiceBaseModel import Limiter

from honeygrove.logging import log

from enum import Enum
import base64, re, time

class SMTPService(ServiceBaseModel):
    def __init__(self):
        super(SMTPService, self).__init__()

        self._name = config.smtpName
        self._port = config.smtpPort
        self._limiter = Limiter(self._fService, config.smtpName, config.SMTP_conn_per_host)

        self.protocol = SMTPProtocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenTCP(self._port, self._limiter)

    def stopService(self):
        self._stop = True
        self._transport.stopListening()

class SMTPProtocol(Protocol, policies.TimeoutMixin):
    
    def __init__(self):
        # buffer for email body
        self.msg = ""

        # authentication methods offered to the client (https://english.stackexchange.com/a/7845)
        self.AuthMethods = ""
        mm = config.SMTPAuthMethods
        for m in mm:
            if (mm[m]):
                self.AuthMethods += " "+m
        del m,mm

        self.username = ""
        self.usernameValid = "honig"
        self.password = ""
        self.passwordValid = "bienenstock"
        
        # source adress given by "MAIL FROM"
        self.mailFrom = ""
        # destination adress given by "RCPT TO"
        self.mailTo = ""

        self.timeoutPreAuth = 60
        self.timeoutPostAuth = 300

        # flags indicating different states to verify correct sequence of commands
        self.state = {"connected": False, "hello": False, "auth": False, "mailfrom": False, "mailto": False, "data": False, "msg": False, "auth": False, "authLOGIN": False, "authLOGINuser": False}

    def connectionMade(self):
        if (self.transport.getHost().port == config.smtpPort):
            self.name = config.smtpName
        elif (self.transport.getHost().port == config.smtpsPort):
            self.name = config.smtpsName
        else:
            log.err("Please check SMTP/SMTPS port configuration!")
            self.name = "SMTP/SMTPS"

        self.setTimeout(self.timeoutPreAuth)

        log.info(self.name+" established connection to "+str(self.transport.getPeer().host)+":"+str(self.transport.getPeer().port))
        
        # add connection to dictionary
        self.factory.clients[self] = (str(self.transport.getPeer().host) + ":" + str(self.transport.getPeer().port))
        
        # protocol state
        self.state["connected"] = True
        self.peerOfAttacker = self.transport.getPeer().host

        response = "220 Service ready ESMTP\r\n"
        self.transport.write(response.encode("UTF-8"))

    def connectionLost(self, reason):
        self.setTimeout(None)

        log.info(self.name+" lost connection to "+str(self.transport.getPeer().host)+":"+str(self.transport.getPeer().port))
        # remove connection from dictionary
        del self.factory.clients[self]

    def timeoutConnection(self):
        response = "451 Timeout waiting for client input\r\n"
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
            if (not self.state["data"] and not self.state["authLOGIN"] and not self.state["authLOGINuser"]):
                log.request(self.name, self.peerOfAttacker, config.smtpPort, line, self.username)

            # moved this block to the top:
            # if self.state["data"] gets verified after commands, a mail body containing these valid commands executes them
            if(self.state["data"]): # doesn't have to start with anything specific
                self.msg += data
                if ("\r\n.\r\n" in self.msg):
                    self.msg = self.msg[:self.msg.find("\r\n.\r\n")+2] # "+2" adds linebreak ("\r\n") to the end of the mail body
                    self.state["data"] = False
                    self.state["msg"] = True
                    response = "250 OK\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "250 OK")
                    self.transport.write(response.encode("UTF-8"))

            elif(re.match('^RSET( .*)?$', line, re.IGNORECASE)):
                # TODO: store data received from attacker somewhere else
                self.state = {"connected": False, "hello": False, "auth": False, "mailfrom": False, "mailto": False, "data": False, "msg": False, "auth": False, "authLOGIN": False, "authLOGINuser": False}
                self.msg = ""
                self.mailFrom = ""
                self.mailTo = ""
                self.username = ""
                self.password = ""
                response = "250 OK\r\n"
                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "250 OK")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match('^NOOP( .*)?$', line, re.IGNORECASE)):
                response = "250 OK\r\n"
                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "250 OK")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match('^QUIT( .*)?$', line, re.IGNORECASE)):
                # make sure QUIT doesn't have parameters (unimportant for correct functioning but good for concealment)
                if (line == "QUIT"):
                    self.state["connected"] = False
                    response = "221 Service closing transmission channel\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "221 OK (closing)")
                    self.transport.write(response.encode("UTF-8"))
                    # close connection
                    self.transport.loseConnection()
                else:
                    response = "501 Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "501 (syntax)")
                    self.transport.write(response.encode("UTF-8"))

            elif(self.state["authLOGIN"]): # doesn't start with anything recognisable
                # state after client chose LOGIN authentication method
                # TODO: missing protection against malformed inputs
                self.username = base64.b64decode(line).decode("utf-8")
                self.state["authLOGIN"] = False
                self.state["authLOGINuser"] = True
                response = "334 UGFzc3dvcmQ6\r\n" # "334 Password:"
                self.transport.write(response.encode("UTF-8"))

            elif(self.state["authLOGINuser"]): # doesn't start with anything recognisable
                # state after client sent username for LOGIN authentication method
                # TODO: missing protection against malformed inputs
                self.password = base64.b64decode(line).decode("utf-8")
                self.state["authLOGINuser"] = False
                # TODO: implement honeytokendb check
                if (True):
                    log.login(self.name, self.peerOfAttacker, config.smtpPort, True, self.username, self.password, "")
                    self.state["auth"] = True
                    self.setTimeout(self.timeoutPostAuth)
                    response = "235 OK\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "235 OK")
                else:
                    log.login(self.name, self.peerOfAttacker, config.smtpPort, False, self.username, self.password, "")
                    response = "535 SMTP Authentication unsuccessful/Bad username or password\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "535 (credentials)")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match('^HELP( .*)?$', line, re.IGNORECASE)):
                # don't react to arguments (exactly like e.g. smtp.outlook.com)
                response="214 This server supports the following commands:\r\n214 HELO EHLO RCPT DATA MAIL QUIT HELP AUTH VRFY RSET NOOP\r\n"
                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "214 OK")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match('^(HELO|EHLO)( .*)?$', line, re.IGNORECASE)):
                self.state["hello"] = True
                if (self.AuthMethods != ""):
                    response = "250 AUTH"+self.AuthMethods+"\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "250 OK")
                else:
                    # authentication completed without authentication
                    self.state["auth"] = True
                    self.setTimeout(self.timeoutPostAuth)
                    response = "250 OK\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "250 OK")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match("^AUTH( .*)?$", line, re.IGNORECASE)):
                if(line == "AUTH"):
                    response = "501 Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "501 (syntax")
                else:
                    if(self.state["hello"]):
                        if(re.match("^AUTH PLAIN \S*$", line, re.IGNORECASE)):
                            if ("PLAIN" in self.AuthMethods):
                                # b64decode everything from 12th char
                                # TODO: missing protection against malformed inputs
                                credentials = base64.b64decode(line[11:]).decode("utf-8")[1:]
                                self.username = credentials[:credentials.find("\x00")]
                                self.password = credentials[credentials.find("\x00")+1:]
                                # TODO: implement honeytokendb check
                                if (True):
                                    self.state["auth"] = True
                                    self.setTimeout(self.timeoutPostAuth)
                                    response = "235 OK\r\n"
                                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "235 OK")
                                else:
                                    response = "535 SMTP Authentication unsuccessful/Bad username or password\r\n"
                                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "535 (credentials)")
                            else:
                                response = "535 SMTP Authentication unsuccessful/Bad username or password\r\n"
                                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "535 (unsupported)")
                        elif(line == "AUTH LOGIN"):
                            if ("LOGIN" in self.AuthMethods):
                                self.state["authLOGIN"] = True
                                response = "334 VXNlcm5hbWU6\r\n" # "334 Username:"
                            else:
                                response = "535 SMTP Authentication unsuccessful/Bad username or password\r\n"
                                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "535 (unsupported)")
                        elif(line == "AUTH CRAM-MD5"):
                            # TODO: implement CRAM-MD5 or disable this code path
                            if ("CRAM-MD5" in self.AuthMethods):
                                print("CRAM-MD5 not yet implemented")
                                response = "504 Command parameter not implemented\r\n"
                                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "504 (not implemented)")
                                self.transport.write(response.encode("UTF-8"))
                                self.transport.loseConnection()
                            else:
                                response = "535 SMTP Authentication unsuccessful/Bad username or password\r\n"
                                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "535 (unsupported)")
                        elif(line == "AUTH SCRAM-SHA-1"):
                            # TODO: implement SCRAM-SHA-1 or disable this code path
                            if ("SCRAM-SHA-1" in self.AuthMethods):
                                print("SCRAM-SHA-1 not yet implemented")
                                response = "504 Command parameter not implemented\r\n"
                                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "504 (not implemented)")
                                self.transport.write(response.encode("UTF-8"))
                                self.transport.loseConnection()
                            else:
                                response = "535 SMTP Authentication unsuccessful/Bad username or password\r\n"
                                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "535 (unsupported)")
                        else:
                            response = "501 Syntax error in parameters or arguments\r\n"
                            log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "501 (syntax)")
                    else:
                        response = "503 Bad sequence of commands\r\n" # "Send hello first"
                        log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "503 (sequence)")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match("^MAIL FROM:(.*)$", line, re.IGNORECASE)):
                # tolerate additional whitespace
                if(re.match("^MAIL FROM:[ ]?<(.*)>$", line, re.IGNORECASE)): # use "<(.*@.*\..*?)>" to check basic adress syntax
                    if(self.state["auth"]):
                        self.state["mailfrom"] = True
                        self.mailFrom = re.match("^MAIL FROM:[ ]?<(.*)>$", line, re.IGNORECASE).groups()[0] # use "<(.*@.*\..*?)>" to check basic adress syntax
                        response = "250 OK\r\n"
                        log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "250 OK")
                    elif(self.state["hello"]):
                        response = "535 SMTP Authentication unsuccessful/Bad username or password\r\n"
                        log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "535 (credentials)")
                    else:
                        response = "503 Bad sequence of commands\r\n" # "Send hello first"
                        log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "503 (sequence)")
                else:
                    # no email adress given etc.
                    response = "501 Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "501 (syntax)")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match("^RCPT TO:(.*)$", line, re.IGNORECASE)):
                # tolerate additional whitespace
                if(re.match("^RCPT TO:[ ]?<(.*)>$", line, re.IGNORECASE)): # use "<(.*@.*\..*?)>" to check basic adress syntax
                    if(self.state["mailfrom"]):
                        self.state["mailto"] = True
                        self.mailTo = re.match("^RCPT TO:[ ]?<(.*)>$", line, re.IGNORECASE).groups()[0] # use "<(.*@.*\..*?)>" to check basic adress syntax # use "<(.*@.*\..*?)>" to check basic adress syntax
                        response = "250 OK\r\n"
                        log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "250 OK")
                    elif(self.state["hello"]):
                        response = "535 SMTP Authentication unsuccessful/Bad username or password\r\n"
                        log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "535 (credentials)")
                    else:
                        response = "503 Bad sequence of commands\r\n" # "Send hello first"
                        log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "503 (sequence)")
                else:
                    # no email adress given etc.
                    response = "501 Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "501 (syntax)")
                self.transport.write(response.encode("UTF-8"))
            
            elif(re.match("^DATA( .*)?$", line, re.IGNORECASE)):
                if (line == "DATA"):
                    if(self.state["mailto"]):
                        self.state["data"] = True
                        response = "354 Start mail input\r\n"
                    elif(self.state["auth"]):
                        response = "503 Bad sequence of commands\r\n" # "Send hello first"
                        log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "503 (sequence)")
                    elif(self.state["hello"]):
                        response = "535 SMTP Authentication unsuccessful/Bad username or password\r\n"
                        log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "535 (credentials)")
                    else:
                        response = "503 Bad sequence of commands\r\n" # "Send hello first"
                        log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "503 (sequence)")
                else:
                    response = "501 Syntax error in parameters or arguments\r\n"
                    log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "501 (syntax)")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match("^VRFY( .*)?$", line, re.IGNORECASE)):
                response = "252 Cannot VRFY user\r\n"
                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "252 OK")
                self.transport.write(response.encode("UTF-8"))

            elif(re.match("^SIZE( .*)?$", line, re.IGNORECASE)):
                response = "502 Command not implemented\r\n"
                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "502 (not implemented)")
                self.transport.write(response.encode("UTF-8"))

            else:
                response = "500 Unrecognized command \'"+line+"\'\r\n"
                log.response(self.name, self.peerOfAttacker, config.smtpPort, "", self.username, "500 (command)")
                self.transport.write(response.encode("UTF-8"))