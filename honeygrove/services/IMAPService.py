# IMAP-Service

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
import base64, re, time, random

class IMAPService(ServiceBaseModel):
    def __init__(self):
        super(IMAPService, self).__init__()

        self._name = config.imapName
        self._port = config.imapPort
        self._limiter = Limiter(self._fService, config.imapName, config.IMAP_conn_per_host)

        self.protocol = IMAPProtocol
        self._fService.protocol = self.protocol

    def startService(self):
        self._stop = False
        self._transport = reactor.listenTCP(self._port, self._limiter)

    def stopService(self):
        self._stop = True
        self._transport.stopListening()

class IMAPState(Enum):
    # see RFC 3501
    NotAuth = 0
    Auth = 1
    Selected = 2
    Logout = 3

class IMAPProtocol(Protocol, policies.TimeoutMixin):
    
    def __init__(self):
        # buffer for email body
        self.msg = ""
        # authentication methods offered to the client (https://english.stackexchange.com/a/7845)
        self.AuthMethods = ""

        mm = config.SMTPAuthMethods
        for m in mm:
            if (mm[m]):
                # string containing authentication methods (embedded inside server response)
                self.AuthMethods += " "+m
        del m,mm

        self.username = ""
        self.usernameValid = "honig"
        self.password = ""
        self.passwordValid = "bienenstock"

        # temporary storage for values received in append function
        self.appendMailbox = ""
        self.appendTag = ""
        self.appendFlaglist = ""
        self.appendBuffer = ""
        self.appendLength = 0

        # flags indicating different states to verify correct sequence of commands
        self.state = {"connected": False, "appendData": False, "appendCleanUp": False}
        
        # not used by now
        self.validflags = {"\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft", "\\Recent"}

        # values in seconds, timeout prolonged after succesful login
        self.timeoutPreAuth = 60
        self.timeoutPostAuth = 300

        # buffer holding all received lines
        self.dataBuffer = ""
        # e.g. imap.outlook.com accepts 4094 max command line length (4094 Chars + "\r\n" = 4096 Bytes = 4 KB)
        self.maxCommandLength = 4094

        # array containing the default mails available on the server (import them from database.py)
        self.emails = list()
        for mail in database.mails:
            header = ""
            for i in mail[1]:
                header += i+": "+mail[1][i]+"\r\n"
            headerDict = mail[1]
            flags = set()
            r = self.crossSumHash(mail[2])
            if (r > 0.2): flags.add("\\Recent")
            if (r > 0.5): flags.add("\\Seen")
            if (r > 0.75): flags.add("\\Answered")
            self.emails.append([mail[0], flags, headerDict, header, mail[2]])
            # self.emails = [[mailbox,flags,headerDict,header,body], [mailbox,flags,headerDict,header,body], [mailbox,flags,headerDict,header,body], ...]
        self.mailboxes = dict()
        self.calcMailboxStats()
        self.selectedMailbox = ""

    # deterministically assignes a value [0,1] to a string (depends on the string length)
    def crossSumHash(self, text):
        # cross sum of the lenght of the input
        c = 0
        for i in str(len(text)):
            c+=int(i)
        # normalize to a value between 0 and 1
        while (c > 1):
            c = c / 10
        return round(c,3)

    # e.g. Thunderbird pads credentials and other parameters with quotation marks
    def stripPadding(self, input):
        while (input.startswith("\"") and input.endswith("\"")):
            input = input[1:-1]
        return input

    # refresh stats (number of mails for each mailbox) stored in self.mailboxes (dictionary)
    def calcMailboxStats(self):
        self.mailboxes = dict()
        for i in ["INBOX","Drafts","Trash","Spam","Sent"]: # add default mailboxes
            if (i not in self.mailboxes):
                self.mailboxes[i] = 0
        for mail in self.emails: # add custom folders
            if (mail[0] not in self.mailboxes):
                self.mailboxes[mail[0]] = 1
            else:
                self.mailboxes[mail[0]] = self.mailboxes[mail[0]] + 1

    # checks whether a given seq(uence-)number is included in a given seq(uence-)set, returns boolean
    # "Example: a message sequence number set of 2,4:7,9,12:* for a mailbox with 15 messages
    #  is equivalent to 2,4,5,6,7,9,12,13,14,15" (quote from RFC 3501)
    # TODO: improve runtime complexity by redesigning requests
    def sequenceNumberInSet (self, seqset, seqnum):
        for part in seqset.split(","):
            if(not ":" in part):
                if (part == str(seqnum)): # never return False
                    return True
            else:
                r = re.match("^(\d+|\*):(\d+|\*)$", part, re.IGNORECASE)
                if (r != None):
                    a,b = r.groups()
                    #check '*' case first to avoid 'int("*")' error; a <= b included; never return False
                    if (((a == "*" and int(seqnum) >= 1) or (int(seqnum) >= int(a))) and ((b == "*" and maximum >= int(seqnum)) or (int(b) >= int(seqnum)))):
                        return True
        return False

    # 
    def saveEmail(self, mailbox, flaglist, mail):
        # split mail into header...
        header = mail[:mail.find("\r\n\r\n")]
        # build dictionary by splitting headers in key-value pairs
        headerDict = dict()
        for i in header.split("\r\n"):
            headerDict[i[:i.find(": ")]] = i[i.find(": ")+2:]
        # ...and body
        body = mail[mail.find("\r\n\r\n")+4:]
        # append new mail to self.emails and refresh stats
        self.emails.append([mailbox, flaglist, headerDict, header, body])
        self.calcMailboxStats()

    def connectionMade(self):
        if (self.transport.getHost().port == config.imapPort):
            self.name = config.imapName
        elif (self.transport.getHost().port == config.imapsPort):
            self.name = config.imapsName
        else:
            log.err("Please check IMAP/IMAPS port configuration!")
            self.name = "IMAP/IMAPS"

        self.setTimeout(self.timeoutPreAuth)
        log.info(self.name+" established connection to "+str(self.transport.getPeer().host)+":"+str(self.transport.getPeer().port))

        # add connection to dictionary
        self.factory.clients[self] = (str(self.transport.getPeer().host) + ":" + str(self.transport.getPeer().port))

        # protocol state
        self.state["connected"] = True
        self.stateRFC = IMAPState.NotAuth
        self.peerOfAttacker = self.transport.getPeer().host

        # server hello
        response = "* OK IMAP4rev1 Service Ready\r\n"
        self.transport.write(response.encode("UTF-8"))

    def connectionLost(self, reason):
        log.info(self.name+" lost connection to "+str(self.transport.getPeer().host)+":"+str(self.transport.getPeer().port))
        self.setTimeout(None)
        # remove connection from dictionary
        del self.factory.clients[self]

    # partially disabled due to Issue #20
    def timeoutConnection(self):
        response = "* BYE Connection closed due to timeout\r\n"
        log.info(self.name+" ("+self.peerOfAttacker+"): Timeout waiting for client input")
        self.transport.write(response.encode("UTF-8"))
        # close connection gently (nonblocking, send buffers before closing, client is able to receive error message)
        self.transport.loseConnection()
        #time.sleep(5)
        # force close connection after waiting duration
        #self.transport.abortConnection()
        # connectionLost() gets called automatically

    def dataReceived(self, rawData):
        self.resetTimeout()

        # problem: at least Thunderbird pushes sometimes two commands so quickly they are received by twisted as one line
        # solution: put received data in buffer and fetch single lines from there

        # TODO: Verifizieren, dass möglichst alle 503-Fälle ("Bad sequence of commands") abgedeckt sind
        if(rawData.startswith(b'\xff') or rawData.startswith(b'\x04')):
            #ignore Ctrl+C/D/Z etc.
            pass
        else:
            # binary data like b"\xff\x..." causes trouble when decoding (simply ignore it)
            try:
                # decode raw data and add it to buffer
                self.dataBuffer += rawData.decode("UTF-8")
            except Exception as e:
                #print("ignoring invalid chars")
                pass

            # get first line from buffer
            if ("\r\n" in self.dataBuffer):
                line = self.dataBuffer[:self.dataBuffer.find("\r\n")]
                self.dataBuffer = self.dataBuffer[self.dataBuffer.find("\r\n")+2:]
            else:
                print("IMAPService: Warning: Client command didn't end with CRLF!")
                line = self.dataBuffer
                self.dataBuffer = ""

            if (not self.state["appendCleanUp"] and not self.state["appendData"]):
                log.request(self.name, self.peerOfAttacker, config.imapPort, line, self.username)
            
            # ignore one (maybe optional) empty line after append command
            if(self.state["appendCleanUp"]):
                if (line != ""):
                    self.dataBuffer = line + "\r\n" + self.dataBuffer
                self.state["appendCleanUp"] = False
            elif(self.state["appendData"]): # wait for another part of the mail
                # reunify first line and remaining buffer
                self.dataBuffer = line+"\r\n"+self.dataBuffer
                # buffer is bigger than remaining announced transmission
                if (len(self.dataBuffer) >= self.appendLength):
                    self.appendBuffer += self.dataBuffer[:self.appendLength]
                    self.dataBuffer = self.dataBuffer[self.appendLength:]
                    self.appendLength = 0
                    self.state["appendData"] = False
                    self.state["appendCleanUp"] = True
                    # add uploaded mail to storage
                    mail = self.appendBuffer
                    self.saveEmail(self.appendMailbox, self.appendFlaglist, mail)
                    response = self.appendTag + " OK APPEND completed\r\n"
                    log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                    self.transport.write(response.encode("UTF-8"))
                else: # wait for another part of the mail
                    self.appendBuffer += self.dataBuffer
                    self.appendLength -= len(self.dataBuffer)
                    self.dataBuffer = ""
            elif(len(line) > self.maxCommandLength):
                response = "* BAD Command line too long\r\n"
                log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (too long)")
                self.transport.write(response.encode("UTF-8"))
            elif(len(line) == 0):
                response = "* BAD Empty command line\r\n"
                log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (too short)")
                self.transport.write(response.encode("UTF-8"))
            elif(re.match("^[A-Za-z\d]+ .+$", line, re.IGNORECASE)):
                # provides tag value for following answers in all cases
                tag = re.match("^(?P<tag>[A-Za-z\d]+) .+$", line, re.IGNORECASE).group("tag")

                # "command-any" (Valid in all states)
                if(re.match("^"+tag+" CAPABILITY$", line, re.IGNORECASE)):
                    response = "* CAPABILITY IMAP4rev1 LOGIN LOGOUT NOOP LIST LSUB UID SELECT\r\n"+tag+" OK CAPABILITY completed\r\n"
                    log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                    self.transport.write(response.encode("UTF-8"))
                elif(re.match("^"+tag+" LOGOUT$", line, re.IGNORECASE)):
                    self.state["connected"] = False
                    response = "* BYE IMAP4rev1 Server logging out\r\n"+tag+" OK LOGOUT completed\r\n"
                    log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                    self.transport.write(response.encode("UTF-8"))
                    # close connection
                    self.transport.loseConnection()
                elif(re.match("^"+tag+" NOOP$", line, re.IGNORECASE)):
                    response = tag+" OK NOOP completed\r\n"
                    log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                    self.transport.write(response.encode("UTF-8"))
                elif(re.match("^"+tag+" ((CAPABILITY)|(LOGOUT)|(NOOP)) .*$", line, re.IGNORECASE)):
                    # unified error message for several commands
                    response = "* BAD Command argument error\r\n"
                    log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (syntax)")
                    self.transport.write(response.encode("UTF-8"))



                # "command-nonauth" (Valid only when in Not Authenticated state)
                elif(re.match("^"+tag+" LOGIN (?P<userid>\S+) (?P<password>\S+)$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.NotAuth):
                        arguments = re.match("^"+tag+" LOGIN (?P<userid>\S+) (?P<password>\S+)$", line, re.IGNORECASE)

                        self.username = self.stripPadding(arguments.group("userid"))
                        self.password = self.stripPadding(arguments.group("password"))

                        if (True):
                            log.login(self.name, self.peerOfAttacker, config.imapPort, True, self.username, self.password, "")
                            self.setTimeout(self.timeoutPostAuth)
                            self.stateRFC = IMAPState.Auth
                            response = tag+" OK LOGIN completed\r\n"
                            log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                        else:
                            log.login(self.name, self.peerOfAttacker, config.imapPort, False, self.username, self.password, "")
                            response = tag+" NO Invalid credentials\r\n"
                            log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "NO (credentials")
                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                    self.transport.write(response.encode("UTF-8"))
                elif(re.match("^"+tag+" LOGIN .*$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.NotAuth):
                        response = "* BAD Command argument error\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (syntax)")
                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence")
                    self.transport.write(response.encode("UTF-8"))

                    #TODO: implement AUTHENTICATE command (provides SASL auth (GSSAPI etc.))



                # "command-auth" (Valid only in Authenticated or Selected state)
                elif(re.match("^"+tag+" LIST (?P<mailbox>\S+) (?P<listmailbox>\S+)$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.Auth or self.stateRFC == IMAPState.Selected):
                        arguments = re.match("^"+tag+" LIST (?P<mailbox>\S+) (?P<listmailbox>\S+)$", line, re.IGNORECASE)
                        reference = self.stripPadding(arguments.group("mailbox"))
                        mailboxName = self.stripPadding(arguments.group("listmailbox"))

                        response = ""
                        # doesn't really support the wildcard feature, just distinguishes between "everything" and "one specific mailbox"
                        if (mailboxName in ["*", "%"]):
                            for i in self.mailboxes:
                                response += "* LIST (\\HasNoChildren) \".\" \""+i+"\"\r\n"
                            response += tag+" OK LIST Completed\r\n"
                        else:
                            if (mailboxName in self.mailboxes):
                                response += "* LIST (\\HasNoChildren) \".\" \""+mailboxName+"\"\r\n"
                            response += tag+" OK LIST Completed\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                    self.transport.write(response.encode("UTF-8"))

                elif(re.match("^"+tag+" LSUB (?P<mailbox>\S+) (?P<listmailbox>\S+)$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.Auth or self.stateRFC == IMAPState.Selected):
                        arguments = re.match("^"+tag+" LSUB (?P<mailbox>\S+) (?P<listmailbox>\S+)$", line, re.IGNORECASE)
                        reference = self.stripPadding(arguments.group("mailbox"))
                        mailboxName = self.stripPadding(arguments.group("listmailbox"))
                        
                        response = ""
                        # doesn't really support the wildcard feature, just distinguishes between "everything" and "one specific mailbox"
                        if (mailboxName in ["*", "%"]):
                            for i in self.mailboxes:
                                response += "* LSUB (\\HasNoChildren) \".\" \""+i+"\"\r\n"
                            response += tag+" OK LSUB Completed\r\n"
                        else:
                            if (mailboxName in self.mailboxes):
                                response += "* LSUB (\\HasNoChildren) \".\" \""+mailboxName+"\"\r\n"
                            response += tag+" OK LSUB Completed\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                    else:                                   
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                    self.transport.write(response.encode("UTF-8"))

                elif(re.match("^"+tag+" SELECT (?P<mailbox>\S+)$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.Auth or self.stateRFC == IMAPState.Selected):
                        arguments = re.match("^"+tag+" SELECT (?P<mailbox>\S+)$", line, re.IGNORECASE)
                        mailbox = self.stripPadding(arguments.group("mailbox"))
                        if(mailbox in self.mailboxes):
                            self.stateRFC = IMAPState.Selected
                            self.selectedMailbox = mailbox
                            response = "* "+str(self.mailboxes[mailbox])+" EXISTS\r\n* 0 RECENT\r\n"+tag+" OK SELECT completed\r\n"
                            log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                        else:
                            response = tag+" NO Mailbox not found\r\n"
                            log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "NO (mailbox not found)")
                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                    self.transport.write(response.encode("UTF-8"))

                elif(re.match("^"+tag+" STATUS (?P<mailbox>\S+) \((?P<statusatt>\S+( \S+)*)\)$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.Auth or self.stateRFC == IMAPState.Selected):
                        arguments = re.match("^"+tag+" STATUS (?P<mailbox>\S+) \((?P<statusatt>\S+( \S+)*)\)$", line, re.IGNORECASE)
                        mailbox = self.stripPadding(arguments.group("mailbox"))
                        statusatt = arguments.group("statusatt")
                        if (mailbox in self.mailboxes):
                            statusatt = statusatt.replace("MESSAGES","MESSAGES "+str(self.mailboxes[mailbox]))
                            if ("RECENT" in statusatt):
                                c = 0
                                for mail in self.emails:
                                    if(mail[0] == self.selectedMailbox): # just mails in this mailbox
                                        if ("\\Recent" in mail[1]):
                                            c += 1
                                statusatt = statusatt.replace("RECENT","RECENT "+str(c))
                            if ("UNSEEN" in statusatt):
                                c = 0
                                for mail in self.emails:
                                    if(mail[0] == self.selectedMailbox): # just mails in this mailbox
                                        if (not "\\Seen" in mail[1]):
                                            c += 1
                                statusatt = statusatt.replace("UNSEEN","UNSEEN "+str(c))
                                # TODO: research possible values (nonsense values at the moment)
                                statusatt = statusatt.replace("UIDNEXT","UIDNEXT "+str(1))
                                statusatt = statusatt.replace("UIDVALIDITY","UIDVALIDITY "+str(0))

                            response = "* STATUS "+mailbox+" ("+statusatt+")\r\n"
                            response += tag + " OK STATUS completed\r\n"
                            log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                        else:
                            response = "* NO STATUS failure: no status for that name\r\n"
                            log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "NO (mailbox not found)")
                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                    self.transport.write(response.encode("UTF-8"))

                elif(re.match("^"+tag+" APPEND (?P<mailbox>\S+) \((?P<flaglist>\S+( \S+)*)?\)(?P<datetime> .+)? \{(?P<literal>\d+)\}$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.Auth or self.stateRFC == IMAPState.Selected):
                        arguments = re.match("^"+tag+" APPEND (?P<mailbox>\S+) \((?P<flaglist>\S+( \S+)*)?\)(?P<datetime> .+)? \{(?P<literal>\d+)\}$", line, re.IGNORECASE)
                        mailbox = self.stripPadding(arguments.group("mailbox"))
                        flaglist = arguments.group("flaglist")
                        datetime = arguments.group("datetime")
                        literal = arguments.group("literal")
                        # grant up to about 20 * 1 MiB storage (memory-DOS protection)
                        if (int(literal) <= 1048576 and len(self.emails) < 20):
                            self.state["appendData"] = True
                            self.appendTag = tag
                            self.appendMailbox = mailbox
                            self.appendFlaglist = flaglist
                            self.appendBuffer = ""
                            self.appendLength = int(literal)
                            response = "+ Ready for literal data\r\n"
                            self.transport.write(response.encode("UTF-8"))
                        else:
                            response = "* NO APPEND error: can't append to that mailbox, error in flags or date/time or message text\r\n"
                            log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "NO (storage limitation)")
                            self.transport.write(response.encode("UTF-8"))
                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                        self.transport.write(response.encode("UTF-8"))

                elif(re.match("^"+tag+" (LIST|LSUB|SELECT|STATUS|APPEND) .*$", line, re.IGNORECASE)):
                    # unified error message for several commands
                    if (self.stateRFC == IMAPState.Auth or self.stateRFC == IMAPState.Selected):
                        response = "* BAD Command argument error\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (syntax)")
                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                    self.transport.write(response.encode("UTF-8"))



                # "command-select" (Valid only when in Selected state)
                elif(re.match("^"+tag+" CLOSE$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.Selected):
                        #TODO: delete accordingly flagged mails
                        self.stateRFC = IMAPState.Auth
                        response = tag+" OK CLOSE completed\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                    self.transport.write(response.encode("UTF-8"))

                elif(re.match("^"+tag+"CLOSE .*$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.Selected):
                        response = "* BAD Command argument error\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (syntax)")
                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                    self.transport.write(response.encode("UTF-8"))

                elif(re.match("^"+tag+" UID FETCH (?P<sequenceset>\S+) (?P<entries>.+)$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.Selected):

                        arguments = re.match("^"+tag+" UID FETCH (?P<sequenceset>\S+) (?P<entries>.+)$", line, re.IGNORECASE)
                        sequenceset = arguments.group("sequenceset")
                        entries = arguments.group("entries")

                        # resolve fetch macros (according to RFC 3501) for parsing
                        macros = {"ALL": "(FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)", "FAST": "(FLAGS INTERNALDATE RFC822.SIZE)", "FULL": "(FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY)"}
                        if (entries in macros):
                            entries = macros[entries]

                        response = ""
                        c = 1  # sequence number of mail in mailbox (use position in mail array as ascending UID)
                        for i, mail in enumerate(self.emails):
                            if(mail[0] == self.selectedMailbox): # just mails in this mailbox
                                if (sequenceset == "1:*" or self.sequenceNumberInSet(sequenceset,i)): # important performance improvement for default parameter
                                    if (entries in ["FLAGS", "(FLAGS)"]):
                                        response += "* "+str(c)+" FETCH (UID "+str(i)+" FLAGS ("+(" ".join(mail[1]))+"))\r\n"
                                    else:   
                                        response += "* "+str(c)+" FETCH "

                                        # TODO: best solution: parse fetch-att parameters and select accordingly which attributes to send
                                        entriesProcessed = entries.upper()[:-1]
                                        entriesProcessed = entriesProcessed.replace("UID","UID "+str(i))
                                        entriesProcessed = entriesProcessed.replace("RFC822.SIZE","RFC822.SIZE "+str(len(mail[3])+len(mail[4])))
                                        entriesProcessed = entriesProcessed.replace("FLAGS","FLAGS ("+(" ".join(mail[1]))+")")
                                        entriesProcessed = entriesProcessed.replace("BODY.PEEK","BODY")
                                        buffer = ""
                                        if("BODY" in entriesProcessed or "ENVELOPE" in entriesProcessed or "TEXT" in entriesProcessed):
                                            buffer += mail[3]+"\r\n"+mail[4]
                                        response += entriesProcessed+" {"+str(len(buffer))+"}\r\n"+buffer

                                        response += "\r\n)\r\n"
                                c += 1
                        response += tag+" OK FETCH complete\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")

                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                    self.transport.write(response.encode("UTF-8"))
 
                elif(re.match("^"+tag+" UID FETCH .+$", line, re.IGNORECASE)): 
                    response = "* BAD Command argument error\r\n"
                    log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (syntax)")
                    self.transport.write(response.encode("UTF-8")) 
                         
                    # temporary workaround to avoid the client to throw an error after uploading the mail
                elif(re.match("^"+tag+" UID SEARCH *$", line, re.IGNORECASE)):
                    if (self.stateRFC == IMAPState.Selected):
                        response = "* SEARCH\r\n"+tag+" OK SEARCH completed\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "OK")
                    else:
                        response = tag+" BAD Command received in invalid state.\r\n"
                        log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (sequence)")
                    self.transport.write(response.encode("UTF-8"))

                else:
                    response = "* BAD Command unknown\r\n"
                    log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (command)")
                    self.transport.write(response.encode("UTF-8"))

            else:
                response = "* BAD Syntax error\r\n"
                log.response(self.name, self.peerOfAttacker, config.imapPort, "", self.username, "BAD (syntax)")
                self.transport.write(response.encode("UTF-8"))