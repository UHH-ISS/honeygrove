from honeygrove import log as hg_log
from honeygrove.config import Config
from honeygrove.core.FilesystemParser import FilesystemParser
from honeygrove.core.HoneytokenDB import HoneytokenDataBase
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel

from datetime import datetime as dt
import random

from twisted.cred.portal import Portal
from twisted.protocols.ftp import *
from twisted.protocols.ftp import _FileReader as FR
from twisted.protocols.ftp import _FileWriter as FW


# flake8: noqa
# Disable flake8 to hide start-import related imports
class FTPService(ServiceBaseModel):

    credchecker = HoneytokenDataBase("FTP")
    # Make name and port accessible for logging in FTPProtocol
    _name = Config.ftp.name
    _port = Config.ftp.port

    def __init__(self):

        super(FTPService, self).__init__()

        portal = Portal(FTPRealm('./'), [self.credchecker])

        self._fService = FTPFactory(portal)

        self._name = Config.ftp.name
        self._port = Config.ftp.port

        self._limiter = Limiter(self._fService, self._name, Config.ftp.connections_per_host)

        self.protocol = FTPProtocol
        self._fService.protocol = self.protocol


class FTPProtocol(FTP):
    overwritten_commands_whitelist = ['CWD', 'DELE', 'LIST', 'MDTM', 'MKD',
                                      'PASS', 'PWD', 'RETR', 'RMD', 'RNTO', 'SIZE', 'STOR', 'USER']

    inherited_commands_whitelist = ['FEAT', 'CDUP', 'NOOP', 'PASV', 'QUIT', 'RNFR', 'PORT', 'TYPE', 'SYST', 'STRU',
                                    'MODE']

    inherited_responses = {'FEAT': " ",
                           'NOOP': RESPONSE.get(CMD_OK),
                           'PASV': RESPONSE.get(ENTERING_PASV_MODE),
                           'QUIT': " ",
                           'RNFR': RESPONSE.get(REQ_FILE_ACTN_PENDING_FURTHER_INFO),
                           'PORT': " ",
                           'TYPE': " ",
                           'SYST': " ",
                           'STRU': " ",
                           'MODE': " "
                           }

    honeytokenDirectory = str(Config.folder.honeytoken_files)
    receivedDataDirectory = str(Config.folder.quarantine)

    lastmodified = dt.now()

    def __init__(self):
        self._parser = FilesystemParser()
        self.user = "anonymous"
        self.l = hg_log

    def ftp_PWD(self):
        """
        Print current directory in faked filesystem.
        """
        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "PWD", self.user, "PWD")
        cur = " " + self._parser.get_formatted_path()
        self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, cur, self.user, "PWD")
        return PWD_REPLY, cur

    def ftp_CWD(self, path):
        """
        Change current directory in faked filesystem to path
        if path is valid.

        @param path: path to navigate to
        @type path: str
        """
        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "CWD " + path, self.user, "CWD")
        if self._parser.valid_directory(path):
            self._parser.cd(path)
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port,
                            RESPONSE.get(REQ_FILE_ACTN_COMPLETED_OK, "ab"), self.user, "CWD")
            return (REQ_FILE_ACTN_COMPLETED_OK,)
        self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, RESPONSE.get(FILE_NOT_FOUND),
                        self.user, "CWD")
        return defer.fail(FileNotFoundError(path))

    def ftp_DELE(self, path):
        """
        If path is valid path in faked filesystem, delete
        directory/file at path in faked filesystem.

        @param path: path of directory/file
        @type path: str
        """
        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "DELE " + path, self.user, "DELE")
        if self._parser.valid_path(path):
            self._parser.delete(path)
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, RESPONSE.get(REQ_FILE_ACTN_COMPLETED_OK),
                            self.user, "DELE")
            return REQ_FILE_ACTN_COMPLETED_OK
        self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, RESPONSE.get(FILE_NOT_FOUND), self.user, "DELE")
        return defer.fail(FileNotFoundError(path))

    def ftp_LIST(self, path=''):
        """
        Return childs of directory at path in fake filesystem.
        (first 5 lines copied from twisted.protocols.ftp.FTP.ftp_LIST)

        @param path: path of directory
        @type path: str
        """
        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "LS " + path, self.user, "LS")
        if self.dtpInstance is None or not self.dtpInstance.isConnected:
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port,
                            BAD_CMD_SEQ + ': PORT or PASV required before RETR', self.user, "LS")
            return defer.fail(BadCmdSequenceError('must send PORT or PASV before RETR'))

        if path.lower() in ['-a', '-l', '-la', '-al']:
            path = ''

        if self._parser.valid_directory(path):
            files = self._parser.ls(path).split()
            self.reply(DATA_CNX_ALREADY_OPEN_START_XFR)
            [self.dtpInstance.sendLine(file.encode(self._encoding)) for file in files]
            self.dtpInstance.transport.loseConnection()
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port,
                            RESPONSE.get(TXFR_COMPLETE_OK), self.user, "LS")
            return (TXFR_COMPLETE_OK,)
        self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, RESPONSE.get(FILE_NOT_FOUND),
                        self.user, "LS")
        return defer.fail(FileNotFoundError(path))

    def ftp_MDTM(self, path):
        """
        If path is valid path to 'file' in faked filesystem,
        return self.lastmodified.

        @param path: path to file/directory
        @type path: str
        """
        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "MDTM " + path, self.user, "MDTM")
        if self._parser.valid_path(path):
            response = self.lastmodified.strftime('%Y%m%d%H%M%S')
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, FILE_STATUS + " " + response,
                            self.user, "MDTM")
            return (FILE_STATUS, response)
        self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, RESPONSE.get(FILE_NOT_FOUND),
                        self.user, "MDTM")
        return defer.fail(FileNotFoundError(path))

    def ftp_MKD(self, name):
        """
        In faked filesystem: create a directory at path.

        @param path: new directory's path
        @type path: str
        """
        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "MKD " + name, self.user, "MKD")
        validName = not set('[~!@#$%^&*()+{}":;\']+$').intersection(name)
        if (not self._parser.valid_directory(name)) and validName:
            self._parser.mkdir(name)
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port,
                            RESPONSE.get(MKD_REPLY) + " " + name, self.user, "MKD")
            return (MKD_REPLY, name)
        self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, RESPONSE.get(FILE_NOT_FOUND),
                        self.user, "MKD")
        return defer.fail(FileNotFoundError(name))

    def ftp_RMD(self, path):
        """
        In faked filesystem: remove directory at path.

        @param path: path to directory
        @type path: str
        """
        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "RMD " + path, self.user, "RMD")
        if self._parser.valid_directory(path):
            self._parser.delete(path)
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port,
                            RESPONSE.get(REQ_FILE_ACTN_COMPLETED_OK), self.user, "RMD")
            return (REQ_FILE_ACTN_COMPLETED_OK,)
        self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, RESPONSE.get(FILE_NOT_FOUND),
                        self.user, "RMD")
        return defer.fail(FileNotFoundError(path))

    def ftp_RNTO(self, toName):
        """
        Renames a previously chosen file to toName.

        @param toName: new name of the file
        @type toName: str
        """
        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "RNTO " + toName, self.user, "RNTO")
        fromName = self._fromName
        del self._fromName
        self.state = self.AUTHED
        validToName = not set('[~!@#$%^&*()+{}":;\']+$').intersection(toName)

        if (self._parser.valid_path(fromName)) and validToName:
            self._parser.rename(fromName, toName)
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port,
                            RESPONSE.get(REQ_FILE_ACTN_COMPLETED_OK), self.user, "RNTO")
            return (REQ_FILE_ACTN_COMPLETED_OK,)
        self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port,
                        RESPONSE.get(FILE_NOT_FOUND) % fromName, self.user, "RNTO")
        return defer.fail(FileNotFoundError(fromName))

    def ftp_SIZE(self, path):
        """
        Return a random number between 100 and 5000000,
        if path is a valid path in faked filesystem.

        @param path: path to file
        @type path: str
        """
        response = ''
        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "SIZE " + path, self.user, "SIZE")
        if not self._parser.valid_path(path):
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, RESPONSE.get(FILE_NOT_FOUND),
                            self.user, "SIZE")
            return defer.fail(FileNotFoundError(path))
        if self._parser.valid_directory(path):
            response = random.randint(20000, 5000000)
        if self._parser.valid_file(path):
            response = random.randint(100, 30000)
        self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, FILE_STATUS + " " + str(response),
                        self.user, "SIZE")
        return FILE_STATUS, response

    def ftp_STOR(self, path):
        """
        Stores an uploaded  File in  self.receivedDataDirectory.

        @param path: path to file
        @type path: str
        """
        abs_path = self._parser.get_absolute_path(path)  # Windows-Mode etc.
        filename = abs_path.split("/")[-1]

        if self.dtpInstance is None:
            raise BadCmdSequenceError('PORT or PASV required before STOR')

        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "STOR " + path, self.user, "STOR")

        if not self._parser.valid_file(path):
            self._parser.touch(path)

        self.setTimeout(None)

        def enableTimeout(result):
            self.setTimeout(self.factory.timeOut)
            return result

        def cbOpened(file):
            """
            File was open for reading. Launch the data transfer channel via
            the file consumer.
            """
            d = file.receive()
            d.addCallback(cbConsumer)
            d.addCallback(lambda ignored: file.close())
            d.addCallbacks(cbSent, ebSent)
            return d

        def ebOpened(err):
            """
            Called when failed to open the file for reading.
            For known errors, return the FTP error code.
            For all other, return a file not found error.
            """
            if isinstance(err.value, FTPCmdError):
                return (err.value.errorCode, path)
            log.err(err, "Unexpected error received while opening file:")
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, RESPONSE.get(FILE_NOT_FOUND),
                            self.user, "STOR")
            return FILE_NOT_FOUND, path

        def cbConsumer(cons):
            """
            Called after the file was opended for reading.
            Prepare the data transfer channel and send the response
            to the command channel.
            """
            if not self.binary:
                cons = ASCIIConsumerWrapper(cons)

            d = self.dtpInstance.registerConsumer(cons)

            if self.dtpInstance.isConnected:
                self.reply(DATA_CNX_ALREADY_OPEN_START_XFR)
            else:
                self.reply(FILE_STATUS_OK_OPEN_DATA_CNX)
            return d

        def cbSent(result):
            """
            Called from data transport when tranfer is done.
            """
            if Config.ftp.accept_files:
                self.l.file(FTPService._name, self.transport.getPeer().host, FTPService._port, filename, self.receivedDataDirectory + "/" + filename,
                            self.user)
            else:
                self.l.file(FTPService._name, self.transport.getPeer().host, FTPService._port, filename, user=self.user)
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, RESPONSE.get(TXFR_COMPLETE_OK),
                            self.user, "STOR")
            return (TXFR_COMPLETE_OK,)

        def ebSent(err):
            """
            Called from data transport when there are errors during the
            transfer.
            """
            log.err(err, "Unexpected error received during transfer:")
            if err.check(FTPCmdError):
                return err
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port,
                            RESPONSE.get(CNX_CLOSED_TXFR_ABORTED), self.user, "STOR")
            return (CNX_CLOSED_TXFR_ABORTED,)

        if Config.ftp.accept_files:
            i = 1
            name = filename
            while name in os.listdir(self.receivedDataDirectory):
                name = filename + "." + str(i)
                i += 1
            fObj = open(self.receivedDataDirectory + "/" + name, 'wb')
            d = defer.succeed(FW(fObj))
        else:
            d = defer.succeed()
        d.addCallbacks(cbOpened, ebOpened)
        d.addBoth(enableTimeout)

        return d

    def ftp_RETR(self, path):
        """
        This command causes the content of a file to be sent over the data
        transfer channel. If the path is to a folder, an error will be raised.

        @type path: str
        @param path: The path to the file which should be transferred over the
        data transfer channel.
        """
        if self.dtpInstance is None:
            raise BadCmdSequenceError('PORT or PASV required before RETR')

        self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, "RETR " + path, self.user, "RETR")

        honeytoken_filenames = os.listdir(self.honeytokenDirectory)

        if not (self._parser.valid_file(path) and path in honeytoken_filenames):
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, FILE_NOT_FOUND, self.user,
                            "RETR")
            return FILE_NOT_FOUND, path

        self.setTimeout(None)

        def enableTimeout(result):
            self.setTimeout(self.factory.timeOut)
            return result

        if not self.binary:
            cons = ASCIIConsumerWrapper(self.dtpInstance)
        else:
            cons = self.dtpInstance

        def cbSent(result):
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, TXFR_COMPLETE_OK, self.user,
                            "RETR")
            return (TXFR_COMPLETE_OK,)

        def ebSent(err):
            log.msg("Unexpected error attempting to transmit file to client:")
            log.err(err)
            if err.check(FTPCmdError):
                return err
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, CNX_CLOSED_TXFR_ABORTED, self.user, "RETR")
            return (CNX_CLOSED_TXFR_ABORTED,)

        def cbOpened(file):
            if self.dtpInstance.isConnected:
                self.reply(DATA_CNX_ALREADY_OPEN_START_XFR)
            else:
                self.reply(FILE_STATUS_OK_OPEN_DATA_CNX)

            d = file.send(cons)
            d.addCallbacks(cbSent, ebSent)
            return d

        def ebOpened(err):
            if not err.check(PermissionDeniedError, FileNotFoundError, IsADirectoryError):
                log.msg("Unexpected error attempting to open file for transmission:")
                log.err(err)
            if err.check(FTPCmdError):
                return (err.value.errorCode, path)
            self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port, FILE_NOT_FOUND, self.user, "RETR")
            return FILE_NOT_FOUND, path

        fObj = open(self.honeytokenDirectory + '/' + path, 'rb')
        d = defer.succeed(FR(fObj))
        d.addCallbacks(cbOpened, ebOpened)
        d.addBoth(enableTimeout)

        return d

    def ftp_PASS(self, password):
        """
        Second part of login.  Get the password the peer wants to
        authenticate with.
        """
        if self.factory.allowAnonymous and self._user == self.factory.userAnonymous:
            # anonymous login
            creds = credentials.Anonymous()
            reply = GUEST_LOGGED_IN_PROCEED
        else:
            # user login
            creds = credentials.UsernamePassword(self._user, password)
            reply = USR_LOGGED_IN_PROCEED
            self.user = self._user
        del self._user

        def _cbLogin(result):
            (interface, avatar, logout) = result
            assert interface is IFTPShell, "The realm is busted, jerk."
            self.shell = avatar
            self.logout = logout
            self.workingDirectory = []
            self.state = self.AUTHED
            self.l.login(FTPService._name, self.transport.getPeer().host, FTPService._port, True, self.user, password, str(FTPService.credchecker.try_get_tokens(self.user, password)))
            return reply

        def _ebLogin(failure):
            failure.trap(cred_error.UnauthorizedLogin, cred_error.UnhandledCredentials)
            self.state = self.UNAUTH
            self.l.login(FTPService._name, self.transport.getPeer().host, FTPService._port, False, self.user, password, str(FTPService.credchecker.try_get_tokens(self.user, password)))
            self.user = 'anonymous'
            raise AuthorizationError

        d = self.portal.login(creds, None, IFTPShell)
        d.addCallbacks(_cbLogin, _ebLogin)
        return d

    def ftp_USER(self, username):
        """
        First part of login.  Get the username the peer wants to
        authenticate as.
        """
        if not username:
            return defer.fail(CmdSyntaxError('USER requires an argument'))

        self._user = username
        self.state = self.INAUTH
        if self.factory.allowAnonymous and self._user == self.factory.userAnonymous:
            return GUEST_NAME_OK_NEED_EMAIL
        else:
            return USR_NAME_OK_NEED_PASS, username

    def processCommand(self, cmd, *params):
        """
        Processes an FTP-Command.

        @param cmd: Received FTP-Command
        @param params: Received Parameters for FTP-Command
        """
        def call_ftp_command(command):
            if command in self.overwritten_commands_whitelist:
                method = getattr(self, "ftp_" + command, None)
                return method(*params)
            if command in self.inherited_commands_whitelist:
                self.l.request(FTPService._name, self.transport.getPeer().host, FTPService._port, command, self.user, command)
                self.l.response(FTPService._name, self.transport.getPeer().host, FTPService._port,
                                self.inherited_responses.get(command), self.user, command)
                method = getattr(self, "ftp_" + command, None)
                return method(*params)
            return defer.fail(CmdNotImplementedError(command))

        cmd = cmd.upper()

        if self.state == self.UNAUTH:
            if cmd == 'USER':
                return self.ftp_USER(*params)
            elif cmd == 'PASS':
                return BAD_CMD_SEQ, "USER required before PASS"
            else:
                return NOT_LOGGED_IN

        elif self.state == self.INAUTH:
            if cmd == 'PASS':
                return self.ftp_PASS(*params)
            else:
                return BAD_CMD_SEQ, "PASS required after USER"

        elif self.state == self.AUTHED:
            return call_ftp_command(cmd)

        elif self.state == self.RENAMING:
            if cmd == 'RNTO':
                return self.ftp_RNTO(*params)
            else:
                return BAD_CMD_SEQ, "RNTO required after RNFR"


if __name__ == '__main__':
    service = FTPService()
    service.startService()
