from honeygrove import log
from honeygrove.config import Config
from honeygrove.core.Credential import Credential
from honeygrove.core.FilesystemParser import FilesystemParser
from honeygrove.core.HoneytokenDatabase import HoneytokenDatabase
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from twisted.conch import avatar, error, insults, interfaces, recvline
from twisted.conch.ssh import factory, keys, session, userauth, common, transport
from twisted.cred.portal import Portal
from twisted.internet import defer
from twisted.python import components

from datetime import datetime, timedelta
import json
import os
from os.path import expanduser, exists, dirname
from random import randint
import re
import subprocess
import time
from urllib import request

transport.SSHTransportBase.ourVersionString = Config.ssh.banner

lastLoginTime = dict()


def load_database():
    global lastLoginTime
    try:
        with open(str(Config.ssh.database_path), 'r') as fp:
            lastLoginTime = json.loads(fp.read())
    except FileNotFoundError:
        pass
    except Exception:
        # e.g. damaged json encoding
        log.err("Failed to load lastLoginTime from existing file \""+str(Config.ssh.database_path)+"\"")


def save_database():
    try:
        with open(str(Config.ssh.database_path), 'w') as fp:
            fp.write(json.dumps(lastLoginTime))
    except Exception:
        # e.g. insufficient write permissions, io error etc.
        log.err("Failed to write lastLoginTime to file \""+str(Config.ssh.database_path)+"\"")


class SSHService(ServiceBaseModel):
    honeytokendb = HoneytokenDatabase(servicename=Config.ssh.name)

    def __init__(self):
        super(SSHService, self).__init__()

        self._name = Config.ssh.name
        self._port = Config.ssh.port

        # Create a custom portal with the honeytoken database as credential backend
        p = Portal(SSHRealm())
        p.registerChecker(self.honeytokendb)

        self._fService = factory.SSHFactory()
        self._fService.services[b'ssh-userauth'] = groveUserAuth

        self._limiter = Limiter(self._fService, Config.ssh.name, Config.ssh.connections_per_host)

        self._fService.portal = p

        # self.protocol = SSHProtocol
        # self._fService.protocol = self.protocol
        home = expanduser('~')

        # XXX: These paths should be configurable
        privateKeyPath = home + '/.ssh/id_honeygrove'
        publicKeyPath = home + '/.ssh/id_honeygrove.pub'

        # Generate RSA keys if they don't exist
        if not (exists(privateKeyPath) and exists(publicKeyPath)):
            key = keys.rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            private_key = key.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.TraditionalOpenSSL,
                                            serialization.NoEncryption())
            public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                       serialization.PublicFormat.OpenSSH)

            # make .ssh directory, if it doesn't exist
            os.makedirs(dirname(publicKeyPath), exist_ok=True)

            with open(privateKeyPath, 'w') as f:
                f.write(private_key.decode())
            with open(publicKeyPath, 'w') as f:
                f.write(public_key.decode())

        self._fService.privateKeys = {b'ssh-rsa': keys.Key.fromFile(privateKeyPath)}
        self._fService.publicKeys = {b'ssh-rsa': keys.Key.fromFile(publicKeyPath)}


class SSHProtocol(recvline.HistoricRecvLine):

    def connectionMade(self):
        """
        Initializes the session
        """
        super(SSHProtocol, self).connectionMade()

        # Service related
        self.service_name = Config.ssh.name
        self.local_ip = Config.general.address
        self.local_port = Config.ssh.port
        self.log = log

        # Connection related
        self.user = self.terminal.transport.session.avatar
        self.remote = self.user.conn.transport.transport.client

        self._parser = FilesystemParser(Config.folder.filesystem)
        self.current_dir = expanduser("~")

        load = self.loadLoginTime(self.user.username)
        if not load:
            # Random, plausible last login time
            tdelta = timedelta(days=randint(1, 365), seconds=randint(0, 60), minutes=randint(0, 60), hours=randint(0, 24))
            now = datetime.now()
            login = now - tdelta
            loginStr = str(login.ctime())
        else:
            loginStr = load

        self.saveLoginTime(self.user.username)
        self.terminal.write("Last login: " + loginStr)
        self.terminal.nextLine()

        self.showPrompt()

    def saveLoginTime(self, username):
        global lastLoginTime
        # limits number of saved "user profiles" to keep an attacker from filling the memory
        if len(lastLoginTime) <= 10000:
            if Config.general.use_utc:
                lastLoginTime[username] = str(datetime.utcnow().ctime())
            else:
                lastLoginTime[username] = str(datetime.now().ctime())

    def loadLoginTime(self, username):
        if username in lastLoginTime:
            return lastLoginTime[username]
        else:
            return False

    def print(self, lines, log=None):
        """
        Prints a  response to the client's terminal
        :param lines: a line or list of lines to be printed
        :param log: string that will appear in the log file
        """
        if not isinstance(lines, list):  # if only a single line should be printed
            lines = [lines]
        for line in lines:
            self.terminal.write(line)
            self.terminal.nextLine()
        if not log:
            log = lines
        self.log.response(self.service_name, self.remote[0], self.remote[1],
                          self.local_ip, self.local_port, log, self.user.username)

    def showPrompt(self):
        """
        Show prompt at start of line.
        """
        self.terminal.write(self.user.username + "@" + Config.general.hostname + ":" + self._parser.get_formatted_path() + "$ ")

    def getCommandFunc(self, cmd):
        """
        Get the corresponding function to a command.
        :param cmd: the command to search for
        :return: the corresponding "ssh_" function
        """
        return getattr(self, 'ssh_' + cmd, None)

    def get_help(self, cmd):
        """
        Get the helptext for a command
        :param cmd:
        :return: the corresponding text
        """
        helptext = ""
        append = False
        with open(str(Config.ssh.helptext_folder)) as helps:
            for line in helps:
                if append and re.match("^\S", line):
                    return helptext
                if re.match("^" + cmd, line):
                    append = True
                if append:
                    helptext = helptext + line
        return helptext

    def handle_arguments(self, args):
        """
        Split arguments in path and list of arguments
        :param args: arguments
        :return: path, arguments
        """
        path = ""
        arguments = []

        for arg in args:
            if not arg.startswith("-"):
                path = arg
            else:
                for char in arg:
                    if char != "-":
                        arguments.append(char)
        return path, arguments

    def lineReceived(self, line):
        """
        What to do, when we receive input. Also handles real command execution.
        :param line: the line received
        """
        line = line.strip()
        if line:
            line = line.decode()

            # log call, we received a request
            self.log.request(self.service_name, self.remote[0], self.remote[1],
                             self.local_ip, self.local_port, line, self.user.username)

            res = None

            if Config.ssh.real_shell:
                # Forwarding commands to the real shell

                if "cd" in line:
                    try:
                        self.current_dir = subprocess.check_output(line + " && pwd",
                                                                   stderr=subprocess.STDOUT,
                                                                   shell=True,
                                                                   cwd=self.current_dir).decode().strip()
                    except subprocess.CalledProcessError as e:
                        res = e.output
                        res = res.decode()
                        res = res.split("\n")[:-1]
                if "exit" in line:
                    self.ssh_exit()
                else:
                    try:
                        res = subprocess.check_output(line, stderr=subprocess.STDOUT, shell=True, cwd=self.current_dir)
                    except subprocess.CalledProcessError as e:
                        res = e.output
                    res = res.decode()
                    res = res.split("\n")[:-1]

            else:
                # faking an ssh session

                cmdAndArgs = line.split()
                cmd = cmdAndArgs[0]
                args = cmdAndArgs[1:]
                func = self.getCommandFunc(cmd)
                if func:
                    try:
                        res = func(*args)
                    except Exception as e:
                        self.log.err(str(e))
                else:
                    res = cmd + ": command not found"

            if res:
                if not isinstance(res, tuple):  # If only response and no log text
                    res = (res, "")
                self.print(*res)
        self.showPrompt()

    def ssh_help(self, cmd=''):
        """
        Prints the GNU bash help for cmd or the universal help text if cmd is not given
        :param cmd: the command
        """

        if cmd:
            func = self.getCommandFunc(cmd)
            if func:
                text = self.get_help(cmd)
            if not func or not text:
                text = "help: no help topics match `{}'.  " \
                       "Try `help help' or `man -k {}' or `info {}'.".format(cmd, cmd, cmd)
            return text

        gnuhelp = []

        with open(str(Config.ssh.gnuhelp_folder)) as file:
            for line in file:
                gnuhelp.append(line)

        return gnuhelp, "Help text"

    def ssh_pwd(self):
        """
        Prints the path to the current directory in fake filesystem
        """
        return self._parser.get_current_path()

    def ssh_echo(self, *args):
        """
        Prints whatever is in args
        """
        return " ".join(args)

    def ssh_whoami(self):
        """
        prints the username
        """
        return self.user.username

    def ssh_exit(self):
        """
        close the connection
        """
        self.terminal.nextLine()
        self.terminal.loseConnection()

    def ssh_clear(self):
        """clear the terminal"""
        self.terminal.reset()

    def ssh_cd(self, *args):
        """
        Change directory in fake filesystem
        :param args: arguments and path
        """
        res = None
        if args:
            res = self._parser.cd(args[-1])
        return res

    def ssh_ls(self, *args):
        """
        Lists the content of the given directory in faked filesystem
        or of the current one if no path is given in args
        :param args: arguments and path
        """
        path, arguments = self.handle_arguments(args)

        try:
            lines = self._parser.ls(path).split("\n")[:-1]  # Split puts an empty string after the last "/n"
        except Exception:
            return "ls: " + path + ": No such file or directory."

        for line in lines:
            if line and line[0] == "." and "a" not in arguments:
                lines.remove(line)
        lines = lines

        return lines, "ls Text"

    def ssh_mkdir(self, *args):
        """
        Creates a directory in the fake filesystem
        :param args: path to be created
        :return:
        """
        return self._parser.mkdir(args[-1])

    def ssh_touch(self, *args):
        """
        Creates a file in the fake filesystem
        :param args: path to the new file
        """
        return self._parser.touch(args[-1])

    def ssh_rm(self, *args):
        """
        removes whatever is at the specified path
        :param args: arguments and path
        :return:
        """
        path, arguments = self.handle_arguments(args)

        if "r" in arguments and "f" in arguments and path == "/":
            time.sleep(4)
            self.ssh_exit()  # r e a l i s m
            return
        if self._parser.valid_directory(path) and "r" not in arguments:
            return "rm: " + args[-1] + ": is a directory"

        return self._parser.delete(path)

    def ssh_mv(self, *args):
        """
        Moves an element in the fake filesystem
        :param args: arguments, original path, new path
        """
        res = self._parser.move(args[-2], args[-1])
        if res:
            return "mv: " + res

    def ssh_cat(self, *args):
        """
        Display the content of a file
        :param args: filepath
        """
        try:
            response = self._parser.cat(args[-1])
        except Exception as e:
            if str(e) == "File not found":
                response = "cat: " + args[-1] + ": File or directory not found"
            if str(e) == "Is a directory":
                response = "cat: " + args[-1] + ": Is a directory"

        return response

    def ssh_wget(self, *args):
        """
        Downloads a file from the internet
        :param args: url
        """

        # Handle URL
        url = args[-1]
        filename = url.split('/')[-1].split('#')[0].split('?')[0]
        if not re.match(r"^https?://", url):
            url = "http://" + url
        if not re.match(r"^https?://.*\..*/", url):  # wenn die URL nichts hinter dem "/" nach der TLD hat
            filename = "index.html"

        # Determine filename
        i = 1
        while filename in os.listdir(Config.folder.quarantine):
            filename = filename + "." + str(i)
            i += 1

        # Write to disk
        filepath = ""
        if Config.ssh.accept_files:
            request.urlretrieve(url, Config.folder.quarantine / filename)
            filepath = Config.folder.quarantine / filename
        self.log.file(self.name, self.userIP, filename, filepath, self.user.username)

    def ssh_ll(self, *args):
        """
        Alias for ls -l
        :param args: arguments
        """
        return self.ssh_ls(*args + ("-l",))


class SSHSession(session.SSHSession):
    local_ip = Config.general.address
    local_port = Config.ssh.port

    def openShell(self, transport):
        """
        wire the protocol to the transport channel
        :param transport:
        """
        serverProtocol = insults.insults.ServerProtocol(
            SSHProtocol)  # neues ServerProtocol mit SSHProtocol als Terminal
        serverProtocol.makeConnection(transport)
        transport.makeConnection(session.wrapProtocol(serverProtocol))

        remote = transport.session.avatar.conn.transport.transport.client
        log.request("SSH", remote[0], remote[1], self.local_ip, self.local_port,
                    "<open shell>", transport.session.avatar.username)

    def getPty(self, terminal, windowSize, attrs):
        """
        Ignore Pty requests
        :param terminal:
        :param windowSize:
        :param attrs:
        :return:
        """
        pass

    def execCommand(self, pp, cmd):
        """
        Gets called when the client requests command execution (eg. with a pipe)
        We don't support command execution but we still want to log the command (e.g. for forensics)
        :param pp: the transport protocol
        :param cmd: the command the client wants executed
        """

        remote = pp.session.conn.transport.transport.client
        log.request("SSH", remote[0], remote[1], self.local_ip, self.local_port,
                    "<exec '{}'>".format(cmd.decode()), pp.session.avatar.username)
        pp.session.conn.transport.sendDisconnect(7, b"Command Execution is not supported.")

    def windowChanged(self, *args):
        """
        This method would be used to determine the window size of the client terminal.
        """
        pass


class SSHRealm(SSHSession):
    def requestAvatar(avatarId, mind, *interfaces):
        """
        Return the Avatar Object
        :param avatarId: specifies the service (e.g. session, userauth)
        :param mind: username
        :param interfaces:
        :return:
        """
        return interfaces[0], SSHAvatar(username=mind, service=avatarId), lambda: None


class SSHAvatar(avatar.ConchUser):
    def __init__(self, username, service):
        super(SSHAvatar, self).__init__()
        self.username = username
        self.channelLookup.update({b'session': session.SSHSession})

    def lookupChannel(self, channelType, windowSize, maxPacket, data):
        klass = self.channelLookup.get(channelType, None)
        if not klass:
            log.err("Channel {} requested but not found!".format(channelType.decode()))
        else:
            return klass(remoteWindow=windowSize,
                         remoteMaxPacket=maxPacket,
                         data=data, avatar=self)


class groveUserAuth(userauth.SSHUserAuthServer):

    def _decode(self, value, title):
        try:
            return value.decode()
        except UnicodeError:
            # value is invalid utf-8
            log.info('{} was invalid UTF-8: "{}"'.format(title, value))
            return value.decode('replace')

    def auth_password(self, ip, username, password):
        c = Credential(ip, username, password)
        return self.portal.login(c, None, interfaces.IConchUser).addErrback(self._ebPassword)

    def tryAuth(self, auth_type, ip, username, secret):
        auth_type = self._decode(auth_type, "Auth type")
        auth_type = auth_type.replace('-', '_')
        f = getattr(self, 'auth_%s' % (auth_type,), None)
        if f:
            ret = f(ip, username, secret)
            if not ret:
                return defer.fail(
                        error.ConchError('%s return None instead of a Deferred' % (auth_type, )))
            else:
                return ret
        return defer.fail(error.ConchError('bad auth type: %s' % (auth_type,)))

    def ssh_USERAUTH_REQUEST(self, packet):
        """
        Base taken from twisted and modified to track login attempts
        """

        # Parse login packet
        user, next_service, auth_type, secret = common.getNS(packet, 3)

        # Decode username and secret
        user = self._decode(user, "User")
        secret = self._decode(secret[5:], "Secret")

        # Store remote information for later
        remote_ip, remote_port = self.transport.transport.client

        # Check we are in the correct session? FIXME: figure out why eaxctly we need this
        if user != self.user or next_service != self.nextService:
            self.authenticatedWith = []  # clear auth state

        # Store some state for twisted internals
        self.user = user
        self.nextService = next_service
        self.method = auth_type

        # Start point for deferred
        d = self.tryAuth(auth_type, remote_ip, user, secret)

        # Currently we only care about password authentication (and only log the rest)
        if auth_type != b'password':
            if auth_type == b'publickey':
                # Extract key from `secret`
                # TODO: decode key and log it
                algorithm, secret, blobrest = common.getNS(secret[1:], 2)

            d.addCallback(self._cbFinishedAuth)
            d.addErrback(log.defer_login, Config.ssh.name, Config.ssh.port, remote_ip, remote_port,
                         auth_type, False, user, secret)
            d.addErrback(self._ebMaybeBadAuth)
            d.addErrback(self._ebBadAuth)
            return d

        # Do we know a honeytoken for this credential pair?
        honeytoken = SSHService.honeytokendb.try_get_token(user, secret)

        # Callbacks and Errbacks
        #
        # If the login suceeds (via HoneytokenDatabase) then we expect to find a honeytoken above
        # and we pass it to the Callback. If the login does not succeed, than we should not find a
        # honeytoken and thus we do not pass `None` to the Errback.
        d.addCallback(self._cbFinishedAuth)
        d.addCallback(log.defer_login, Config.ssh.name, Config.ssh.port, remote_ip, remote_port,
                      auth_type, True, user, secret, honeytoken)
        d.addErrback(log.defer_login, Config.ssh.name, Config.ssh.port, remote_ip, remote_port,
                     auth_type, False, user, secret)
        d.addErrback(self._ebMaybeBadAuth)
        d.addErrback(self._ebBadAuth)

        return d


# SSHAvatar created by SSHSession implement ISession
components.registerAdapter(SSHSession, SSHAvatar, session.ISession)

if __name__ == '__main__':
    service = SSHService()
    service.startService()
