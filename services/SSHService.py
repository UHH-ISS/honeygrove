# SSH-Service
import os
import re
import subprocess
import time
from datetime import datetime, timedelta
from os.path import expanduser, exists, dirname
from random import randint as ri
from urllib import request

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from twisted.conch import recvline, avatar, insults, error
from twisted.conch.ssh import factory, keys, session, userauth, common, transport
from honeygrove import config
transport.SSHTransportBase.ourVersionString = config.sshBanner

from twisted.cred.portal import Portal
from twisted.internet import reactor
from twisted.python import components, failure

from honeygrove.resources.ssh_resources import database

from honeygrove import config
from honeygrove.core.FilesystemParser import FilesystemParser
from honeygrove.core.HoneytokenDB import HoneytokenDataBase
from honeygrove.logging import log
from honeygrove.services.ServiceBaseModel import ServiceBaseModel
from honeygrove.services.ServiceBaseModel import Limiter

class SSHService(ServiceBaseModel):
    c = HoneytokenDataBase(servicename=config.sshName)


    def __init__(self):
        super(SSHService, self).__init__()

        self._name = config.sshName
        self._port = config.sshPort

        p = Portal(SSHRealm())
        p.registerChecker(SSHService.c)

        self._fService = factory.SSHFactory()
        self._fService.services[b'ssh-userauth'] = groveUserAuth
        
        self._limiter = Limiter(self._fService, config.sshName, config.SSH_conn_per_host)        

        self._fService.portal = p

        # self.protocol = SSHProtocol
        # self._fService.protocol = self.protocol
        home = expanduser('~')

        privateKeyPath = home + '/.ssh/id_rsa'
        publicKeyPath = home + '/.ssh/id_rsa.pub'

        # Generate RSA keys if they don't exist

        if not (exists(privateKeyPath) and exists(publicKeyPath)):
            key = keys.rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
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

    def startService(self):
        self._stop = False
        self._transport = reactor.listenTCP(self._port, self._limiter)

    def stopService(self):
        self._stop = True
        self._transport.stopListening()


class SSHProtocol(recvline.HistoricRecvLine):

    def connectionMade(self):
        """
        Initializes the session
        """
        super(SSHProtocol, self).connectionMade()

        self.user = self.terminal.transport.session.avatar
        self.userName = self.user.username.decode()
        self.name = config.sshName
        self.port = config.sshPort
        self._parser = FilesystemParser(config.path_to_filesys)
        self.userIP = self.user.conn.transport.transport.client[0]
        self.l = log
        self.current_dir = expanduser("~")
        
        load = self.loadLoginTime(self.userName)
        if load == False:
            # Zufällige, plausible last login time
            tdelta = timedelta(days=ri(1, 365), seconds=ri(0, 60), minutes=ri(0, 60), hours=ri(0, 24))
            now = datetime.now()
            login = now - tdelta
            loginStr = str(login.ctime())
        else:
            loginStr = load

        self.saveLoginTime(self.userName)
        self.terminal.write("Last login: " + loginStr)
        self.terminal.nextLine()

        self.showPrompt()


    def saveLoginTime(self, username):
        # limits number of saved "user profiles" to keep an attacker from filling the memory 
        if len(database.lastLoginTime) <= 10000:
            if config.use_utc:
                database.lastLoginTime[username] = str(datetime.utcnow().ctime())
            else:
                database.lastLoginTime[username] = str(datetime.now().ctime())


    def loadLoginTime(self, username):
        if username in database.lastLoginTime:
            return database.lastLoginTime[username]
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
        self.l.response(self.name, self.userIP, self.port, log, self.userName)

    def showPrompt(self):
        """
        Show prompt at start of line.
        """
        self.terminal.write(self.userName + "@" + config.machine_name + ":" + self._parser.get_formatted_path() + "$ ")

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
        with open(config.resources_dir + "ssh_resources/helptexts") as helps:
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
            self.l.request(self.name, self.userIP, self.port, line, self.userName)

            res = None

            if config.ssh_real_shell:
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
                        self.l.err(str(e))
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

        with open(config.resources_dir + "ssh_resources/gnuhelp") as file:
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
        return self.userName

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
        except:
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
        if self._parser.valid_directory(path) and not "r" in arguments:
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
        while filename in os.listdir(config.quarantineDir):
            filename = filename + "." + str(i)
            i += 1

        # Write to disk
        filepath = ""
        if config.sshAcceptsFiles:
            request.urlretrieve(url, config.quarantineDir + "/" + filename)
            filepath = config.quarantineDir + "/" + filename
        self.l.file(self.name, self.userIP, filename, filepath, self.userName)

    def ssh_ll(self, *args):
        """
        Alias for ls -l
        :param args: arguments
        """
        return self.ssh_ls(*args + ("-l",))


class SSHSession(session.SSHSession):
    def openShell(self, transport):
        """
        wire the protocol to the transport channel
        :param transport:
        """
        serverProtocol = insults.insults.ServerProtocol(
            SSHProtocol)  # neues ServerProtocol mit SSHProtocol als Terminal
        serverProtocol.makeConnection(transport)
        transport.makeConnection(session.wrapProtocol(serverProtocol))

        ip = transport.session.avatar.conn.transport.transport.client[0]
        port = transport.session.avatar.conn.transport.transport.server._realPortNumber
        log.request("SSH", ip, port, "Request shell", transport.session.avatar.username.decode())

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
        ip = pp.session.avatar.conn.transport.transport.client[0]
        port = pp.session.avatar.conn.transport.transport.server._realPortNumber
        log.request("SSH", ip, port, "execCommand " + cmd.decode(), pp.session.avatar.username.decode())
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
    def ssh_USERAUTH_REQUEST(self, packet):
        """
        Literally taken from Twisted and modified to enable detection of login attempts
        """
        user, nextService, method, rest = common.getNS(packet, 3)
        if user != self.user or nextService != self.nextService:
            self.authenticatedWith = []  # clear auth state
        self.user = user
        self.nextService = nextService
        self.method = method

        is_key = False
        if method == b"publickey":
            is_key = True

        d = self.tryAuth(method, user, rest)
        if is_key:
            algName, rest, blobrest = common.getNS(rest[1:], 2)
        else:
            rest = rest[5:]

        if not d:
            self._ebBadAuth(
                failure.Failure(error.ConchError('auth returned none')))
            return

        honeytoken_actual = str(SSHService.c.getActual(user.decode(), rest, is_key))
        if is_key:
            rest = keys.Key.fromString(data=rest)._toString_OPENSSH(None)

        d.addCallback(self._cbFinishedAuth)
        d.addCallback(log.defer_login, config.sshName, self.transport.transport.client[0], config.sshPort, True,
                      user.decode(), rest.decode("unicode_escape"), honeytoken_actual)

        d.addErrback(log.defer_login, config.sshName, self.transport.transport.client[0], config.sshPort, False,
                     user.decode(), rest.decode("unicode_escape"), honeytoken_actual)
        d.addErrback(self._ebMaybeBadAuth)
        d.addErrback(self._ebBadAuth)

        return d


# SSHAvatar created by SSHSession implement ISession
components.registerAdapter(SSHSession, SSHAvatar, session.ISession)

if __name__ == '__main__':
    service = SSHService()
    service.startService()
