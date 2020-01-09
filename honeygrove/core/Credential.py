from twisted.cred.credentials import IUsernamePassword
from zope.interface import implementer


@implementer(IUsernamePassword)
class Credential:

    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password

    def __str__(self):
        return "Credential({} - {}:{})".format(self.ip, self.username, self.password)

    def checkPassword(self, password):
        return self.password == password
