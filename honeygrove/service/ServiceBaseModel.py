# coding=utf-8
# "Prototype" for all Services.
from abc import ABC, abstractmethod

from twisted.internet.protocol import Factory


class ServiceBaseModel(ABC):
    def __init__(self):
        """
        Initializeses some needed service parts.
        Only add variables here if they are needet in all services.
        """
        self._fService = Factory()
        self._fService.clients = dict([])

        # Only these variables should be changeable

        self._name = None
        self._port = None
        self._stop = True
        self._status = None
        self._transport = None

    @abstractmethod
    def startService(self):
        """
        Starts the specific service
        """
        pass

    @abstractmethod
    def stopService(self):
        """
        Stops the specific service
        :return:
        """
        pass

    def changePort(self, port):
        """
        changes the port. If it is not possible the service will be terminatet.
        Eg. port is already in use.
        :param port: int
        """
        self.stopService()
        self._port = port
        self.startService()
