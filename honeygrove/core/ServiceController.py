from honeygrove import log
from honeygrove.config import Config
from honeygrove.services import ServiceBaseModel
from honeygrove.tests.testresources import serviceControllerTestPkg  # Actually used

import threading

from twisted.internet import reactor


class ServiceController():
    def __init__(self):
        """
        Instantiates all subclasses of ServiceBaseModel and keeps track of them in a dict.
        """
        threading.Thread(target=reactor.run, args=(False,)).start()

        self.serviceList = []

        for service in ServiceBaseModel.ServiceBaseModel.__subclasses__():
            self.serviceList.append(service())

        self.serviceDict = dict([(service._name, service) for service in self.serviceList])

        self.listen = self.serviceDict[Config.listenServiceName]
        self.runningServicesDict = dict([])

    def startService(self, name):
        """
        Starts the given service and adds it to threadDict
        :param name: Name of the service (str)
        """
        service = self.serviceDict[name]
        address = service._address
        if service._port:
            address += ":{}".format(service._port)
        log.info("{}: Starting on {}".format(name, address))
        if name not in self.runningServicesDict:
            if name not in Config.noPortSpecificService:
                self.listen.stopOnPort(service._port)
            service.startService()
            self.runningServicesDict[name] = service
            return True
        else:
            return False

    def stopService(self, name):
        """
        Stops the given service and removes it from threadDict
        :param name: Name of the service (str)
        """
        log.info("Stop Service: " + name)
        if name in self.runningServicesDict:
            self.serviceDict[name].stopService()
            self.runningServicesDict.pop(name)
            if name not in Config.noPortSpecificService:
                self.listen.startOnPort(self.serviceDict[name]._port)
            return True
        else:
            return False
