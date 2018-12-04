import threading

from twisted.internet import reactor

from honeygrove import config
from honeygrove.logging import log
from honeygrove.tests.testresources import serviceControllerTestPkg  # Actually used
from honeygrove.services import ServiceBaseModel


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

        self.listen = self.serviceDict[config.listenServiceName]
        self.runningServicesDict = dict([])



    def startService(self, name):
        """ 
        Starts the given service and adds it to threadDict
        :param name: Name of the service (str)
        """
        if (self.serviceDict[name]._port != None):
            log.info("Try StartService: " + name + " (port "+ str(self.serviceDict[name]._port) + ")")
        else:
            log.info("Try StartService: " + name)
        if name not in self.runningServicesDict:
            if name not in config.noPortSpecificService:
                self.listen.stopOnPort(self.serviceDict[name]._port)
            self.serviceDict[name].startService()
            self.runningServicesDict[name] = self.serviceDict[name]
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
            if name not in config.noPortSpecificService:
                self.listen.startOnPort(self.serviceDict[name]._port)
            return True
        else:
            return False
