# coding=utf-8
# Wird nur! für den ControllerTest benötigt!

from honeygrove.services.ServiceBaseModel import ServiceBaseModel
from twisted.internet.protocol import Protocol


class ExampleService(ServiceBaseModel):
    def __init__(self):
        super(ExampleService, self).__init__()
        self._name = "serviceControllerTestService"
        self._port = 9991
        self._fService.protocol = self.protokoll

    # -----Protokoll----#
    class protokoll(Protocol):
        def __init__(self):
            self.state = None

    def startService(self):
        self._stop = False

    def stopService(self):
        self._stop = True
