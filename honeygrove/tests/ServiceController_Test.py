import unittest
import twisted.internet.reactor
from honeygrove.core.ServiceController import ServiceController


class serviceControllerTest(unittest.TestCase):
    isTest = None
    def setUp(self):
        serviceControllerTest.isTest = True
        self.TestServiceController = ServiceController()

    def tearDown(self):
        twisted.internet.reactor.callFromThread(twisted.internet.reactor.stop)


    def testInit(self):
        """
        Test if the initialisierung is correct
        """
        self.assertTrue(self.TestServiceController.serviceList)
        self.assertTrue(self.TestServiceController.serviceDict)
        self.assertTrue(not self.TestServiceController.runningServicesDict)


    def testStartServiceByName(self):
        """
        Test if we are able to start a Service by name.
        :return:
        """
        self.assertTrue(self.TestServiceController.serviceDict["serviceControllerTestService"])
        self.assertTrue(self.TestServiceController.serviceDict["serviceControllerTestService"]._stop)

        self.TestServiceController.startService("serviceControllerTestService")

        self.assertTrue(not self.TestServiceController.serviceDict["serviceControllerTestService"]._stop)


    def testStopServiceByName(self):
        """
        Test if we can stop a Service by name
        """
        self.TestServiceController.startService("serviceControllerTestService")
        self.TestServiceController.stopService("serviceControllerTestService")
        self.assertTrue(self.TestServiceController.serviceDict["serviceControllerTestService"]._stop)

    def testStartSecondTime(self):
        """
        Test that multible starting of a service is not possible
        """
        self.TestServiceController.startService("serviceControllerTestService")
        self.assertFalse(self.TestServiceController.startService("serviceControllerTestService"))
        self.TestServiceController.stopService("serviceControllerTestService")


    def testStopSecondTime(self):
        """
        Test that multiple stopping of a service is not possible
        """
        self.TestServiceController.startService("serviceControllerTestService")
        self.TestServiceController.stopService("serviceControllerTestService")
        self.assertFalse(self.TestServiceController.stopService("serviceControllerTestService"))






