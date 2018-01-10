import unittest
from honeygrove.core.ServiceController import ServiceController as SC
from honeygrove.services.ListenService import ListenService
from honeygrove import config
import twisted.internet.reactor
import time

class ListenServiceTest(unittest.TestCase):
    listen = None
    Controller = None

    @classmethod
    def setUpClass(cls):
        config.listenServicePorts = [9991,9992]

    def setUp(self):
        ListenServiceTest.listen = ListenService()
        ListenServiceTest.Controller = SC()
        ListenServiceTest.Controller.listen = ListenServiceTest.listen

    def tearDown(self):
        ListenServiceTest.listen.stopService()
        twisted.internet.reactor.callFromThread(twisted.internet.reactor.stop)


    def testInit(self):
        """
        Test if all Ports are initialisiert
        """
        self.assertEqual(ListenServiceTest.listen._port, [9991,9992])
        self.assertEqual(ListenServiceTest.listen._stop, True)
        self.assertEqual(ListenServiceTest.listen._transport, dict([]))

    def testStart(self):
        """
        Tests if the service is active after start
        """
        self.assertRaises(KeyError, lambda: ListenServiceTest.listen._transport[9991])
        self.assertRaises(KeyError, lambda: ListenServiceTest.listen._transport[9992])

        ListenServiceTest.listen.startService()

        self.assertNotEqual(ListenServiceTest.listen._transport[9991], None)
        self.assertNotEqual(ListenServiceTest.listen._transport[9992], None)

    def testStopOnPort(self):
        """
        Tests if an specific service can start on a port used by ListenService
        """
        ListenServiceTest.listen.startService()

        self.assertNotEqual(ListenServiceTest.listen._transport[9991], None)
        self.assertNotEqual(ListenServiceTest.listen._transport[9992], None)

        ListenServiceTest.Controller.startService("serviceControllerTestService")

        self.assertRaises(KeyError, lambda: ListenServiceTest.listen._transport[9991])

    def testStartOnPort(self):
        """
        Test if the service will start automaticly after a service stops on the port
        """
        ListenServiceTest.Controller.startService("serviceControllerTestService")
        ListenServiceTest.listen.startService()

        ListenServiceTest.listen.stopOnPort(9991)
        self.assertNotEqual(ListenServiceTest.listen._transport[9992], None)

        ListenServiceTest.Controller.stopService("serviceControllerTestService")
        self.assertNotEqual(ListenServiceTest.listen._transport[9991], None)


