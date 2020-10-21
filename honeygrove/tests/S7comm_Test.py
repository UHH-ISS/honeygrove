import unittest
import snap7

from honeygrove.config import Config
from honeygrove.core.ServiceController import ServiceController

controller = ServiceController()

class S7comm_Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        controller.startService(Config.s7comm.name)

    @classmethod
    def tearDownClass(cls):
        controller.stopService(Config.s7comm.name)

    def testStopPlc(self):
        client = snap7.client.Client()
        # client.connect does not except 'localhost'
        client.connect('0.0.0.0', 0, 1, 102)
        info = client.plc_stop()
        self.assertIsNotNone(info)
        client.disconnect()

    def testGetDeviceInformationSerialNumber(self):
        plc = snap7.client.Client()
        # client.connect does not except 'localhost'
        plc.connect('0.0.0.0', 0, 1, 102)
        info = plc.get_cpu_info().SerialNumber
        # Serial Number of the snap7 server can be found in the snap7 code
        self.assertEqual(info, b'S C-C2UR28922012')
        plc.disconnect()
