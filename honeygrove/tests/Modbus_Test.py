import unittest

from pymodbus.client.sync import ModbusTcpClient

from honeygrove.config import Config
from honeygrove.core.ServiceController import ServiceController

controller = ServiceController()

class Modbus_Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        controller.startService(Config.modbus.name)

    @classmethod
    def tearDownClass(cls):
        controller.stopService(Config.modbus.name)

    def testReadCoils(self):
        client = ModbusTcpClient("localhost", 502)
        result = client.read_coils(1, 10, unit=1)
        self.assertIsNotNone(result)
        client.close()

    def testWriteCoilTrue(self):
        client = ModbusTcpClient("localhost", 502)
        client.write_coil(1, 0, unit=1)
        # Coil that is not 0 is True
        client.write_coil(1, 1, unit=1)
        result = client.read_coils(1, 1, unit=1)
        self.assertIs(result.bits[0], True)
        client.close()

    def testWriteCoilFalse(self):
        client = ModbusTcpClient("localhost", 502)
        client.write_coil(1, 1, unit=1)
        # Coil that is not 0 is True
        client.write_coil(1, 0, unit=1)
        result = client.read_coils(1, 1, unit=1)
        self.assertIs(result.bits[0], False)
        client.close()

    def testReadDiscreteInputs(self):
        client = ModbusTcpClient("localhost", 502)
        result = client.read_discrete_inputs(1, 10, unit=1)
        self.assertIsNotNone(result)
        client.close()

    def testReadInputRegisters(self):
        client = ModbusTcpClient("localhost", 502)
        result = client.read_input_registers(1, 10, unit=1)
        self.assertIsNotNone(result)
        client.close()

