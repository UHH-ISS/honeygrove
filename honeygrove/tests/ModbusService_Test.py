targetIP = '195.37.209.23'
targetIP= '192.168.0.9'

from pymodbus.client.sync import ModbusTcpClient

client = ModbusTcpClient('192.168.0.9', 502)
result = client.read_coils(1,10,unit=1)
print(result.bits[0])
result = client.read_coils(1,10,unit=2)
print(result)
result = client.read_coils(1,10,unit=3)
print(result.bits[0])
# client.write_coil(1,False)
# result = client.read_coils(1,10)
# print(result.bits[0])
# client.write_coil(1,True)
# result = client.read_coils(1,10)
# print(result.bits[0])
# client.write_coil(1,False)
# print(result.bits[0])
client.close()

import easymodbus.modbusClient
# http://easymodbustcp.net/en/python-codesamples
from easymodbus.modbusClient import ModbusClient

# Read 8 Inputs Registers from Modbus-TCP Server – Server available at Port 502 (IP-Address 190.172.268.100) –
# Starting Address “1”, Number of Registers to Read: “8” (Notice that the Starting address might be shifted by “1”.
# In this example we are reading 8 Registers, the first is Register “1” (Addressed with “0”)

modbusclient = ModbusClient(targetIP, 502)
modbusclient.connect()
discreteInputs = modbusclient.read_discreteinputs(0, 8)
print(discreteInputs)
modbusclient.close()

# Read 8 Inputs Registers from Modbus-TCP Server – Server available at Port 502 (IP-Address 190.172.268.100) –
# Starting Address “1”, Number of Registers to Read: “8” (Notice that the Starting address might be shifted by “1”.
# In this example we are reading 8 Registers, the first is Register “1” (Addressed with “0”)

modbusclient = ModbusClient(targetIP, 502)
modbusclient.connect()
inputRegisters = modbusclient.read_inputregisters(0, 8)
print(inputRegisters)
modbusclient.close()

# Write a single coil to the Server – Coil number “1”

modbusclient = easymodbus.modbusClient.ModbusClient(targetIP, 502)
modbusclient.connect()
modbusclient.write_single_coil(0,True)
modbusclient.read_coils(0,1)
modbusclient.close()

# Write a float value to a Modbus TCP Server (Two Registers are required, since one Modbus Register has 16 Bit)

# modbusclient = easymodbus.modbusClient.ModbusClient(targetIP, 502)
# modbusclient.connect()
# modbusclient.write_multiple_registers(0, easymodbus.modbusClient.convert_float_to_two_registers(3.141517))
# modbusclient.close()

# Read a Float Value from Modbus TCP Server (Two Registers are required, since one Modbus Register has 16 Bit

modbusclient = easymodbus.modbusClient.ModbusClient(targetIP, 502)
modbusclient.connect()
holdingRegisters = easymodbus.modbusClient.convert_registers_to_float(modbusclient.read_holdingregisters(0,2))
print(holdingRegisters)
modbusclient.close()

from pymodbus.mei_message import *
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
modbusclient = ModbusClient(targetIP, 502)
modbusclient.connect()
rq = ReadDeviceInformationRequest(unit=1)
rr = modbusclient.execute(rq)
print(rr.function_code < 0x80)                 # test that we are not an error
print(rr.information[0])  # test the vendor name
print(rr.information[1])          # test the product code
print(rr.information[2])     # test the code revisiono

modbusclient = ModbusClient(targetIP, 502)
modbusclient.connect()
rq = ReadDeviceInformationRequest(unit=4)
rr = modbusclient.execute(rq)



