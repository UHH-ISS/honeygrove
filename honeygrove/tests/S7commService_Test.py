import snap7

client = snap7.client.Client()
client.connect('192.168.0.9', 0, 1, 102)
info = client.plc_stop()
print(info)
client.disconnect()

from snap7.util import *
plc = snap7.client.Client()
plc.set_connection_type(0xFD)
plc.connect('192.168.0.9', 0, 1, 102)
print(plc.get_cpu_state())
print(plc.get_cpu_info().ModuleTypeName)
print(plc.get_cpu_info().SerialNumber)
print(plc.get_cpu_info().ASName)
print(plc.get_cpu_info().Copyright)
print(plc.get_cpu_info().ModuleName)
area1 = 0x83  # srvAreaMK
area2 = 0x82  # srvAreaPA
area3 = 0x81  # srvAreaPE
start = 0
length = 4
float1 = plc.read_area(area1, 0, start, length)
float2 = plc.read_area(area2, 0, start, length)
float3 = plc.read_area(area3, 0, start, length)
print("Area=MK, [0,4]={}".format(get_real(float1, 0)))
print("Area=PA, [0,4]={}".format(get_real(float2, 0)))
print("Area=PE, [0,4]={}".format(get_real(float3, 0)))

plc2 = snap7.client.Client()
plc2.connect('192.168.0.9', 0, 1, 102)

plc3 = snap7.client.Client()
plc3.connect('192.168.0.9', 0, 1, 102)

plc.disconnect()
plc3.disconnect()

client2 = snap7.client.Client()
client2.connect('192.168.0.9', 0, 3, 102)
info = client2.db_get(1)
print(info)
client2.disconnect()


