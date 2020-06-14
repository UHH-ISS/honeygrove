"""
Implementation of a Threaded Modbus Server
------------------------------------------
"""

from binascii import b2a_hex

from pymodbus.compat import IS_PYTHON3
from pymodbus.constants import Defaults
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSparseDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.device import ModbusAccessControl
from pymodbus.device import ModbusControlBlock
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.exceptions import NoSuchSlaveException
from pymodbus.factory import ServerDecoder
from pymodbus.internal.ptwisted import InstallManagementConsole
from pymodbus.pdu import ModbusExceptions as merror
from pymodbus.transaction import *
from pymodbus.utilities import hexlify_packets
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.protocols.policies import ProtocolWrapper

from honeygrove import log
from honeygrove.config import Config
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel


class ModbusService(ServiceBaseModel):
    def __init__(self):
        super(ModbusService, self).__init__()

        self._name = Config.modbus.name
        self._port = Config.modbus.port

    def startService(self):
        try:
            self._stop = False
            self.run_server()

        except Exception as e:
            self._stop = True
            self.stopService()

    def run_server(self):

        # ----------------------------------------------------------------------- #
        # initialize your data store
        # ----------------------------------------------------------------------- #
        # The datastores only respond to the addresses that they are initialized to
        # Therefore, if you initialize a DataBlock to addresses of 0x00 to 0xFF, a
        # request to 0x100 will respond with an invalid address exception. This is
        # because many devices exhibit this kind of behavior (but not all)::
        #
        #     block = ModbusSequentialDataBlock(0x00, [0]*0xff)
        #
        # Continuing, you can choose to use a sequential or a sparse DataBlock in
        # your data context.  The difference is that the sequential has no gaps in
        # the data while the sparse can. Once again, there are devices that exhibit
        # both forms of behavior::
        #
        #     block = ModbusSparseDataBlock({0x00: 0, 0x05: 1})
        #     block = ModbusSequentialDataBlock(0x00, [0]*5)
        #
        # Alternately, you can use the factory methods to initialize the DataBlocks
        # or simply do not pass them to have them initialized to 0x00 on the full
        # address range::
        #
        #     store = ModbusSlaveContext(di = ModbusSequentialDataBlock.create())
        #     store = ModbusSlaveContext()
        #
        # Finally, you are allowed to use the same DataBlock reference for every
        # table or you may use a separate DataBlock for each table.
        # This depends if you would like functions to be able to access and modify
        # the same data or not::
        #
        #     block = ModbusSequentialDataBlock(0x00, [0]*0xff)
        #     store = ModbusSlaveContext(di=block, co=block, hr=block, ir=block)
        #
        # The server then makes use of a server context that allows the server to
        # respond with different slave contexts for different unit ids. By default
        # it will return the same context for every unit id supplied (broadcast
        # mode).
        # However, this can be overloaded by setting the single flag to False and
        # then supplying a dictionary of unit id to context mapping::
        #
        #     slaves  = {
        #         0x01: ModbusSlaveContext(...),
        #         0x02: ModbusSlaveContext(...),
        #         0x03: ModbusSlaveContext(...),
        #     }
        #     context = ModbusServerContext(slaves=slaves, single=False)
        #
        # The slave context can also be initialized in zero_mode which means that a
        # request to address(0-7) will map to the address (0-7). The default is
        # False which is based on section 4.4 of the specification, so address(0-7)
        # will map to (1-8)::
        #
        #     store = ModbusSlaveContext(..., zero_mode=True)
        # ----------------------------------------------------------------------- #

        slaves = {
            0x01: ModbusSlaveContext(
                di=ModbusSequentialDataBlock(0, [17] * 100),
                co=ModbusSequentialDataBlock(0, [17] * 100),
                hr=ModbusSequentialDataBlock(0, [17] * 100),
                ir=ModbusSequentialDataBlock(0, [17] * 100)),
            0x02: ModbusSlaveContext(
                di=ModbusSequentialDataBlock(0, [17] * 100),
                co=ModbusSparseDataBlock({0x00: 0, 0x05: 1}),
                hr=ModbusSequentialDataBlock(0, [17] * 100),
                ir=ModbusSequentialDataBlock.create()),
            0x03: ModbusSlaveContext(...)
        }

        context = ModbusServerContext(slaves=slaves, single=False)

        # ----------------------------------------------------------------------- #
        # initialize the server information
        # ----------------------------------------------------------------------- #
        # If you don't set this or any fields, they are defaulted to empty strings.
        # ----------------------------------------------------------------------- #
        identity = ModbusDeviceIdentification()
        identity.VendorName = Config.modbus.vendor_name
        identity.ProductCode = Config.modbus.product_code
        identity.VendorUrl = Config.modbus.vendor_url
        identity.ProductName = Config.modbus.product_name
        identity.ModelName = Config.modbus.model_name
        identity.MajorMinorRevision = Config.modbus.major_minor_revision

        # ----------------------------------------------------------------------- #
        # run the server
        # ----------------------------------------------------------------------- #
        StartTcpServer(context, identity=identity, address=(self._address, self._port))

    def stopService(self):
        self._stop = True


# --------------------------------------------------------------------------- #
# Modbus TCP Protocol
# --------------------------------------------------------------------------- #
class ModbusTcpProtocol(protocol.Protocol):
    """ Implements a modbus server in twisted """

    def connectionMade(self):
        """ Callback for when a client connects
        ..note:: since the protocol factory cannot be accessed from the
                 protocol __init__, the client connection made is essentially
                 our __init__ method.
        """
        log.connect("Modbus, Client Connected [%s]" % self.transport.getPeer())
        self.framer = self.factory.framer(decoder=self.factory.decoder,
                                          client=None)

    def connectionLost(self, reason):
        """ Callback for when a client disconnects
        :param reason: The client's reason for disconnecting
        """
        log.disconnect("Modbus, Client Disconnected: %s" % self.transport.getPeer())

    def dataReceived(self, data):
        """ Callback when we receive any data
        :param data: The data sent by the client
        """
        log.event('Modbus, Data Received (Raw): ' + str(data))
        log.event('Modbus, Data Received (Hex): ' + hexlify_packets(data))
        if not self.factory.control.ListenOnly:
            units = self.factory.store.slaves()
            single = self.factory.store.single
            self.framer.processIncomingPacket(data, self._execute,
                                              single=single,
                                              unit=units)

    def _execute(self, request):
        """ Executes the request and returns the result
        :param request: The decoded request message
        """
        log.event("Modbus, " + str(request) + " (unit-id: %s)" % request.unit_id)
        try:
            context = self.factory.store[request.unit_id]
            response = request.execute(context)
            log.event("Modbus, " + str(response))
        except NoSuchSlaveException as ex:
            log.event("Modbus, requested slave does not exist: %s" % request.unit_id)
            if self.factory.ignore_missing_slaves:
                return  # the client will simply timeout waiting for a response
            response = request.doException(merror.GatewayNoResponse)
            log.event("Modbus, " + str(response))
        except Exception as ex:
            log.event("Modbus, Datastore unable to fulfill request: %s" % ex)
            response = request.doException(merror.SlaveFailure)
            log.event("Modbus, " + response)

        response.transaction_id = request.transaction_id
        response.unit_id = request.unit_id
        self._send(response)

    def _send(self, message):
        """ Send a request (string) to the network
        :param message: The unencoded modbus response
        """
        if message.should_respond:
            self.factory.control.Counter.BusMessage += 1
            pdu = self.framer.buildPacket(message)
            log.event('Modbus, send: %s' % b2a_hex(pdu))
            return self.transport.write(pdu)


# --------------------------------------------------------------------------- #
# Modbus Server Factory
# --------------------------------------------------------------------------- #
class ModbusServerFactory(ServerFactory):
    """
    Builder class for a modbus server
    This also holds the server datastore so that it is
    persisted between connections
    """

    protocol = ModbusTcpProtocol
    connectionCount = 0
    connectionLimit = Config.modbus.connections_per_host
    overflowProtocol = None

    def __init__(self, store, framer=None, identity=None, **kwargs):
        """ Overloaded initializer for the modbus factory
        If the identify structure is not passed in, the ModbusControlBlock
        uses its own empty structure.
        :param store: The ModbusServerContext datastore
        :param framer: The framer strategy to use
        :param identity: An optional identify structure
        :param ignore_missing_slaves: True to not send errors on a request to a missing slave
        """
        self.decoder = ServerDecoder()
        self.framer = framer or ModbusSocketFramer
        self.store = store or ModbusServerContext()
        self.control = ModbusControlBlock()
        self.access = ModbusAccessControl()
        self.ignore_missing_slaves = kwargs.get('ignore_missing_slaves', Defaults.IgnoreMissingSlaves)

        if isinstance(identity, ModbusDeviceIdentification):
            self.control.Identity.update(identity)

    def buildProtocol(self, addr):
        if (self.connectionLimit is None or
                self.connectionCount < self.connectionLimit):
            # Build the normal protocol
            wrappedProtocol = self.protocol()
        elif self.overflowProtocol is None:
            # Just drop the connection
            log.limit_reached(Config.modbus.name, str(addr))
            return None
        else:
            # Too many connections, so build the overflow protocol
            wrappedProtocol = self.overflowProtocol()

        wrappedProtocol.factory = self
        protocol = ProtocolWrapper(self, wrappedProtocol)
        self.connectionCount += 1
        return protocol

    def registerProtocol(self, p):
        pass

    def unregisterProtocol(self, p):
        self.connectionCount -= 1


# --------------------------------------------------------------------------- #
# Starting Factory
# --------------------------------------------------------------------------- #
def _is_main_thread():
    import threading

    if IS_PYTHON3:
        if threading.current_thread() != threading.main_thread():
            # log.event("Modbus, Running in spawned thread")
            return False
    else:
        if not isinstance(threading.current_thread(), threading._MainThread):
            # log.event("Modbus, Running in spawned thread")
            return False
    # log.event("Modbus, Running in Main thread")
    return True


def StartTcpServer(context, identity=None, address=None,
                   console=False, defer_reactor_run=False, custom_functions=[],
                   **kwargs):
    """
    Helper method to start the Modbus Async TCP server
    :param context: The server data context
    :param identify: The server identity to use (default empty)
    :param address: An optional (interface, port) to bind to.
    :param console: A flag indicating if you want the debug console
    :param ignore_missing_slaves: True to not send errors on a request \
    to a missing slave
    :param defer_reactor_run: True/False defer running reactor.run() as part \
    of starting server, to be explictly started by the user
    :param custom_functions: An optional list of custom function classes
        supported by server instance.
    """
    address = address or ("", Defaults.Port)
    framer = kwargs.pop("framer", ModbusSocketFramer)
    factory = ModbusServerFactory(context, framer, identity, **kwargs)
    for f in custom_functions:
        factory.decoder.register(f)
    if console:
        InstallManagementConsole({'factory': factory})
    # log.event("Modbus, Starting Modbus TCP Server on %s:%s" % address)
    reactor.listenTCP(address[1], factory, interface=address[0])
    if not defer_reactor_run:
        reactor.run(installSignalHandlers=_is_main_thread())
