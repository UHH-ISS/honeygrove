"""
Implementation of a Threaded Modbus Server
------------------------------------------
"""

import struct

from pymodbus.bit_read_message import *
from pymodbus.bit_write_message import *
from pymodbus.compat import IS_PYTHON3
from pymodbus.compat import byte2int
from pymodbus.compat import iteritems, iterkeys, itervalues, get_next
from pymodbus.constants import Defaults
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore.store import BaseModbusDataBlock
from pymodbus.device import ModbusAccessControl
from pymodbus.device import ModbusControlBlock
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.diag_message import *
from pymodbus.exceptions import InvalidMessageReceivedException
from pymodbus.exceptions import ModbusException, MessageRegisterException
from pymodbus.exceptions import ModbusIOException
from pymodbus.exceptions import NoSuchSlaveException
from pymodbus.exceptions import ParameterException
from pymodbus.file_message import *
from pymodbus.framer import ModbusFramer, SOCKET_FRAME_HEADER
from pymodbus.interfaces import IModbusDecoder
from pymodbus.interfaces import IModbusSlaveContext
from pymodbus.internal.ptwisted import InstallManagementConsole
from pymodbus.mei_message import *
from pymodbus.other_message import *
from pymodbus.pdu import ExceptionResponse
from pymodbus.pdu import IllegalFunctionRequest
from pymodbus.pdu import ModbusExceptions as merror
from pymodbus.pdu import ModbusRequest
from pymodbus.register_read_message import *
from pymodbus.register_write_message import *
from pymodbus.transaction import *
from pymodbus.utilities import hexlify_packets
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.protocols.policies import ProtocolWrapper

from honeygrove import log
from honeygrove.config import Config
from honeygrove.services.ServiceBaseModel import ServiceBaseModel


class ModbusService(ServiceBaseModel):
    def __init__(self):
        super(ModbusService, self).__init__()

        self._name = Config.modbus.name
        self._port = Config.modbus.port

    def startService(self):
        try:
            self.run_server()

        except Exception as e:
            pass

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
            0x00: ModbusSlaveContext(
                di=CustomModbusSequentialDataBlock(0, [17] * 100),
                co=CustomModbusSequentialDataBlock(0, [1] * 100),
                hr=CustomModbusSequentialDataBlock(0, [17] * 100),
                ir=CustomModbusSequentialDataBlock(0, [17] * 100)),
            0x01: ModbusSlaveContext(
                di=CustomModbusSequentialDataBlock(0, [17] * 100),
                co=CustomModbusSequentialDataBlock(0, [0] * 100),
                hr=CustomModbusSequentialDataBlock(0, [17] * 100),
                ir=CustomModbusSequentialDataBlock(0, [17] * 100)),
            0x02: ModbusSlaveContext(
                di=CustomModbusSequentialDataBlock(0, [30] * 100),
                co=CustomModbusSparseDataBlock({0x00: 0, 0x05: 1}),
                hr=CustomModbusSequentialDataBlock(0, [17] * 100),
                ir=CustomModbusSequentialDataBlock.create()),
            0x03: ModbusSlaveContext(
                di=CustomModbusSequentialDataBlock(0, [13] * 1),
                co=CustomModbusSequentialDataBlock(0, [1] * 23),
                hr=CustomModbusSequentialDataBlock(0, [65] * 18),
                ir=CustomModbusSequentialDataBlock(0, [178] * 56)),
            0x04: ModbusSlaveContext(
                di=CustomModbusSequentialDataBlock(6, [17] * 100),
                co=CustomModbusSequentialDataBlock(2, [0] * 100),
                hr=CustomModbusSequentialDataBlock(45, [17] * 100),
                ir=CustomModbusSequentialDataBlock(33, [17] * 100)),
            0x05: ModbusSlaveContext(
                di=CustomModbusSequentialDataBlock(0, [42] * 100),
                co=CustomModbusSequentialDataBlock(0, [1] * 100),
                hr=CustomModbusSequentialDataBlock(0, [76] * 100),
                ir=CustomModbusSequentialDataBlock(0, [32] * 100)),
            0xFF: ModbusSlaveContext(
                di=CustomModbusSequentialDataBlock(0, [17] * 100),
                co=CustomModbusSequentialDataBlock(0, [1] * 100),
                hr=CustomModbusSequentialDataBlock(0, [17] * 100),
                ir=CustomModbusSequentialDataBlock(0, [17] * 100))
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
        identity.UserApplicationName = Config.modbus.user_application_name

        # ----------------------------------------------------------------------- #
        # run the server
        # ----------------------------------------------------------------------- #
        StartTcpServer(context, identity=identity, address=(self._address, self._port), transport=self._transport)

    def stopService(self):
        log.event("Modbus, stopping server")
        self._transport.stopListening()
        self._transport.stop()


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
        log.event('Modbus, IPv4Address[{}]: Data Received (Raw): '.format(self.transport.getPeer().host) + str(data))
        log.event('Modbus, IPv4Address[{}]: Data Received (Hex): '.format(self.transport.getPeer().host) + hexlify_packets(data))
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
        log.event("Modbus, IPv4Address[{}]: ".format(self.transport.getPeer().host)
                  + str(request) + " (unit-id: %s)" % request.unit_id)
        try:
            context = self.factory.store[request.unit_id]
            response = request.execute(context)
            log.event("Modbus, IPv4Address[{}]: Response: ".format(self.transport.getPeer().host) + str(response))
        except NoSuchSlaveException as ex:
            log.event("Modbus, IPv4Address[{}]: requested slave does not exist: %s".format(self.transport.getPeer().host) % request.unit_id)
            if self.factory.ignore_missing_slaves:
                return  # the client will simply timeout waiting for a response
            response = request.doException(merror.GatewayNoResponse)
            log.event("Modbus, IPv4Address[{}]: ".format(self.transport.getPeer().host) + str(response))
        except Exception as ex:
            log.event("Modbus, IPv4Address[{}]: Datastore unable to fulfill request: %s".format(self.transport.getPeer().host) % ex)
            response = request.doException(merror.SlaveFailure)
            log.event("Modbus, IPv4Address[{}]: ".format(self.transport.getPeer().host) + response)

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
            log.event('Modbus, IPv4Address[{}]: send: %s'.format(self.transport.getPeer().host) % pdu)
            #log.event('Modbus, send: %s' % b2a_hex(pdu))
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
        self.decoder = CustomServerDecoder()
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


def StartTcpServer(context, transport, identity=None, address=None,
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
    framer = kwargs.pop("framer", ModbusSocketCustomFramer)
    factory = ModbusServerFactory(context, framer, identity, **kwargs)
    for f in custom_functions:
        factory.decoder.register(f)
    if console:
        InstallManagementConsole({'factory': factory})
    # log.event("Modbus, Starting Modbus TCP Server on %s:%s" % address)
    transport = reactor.listenTCP(address[1], factory, interface=address[0])
    if not defer_reactor_run:
        reactor.run(installSignalHandlers=_is_main_thread())


# --------------------------------------------------------------------------- #
# Modbus TCP Message
# --------------------------------------------------------------------------- #

class ModbusSocketCustomFramer(ModbusFramer):
    """ Modbus Socket Frame controller

    Before each modbus TCP message is an MBAP header which is used as a
    message frame.  It allows us to easily separate messages as follows::

        [         MBAP Header         ] [ Function Code] [ Data ] \
        [ tid ][ pid ][ length ][ uid ]
          2b     2b     2b        1b           1b           Nb

        while len(message) > 0:
            tid, pid, length`, uid = struct.unpack(">HHHB", message)
            request = message[0:7 + length - 1`]
            message = [7 + length - 1:]

        * length = uid + function code + data
        * The -1 is to account for the uid byte
    """

    def __init__(self, decoder, client=None):
        """ Initializes a new instance of the framer

        :param decoder: The decoder factory implementation to use
        """
        self._buffer = b''
        self._header = {'tid': 0, 'pid': 0, 'len': 0, 'uid': 0}
        self._hsize = 0x07
        self.decoder = decoder
        self.client = client

    # ----------------------------------------------------------------------- #
    # Private Helper Functions
    # ----------------------------------------------------------------------- #
    def checkFrame(self):
        """
        Check and decode the next frame Return true if we were successful
        """
        if self.isFrameReady():
            (self._header['tid'], self._header['pid'],
             self._header['len'], self._header['uid']) = struct.unpack(
                '>HHHB', self._buffer[0:self._hsize])

            # someone sent us an error? ignore it
            if self._header['len'] < 2:
                self.advanceFrame()
            # we have at least a complete message, continue
            elif len(self._buffer) - self._hsize + 1 >= self._header['len']:
                return True
        # we don't have enough of a message yet, wait
        return False

    def advanceFrame(self):
        """ Skip over the current framed message
        This allows us to skip over the current message after we have processed
        it or determined that it contains an error. It also has to reset the
        current frame header handle
        """
        length = self._hsize + self._header['len'] - 1
        self._buffer = self._buffer[length:]
        self._header = {'tid': 0, 'pid': 0, 'len': 0, 'uid': 0}

    def isFrameReady(self):
        """ Check if we should continue decode logic
        This is meant to be used in a while loop in the decoding phase to let
        the decoder factory know that there is still data in the buffer.

        :returns: True if ready, False otherwise
        """
        return len(self._buffer) > self._hsize

    def addToFrame(self, message):
        """ Adds new packet data to the current frame buffer

        :param message: The most recent packet
        """
        self._buffer += message

    def getFrame(self):
        """ Return the next frame from the buffered data

        :returns: The next full frame buffer
        """
        length = self._hsize + self._header['len'] - 1
        return self._buffer[self._hsize:length]

    def populateResult(self, result):
        """
        Populates the modbus result with the transport specific header
        information (pid, tid, uid, checksum, etc)

        :param result: The response packet
        """
        result.transaction_id = self._header['tid']
        result.protocol_id = self._header['pid']
        result.unit_id = self._header['uid']

    # ----------------------------------------------------------------------- #
    # Public Member Functions
    # ----------------------------------------------------------------------- #
    def decode_data(self, data):
        if len(data) > self._hsize:
            tid, pid, length, uid, fcode = struct.unpack(SOCKET_FRAME_HEADER,
                                                         data[0:self._hsize+1])
            log.event("Modbus, tid: {} | pid: {} | length: {} | unit: {} | fcode: {}".format(tid, pid, length, uid, fcode))
            return dict(tid=tid, pid=pid, lenght=length, unit=uid, fcode=fcode)
        log.event("Modbus, Data length under {}".format(self._hsize))
        return dict()

    def processIncomingPacket(self, data, callback, unit, **kwargs):
        """
        The new packet processing pattern

        This takes in a new request packet, adds it to the current
        packet stream, and performs framing on it. That is, checks
        for complete messages, and once found, will process all that
        exist.  This handles the case when we read N + 1 or 1 // N
        messages at a time instead of 1.

        The processed and decoded messages are pushed to the callback
        function to process and send.

        :param data: The new packet data
        :param callback: The function to send results to
        :param unit: Process if unit id matches, ignore otherwise (could be a
               list of unit ids (server) or single unit id(client/server)
        :param single: True or False (If True, ignore unit address validation)
        :return:
        """
        if not isinstance(unit, (list, tuple)):
            unit = [unit]
        single = kwargs.get("single", False)
        self.addToFrame(data)
        self.decode_data(data)
        while True:
            if self.isFrameReady():
                if self.checkFrame():
                    if self._validate_unit_id(unit, single):
                        self._process(callback)
                    else:
                        log.event("Modbus, Not a valid unit id - {}, "
                                      "ignoring!!".format(self._header['uid']))
                        self.resetFrame()
                else:
                    log.event("Modbus, Frame check failed, ignoring!!")
                    self.resetFrame()
            else:
                if len(self._buffer):
                    # Possible error ???
                    if self._header['len'] < 2:
                        self._process(callback, error=True)
                break

    def _process(self, callback, error=False):
        """
        Process incoming packets irrespective error condition
        """
        data = self.getRawFrame() if error else self.getFrame()
        result = self.decoder.decode(data)
        if result is None:
            log.event("Modbus, Unable to decode request")
            raise ModbusIOException("Unable to decode request")
        elif error and result.function_code < 0x80:
            log.event("Modbus, Invalid Message")
            raise InvalidMessageReceivedException(result)
        else:
            self.populateResult(result)
            self.advanceFrame()
            callback(result)  # defer or push to a thread?

    def resetFrame(self):
        """
        Reset the entire message frame.
        This allows us to skip ovver errors that may be in the stream.
        It is hard to know if we are simply out of sync or if there is
        an error in the stream as we have no way to check the start or
        end of the message (python just doesn't have the resolution to
        check for millisecond delays).
        """
        self._buffer = b''
        self._header = {'tid': 0, 'pid': 0, 'len': 0, 'uid': 0}

    def getRawFrame(self):
        """
        Returns the complete buffer
        """
        return self._buffer

    def buildPacket(self, message):
        """ Creates a ready to send modbus packet

        :param message: The populated request/response to send
        """
        data = message.encode()
        packet = struct.pack(SOCKET_FRAME_HEADER,
                             message.transaction_id,
                             message.protocol_id,
                             len(data) + 2,
                             message.unit_id,
                             message.function_code)
        packet += data
        return packet


# --------------------------------------------------------------------------- #
# Server Decoder
# --------------------------------------------------------------------------- #
class CustomServerDecoder(IModbusDecoder):
    """ Request Message Factory (Server)

    To add more implemented functions, simply add them to the list
    """
    __function_table = [
        ReadHoldingRegistersRequest,
        ReadDiscreteInputsRequest,
        ReadInputRegistersRequest,
        ReadCoilsRequest,
        WriteMultipleCoilsRequest,
        WriteMultipleRegistersRequest,
        WriteSingleRegisterRequest,
        WriteSingleCoilRequest,
        ReadWriteMultipleRegistersRequest,
        DiagnosticStatusRequest,
        ReadExceptionStatusRequest,
        GetCommEventCounterRequest,
        GetCommEventLogRequest,
        ReportSlaveIdRequest,
        ReadFileRecordRequest,
        WriteFileRecordRequest,
        MaskWriteRegisterRequest,
        ReadFifoQueueRequest,
        ReadDeviceInformationRequest,
    ]
    __sub_function_table = [
        ReturnQueryDataRequest,
        RestartCommunicationsOptionRequest,
        ReturnDiagnosticRegisterRequest,
        ChangeAsciiInputDelimiterRequest,
        ForceListenOnlyModeRequest,
        ClearCountersRequest,
        ReturnBusMessageCountRequest,
        ReturnBusCommunicationErrorCountRequest,
        ReturnBusExceptionErrorCountRequest,
        ReturnSlaveMessageCountRequest,
        ReturnSlaveNoResponseCountRequest,
        ReturnSlaveNAKCountRequest,
        ReturnSlaveBusyCountRequest,
        ReturnSlaveBusCharacterOverrunCountRequest,
        ReturnIopOverrunCountRequest,
        ClearOverrunCountRequest,
        GetClearModbusPlusRequest,
        ReadDeviceInformationRequest,
    ]

    def __init__(self):
        """ Initializes the client lookup tables
        """
        functions = set(f.function_code for f in self.__function_table)
        self.__lookup = dict([(f.function_code, f) for f in self.__function_table])
        self.__sub_lookup = dict((f, {}) for f in functions)
        for f in self.__sub_function_table:
            self.__sub_lookup[f.function_code][f.sub_function_code] = f

    def decode(self, message):
        """ Wrapper to decode a request packet

        :param message: The raw modbus request packet
        :return: The decoded modbus message or None if error
        """
        try:
            return self._helper(message)
        except ModbusException as er:
            log.event("Modbus, Unable to decode request %s" % er)
        return None

    def lookupPduClass(self, function_code):
        """ Use `function_code` to determine the class of the PDU.

        :param function_code: The function code specified in a frame.
        :returns: The class of the PDU that has a matching `function_code`.
        """
        return self.__lookup.get(function_code, ExceptionResponse)

    def _helper(self, data):
        """
        This factory is used to generate the correct request object
        from a valid request packet. This decodes from a list of the
        currently implemented request types.

        :param data: The request packet to decode
        :returns: The decoded request or illegal function request object
        """
        function_code = byte2int(data[0])
        request = self.__lookup.get(function_code, lambda: None)()
        if not request:
            log.event("Modbus, Illegal Function Request[%d]" % function_code)
            request = IllegalFunctionRequest(function_code)
        else:
            fc_string = "%s: %s" % (
                str(self.__lookup[function_code]).split('.')[-1].rstrip(
                    "'>"),
                function_code
            )
            log.event("Modbus, Request[%s]" % fc_string)
        request.decode(data[1:])

        if hasattr(request, 'sub_function_code'):
            lookup = self.__sub_lookup.get(request.function_code, {})
            subtype = lookup.get(request.sub_function_code, None)
            if subtype: request.__class__ = subtype

        return request

    def register(self, function=None):
        """
        Registers a function and sub function class with the decoder
        :param function: Custom function class to register
        :return:
        """
        if function and not issubclass(function, ModbusRequest):
            raise MessageRegisterException("'{}' is Not a valid Modbus Message"
                                           ". Class needs to be derived from "
                                           "`pymodbus.pdu.ModbusRequest` "
                                           "".format(
                function.__class__.__name__
            ))
        self.__lookup[function.function_code] = function
        if hasattr(function, "sub_function_code"):
            if function.function_code not in self.__sub_lookup:
                self.__sub_lookup[function.function_code] = dict()
            self.__sub_lookup[function.function_code][
                function.sub_function_code] = function

"""
Modbus Server Datastore
-------------------------

For each server, you will create a ModbusServerContext and pass
in the default address space for each data access.  The class
will create and manage the data.

Further modification of said data accesses should be performed
with [get,set][access]Values(address, count)

Datastore Implementation
-------------------------

There are two ways that the server datastore can be implemented.
The first is a complete range from 'address' start to 'count'
number of indecies.  This can be thought of as a straight array::

    data = range(1, 1 + count)
    [1,2,3,...,count]

The other way that the datastore can be implemented (and how
many devices implement it) is a associate-array::

    data = {1:'1', 3:'3', ..., count:'count'}
    [1,3,...,count]

The difference between the two is that the latter will allow
arbitrary gaps in its datastore while the former will not.
This is seen quite commonly in some modbus implementations.
What follows is a clear example from the field:

Say a company makes two devices to monitor power usage on a rack.
One works with three-phase and the other with a single phase. The
company will dictate a modbus data mapping such that registers::

    n:      phase 1 power
    n+1:    phase 2 power
    n+2:    phase 3 power

Using this, layout, the first device will implement n, n+1, and n+2,
however, the second device may set the latter two values to 0 or
will simply not implmented the registers thus causing a single read
or a range read to fail.

I have both methods implemented, and leave it up to the user to change
based on their preference.
"""
class CustomModbusSequentialDataBlock(BaseModbusDataBlock):
    ''' Creates a sequential modbus datastore '''

    def __init__(self, address, values):
        ''' Initializes the datastore

        :param address: The starting address of the datastore
        :param values: Either a list or a dictionary of values
        '''
        self.address = address
        if hasattr(values, '__iter__'):
            self.values = list(values)
        else:
            self.values = [values]
        self.default_value = self.values[0].__class__()

    @classmethod
    def create(klass):
        ''' Factory method to create a datastore with the
        full address space initialized to 0x00

        :returns: An initialized datastore
        '''
        return klass(0x00, [0x00] * 65536)

    def validate(self, address, count=1):
        ''' Checks to see if the request is in range

        :param address: The starting address
        :param count: The number of values to test for
        :returns: True if the request in within range, False otherwise
        '''
        result  = (self.address <= address)
        result &= ((self.address + len(self.values)) >= (address + count))
        return result

    def getValues(self, address, count=1):
        ''' Returns the requested values of the datastore

        :param address: The starting address
        :param count: The number of values to retrieve
        :returns: The requested values from a:a+c
        '''
        start = address - self.address
        log.event("Modbus, Requestes values: " + str(self.values[start:start + count]))
        return self.values[start:start + count]

    def setValues(self, address, values):
        ''' Sets the requested values of the datastore

        :param address: The starting address
        :param values: The new values to be set
        '''
        if not isinstance(values, list):
            values = [values]
        start = address - self.address
        self.values[start:start + len(values)] = values
        log.event("Modbus, Set values: " + str(self.values[start:start + len(values)]))



class CustomModbusSparseDataBlock(BaseModbusDataBlock):
    ''' Creates a sparse modbus datastore '''

    def __init__(self, values):
        ''' Initializes the datastore

        Using the input values we create the default
        datastore value and the starting address

        :param values: Either a list or a dictionary of values
        '''
        if isinstance(values, dict):
            self.values = values
        elif hasattr(values, '__iter__'):
            self.values = dict(enumerate(values))
        else: raise ParameterException(
            "Values for datastore must be a list or dictionary")
        self.default_value = get_next(itervalues(self.values)).__class__()
        self.address = get_next(iterkeys(self.values))

    @classmethod
    def create(klass):
        ''' Factory method to create a datastore with the
        full address space initialized to 0x00

        :returns: An initialized datastore
        '''
        return klass([0x00] * 65536)

    def validate(self, address, count=1):
        ''' Checks to see if the request is in range

        :param address: The starting address
        :param count: The number of values to test for
        :returns: True if the request in within range, False otherwise
        '''
        if count == 0:
            return False
        handle = set(range(address, address + count))
        return handle.issubset(set(iterkeys(self.values)))

    def getValues(self, address, count=1):
        ''' Returns the requested values of the datastore

        :param address: The starting address
        :param count: The number of values to retrieve
        :returns: The requested values from a:a+c
        '''
        log.event("Modbus, Requestes values: " + str([self.values[i] for i in range(address, address + count)]))
        return [self.values[i] for i in range(address, address + count)]

    def setValues(self, address, values):
        ''' Sets the requested values of the datastore

        :param address: The starting address
        :param values: The new values to be set
        '''
        log.event("Modbus, Set values: " + str(values))
        if isinstance(values, dict):
            for idx, val in iteritems(values):
                self.values[idx] = val
        else:
            if not isinstance(values, list):
                values = [values]
            for idx, val in enumerate(values):
                self.values[address + idx] = val
