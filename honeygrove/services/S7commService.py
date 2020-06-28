"""
Snap7 server used for mimicking a siemens 7 server.
"""
import ctypes
import ipaddress
import re
import struct
import socket

import snap7.snap7types
from snap7 import six
from snap7.common import check_error, load_library, ipv4

from honeygrove import log
from honeygrove.config import Config
from honeygrove.services.ServiceBaseModel import Limiter, ServiceBaseModel


class S7commService(ServiceBaseModel):
    def __init__(self):
        super(S7commService, self).__init__()

        self._name = Config.s7comm.name
        self._port = Config.s7comm.port
        self._limiter = Limiter(self._fService, Config.s7comm.name, Config.s7comm.connections_per_host)
        self.server = Server()

    def startService(self):
        try:
            self._stop = False

            size = 10
            globaldata = (snap7.snap7types.wordlen_to_ctypes[snap7.snap7types.S7WLByte] * size)()
            outputs = (snap7.snap7types.wordlen_to_ctypes[snap7.snap7types.S7WLByte] * size)()
            inputs = (snap7.snap7types.wordlen_to_ctypes[snap7.snap7types.S7WLByte] * size)()

            self.server.register_area(snap7.snap7types.srvAreaPA, 0, outputs)
            self.server.register_area(snap7.snap7types.srvAreaMK, 0, globaldata)
            self.server.register_area(snap7.snap7types.srvAreaPE, 0, inputs)

            snap7.util.set_real(outputs, 0, 1.234)  # srvAreaPA
            snap7.util.set_real(globaldata, 0, 2.234)  # srvAreaMK
            snap7.util.set_real(inputs, 0, 3.234)  # srvAreaPE

            self.server.start(self._port)


        except Exception as e:
            self._stop = True
            self.server.clear_events()
            self.server.stop()

    def stopService(self):
        self._stop = True
        self.server.clear_events()
        self.server.stop()

# --------------------------------------------------------------------------- #
# Snap7 S7 Server Log Override
# --------------------------------------------------------------------------- #
def error_wrap(func):
    """Parses a s7 error code returned the decorated function."""

    def f(*args, **kw):
        code = func(*args, **kw)
        check_error(code, context="server")

    return f


class Server(object):
    """
    A fake S7 server.
    """
    pointer = None
    callback = None
    library = None

    def __init__(self):
        """
        Create a fake S7 server. set log to false if you want to disable
        event logging to python logging.
        """
        self.library = load_library()
        self.create()
        self._set_log_callback()

    def __del__(self):
        self.destroy()

    def event_text(self, event):
        """Returns a textual explanation of a given event object
        :param event: an PSrvEvent struct object
        :returns: the error string
        """
        #log.info("error text for %s" % hex(event.EvtCode))

        len_ = 1024
        text_type = ctypes.c_char * len_
        text = text_type()
        error = self.library.Srv_EventText(ctypes.byref(event),
                                           ctypes.byref(text), len_)
        check_error(error)
        if six.PY2:
            return text.value
        else:
            return text.value.decode('ascii')

    def create(self):
        """
        create the server.
        """
        #log.info("creating server")
        self.library.Srv_Create.restype = snap7.snap7types.S7Object
        self.pointer = snap7.snap7types.S7Object(self.library.Srv_Create())

    @error_wrap
    def register_area(self, area_code, index, userdata):
        """Shares a memory area with the server. That memory block will be
        visible by the clients.
        """
        size = ctypes.sizeof(userdata)
        #log.info("registering area %s, index %s, size %s" % (area_code, index, size))
        size = ctypes.sizeof(userdata)
        return self.library.Srv_RegisterArea(self.pointer, area_code, index,
                                             ctypes.byref(userdata), size)

    @error_wrap
    def set_events_callback(self, call_back):
        """Sets the user callback that the Server object has to call when an
        event is created.
        """
        #log.info("setting event callback")
        callback_wrap = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
                                         ctypes.POINTER(snap7.snap7types.SrvEvent),
                                         ctypes.c_int)

        def wrapper(usrptr, pevent, size):
            """
            Wraps python function into a ctypes function
            :param usrptr: not used
            :param pevent: pointer to snap7 event struct
            :param size:
            :returns: should return an int
            """
            #log.info("callback event: " + self.event_text(pevent.contents))
            call_back(pevent.contents)
            return 0

        self._callback = callback_wrap(wrapper)
        usrPtr = ctypes.c_void_p()
        return self.library.Srv_SetEventsCallback(self.pointer, self._callback, usrPtr)

    @error_wrap
    def set_read_events_callback(self, call_back):
        """
        Sets the user callback that the Server object has to call when a Read
        event is created.
        :param call_back: a callback function that accepts a pevent argument.
        """
        #log.info("setting read event callback")
        callback_wrapper = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
                                            ctypes.POINTER(snap7.snap7types.SrvEvent),
                                            ctypes.c_int)

        def wrapper(usrptr, pevent, size):
            """
            Wraps python function into a ctypes function
            :param usrptr: not used
            :param pevent: pointer to snap7 event struct
            :param size:
            :returns: should return an int
            """
            #log.info("callback event: " + self.event_text(pevent.contents))
            call_back(pevent.contents)
            return 0

        self._read_callback = callback_wrapper(wrapper)
        return self.library.Srv_SetReadEventsCallback(self.pointer,
                                                      self._read_callback)

    def _set_log_callback(self):
        """Sets a callback that logs the events
        """
        #log.info("setting up event logger")

        def log_callback(event):
            switcher = {
                0x00000001: "evcServerStarted",
                0x00000002: "evcServerStopped",
                0x00000004: "evcListenerCannotStart",
                0x00000008: "evcClientAdded",
                0x00000010: "evcClientRejected",
                0x00000020: "evcClientNoRoom",
                0x00000040: "evcClientException",
                0x00000080: "evcClientDisconnected",
                0x00000100: "evcClientTerminated",
                0x00000200: "evcClientsDropped",
                0x00000400: "evcReserved_00000400",
                0x00000800: "evcReserved_00000800",
                0x00001000: "evcReserved_00001000",
                0x00002000: "evcReserved_00002000",
                0x00004000: "evcReserved_00004000",
                0x00008000: "evcReserved_00008000",
                0x00010000: "evcPDUincoming",
                0x00020000: "evcDataRead",
                0x00040000: "evcDataWrite",
                0x00080000: "evcNegotiatePDU",
                0x00100000: "evcReadSZL",
                0x00200000: "evcClock",
                0x00400000: "evcUpload",
                0x00800000: "evcDownload",
                0x01000000: "evcDirectory",
                0x02000000: "evcSecurity",
                0x04000000: "evcControl",
                0x08000000: "evcReserved_08000000",
                0x10000000: "evcReserved_10000000",
                0x20000000: "evcReserved_20000000",
                0x40000000: "evcReserved_40000000"
            }
            event_output = switcher.get(event.EvtCode, 0)

            log.info(socket.inet_ntoa(struct.pack("=i", event.EvtSender)))
            #print(self.get_status())
            #log.info("S7comm, callback event: " + self.event_text(event))
            split_ip = str(ipaddress.ip_address(event.EvtSender)).split(".")
            client_ip = split_ip[3] + "." + split_ip[2] + "." + split_ip[1] + "." + split_ip[0]
            #log.info("S7comm,, IPv4Address:" + split_ip[3] + "." + split_ip[2] + "." + split_ip[1] + "." + split_ip[0])
            event_text = self.event_text(event)
            event_text_filtered = re.sub("(?:[\\d]{4}-[\\d]{2}-[\\d]{2})|"
                               "(?:[\\d]{2}:[\\d]{2}:[\\d]{2})|"
                               "(?:\\[(?:[\\d]{1,3}\\.){3}[\\d]{1,3}\\])", "", event_text)
            event_extension = ""
            if event.EvtCode == 0x00000008:
                event_extension = " (Clients connected: " + str(self.get_client_amount_connected()) + ")"

            log_func = log.info
            if 0x00000001 <= event.EvtCode <= 0x00000002:
                log_func = log.dont
            elif event.EvtCode <= 0x00000008:
                log_func = log.connect
            elif 0x00000010 <= event.EvtCode <= 0x00000040:
                log_func = log.err
            elif 0x00000080 <= event.EvtCode <= 0x00000200:
                log_func = log.disconnect
            elif 0x00000400 <= event.EvtCode <= 0x00008000:
                log_func = log.undefined
            elif 0x00010000 <= event.EvtCode <= 0x04000000:
                log_func = log.event
            elif 0x08000000 <= event.EvtCode <= 0x40000000:
                log_func = log.undefined
            log_func("S7comm, IPv4Address[" + client_ip + "]: " + event_text_filtered.strip() + event_extension
                     + " [" + event_output + "]")

        self.set_events_callback(log_callback)

    @error_wrap
    def start(self, tcpport=102):
        """
        start the server.
        """
        if tcpport != 102:
            #log.info("S7comm, setting server TCP port to %s" % tcpport)
            self.set_param(snap7.snap7types.LocalPort, tcpport)
        #log.info("S7comm, starting server on 0.0.0.0:%s" % tcpport)
        return self.library.Srv_Start(self.pointer)

    @error_wrap
    def stop(self):
        """
        stop the server.
        """
        #log.info("S7comm, stopping server")
        return self.library.Srv_Stop(self.pointer)

    def destroy(self):
        """
        destroy the server.
        """
        log.info("S7comm, destroying server")
        if self.library:
            self.library.Srv_Destroy(ctypes.byref(self.pointer))

    def get_status(self):
        """Reads the server status, the Virtual CPU status and the number of
        the clients connected.
        :returns: server status, cpu status, client count
        """
        log.info("S7comm, get server status")
        server_status = ctypes.c_int()
        cpu_status = ctypes.c_int()
        clients_count = ctypes.c_int()
        error = self.library.Srv_GetStatus(self.pointer, ctypes.byref(server_status),
                                           ctypes.byref(cpu_status),
                                           ctypes.byref(clients_count))
        check_error(error)
        log.info("S7comm, status server %s cpu %s clients %s" %
                     (server_status.value, cpu_status.value,
                      clients_count.value))
        return snap7.snap7types.server_statuses[server_status.value], \
               snap7.snap7types.cpu_statuses[cpu_status.value], \
               clients_count.value

    def get_client_amount_connected(self):
        server_status = ctypes.c_int()
        cpu_status = ctypes.c_int()
        clients_count = ctypes.c_int()
        error = self.library.Srv_GetStatus(self.pointer, ctypes.byref(server_status),
                                           ctypes.byref(cpu_status),
                                           ctypes.byref(clients_count))
        check_error(error)
        return clients_count.value

    @error_wrap
    def unregister_area(self, area_code, index):
        """'Unshares' a memory area previously shared with Srv_RegisterArea().
        That memory block will be no longer visible by the clients.
        """
        return self.library.Srv_UnregisterArea(self.pointer, area_code, index)

    @error_wrap
    def unlock_area(self, code, index):
        """Unlocks a previously locked shared memory area.
        """
        #log.info("S7comm, unlocking area code %s index %s" % (code, index))
        return self.library.Srv_UnlockArea(self.pointer, code, index)

    @error_wrap
    def lock_area(self, code, index):
        """Locks a shared memory area.
        """
        #log.info("S7comm, locking area code %s index %s" % (code, index))
        return self.library.Srv_LockArea(self.pointer, code, index)

    @error_wrap
    def start_to(self, ip, tcpport=102):
        """
        start server on a specific interface.
        """
        if tcpport != 102:
            #log.info("S7comm, setting server TCP port to %s" % tcpport)
            self.set_param(snap7.snap7types.LocalPort, tcpport)
        assert re.match(ipv4, ip), '%s is invalid ipv4' % ip
        #log.info("S7comm, starting server to %s:102" % ip)
        return self.library.Srv_Start(self.pointer, ip)

    @error_wrap
    def set_param(self, number, value):
        """Sets an internal Server object parameter.
        """
        #log.info("S7comm, setting param number %s to %s" % (number, value))
        return self.library.Srv_SetParam(self.pointer, number,
                                         ctypes.byref(ctypes.c_int(value)))

    @error_wrap
    def set_mask(self, kind, mask):
        """Writes the specified filter mask.
        """
        #log.info("S7comm, setting mask kind %s to %s" % (kind, mask))
        return self.library.Srv_SetMask(self.pointer, kind, mask)

    @error_wrap
    def set_cpu_status(self, status):
        """Sets the Virtual CPU status.
        """
        assert status in snap7.snap7types.cpu_statuses, 'unknown cpu state %s' % status
        #log.info("S7comm, setting cpu status to %s" % status)
        return self.library.Srv_SetCpuStatus(self.pointer, status)

    def pick_event(self):
        """Extracts an event (if available) from the Events queue.
        """
        #log.info("S7comm, checking event queue")
        event = snap7.snap7types.SrvEvent()
        ready = ctypes.c_int32()
        code = self.library.Srv_PickEvent(self.pointer, ctypes.byref(event),
                                          ctypes.byref(ready))
        check_error(code)
        if ready:
            #log.info("S7comm, one event ready: %s" % event)
            return event
        #log.info("S7comm, no events ready")

    def get_param(self, number):
        """Reads an internal Server object parameter.
        """
        #log.info("S7comm, retreiving param number %s" % number)
        value = ctypes.c_int()
        code = self.library.Srv_GetParam(self.pointer, number,
                                         ctypes.byref(value))
        check_error(code)
        return value.value

    def get_mask(self, kind):
        """Reads the specified filter mask.
        """
        #log.info("S7comm, retrieving mask kind %s" % kind)
        mask = snap7.snap7types.longword()
        code = self.library.Srv_GetMask(self.pointer, kind, ctypes.byref(mask))
        check_error(code)
        return mask

    @error_wrap
    def clear_events(self):
        """Empties the Event queue.
        """
        #log.info("S7comm, clearing event queue")
        return self.library.Srv_ClearEvents(self.pointer)