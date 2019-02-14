# this file is not intended to be executed itself, but imported into another file

import struct
import binascii
import hexdump as hxdump

# known object types
# yapf: disable
XPC_NULL              = 0x00001000
XPC_BOOL              = 0x00002000
XPC_INT64             = 0x00003000
XPC_UINT64            = 0x00004000
XPC_DOUBLE            = 0x00005000
XPC_POINTER           = 0x00006000
XPC_DATE              = 0x00007000
XPC_DATA              = 0x00008000
XPC_STRING            = 0x00009000
XPC_UUID              = 0x0000a000
XPC_FD                = 0x0000b000
XPC_SHMEM             = 0x0000c000
XPC_MACH_SEND         = 0x0000d000
XPC_ARRAY             = 0x0000e000
XPC_DICTIONARY        = 0x0000f000
XPC_ERROR             = 0x00010000
XPC_CONNECTION        = 0x00011000
XPC_ENDPOINT          = 0x00012000
XPC_SERIALIZER        = 0x00013000
XPC_PIPE              = 0x00014000
XPC_MACH_RECV         = 0x00015000
XPC_BUNDLE            = 0x00016000
XPC_SERVICE           = 0x00017000
XPC_SERVICE_INSTANCE  = 0x00018000
XPC_ACTIVITY          = 0x00019000
XPC_FILE_TRANSFER     = 0x0001a000

XPC_MAGIC             = 0x42133742
XPC_PROTO_VER         = 0x00000005
# yapf: enable

ENDIANNESS = "little"
#ENDIANNESS = "big"
STRUCT_ENDIAN = "<" if ENDIANNESS == "little" else ">"


def round_up(i, multiple):
    return i + (-i % multiple)


def pad(data):
    padding = -len(data) % 4
    return data + b"\x00" * padding


def string_to_aligned_bytes(s):
    s_bytes = bytes(s, "utf-8")
    return pad(s_bytes + b"\x00")


class XPCByteStream:
    def __init__(self, data):
        self.data = data

    def __len__(self):
        return len(self.data)

    def __nonzero__(self):
        return len(self.data) > 0

    def pop_bytes(self, length):
        length_up = round_up(length, 4)
        ret, self.data = self.data[:length], self.data[length_up:]
        return ret

    def pop_uint32(self):
        ret, self.data = int.from_bytes(self.data[:4],
                                        ENDIANNESS), self.data[4:]
        return ret

    def pop_int64(self):
        ret, self.data = int.from_bytes(
            self.data[:8], ENDIANNESS, signed=True), self.data[8:]
        return ret

    def pop_uint64(self):
        ret, self.data = int.from_bytes(self.data[:8],
                                        ENDIANNESS), self.data[8:]
        return ret

    def pop_double(self):
        double_bytes, self.data = self.data[:8], self.data[8:]
        return struct.unpack(STRUCT_ENDIAN + "d", double_bytes)[0]

    def pop_aligned_string_len(self, length):
        aligned_length = round_up(length, 4)
        s, self.data = self.data[:aligned_length], self.data[aligned_length:]
        return str(s, "utf-8").rstrip('\0')

    def pop_stream(self, length):
        assert length % 4 == 0
        ret, self.data = XPCByteStream(self.data[:length]), self.data[length:]
        return ret

    def pop_dict_key(self):
        pos = self.data.find(b"\x00")
        return self.pop_aligned_string_len(pos + 1)

    # this method will peek at the next object and attempt to resolve it to a class
    def next_object_class(self):
        type_ = int.from_bytes(self.data[:4], ENDIANNESS)
        # yapf: disable
        switcher = {
            XPC_NULL:               XPC_Null,
            XPC_BOOL:               XPC_Bool,
            XPC_INT64:              XPC_Int64,
            XPC_UINT64:             XPC_Uint64,
            XPC_DOUBLE:             XPC_Double,
            XPC_POINTER:            XPC_Pointer,
            XPC_DATE:               XPC_Date,
            XPC_DATA:               XPC_Data,
            XPC_STRING:             XPC_String,
            XPC_UUID:               XPC_Uuid,
            XPC_FD:                 XPC_Fd,
            XPC_SHMEM:              XPC_Shmem,
            XPC_MACH_SEND:          XPC_Mach_Send,
            XPC_ARRAY:              XPC_Array,
            XPC_DICTIONARY:         XPC_Dictionary,
            XPC_ERROR:              XPC_Error,
            XPC_CONNECTION:         XPC_Connection,
            XPC_ENDPOINT:           XPC_Endpoint,
            XPC_SERIALIZER:         XPC_Serializer,
            XPC_PIPE:               XPC_Pipe,
            XPC_MACH_RECV:          XPC_Mach_Recv,
            XPC_BUNDLE:             XPC_Bundle,
            XPC_SERVICE:            XPC_Service,
            XPC_SERVICE_INSTANCE:   XPC_Service_Instance,
            XPC_ACTIVITY:           XPC_Activity,
            XPC_FILE_TRANSFER:      XPC_File_Transfer
        }
        # yapf: enable
        obj = switcher.get(type_, None)
        if not obj:
            print("Couldn't identify a type.")
            return None
        elif not "pretty_string" in dir(obj):  # unimplemented obj
            print(
                "Attempting to decode unimplemented type \"%s\". This will fail."
                % (obj.__name__))
            return None
        return obj


class XPC_Null:
    def __init__(self, arg=None):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_NULL
        elif arg is None:
            self.type = XPC_NULL
        else:
            raise Exception("Requires valid argument, or no argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "Null\n"

    def to_bytes(self):
        return XPC_NULL.to_bytes(4, ENDIANNESS)


class XPC_Bool:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_BOOL
            self.value = bool(arg.pop_uint32())
        elif isinstance(arg, bool):
            self.type = XPC_BOOL
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + ("True\n" if self.value else "False\n")

    def to_bytes(self):
        return XPC_BOOL.to_bytes(4, ENDIANNESS) + self.value.to_bytes(
            4, ENDIANNESS)


class XPC_Int64:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_INT64
            self.value = arg.pop_int64()
        elif isinstance(arg, int):
            self.type = XPC_INT64
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + 'int64 0x%016x: %d' % (self.value,
                                                      self.value) + "\n"

    def to_bytes(self):
        return XPC_INT64.to_bytes(4, ENDIANNESS) + self.value.to_bytes(
            8, ENDIANNESS)


class XPC_Uint64:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_UINT64
            self.value = arg.pop_uint64()
        elif isinstance(arg, int) and arg >= 0:
            self.type = XPC_UINT64
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + 'uint64 0x%016x: %d' % (self.value,
                                                       self.value) + "\n"

    def to_bytes(self):
        return XPC_UINT64.to_bytes(4, ENDIANNESS) + self.value.to_bytes(
            8, ENDIANNESS)


class XPC_Double:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_DOUBLE
            self.value = arg.pop_double()
        elif isinstance(arg, (float, int)):
            arg = float(arg)
            self.type = XPC_DOUBLE
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + 'double %f' % (self.value) + "\n"

    def to_bytes(self):
        return XPC_DOUBLE.to_bytes(4, ENDIANNESS) + struct.pack(
            STRUCT_ENDIAN + "d", self.value)


class XPC_Pointer:
    pass


class XPC_Date:
    # stored as nanoseconds since the epoch
    # same format as UINT64
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_DATE
            self.value = arg.pop_uint64()
        elif isinstance(arg, int) and arg >= 0:
            self.type = XPC_DATE
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + 'date 0x%016x: %d' % (self.value,
                                                     self.value) + "\n"

    def to_bytes(self):
        return XPC_DATE.to_bytes(4, ENDIANNESS) + self.value.to_bytes(
            8, ENDIANNESS)


class XPC_Data:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_DATA
            self.length = arg.pop_uint32()
            self.value = arg.pop_bytes(length)
        elif isinstance(arg, bytes):
            self.type = XPC_DOUBLE
            self.length = len(arg)
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "data 0x" + "".join("{:02x}".format(x)
                                                   for x in self.value) + "\n"

    def to_bytes(self):
        return XPC_DATA.to_bytes(4, ENDIANNESS) + self.length.to_bytes(
            4, ENDIANNESS) + pad(self.value)


class XPC_String:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_STRING
            length = arg.pop_uint32()
            self.value = arg.pop_aligned_string_len(length)
        elif isinstance(arg, str):
            self.type = XPC_STRING
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + '"%s"' % self.value + "\n"

    def to_bytes(self):
        return XPC_STRING.to_bytes(
            4, ENDIANNESS) + (len(self.value) + 1).to_bytes(
                4, ENDIANNESS) + string_to_aligned_bytes(self.value)


class XPC_Uuid:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_UUID
            self.value = arg.pop_bytes(16)
            assert len(self.value) == 16
        elif isinstance(arg, bytes) and len(arg) == 16:
            self.type = XPC_UUID
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + 'uuid 0x%s' % (binascii.hexlify(
            self.value)) + "\n"

    def to_bytes(self):
        return XPC_UUID.to_bytes(4, ENDIANNESS) + self.value


class XPC_Fd:
    # doesn't seem to be possible to pass Fd's outside a process, so they show
    # up as just the type field and no value
    def __init__(self, arg=None):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_FD
        elif arg is None:
            self.type = XPC_FD
        else:
            raise Exception("Requires valid argument, or no argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "File Descriptor (missing)\n"

    def to_bytes(self):
        return XPC_FD.to_bytes(4, ENDIANNESS)


class XPC_Shmem:
    def __init__(self, arg=None):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_SHMEM
            self.length = arg.pop_uint32()
            _ = arg.pop_uint32()  # pop off the 4 null bytes
        elif isinstance(arg, int) and arg >= 0:
            self.type = XPC_SHMEM
            self.length = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "Shared Memory length: %d" % (
            self.length) + "\n"

    def to_bytes(self):
        return XPC_SHMEM.to_bytes(4, ENDIANNESS) + self.length.to_bytes(
            4, ENDIANNESS) + b"\x00\x00\x00\x00"


class XPC_Mach_Send:
    pass


class XPC_Array:
    # type, length, num_entries, [entry entry entry ...]
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_DICTIONARY
            length = arg.pop_uint32()
            array_stream = arg.pop_stream(length)
            num_entries = array_stream.pop_uint32()
            self.value = []
            for i in range(num_entries):
                assert len(array_stream)
                xpc_obj_class = array_stream.next_object_class()
                if not xpc_obj_class:  # if None was returned
                    print("Couldn't decode xpc_object_t type 0x%08x" %
                          array_stream.pop_uint32())
                    hxdump.hexdump(array_stream.pop_bytes(len(array_stream)))
                    return
                self.value.append(xpc_obj_class(array_stream))
        elif isinstance(arg, (tuple, list)):
            # format is a tuple or list with values that are other XPC_xxx types
            # we don't do any validation checking of the values that are passed in
            self.type = XPC_ARRAY
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        ret = ""
        # open {
        ret += "    " * numi + "[\n"
        # entries
        for v in self.value:
            ret += v.pretty_string(numi + 1)
        # close }
        ret += "    " * numi + "]\n"
        return ret

    def to_bytes(self):
        obj_bytes = b""
        for v in self.value:
            obj_bytes += v.to_bytes()
        return XPC_ARRAY.to_bytes(4, ENDIANNESS) + (
            len(obj_bytes) + 4).to_bytes(4, ENDIANNESS) + len(
                self.value).to_bytes(4, ENDIANNESS) + obj_bytes

    def is_empty(self):
        return len(self.value) == 0


class XPC_Dictionary:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_DICTIONARY
            length = arg.pop_uint32()
            dict_stream = arg.pop_stream(length)
            num_entries = dict_stream.pop_uint32()
            self.value = {}
            for i in range(num_entries):
                assert len(dict_stream)
                key = dict_stream.pop_dict_key()
                xpc_obj_class = dict_stream.next_object_class()
                if not xpc_obj_class:  # if None was returned
                    print("Couldn't decode xpc_object_t type 0x%08x" %
                          dict_stream.pop_uint32())
                    hxdump.hexdump(dict_stream.pop_bytes(len(dict_stream)))
                    return
                self.value[key] = xpc_obj_class(dict_stream)
        elif isinstance(arg, dict):
            # format is a dictionary with string keys and values that are other XPC_xxx types
            # we don't do any validation checking of the dictionary entries that are passed in
            self.type = XPC_DICTIONARY
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        ret = ""
        # open {
        ret += "    " * numi + "{\n"
        #ret += "    " * numi + "{ ~%d entries~\n" % len(self.value) if len(
        #    self.value) != 1 else "    " * numi + "{ ~1 entry~\n"
        numi += 1
        # entries
        for k, v in self.value.items():
            ret += "    " * numi + '"%s":\n' % k
            ret += v.pretty_string(numi + 1)
        numi -= 1
        # close }
        ret += "    " * numi + "}\n"
        return ret

    def to_bytes(self):
        obj_bytes = b""
        for k, v in self.value.items():
            obj_bytes += string_to_aligned_bytes(k) + v.to_bytes()
        return XPC_DICTIONARY.to_bytes(4, ENDIANNESS) + (
            len(obj_bytes) + 4).to_bytes(4, ENDIANNESS) + len(
                self.value).to_bytes(4, ENDIANNESS) + obj_bytes

    def is_empty(self):
        return len(self.value) == 0


class XPC_Error:
    # https://developer.apple.com/documentation/xpc/xpc_type_error?language=objc
    # "Errors in XPC are dictionaries"
    # so this is entirely a guess, but we'll interpret this as we do a dictionary
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_ERROR
            length = arg.pop_uint32()
            dict_stream = arg.pop_stream(length)
            num_entries = dict_stream.pop_uint32()
            self.value = {}
            for i in range(num_entries):
                assert len(dict_stream)
                key = dict_stream.pop_dict_key()
                xpc_obj_class = dict_stream.next_object_class()
                if not xpc_obj_class:  # if None was returned
                    print("Couldn't decode xpc_object_t type 0x%08x" %
                          dict_stream.pop_uint32())
                    hxdump.hexdump(dict_stream.pop_bytes(len(dict_stream)))
                    return
                self.value[key] = xpc_obj_class(dict_stream)
        elif isinstance(arg, dict):
            # format is a dictionary with string keys and values that are other XPC_xxx types
            # we don't do any validation checking of the dictionary entries that are passed in
            # WARNING: We haven't actually seen any XPC_Errors, so be wary what you stick in here
            self.type = XPC_ERROR
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        ret = ""
        # open {
        ret += "    " * numi + "ERROR: {\n"
        numi += 1
        # entries
        for k, v in self.value.items():
            ret += "    " * numi + '"%s":\n' % k
            ret += v.pretty_string(numi + 1)
        numi -= 1
        # close }
        ret += "    " * numi + "}\n"
        return ret

    def to_bytes(self):
        obj_bytes = b""
        for k, v in self.value.items():
            obj_bytes += string_to_aligned_bytes(k) + v.to_bytes()
        return XPC_ERROR.to_bytes(4, ENDIANNESS) + (
            len(obj_bytes) + 4).to_bytes(4, ENDIANNESS) + len(
                self.value).to_bytes(4, ENDIANNESS) + obj_bytes

    def is_empty(self):
        return len(self.value) == 0


class XPC_Connection:
    # in our testing, connections show up as just the type field and no value,
    # but under the XPC_ENDPOINT type
    def __init__(self, arg=None):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_CONNECTION
        elif arg is None:
            self.type = XPC_CONNECTION
        else:
            raise Exception("Requires valid argument, or no argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "Connection (missing)\n"

    def to_bytes(self):
        return XPC_CONNECTION.to_bytes(4, ENDIANNESS)


class XPC_Endpoint:
    # in our testing, connections show up as just the type field and no value,
    # but under the XPC_ENDPOINT type
    def __init__(self, arg=None):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_ENDPOINT
        elif arg is None:
            self.type = XPC_ENDPOINT
        else:
            raise Exception("Requires valid argument, or no argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "Endpoint (missing)\n"

    def to_bytes(self):
        return XPC_ENDPOINT.to_bytes(4, ENDIANNESS)


class XPC_Serializer:
    pass


class XPC_Pipe:
    pass


class XPC_Mach_Recv:
    pass


class XPC_Bundle:
    pass


class XPC_Service:
    pass


class XPC_Service_Instance:
    pass


class XPC_Activity:
    pass


# value should be a tuple or list of two elements
# (msg_id, transfer_size)
class XPC_File_Transfer:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_FILE_TRANSFER
            self.msg_id = arg.pop_uint64()
            dict_type = arg.pop_uint32()  # dict type field
            assert dict_type == XPC_DICTIONARY
            dict_length = arg.pop_uint32()  # dict length field
            dict_stream = arg.pop_stream(dict_length)
            dict_entries = dict_stream.pop_uint32()  # dict num entries field
            assert dict_entries == 1
            dict_key = dict_stream.pop_dict_key()
            assert dict_key == "s", "dict_key was \"%s\"" % repr(dict_key)
            dict_value_type = dict_stream.pop_uint32()
            assert dict_value_type == XPC_UINT64
            self.transfer_size = dict_stream.pop_uint64()
        elif isinstance(arg, (list, tuple)) and len(arg) == 2 and isinstance(
                arg[0], int) and isinstance(arg[1], int):
            self.type = XPC_FILE_TRANSFER
            self.msg_id = arg[0]
            self.transfer_size = arg[1]
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        ret = "    " * numi + "MessageId: 0x%x " % (self.msg_id) + "\n"
        ret += "    " * numi + 'File transfer size: 0x%016x %d' % (
            self.transfer_size, self.transfer_size) + "\n"
        return ret

    def to_bytes(self):
        temp_dict = XPC_Dictionary({"s": XPC_Uint64(self.value)})
        return XPC_FILE_TRANSFER.to_bytes(
            4, ENDIANNESS) + self.transfer_size.to_bytes(
                8, ENDIANNESS) + temp_dict.to_bytes()


class XPC_Root:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            magic = arg.pop_uint32()
            assert magic == XPC_MAGIC
            proto = arg.pop_uint32()
            assert proto == XPC_PROTO_VER
            self.value = XPC_Dictionary(arg)
        elif isinstance(arg, XPC_Dictionary):
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.value.pretty_string(0)  # indentation level

    def to_bytes(self):
        return XPC_MAGIC.to_bytes(4, ENDIANNESS) + XPC_PROTO_VER.to_bytes(
            4, ENDIANNESS) + self.value.to_bytes()

    def is_empty_dict(self):
        return self.value.is_empty()


# quick test to make sure this is working
def _test():
    raw_bytes_with_magic = b"\x42\x37\x13\x42\x05\x00\x00\x00\x00\xf0\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x44\x55\x4f\x00\x00\x90\x00\x00\x04\x00\x00\x00\x64\x75\x6f\x00"
    #raw_bytes = b"\x00\xf0\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x44\x55\x4f\x00\x00\x90\x00\x00\x04\x00\x00\x00\x64\x75\x6f\x00"
    print(raw_bytes_with_magic)
    stream = XPCByteStream(raw_bytes_with_magic)
    x = XPC_Root(stream)
    print(x)
    hxdump.hexdump(x.to_bytes())

    d = XPC_Root(
        XPC_Dictionary({
            "DUO": XPC_String("duo"),
            "CISCO": XPC_String("cisco"),
        }))
    print(d)
    hxdump.hexdump(d.to_bytes())


if __name__ == "__main__":
    _test()
