import struct


class XpcWrapper:
    format_string = "<LIQQ"
    hdr_len = struct.calcsize(format_string)
    magic_bytes = 0x29b00b92

    def __init__(self, magic, flags, leng, msgid):
        self.magic = magic
        self.flags = flags
        self.body_length = leng
        self.msg_id = msgid

    @classmethod
    def from_bytes(cls, data):
        if len(data) >= XpcWrapper.hdr_len and \
                XpcWrapper.magic_bytes == int.from_bytes(data[:4], 'little'):
            try:
                wrapper = XpcWrapper(*struct.unpack(XpcWrapper.format_string,
                                                    data[:XpcWrapper.hdr_len]))
            except AttributeError:  # happens with malformed/cropped packet
                print("Error: Frame: " + str(frame.summary()) + " Bytes: " +
                      str(frame))
                return None, data
            return wrapper, data[XpcWrapper.hdr_len:]

        else:
            return None, data

    def __repr__(self):
        return "Magic: 0x{:x}, Flags: 0b{:032b}, BodyLength: 0x{:x}, MessageId: 0x{:x}".format(
            self.magic, self.flags, self.body_length, self.msg_id)

    def __str__(self):
        return "XPC Wrapper: {{\n    Magic: 0x{:x}\n    Flags: 0b {:08b} {:08b} {:08b} {:08b} (0x{:x})\n    BodyLength: 0x{:x}\n    MessageId: 0x{:x}\n}}".format(
            self.magic, self.flags >> 24, (self.flags >> 16) & 255,
            (self.flags >> 8) & 255, self.flags & 255, self.flags,
            self.body_length, self.msg_id)

    def __bytes__(self):
        return struct.pack(XpcWrapper.format_string, self.magic, self.flags,
                           self.body_length, self.msg_id)

    def to_bytes(self):
        return bytes(self)
