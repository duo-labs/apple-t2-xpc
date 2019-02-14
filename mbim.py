import scapy.packet as packet
from scapy.all import Ether, raw

ENDIANNESS = 'little'


class MBIMStream:
    def __init__(self, data):
        self.data = data

    def __len__(self):
        return len(self.data)

    def pop_raw(self, length):
        ret, self.data = self.data[:length], self.data[length:]
        return ret

    def pop_str_len(self, length):
        return str(self.pop_raw(length), "utf-8")

    def pop_uint16(self):
        return int.from_bytes(self.pop_raw(2), ENDIANNESS)


class MBIM:
    def __init__(self, pkt):
        if isinstance(pkt, packet.Packet):
            assert len(pkt) >= 0x20
            self.ndps = []
            self.dgs = []
            s = MBIMStream(raw(pkt))
            self.usb_urb = s.pop_raw(0x20)
            if len(s) < 0x1e:  # no payload
                return
            assert s.pop_str_len(4) == "NCMH"
            self.header_len = s.pop_uint16()
            self.seq = s.pop_uint16()
            assert s.pop_uint16() == len(pkt) - len(
                self.usb_urb
            )  # if this fails, it probably means we had multiple datagram pointers in this packet
            self.ndp_idx = s.pop_uint16()
            # ^^^ Header, vvv pointer
            assert s.pop_str_len(4) == "NCM0"
            self.ndp_len = s.pop_uint16()
            self.ndp_next_idx = s.pop_uint16()
            max_ndps = (self.ndp_len - 8) // 4
            # ^^^ using // because we want to truncate
            for i in range(max_ndps):
                dg_idx = s.pop_uint16()
                dg_len = s.pop_uint16()
                if dg_idx == 0 and dg_len == 0:
                    break
                self.ndps.append((dg_idx, dg_len))
                self.dgs.append(
                    Ether(raw(pkt)[0x20 + dg_idx:0x20 + dg_idx + dg_len]))

        else:
            print("MBIM construction is not yet implemented.")

    def __iter__(self):
        for dg in self.dgs:
            yield dg

    def __len__(self):
        return len(self.dgs)
