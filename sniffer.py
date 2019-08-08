#!/usr/bin/env python3.6

import argparse
import struct
from scapy.all import *
import scapy.contrib.http2 as h2

from xpc_types import *
from mbim import MBIM
from xpc_wrapper import XpcWrapper

IFACE = "VHC128"

IP_TO_NAME = {
    "fe80::aede:48ff:fe00:1122": "imac",
    "fe80::aede:48ff:fe33:4455": "t2"
}

#DEBUG = False
DEBUG = True
PAUSE = False

# global streams variable for storing all the streams we've seen so far
tcp_streams = {}


def main():
    # check for a capture filename as command-line arg
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", metavar="FILENAME", help="pcap filename")
    parser.add_argument("-c", metavar="", help="create a test packet")
    args = parser.parse_args()
    # if we have a pcap file specified on the command line, use that -- otherwise sniff
    if args.f:
        if os.path.isfile(args.f):
            print(
                "Reading packets from file. Operation will pause after interesting packets.\nPress <Enter> to jump to the next interesting packet."
            )
            global PAUSE
            PAUSE = True
            packets = rdpcap(args.f)
            for p in packets:
                process_packet(p)
        else:
            print("Invalid file specified")
    elif args.c:
        # if we want to create a packet
        create_packet()
    else:
        # sniff packets on specified interface, pass them to the packet parsing function
        sniff(iface=IFACE, prn=process_packet)


def process_packet(p):
    try:
        m = MBIM(p)
    except:
        return
    print("New MBIM packet with %d Ethernet frames inside" % len(m))
    for packet in m:
        #if DEBUG: packet.show()
        if packet.haslayer(TCP):
            if packet[TCP].payload:
                process_tcp(packet)


def process_tcp(pkt):
    # we are going to separate TCP packets into TCP streams between unique
    # endpoints (ip/port) then, for each stream, we will create a new TCPStream
    # object and pass TCP packets into it TCPStream objects will take the bytes
    # from each TCP packet and add them to the stream.  No error correction /
    # checksum checking will be done. The stream will just overwrite its bytes
    # with whatever is presented in the packets. If the stream receives packets
    # out of order, it will add the bytes at the proper index.
    net_pkt = None
    if pkt.haslayer(IP):
        net_pkt = pkt[IP]
    elif pkt.haslayer(IPv6):
        net_pkt = pkt[IPv6]
    else:
        print("Invalid network layer for packet:")
        pkt.show()
        return
    # we assume the parent function already checked to make sure this packet has a TCP layer
    tcp_pkt = pkt[TCP]
    stream_id = create_stream_id(net_pkt.src, net_pkt.dst, tcp_pkt.sport,
                                 tcp_pkt.dport)
    tcp_stream = tcp_streams.setdefault(stream_id, TCPStream(stream_id))
    # ^^^ like dict.get, but creates new entry if it doesn't exist
    in_order = tcp_stream.add(tcp_pkt)
    if in_order:  # if we just added something in order
        handle_stream(tcp_stream)
    #if PAUSE: input()


def create_stream_id(src, dst, sport, dport):
    s = "%s/%d" % (src, sport)
    d = "%s/%d" % (dst, dport)
    return "//".join([s, d])  # we use this for directional streams
    #return "//".join(sorted([s, d])) # we'd use this if we wanted bidirectional streams


class TCPStream:
    def __init__(self, key):
        self.key = key
        self.data = bytearray()
        self.seq = -1  # so we know seq hasn't been initialized yet
        self.later = {}  # data segments to add later
        # ^^^ {seq: payload, seq: payload, ...}

    def __repr__(self):
        return "Stream<%s>" % self.key

    def __len__(self):
        return len(self.data)

    def src(self):
        return self.key.split("/")[0]

    def dst(self):
        return self.key.split("/")[3]

    def sport(self):
        return int(self.key.split("/")[1])

    def dport(self):
        return int(self.key.split("/")[4])

    # returns true if we added an in-order segment, false if not
    def add(self, tcp_pkt):
        # if this is a new stream
        if self.seq == -1:
            # set initial seq
            self.seq = tcp_pkt.seq
        # grab payload bytes
        data = bytes(tcp_pkt.payload)
        data_len = len(data)
        seq_idx = tcp_pkt.seq - self.seq
        if len(self.data) < seq_idx:
            # if this data is out of order and needs to be inserted later
            self.later[seq_idx] = data
            return False
        else:
            # if this data is in order (has a place to be inserted)
            self.data[seq_idx:seq_idx + data_len] = data
            # check if there are any waiting data segments to add
            for seq_i in sorted(self.later.keys()):
                if seq_i <= len(
                        self.data):  # if we can add this segment to the stream
                    pl = self.later[seq_i]
                    self.data[seq_i:seq_i + len(pl)] = pl
                    del self.later[seq_i]  # remove from later dict
                else:
                    break  # short circuit because list is sorted
            return True

    def pop_magic(self):
        # if self.data starts with the http/2 magic bytes, pop them off
        magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        magic_len = len(magic)
        if self.data[:magic_len] == magic:
            self.data = self.data[magic_len:]
            self.seq += magic_len
            return magic
        return b""

    def pop_frames(self):
        # iterate over self.data and attempt to form HTTP/2 frames
        idx = 0
        frame_size = len(h2.H2Frame())
        frames = []
        while len(self.data) >= frame_size:
            try:
                frame_len = h2.H2Frame(self.data).len
            except AssertionError:  # when not enough data
                break
            except:
                # can't decode as a frame? what are we looking at?
                print("can't decode data into http/2 frame")
                hexdump(self.data)
                raise
            # if we've got a frame, but don't have all the data for it yet
            if frame_len > len(self.data):
                break  # without adding this frame
            # if we pop this frame, remove its data from self.data
            # and push self.seq up by len(frame)
            frame, self.data = h2.H2Frame(
                self.data[:frame_size + frame_len]), self.data[frame_size +
                                                               frame_len:]
            self.seq += frame_size + frame_len
            frames.append(frame)
        return frames


def handle_stream(tcp_stream):
    if tcp_stream.pop_magic():
        print("HTTP/2 magic bytes")
    # Does this tcp_stream contain an HTTP/2 frame?
    frames = tcp_stream.pop_frames()
    # if we get back an empty list, then the stream may have something else on
    # it, but I don't know what that would be right now
    if not frames:
        # this might be because we just got a HUGE frame and have to wait for
        # it to be reassembled, so check the first three bytes as a length
        # field and see if tcp_stream is shorter than this
        if len(tcp_stream) >= 3:
            len_bytes = struct.unpack("BBB", tcp_stream.data[:3])
            potential_len = (len_bytes[0] << 16) + (
                len_bytes[1] << 8) + len_bytes[2]
            # ^^^ this is big-endian for some reason
            if potential_len > len(tcp_stream):
                print("Received %d bytes of a %d-byte http/2 frame" %
                      (len(tcp_stream), potential_len))
                return
        print("%s doesn't appear to have an http/2 frame" % str(tcp_stream))
        hexdump(tcp_stream.data)
        return
    # each packet can store multiple frames -- we only care about data frames
    for frame in frames:
        print("New HTTP/2 frame")
        #print(frame.summary())
        if frame.fields.get("type", None) == 1:  # Header Frame
            print("%s opening stream %d for communication on port %d." %
                  (IP_TO_NAME.get(tcp_stream.src()), frame.stream_id,
                   tcp_stream.dport() if IP_TO_NAME.get(
                       tcp_stream.dst()) == "t2" else tcp_stream.sport()))
            if PAUSE: input()
        elif frame.fields.get("type", None) == 3:  # Reset Frame
            print("%s closing stream %d on port %d." %
                  (IP_TO_NAME.get(tcp_stream.src()), frame.stream_id,
                   tcp_stream.dport() if IP_TO_NAME.get(
                       tcp_stream.dst()) == "t2" else tcp_stream.sport()))
            if PAUSE: input()
        elif frame.fields.get("type", None) == 0:  # Data Frame
            try:
                frame.data  # for some reason, some malformed packets don't contain this data field
            except AttributeError:
                print(
                    "Received empty http/2 data frame on Stream %d on port %d"
                    % (frame.stream_id, tcp_stream.dport() if IP_TO_NAME.get(
                        tcp_stream.dst()) == "t2" else tcp_stream.sport()))
                if PAUSE: input()
                continue
            if len(frame.data) >= XpcWrapper.hdr_len and \
                    XpcWrapper.magic_bytes == int.from_bytes(frame.data[:4], 'little'):
                try:
                    wrapper, xpc_payload = XpcWrapper.from_bytes(frame.data)
                except AttributeError:  # happens with malformed/cropped packet
                    print("Error: Frame: " + str(frame.summary()) +
                          " Bytes: " + str(frame))
                # if we have a payload that matches the XPC header we're expecting:
                print(
                    "New XPC Packet {}->{} on HTTP/2 stream {:d} TCP port {:d}"
                    .format(
                        IP_TO_NAME.get(tcp_stream.src()),
                        IP_TO_NAME.get(tcp_stream.dst()), frame.stream_id,
                        tcp_stream.dport() if IP_TO_NAME.get(
                            tcp_stream.dst()) == "t2" else tcp_stream.sport()))
                print(wrapper)
                if xpc_payload and len(xpc_payload) > 8:
                    #hexdump(xpc_payload)
                    stream = XPCByteStream(xpc_payload)
                    x = XPC_Root(stream)
                    print(x)
                else:
                    print("No Payload.")
                if PAUSE: input()
            else:  # if we don't know what this payload is
                print(
                    "New Data frame {}->{} on HTTP/2 stream {:d} TCP port {:d}"
                    .format(
                        IP_TO_NAME.get(tcp_stream.src()),
                        IP_TO_NAME.get(tcp_stream.dst()), frame.stream_id,
                        tcp_stream.dport() if IP_TO_NAME.get(
                            tcp_stream.dst()) == "t2" else tcp_stream.sport()))
                hexdump(frame.data[:64])
                if len(frame.data) > 64:
                    print("... %d bytes" % len(frame.data))
                if PAUSE: input()


def create_packet():
    xpc_obj = XPC_Root(
        XPC_Dictionary({
            "MessageType": XPC_String("Heartbeat"),
            "SequenceNumber": XPC_Uint64(78789),
        }))
    xpc_bytes = xpc_obj.to_bytes()
    header = b'\x92\x0b\xb0)\x01\x01\x01\x00P\x00\x00\x00\x00\x00\x00\x00\x8bg\x02\x00\x00\x00\x00\x00'
    payload = header + xpc_bytes
    packet = h2.H2Frame(type=0, stream_id=1) / h2.H2DataFrame(data=payload)
    hexdump(packet)


if __name__ == "__main__":
    main()
