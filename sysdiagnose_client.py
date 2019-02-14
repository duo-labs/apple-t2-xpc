#!/usr/bin/env python3.6

# This script originated from the example here:
# https://github.com/python-hyper/hyper-h2/blob/621dc4ba64a1e06750812094d86df6eca5d76fd9/examples/twisted/twisted-server.py
# which was licensed under the MIT license, included here.
#
# The MIT License (MIT)
#
# Copyright (c) 2015-2016 Cory Benfield and contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Modifications are provided under the BSD-3 license provided in this
# repository. Copyright (c) 2019, Duo Labs

#####
# To make modifications to the XPC request sent to the sysdiagnose server,
# look at the getXPCObject() method near the bottom of this file
#####

import sys
import subprocess
import struct
import hexdump

from twisted.internet import reactor, defer
from twisted.internet.endpoints import connectProtocol, TCP4ClientEndpoint
from twisted.internet.protocol import Protocol
from h2.connection import H2Connection
from h2.events import (
    ResponseReceived,
    DataReceived,
    StreamEnded,
    StreamReset,
)

from xpc_types import *
from xpc_wrapper import XpcWrapper

DUMP_FILE = True

# phases of sysdiagnose client
# 1) "init" - never receives packets
#    open [1,3], send initial messages, send XPC object
# 2) "wait"
#    ignore empty messages on streams [1,3],
#    listen for RESPONSE_TYPE=1 message and new open stream,
#    open new stream
# 3) "accept"
#    grab tons of data from new stream until empty packet,
#    send empty packet then close


# the connectionMade() and dataReceived() methods are registered as callbacks
# if reading through the code for the first time, start reading from those
# methods
class SysdiagnoseProtocol(Protocol):
    def __init__(self):
        self.h2conn = H2Connection()
        self.file_tx_size = -1
        self.bytes_received = 0
        self.sysdiagnose_bytes = []  # list of bytestrings
        self.sysdiagnose_filename = ""
        # state vars
        self.accept_phase = False  # determines whether we are in "wait" phase or "accept" phase
        self.response_received = False
        self.file_stream_open = False

    # this will get a callback immediately -- start here
    def connectionMade(self):
        """
        Called by Twisted when the TCP connection is established. We can start
        sending some data now: we should open with the connection preamble.
        """
        self.h2conn.initiate_connection()
        # "init" state -- open streams and send the initial request
        print("Opening stream 1 with empty dictionary")
        self.openStreamDict(1, 0)
        print("Opening stream 3 with empty payload")
        self.openStreamEmptyNoUse(3, 0)
        self.makeXPCRequest(1)

        self.transport.write(self.h2conn.data_to_send())

    def makeXPCRequest(self, stream_idx):
        xpc_obj = getXPCObject()
        xpc_bytes = xpc_obj.to_bytes()
        header = XpcWrapper(XpcWrapper.magic_bytes, 0x101, len(xpc_bytes), 1)
        header_bytes = bytes(header)
        payload = header_bytes + xpc_bytes
        print("Sending XPC object on stream %d:" % stream_idx)
        print(header)
        print(xpc_obj)
        self.h2conn.send_data(stream_idx, payload)

    def openStreamEmptyNoUse(self, stream_idx, msg_id):
        # open stream
        self.h2conn.send_headers(stream_idx, [])

        header = XpcWrapper(XpcWrapper.magic_bytes, 0x400001, 0, msg_id)
        header_bytes = bytes(header)
        print("Sending " + str(header))
        self.h2conn.send_data(stream_idx, header_bytes)

    def openStreamForFileTX(self, stream_idx, msg_id):
        # open stream
        self.h2conn.send_headers(stream_idx, [])
        # no payload
        header = XpcWrapper(XpcWrapper.magic_bytes, 0x200001, 0, msg_id)
        header_bytes = bytes(header)
        print("Sending " + str(header))
        self.h2conn.send_data(stream_idx, header_bytes)

    def openStreamDict(self, stream_idx, msg_id):
        # open stream
        self.h2conn.send_headers(stream_idx, [])

        xpc_obj = XPC_Root(XPC_Dictionary({}))
        xpc_bytes = xpc_obj.to_bytes()
        header = XpcWrapper(XpcWrapper.magic_bytes, 0x1, len(xpc_bytes),
                            msg_id)
        header_bytes = bytes(header)
        payload = header_bytes + xpc_bytes
        print("Sending " + str(header) + "\n" + str(xpc_obj))
        self.h2conn.send_data(stream_idx, payload)

    # this is where we will get a callback each time our connection
    # receives data from the sysdiagnose server
    def dataReceived(self, data):
        """
        Called by Twisted when data is received on the connection.

        We want to pass the data to the protocol stack and check what
        events occurred.
        """
        events = self.h2conn.receive_data(data)
        for event in events:
            if isinstance(event, DataReceived):
                self.handleData(event)  # Everything is done here
            elif isinstance(event, ResponseReceived):
                print("T2 opened stream %d" % event.stream_id)
            elif isinstance(event, StreamEnded):
                self.endStream(event)
            elif isinstance(event, StreamReset):
                reactor.stop()
                raise RuntimeError("Stream reset: %d" % event.error_code)

        # the h2 library works by "sending" data on the h2conn, which
        # is really just a state machine.
        # data_to_send() returns the data that should be sent,
        # along with all the proper HTTP/2 packets
        data = self.h2conn.data_to_send()
        if data:
            self.transport.write(data)

    def handleData(self, event):
        """
        This is called every time we receive a data frame
        """

        # inform our h2connection that we have received N bytes and the space
        # should be handed back to the remote side at an opportune time
        self.h2conn.acknowledge_received_data(len(event.data), event.stream_id)

        data = event.data
        stream_id = event.stream_id

        if not self.accept_phase:  # "wait" phase
            if stream_id == 1:
                # this is the RESPONSE_TYPE=1 message. Maybe we should validate
                # this, but I don't think we need to do so right now, so we're just
                # gonna ignore it
                xpc_wrapper, data = XpcWrapper.from_bytes(data)
                if xpc_wrapper == None:
                    return
                xpc_stream = XPCByteStream(data)
                xpc_obj = XPC_Root(xpc_stream)
                response = xpc_obj.value.value.get("RESPONSE_TYPE", None)
                if response == None:
                    return
                print("Received XPC object on stream %d:" % stream_id)
                print(xpc_wrapper)
                print(xpc_obj)
                # we need to get the number of bytes to be transferred and the filename
                self.file_tx_size = xpc_obj.value.value[
                    "FILE_TX"].transfer_size
                self.sysdiagnose_filename = xpc_obj.value.value[
                    "FILE_NAME"].value
                self.response_received = True
            elif stream_id == 2:
                # we need to open stream 2 and then send an empty reply with the
                # correct msg_id so the data transfer can start
                xpc_wrapper, data = XpcWrapper.from_bytes(data)
                if xpc_wrapper == None:
                    return
                if not xpc_wrapper.flags == 0x100001:
                    return
                print("Received XPC object on stream %d:" % stream_id)
                print(xpc_wrapper)
                msg_id = xpc_wrapper.msg_id
                print("Opening stream %d for file transfer, msg_id=%d" %
                      (stream_id, msg_id))
                self.openStreamForFileTX(stream_id, msg_id)
                self.file_stream_open = True
            else:  # we don't care about any messages on any other stream
                return

            if self.response_received and self.file_stream_open:
                print("moving to accept phase")
                self.accept_phase = True

        else:  # "accept" phase
            # we should only be getting messages on stream 2 until we get an
            # empty frame
            if stream_id != 2:
                return
            if len(data) > 0:
                print("New data frame on stream %d:" % stream_id)
                hexdump.hexdump(data[:32])
                self.bytes_received += len(data)
                print("%d bytes of %d" % (self.bytes_received,
                                          self.file_tx_size))
                if DUMP_FILE:
                    self.sysdiagnose_bytes.append(data)
            else:
                self.h2conn.end_stream(stream_id)
                self.h2conn.send_data(1, b"")
                if DUMP_FILE:
                    # write out sysdiagnose file
                    with open(self.sysdiagnose_filename, "wb") as f:
                        for b in self.sysdiagnose_bytes:
                            f.write(b)
                self.endConnection()

    def endConnection(self):
        self.h2conn.close_connection()
        self.transport.write(self.h2conn.data_to_send())
        self.transport.loseConnection()

    def endStream(self, event):
        """
        We call this when the stream is cleanly ended by the remote peer. That
        means that the response is complete.

        """
        if event.stream_id == 2:  # skip ending stream2 because we don't open it properly
            return
        self.h2conn.end_stream(event.stream_id)

    def connectionLost(self, reason=None):
        """
        Called by Twisted when the connection is gone. Regardless of whether
        it was clean or not, we want to stop the reactor.
        """
        if reactor.running:
            reactor.stop()


def getXPCObject():
    # yapf: disable
    xpc_obj = XPC_Root(
        XPC_Dictionary({
            "REQUEST_TYPE": XPC_Uint64(1),
            #"rootPath": XPC_String("/"),
            "archiveName": XPC_String("testArchiveName.tar.gz"),
        }))
    # yapf: enable
    return xpc_obj


def main():
    REMOTECTL_BINARY = '/usr/libexec/remotectl'
    TARGET_CLASS = "com.apple.sysdiagnose.remote"

    port = int(
        subprocess.check_output(
            [REMOTECTL_BINARY, 'relay', 'localbridge', TARGET_CLASS]))

    connectProtocol(
        TCP4ClientEndpoint(reactor, "127.0.0.1", port), SysdiagnoseProtocol())
    reactor.run()


if __name__ == "__main__":
    main()
