# Apple T2 XPC
This project is an exploration of the network communications between macOS and
the T2 chip. It can be used to decode and print the XPC messages, and provides
an example of building a protocol-compliant client to communicate with a
service on the T2 chip.

More information can be found in [our report](https://duo.com/labs/research/apple-t2-xpc).

### Install

This is a Python3 project.

#### Python 3.6

One of the changes in 3.7 was how python handles multiple inheritance,
particularly with method resolution order (MRO). Because the h2 library has a
bug with this new method resolution order, we need to use Python 3.6.

On a mac, to do this we need to use pyenv. (use `brew` to install it if you don't have it)
`pyenv install 3.6.7`

And then every time you want to run it (or pip3 install stuff), you'll need to
run this from the project directory:
`eval "$(pyenv init -)"`

#### pip3 stuff

To install, you will need to install:
```pip3 install -r requirements.txt```

#### h2 module

The hyper-h2 module is HTTP/2 spec-compliant. Unfortuantely, Apple
communications are not. We have included a slightly-modified copy
of the h2 module, still under its original MIT license.

### Running it

There are currently two main utilities contained in this repo:
- `vhc128sniff.py` will listen on the VHC128 interface and decode as many XPC messages as it can between the t2 chip and the mac. It can also be run with the `-f` flag and a file path to read from a tcpdump-format packet capture.
- `sysdiagnose_client.py` will attempt to connect to the t2 chip and initiate a sysdiagnose connection.


