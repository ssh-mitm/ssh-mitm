# MOSH Protobuf Definitions

This directory contains the Protocol Buffer (`.proto`) definitions for the MOSH protocol,
along with the generated Python modules used by `sshmitm/apps/mosh.py`.

## Files

| File | Description |
|---|---|
| `transportinstruction.proto` | Outer transport envelope (`TransportBuffers.Instruction`) |
| `userinput.proto` | Client → Server: keystrokes and terminal resize events |
| `hostinput.proto` | Server → Client: host output, resize, echo-ack |
| `transportinstruction_pb2.py` | Generated Python module (do not edit manually) |
| `userinput_pb2.py` | Generated Python module (do not edit manually) |
| `hostinput_pb2.py` | Generated Python module (do not edit manually) |

## Compiling the `.proto` files

Install the compiler (once, into the project virtualenv):

```bash
pip install grpcio-tools
```

Regenerate all `_pb2.py` files from within this directory:

```bash
cd sshmitm/data/mosh
python -m grpc_tools.protoc -I. --python_out=. \
    transportinstruction.proto userinput.proto hostinput.proto
```

> The generated files are checked into the repository so that `protoc` / `grpcio-tools`
> is not required at runtime — only `protobuf` (the Python runtime) is needed.

## Runtime dependency

Add `protobuf` to `requirements.in`:

```
protobuf
```

## Protocol overview

Every encrypted MOSH UDP datagram (after AES-OCB3 decryption and header stripping) is a
serialised `TransportBuffers.Instruction`. The `diff` field inside that instruction contains
the actual payload:

* **Client → Server** (`userinput.proto`): `ClientBuffers.UserMessage`
  — repeated `Instruction` records, each carrying a `Keystroke` or `ResizeMessage` extension.
* **Server → Client** (`hostinput.proto`): `HostBuffers.HostMessage`
  — repeated `Instruction` records, each carrying a `HostBytes`, `ResizeMessage`, or `EchoAck`
  extension.

Multi-fragment messages (high bit of `fragment_num` set = final fragment) must be reassembled
before the Protobuf bytes are parsed; this is handled by `UdpProxy._handle_fragment()`.

The reassembled bytes are zlib-compressed before they are a valid Protobuf message.
`_decode_transport_instruction()` detects the zlib magic header (`0x78 0x9c / 0xda / 0x01`)
and calls `zlib.decompress()` before passing the bytes to the Protobuf parser.
