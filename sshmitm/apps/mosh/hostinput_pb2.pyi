from google.protobuf.internal.containers import RepeatedCompositeFieldContainer
from google.protobuf.internal.extension_dict import _ExtensionFieldDescriptor
from google.protobuf.message import Message

class HostBytes(Message):
    hoststring: bytes

class ResizeMessage(Message):
    width: int
    height: int

class EchoAck(Message):
    echo_ack_num: int

class Instruction(Message): ...

class HostMessage(Message):
    instruction: RepeatedCompositeFieldContainer[Instruction]

hostbytes: _ExtensionFieldDescriptor[Instruction, HostBytes]
resize: _ExtensionFieldDescriptor[Instruction, ResizeMessage]
echoack: _ExtensionFieldDescriptor[Instruction, EchoAck]
