from google.protobuf.internal.containers import RepeatedCompositeFieldContainer
from google.protobuf.internal.extension_dict import _ExtensionFieldDescriptor
from google.protobuf.message import Message

class Keystroke(Message):
    keys: bytes

class ResizeMessage(Message):
    width: int
    height: int

class Instruction(Message): ...

class UserMessage(Message):
    instruction: RepeatedCompositeFieldContainer[Instruction]

keystroke: _ExtensionFieldDescriptor[Instruction, Keystroke]
resize: _ExtensionFieldDescriptor[Instruction, ResizeMessage]
