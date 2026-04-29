from google.protobuf.message import Message

class Instruction(Message):
    protocol_version: int
    old_num: int
    new_num: int
    ack_num: int
    throwaway_num: int
    diff: bytes
    chaff: bytes
