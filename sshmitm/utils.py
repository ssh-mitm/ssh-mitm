import base64
import binascii
import hashlib
import sys

from paramiko import PKey

__all__ = ["SSHPubKey", "format_hex", "metadata", "resources"]

if sys.version_info >= (3, 10):
    from importlib import metadata, resources
else:
    import importlib_metadata as metadata
    import importlib_resources as resources


def format_hex(data: bytes, hexwidth: int = 19) -> str:
    """
    Format the data in hexadecimal format.

    :param data: Data to be formatted
    :param hexwidth: Width of hexadecimal data (default 19)
    :return: Formatted hexadecimal data
    """
    result = []
    for i in range(0, len(data), hexwidth):
        data_part = data[i : i + hexwidth]
        hexa = list(
            map(
                "".join,
                zip(*[iter(binascii.hexlify(data_part).decode("utf-8"))] * 2),
            )
        )
        while hexwidth - len(hexa) > 0:
            hexa.append(" " * 2)
        text = "".join([chr(x) if 0x20 <= x < 0x7F else "." for x in data_part])
        addr = "{:04X}:    {}    {}".format(  # pylint: disable=consider-using-f-string
            i,
            " ".join(hexa),
            text,
        )
        result.append(addr)

    return "\n".join(result)


class SSHPubKey:

    def __init__(self, key: PKey) -> None:
        self.key = key

    def hash_md5(self) -> str:
        """Calculate md5 fingerprint.

        For specification, see RFC4716, section 4."""
        fp_plain = hashlib.md5(self.key.asbytes(), usedforsecurity=False).hexdigest()
        return "MD5:" + ":".join(a + b for a, b in zip(fp_plain[::2], fp_plain[1::2]))

    def hash_sha256(self) -> str:
        """Calculate sha256 fingerprint."""
        fp_plain = hashlib.sha256(self.key.asbytes()).digest()
        return (b"SHA256:" + base64.b64encode(fp_plain).replace(b"=", b"")).decode(
            "utf-8"
        )

    def hash_sha512(self) -> str:
        """Calculates sha512 fingerprint."""
        fp_plain = hashlib.sha512(self.key.asbytes()).digest()
        return (b"SHA512:" + base64.b64encode(fp_plain).replace(b"=", b"")).decode(
            "utf-8"
        )
