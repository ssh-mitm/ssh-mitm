import base64
import hashlib
from typing import Optional

from paramiko import ECDSAKey, Ed25519Key, PKey, RSAKey


class SSHPubKey:

    def __init__(self, key: PKey, comment: Optional[str] = None) -> None:
        self.key = key
        self.comment = comment

    @classmethod
    def from_ssh_line(cls, line: str) -> "SSHPubKey":
        """Loads a public SSH key from a line in the format '<type> <base64> [comment]'"""
        line = line.strip()
        if not line or line.startswith("#"):
            err_msg = "Empty or commented line cannot be loaded"
            raise ValueError(err_msg)

        parts = line.split(None, 2)
        if len(parts) < 2:
            raise ValueError("Ungültige SSH-Zeile: " + line)

        key_type, key_data = parts[0], parts[1]
        comment: Optional[str] = parts[2] if len(parts) == 3 else None
        key_bytes = base64.b64decode(key_data)

        key_obj: PKey
        if key_type == "ssh-rsa":
            key_obj = RSAKey(data=key_bytes)
        elif key_type.startswith("ecdsa-sha2-"):
            key_obj = ECDSAKey(data=key_bytes)
        elif key_type == "ssh-ed25519":
            key_obj = Ed25519Key(data=key_bytes)
        else:
            err_msg = f"Unbekannter Key-Typ: {key_type}"
            raise ValueError(err_msg)

        return cls(key_obj, comment)

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

    def get_name(self) -> str:
        return self.key.get_name()

    def get_bits(self) -> int:
        return self.key.get_bits()

    def get_base64(self) -> str:
        return self.key.get_base64()

    def can_sign(self) -> bool:
        return self.key.can_sign()
