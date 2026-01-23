import base64
import hashlib
from typing import Optional

from paramiko import ECDSAKey, Ed25519Key, PKey, RSAKey


class SSHPubKey:
    """
    A wrapper class for SSH public keys that provides parsing and fingerprint utilities.

    This class supports RSA, ECDSA, and Ed25519 SSH key types and can load
    public keys from the OpenSSH text format. It also offers convenient methods
    to calculate cryptographic fingerprints.
    """

    def __init__(self, key: PKey, comment: Optional[str] = None) -> None:
        """
        Initialize an SSH public key wrapper.

        :param key: A Paramiko public key object.
        :param comment: An optional comment associated with the key.
        """
        self.key = key
        self.comment = comment

    @classmethod
    def from_ssh_line(cls, line: str) -> "SSHPubKey":
        """
        Load a public SSH key from a single OpenSSH-formatted line.

        The expected format is ``<type> <base64-encoded-key> [comment]``.

        :param line: A single line of text containing an SSH public key.
        :returns: An initialized :class:`SSHPubKey` instance.
        :raises ValueError: If the line is empty, commented, or contains an unknown key type.
        """
        line = line.strip()
        if not line or line.startswith("#"):
            err_msg = "Empty or commented line cannot be loaded"
            raise ValueError(err_msg)

        parts = line.split(None, 2)
        if len(parts) < 2:
            raise ValueError("Invalid SSH line: " + line)

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
            err_msg = f"Unknown key type: {key_type}"
            raise ValueError(err_msg)

        return cls(key_obj, comment)

    def hash_md5(self) -> str:
        """
        Calculate the MD5 fingerprint of the key.

        The result follows the format used in RFC4716, section 4.

        :returns: The MD5 fingerprint string in the form ``MD5:xx:xx:...``.
        """
        fp_plain = hashlib.md5(self.key.asbytes(), usedforsecurity=False).hexdigest()
        return "MD5:" + ":".join(
            a + b for a, b in zip(fp_plain[::2], fp_plain[1::2], strict=False)
        )

    def hash_sha256(self) -> str:
        """
        Calculate the SHA-256 fingerprint of the key.

        :returns: The SHA-256 fingerprint string in the form ``SHA256:<base64>``.
        """
        fp_plain = hashlib.sha256(self.key.asbytes()).digest()
        return (b"SHA256:" + base64.b64encode(fp_plain).replace(b"=", b"")).decode(
            "utf-8"
        )

    def hash_sha512(self) -> str:
        """
        Calculate the SHA-512 fingerprint of the key.

        :returns: The SHA-512 fingerprint string in the form ``SHA512:<base64>``.
        """
        fp_plain = hashlib.sha512(self.key.asbytes()).digest()
        return (b"SHA512:" + base64.b64encode(fp_plain).replace(b"=", b"")).decode(
            "utf-8"
        )

    def get_name(self) -> str:
        """
        Return the SSH key algorithm name.

        :returns: The key type name (e.g., ``ssh-rsa`` or ``ssh-ed25519``).
        """
        return self.key.get_name()

    def get_bits(self) -> int:
        """
        Return the key size in bits.

        :returns: The key length as an integer.
        """
        return self.key.get_bits()

    def get_base64(self) -> str:
        """
        Return the Base64-encoded representation of the key.

        :returns: The Base64-encoded public key data as a string.
        """
        return self.key.get_base64()

    def can_sign(self) -> bool:
        """
        Check whether the key is capable of performing signing operations.

        :returns: True if the key can sign, False otherwise.
        """
        return self.key.can_sign()
