class NoAgentKeys(Exception):
    """
    Exception raised when there are no private keys available for authentication.
    """


class NoAgentException(Exception):
    """
    Exception raised when an attempt to access the ssh-agent fails.
    """


class InvalidHostKey(Exception):
    """
    Exception raised when an invalid host key is encountered.
    """


class MissingHostException(Exception):
    """
    Exception raised when the specified host cannot be found.
    """


class KeyGenerationError(Exception):
    """
    Exception raised when an error occurs during key generation.
    """


class MissingClient(Exception):
    """
    Exception raised when a client cannot be found for a given host.
    """
