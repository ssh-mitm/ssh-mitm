from sshmitm.core.modules import SSHMITMBaseModule


class LocalPortForwardingBaseForwarder(SSHMITMBaseModule):
    """Sets the interface for handling client-side tunnel operations, such as local port forwarding."""


class RemotePortForwardingBaseForwarder(SSHMITMBaseModule):
    """Configures the interface for managing server-side tunnel operations, such as remote port forwarding."""
