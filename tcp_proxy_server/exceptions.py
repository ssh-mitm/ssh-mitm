class TcpProxyModuleError(Exception):
    pass


class TcpProxyPubKeyPinError(Exception):
    pass


class TooManyForwarders(Exception):
    pass


class Socks5Error(Exception):
    pass


class TcpProxyHandlerException(Exception):
    pass


class CertificateMissingException(Exception):
    def __init__(self, path):
        self.certificate_path = path
