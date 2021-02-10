entry_points = {
    'TcpProxyChain': [
        'forwardchain = tcp_proxy_server.chains:TcpProxyForwardChain'
    ],
    'TcpProxyManager': [
        'singleproxy = tcp_proxy_server.proxymanager:SingleProxyManager'
    ],
    'TcpProxyForwarder': [
        'simple = tcp_proxy_server.forwarders:SimpleForwarder',
        'tproxy = tcp_proxy_server.forwarders:TProxyForwarder',
        'socks5 = tcp_proxy_server.forwarders:Socks5Forwarder',
        'echo = tcp_proxy_server.forwarders:EchoForwarder'
    ],
    'TcpProxyHandler': [
        'save = tcp_proxy_server.handlers:TcpProxySaveHandler',
        'hexdump = tcp_proxy_server.handlers:TcpProxyHexDump',
        'drop = tcp_proxy_server.handlers:TcpProxyDropHandler',
        'wait = tcp_proxy_server.handlers:TcpProxyWaitHandler'
    ]
}