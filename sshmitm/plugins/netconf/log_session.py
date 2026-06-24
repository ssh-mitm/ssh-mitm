"""NETCONF session-logging plugin.

Logs every RPC operation (operation name + message-id) and every RPC reply
(message-id + ok / error-tag list) to the sshmitm logger.  All messages are
forwarded transparently — nothing is modified.

Enable with::

    ssh-mitm server --netconf-forwarder log-session ...
"""

import logging
import xml.etree.ElementTree as ET

from sshmitm.forwarders.netconf import NetconfBaseForwarder


class NetconfLoggingForwarder(NetconfBaseForwarder):
    """Log all NETCONF RPC operations and replies; forward everything unchanged."""

    def handle_rpc_request(
        self,
        message_id: str,
        operation: str,
        element: ET.Element,
    ) -> ET.Element | None:
        logging.info(
            "NETCONF RPC  [session=%s message-id=%s op=%s]",
            self.session.sessionid,
            message_id,
            operation,
        )
        return None

    def handle_rpc_reply(
        self,
        message_id: str,
        element: ET.Element,
    ) -> ET.Element | None:
        ns = "urn:ietf:params:xml:ns:netconf:base:1.0"
        errors = element.findall(f"{{{ns}}}rpc-error")
        if errors:
            tags = [e.findtext(f"{{{ns}}}error-tag", "unknown") for e in errors]
            logging.warning(
                "NETCONF reply[session=%s message-id=%s error(s)=%s]",
                self.session.sessionid,
                message_id,
                ",".join(str(t) for t in tags),
            )
        else:
            logging.info(
                "NETCONF reply[session=%s message-id=%s ok]",
                self.session.sessionid,
                message_id,
            )
        return None
