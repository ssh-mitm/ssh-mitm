# pylint: disable=too-many-arguments
import datetime
import hashlib
import logging
from threading import Thread
from typing import Optional

import requests


class LogForwarder:
    """
    The constructed payload aims to fulfill field definition as defined by the Elastic Common Schema (https://www.elastic.co/docs/reference/ecs/ecs-field-reference).
    """

    def __init__(
        self,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        log_webhook_dest: Optional[str] = None,
    ) -> None:
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port

        self.log_webhook_dest = log_webhook_dest

        self.username = None
        self.password = None
        self.cipher = None

        self.server_server_extensions = None
        self.server_proto_version = None
        self.server_software_version = None
        self.server_preferred_ciphers = None
        self.server_preferred_kex = None
        self.server_preferred_macs = None
        self.server_preferred_compression = None
        self.server_hassh = None

        self.client_server_extensions = None
        self.client_proto_version = None
        self.client_software_version = None
        self.client_preferred_ciphers = None
        self.client_preferred_kex = None
        self.client_preferred_macs = None
        self.client_preferred_compression = None
        self.client_hassh = None

    def set_credentials(self, username: str, password: str) -> None:
        self.username = username
        self.password = password

    def set_cipher(self, cipher: str) -> None:
        self.cipher = cipher

    def set_server_transport_metadata(
        self,
        server_extensions: str,
        proto_version: str,
        software_version: str,
        preferred_ciphers: tuple,
        preferred_kex: tuple,
        preferred_macs: tuple,
        preferred_compression: tuple,
    ) -> None:
        self.server_server_extensions = server_extensions
        self.server_proto_version = proto_version
        self.server_software_version = software_version
        self.server_preferred_ciphers = ",".join(preferred_ciphers)
        self.server_preferred_kex = ",".join(preferred_kex)
        self.server_preferred_macs = ",".join(preferred_macs)
        self.server_preferred_compression = ",".join(preferred_compression)
        # hassh as defined here: https://github.com/salesforce/hassh
        # ruff: noqa: S324
        self.server_hassh = hashlib.md5(  # nosec
            f"{self.server_preferred_ciphers};{self.server_preferred_kex};{self.server_preferred_macs};{self.server_preferred_compression}".encode(
                "utf-8"
            )
        ).hexdigest()

    def set_client_transport_metadata(
        self,
        server_extensions: str,
        proto_version: str,
        software_version: str,
        preferred_ciphers: tuple,
        preferred_kex: tuple,
        preferred_macs: tuple,
        preferred_compression: tuple,
    ) -> None:
        self.client_server_extensions = server_extensions
        self.client_proto_version = proto_version
        self.client_software_version = software_version
        self.client_preferred_ciphers = ",".join(preferred_ciphers)
        self.client_preferred_kex = ",".join(preferred_kex)
        self.client_preferred_macs = ",".join(preferred_macs)
        self.client_preferred_compression = ",".join(preferred_compression)
        # hassh as defined here: https://github.com/salesforce/hassh
        # ruff: noqa: S324
        self.client_hassh = hashlib.md5(  # nosec
            f"{self.client_preferred_ciphers};{self.client_preferred_kex};{self.client_preferred_macs};{self.client_preferred_compression}".encode(
                "utf-8"
            )
        ).hexdigest()

    def __build_payload(
        self,
        event_outcome: str,
        client_msg: Optional[str] = None,
        client_msg_err: Optional[str] = None,
        server_msg: Optional[str] = None,
        server_msg_err: Optional[str] = None,
    ) -> dict:
        current_timestamp = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
        return {
            # Using current timestamp in @timestamp, because we don't have access to the actual creation timestamp of the ssh action from the source side.
            "@timestamp": current_timestamp,
            "event": {
                "created": current_timestamp,
                "outcome": event_outcome,
            },
            "ssh": {
                # The SSH payload body is based on the following sources:
                # - Suricata: https://docs.suricata.io/en/suricata-6.0.16/output/eve/eve-json-format.html#event-type-ssh
                # - Elastic Common Schema: https://www.elastic.co/docs/reference/ecs/ecs-field-reference
                "cipher": self.cipher,
                "client": {
                    "proto_version": self.client_proto_version,
                    "software_version": self.client_software_version,
                    "preferred_kex": self.client_preferred_kex,
                    "preferred_ciphers": self.client_preferred_ciphers,
                    "preferred_macs": self.client_preferred_macs,
                    "preferred_compression": self.client_preferred_compression,
                    "hassh": self.client_hassh,
                    "message": client_msg,
                    "error_message": client_msg_err,
                },
                "server": {
                    "proto_version": self.server_proto_version,
                    "software_version": self.server_software_version,
                    "preferred_kex": self.server_preferred_kex,
                    "preferred_ciphers": self.server_preferred_ciphers,
                    "preferred_macs": self.server_preferred_macs,
                    "preferred_compression": self.server_preferred_compression,
                    "hassh": self.server_hassh,
                    "message": server_msg,
                    "error_message": server_msg_err,
                },
            },
            "client": {
                "ip": self.client_ip,
                "port": self.client_port,
            },
            "server": {
                "ip": self.server_ip,
                "port": self.server_port,
                "user": {
                    "name": self.username,
                    "password": self.password,
                },
            },
        }

    def forward_client_msg(self, client_msg: str) -> None:
        if self.log_webhook_dest is None:
            return

        payload = self.__build_payload(
            client_msg=client_msg,
            event_outcome="success",
        )
        payload = payload | {
            "destination": {"ip": self.server_ip, "port": self.server_port},
            "source": {"ip": self.client_ip, "port": self.client_port},
        }
        thread = Thread(
            target=LogForwarder.__send_payload, args=(self.log_webhook_dest, payload)
        )
        thread.start()

    def forward_server_msg(self, server_msg: str, client_msg: str) -> None:
        if self.log_webhook_dest is None:
            return

        payload = self.__build_payload(
            client_msg=client_msg,
            event_outcome="success",
            server_msg=server_msg,
        )
        payload = payload | {
            "destination": {"ip": self.client_ip, "port": self.client_port},
            "source": {"ip": self.server_ip, "port": self.server_port},
        }
        thread = Thread(
            target=LogForwarder.__send_payload, args=(self.log_webhook_dest, payload)
        )
        thread.start()

    def forward_client_error_message(
        self, client_msg_err: str, server_msg: str
    ) -> None:
        if self.log_webhook_dest is None:
            return

        payload = self.__build_payload(
            client_msg_err=client_msg_err,
            event_outcome="failure",
            server_msg=server_msg,
        )
        payload = payload | {
            "source": {"ip": self.client_ip, "port": self.client_port},
            "destination": {"ip": self.server_ip, "port": self.server_port},
        }
        thread = Thread(
            target=LogForwarder.__send_payload, args=(self.log_webhook_dest, payload)
        )
        thread.start()

    def forward_server_error_message(
        self, client_msg: str, server_msg_err: str
    ) -> None:
        if self.log_webhook_dest is None:
            return

        payload = self.__build_payload(
            client_msg=client_msg,
            event_outcome="failure",
            server_msg_err=server_msg_err,
        )
        payload = payload | {
            "destination": {"ip": self.client_ip, "port": self.client_port},
            "source": {"ip": self.server_ip, "port": self.server_port},
        }
        thread = Thread(
            target=LogForwarder.__send_payload, args=(self.log_webhook_dest, payload)
        )
        thread.start()

    @staticmethod
    def __send_payload(webhook_dst: str, payload: dict) -> None:
        """
        Send the payload to the webhook destination.
        """
        try:
            response = requests.post(webhook_dst, json=payload, timeout=10)
        except requests.exceptions.RequestException as err:
            # Report transmit exception in STDOUT and don't enforce the parent thread to terminate.
            # ruff: noqa: TRY401
            logging.exception(err)
            return

        logging.debug("Webhook sent to %s", webhook_dst)

        if response.status_code >= 400:
            logging.error(
                "Webhook failed with status code %s. Response: %s",
                response.status_code,
                response.text,
            )
