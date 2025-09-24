import logging
import re
import time
from typing import Optional

import paramiko

from sshmitm.forwarders.scp import SCPBaseForwarder


class NetconfBaseForwarder(SCPBaseForwarder):
    __netconf_terminator = b"]]>]]>"

    @property
    def client_channel(self) -> Optional[paramiko.Channel]:
        return self.session.netconf_channel

    def read_netconf_data(self, chan: paramiko.Channel, responses: int = 1) -> bytes:
        """
        Netconf messages must be read until a terminator or complete chunk is seen.
        Supports both NETCONF 1.0 (]]>]]>) and NETCONF 1.1 (chunked encoding).
        A netconf message can be larger than the supported buffer length.
        """

        response_buf = b""
        terminators_found = 0
        max_iterations = 1000  # Prevent infinite loops
        iterations = 0
        
        logging.debug("DEBUG: read_netconf_data starting - expecting %d responses", responses)
        
        while terminators_found < responses and iterations < max_iterations:
            iterations += 1
            time.sleep(0.05)
            
            logging.debug("DEBUG: read_netconf_data iteration %d - terminators_found=%d, responses=%d", 
                         iterations, terminators_found, responses)
            
            if not chan.recv_ready():
                logging.debug("DEBUG: read_netconf_data - no data ready")
                # No data available, but check if we already have complete messages
                if terminators_found >= responses:
                    logging.debug("DEBUG: read_netconf_data - breaking due to sufficient terminators")
                    break
                # For NETCONF 1.1, check if we have complete chunked messages
                if self._has_complete_netconf11_messages(response_buf, responses):
                    logging.debug("DEBUG: read_netconf_data - breaking due to complete NETCONF 1.1 messages")
                    terminators_found = responses  # Mark as complete
                    break
                continue
                
            response = chan.recv(self.BUF_LEN)
            logging.debug("DEBUG: read_netconf_data - received %d bytes: %s", 
                         len(response), response[:100] if response else b"<empty>")
            
            if not response:  # Empty response, connection might be closing
                logging.debug("DEBUG: read_netconf_data - empty response, breaking")
                break
                
            response_buf += response
            
            # Check for NETCONF 1.0 terminators
            new_terminators = response.count(self.__netconf_terminator)
            if new_terminators > 0:
                terminators_found += new_terminators
                logging.debug("DEBUG: read_netconf_data - found %d NETCONF 1.0 terminators, total=%d", 
                             new_terminators, terminators_found)
            
            # Check for NETCONF 1.1 complete messages
            if self._has_complete_netconf11_messages(response_buf, responses):
                logging.debug("DEBUG: read_netconf_data - found complete NETCONF 1.1 messages")
                terminators_found = responses  # Mark as complete
                break

        logging.debug("DEBUG: read_netconf_data completed - iterations=%d, terminators_found=%d, buffer_len=%d", 
                     iterations, terminators_found, len(response_buf))
        return response_buf

    def _has_complete_netconf11_messages(self, data: bytes, expected_messages: int) -> bool:
        """
        Check if the buffer contains complete NETCONF 1.1 chunked messages.
        NETCONF 1.1 format: \n#<size>\n<data>\n##\n
        """
        if not data:
            return False
            
        # Count complete NETCONF 1.1 messages by counting end markers
        # A complete NETCONF 1.1 message ends with ##\n
        complete_messages = data.count(b'\n##\n')
        
        logging.debug("DEBUG: Found %d complete NETCONF 1.1 end markers in buffer", complete_messages)
        return complete_messages >= expected_messages

    def _clean_netconf_message(self, data: bytes) -> str:
        """
        Clean NETCONF message for logging by removing NETCONF 1.1 chunk markers
        and extra whitespace while preserving the actual XML content.
        """
        try:
            message = data.decode("utf-8")
            
            # Check if this is NETCONF 1.1 chunked format (contains chunk markers)
            if ('\n##\n' in message or message.endswith('##')) and re.search(r'\n#\d+\n', message):
                # Remove NETCONF 1.1 chunk markers and reconstruct the XML
                lines = message.split('\n')
                clean_lines = []
                
                for line in lines:
                    # Skip chunk size markers (lines that are just #<number>)
                    if line.startswith('#') and line[1:].isdigit():
                        continue
                    # Skip end markers
                    if line == '##':
                        continue
                    # Keep actual content lines (even if empty for proper XML formatting)
                    clean_lines.append(line)
                
                # Join lines and clean up excessive whitespace
                cleaned = '\n'.join(clean_lines)
                # Remove all empty lines and excessive whitespace
                cleaned = re.sub(r'\n\s*\n', '\n', cleaned)
                # Remove any remaining multiple newlines
                cleaned = re.sub(r'\n+', '\n', cleaned)
                # Fix closing > that appear on their own line
                cleaned = re.sub(r'\n\s*>', '>', cleaned)
                # Remove leading/trailing whitespace
                return cleaned.strip()
            
            # For NETCONF 1.0 or plain messages, just clean up whitespace
            else:
                # Remove the ]]>]]> terminator if present
                if message.endswith(']]>]]>'):
                    message = message[:-6]
                # Clean up excessive whitespace
                cleaned = re.sub(r'\n\s*\n', '\n', message)
                # Remove any remaining multiple newlines
                cleaned = re.sub(r'\n+', '\n', cleaned)
                # Fix closing > that appear on their own line
                cleaned = re.sub(r'\n\s*>', '>', cleaned)
                return cleaned.strip()
                
        except UnicodeDecodeError:
            return f"<binary data: {len(data)} bytes>"


class NetconfForwarder(NetconfBaseForwarder):
    """forwards a netconf message from or to the remote server"""

    def forward(self) -> None:  # noqa: C901,PLR0915

        # pylint: disable=protected-access
        if self.session.ssh_pty_kwargs is not None:
            self.server_channel.get_pty(**self.session.ssh_pty_kwargs)

        if self.client_channel.eof_received:
            logging.debug("client channel eof received")
            self.server_channel.shutdown_write()
        if self.server_channel.eof_received:
            logging.debug("server channel eof received")
            self.client_channel.shutdown_write()

        # Invoke the netconf subsystem on the server.
        self.server_channel.invoke_subsystem("netconf")

        try:
            while self.session.running:
                if self.client_channel is None:
                    msg = "No Netconf Channel available!"
                    raise ValueError(msg)

                if self.client_channel.recv_ready():
                    buf = self.read_netconf_data(self.client_channel)
                    self.session.netconf_command = buf
                    
                    # Log client request
                    request_size = len(buf)
                    clean_request = self._clean_netconf_message(buf)
                    
                    if request_size > 10000:  # 10KB threshold for requests
                        logging.info(
                            "CLIENT_REQUEST: %d bytes, showing first 500 chars: %s...",
                            request_size,
                            clean_request[:500],
                        )
                    else:
                        logging.info(
                            "CLIENT_REQUEST: %s",
                            clean_request,
                        )
                    
                    self.sendall(self.server_channel, buf, self.server_channel.send)
                if self.server_channel.recv_ready():
                    buf = self.read_netconf_data(self.server_channel)
                    
                    # Log server response
                    response_size = len(buf)
                    clean_response = self._clean_netconf_message(buf)
                    
                    if response_size > 10000:  # 10KB threshold for responses
                        logging.info(
                            "SERVER_RESPONSE: %d bytes, showing first 500 chars: %s...",
                            response_size,
                            clean_response[:500],
                        )
                    else:
                        logging.info(
                            "SERVER_RESPONSE: %s",
                            clean_response,
                        )
                    
                    self.sendall(self.client_channel, buf, self.client_channel.send)
                if self.client_channel.recv_stderr_ready():
                    buf = self.client_channel.recv_stderr(self.BUF_LEN)
                    buf = self.handle_error(buf)
                    self.sendall(
                        self.server_channel, buf, self.server_channel.send_stderr
                    )
                if self.server_channel.recv_stderr_ready():
                    buf = self.server_channel.recv_stderr(self.BUF_LEN)
                    buf = self.handle_error(buf)
                    self.sendall(
                        self.client_channel,
                        buf,
                        self.client_channel.send_stderr,
                    )

                if self.server_channel.exit_status_ready():
                    logging.debug("Exit from server ready")
                    status = self.server_channel.recv_exit_status()
                    self.server_exit_code_received = True
                    self.close_session_with_status(self.client_channel, status)
                    logging.info(
                        "remote netconf command '%s' exited with code: %s",
                        self.session.netconf_command.decode("utf-8"),
                        status,
                    )
                    time.sleep(0.1)
                    break
                if self.client_channel.exit_status_ready():
                    logging.debug("Exit from client ready")
                    status = self.client_channel.recv_exit_status()
                    self.client_exit_code_received = True
                    self.close_session(self.client_channel)
                    break

                if self._closed(self.client_channel):
                    logging.info("client channel closed")
                    self.server_channel.close()
                    self.close_session(self.client_channel)
                    break
                if self._closed(self.server_channel):
                    logging.info("server channel closed")
                    self.close_session(self.client_channel)
                    break
                if self.client_channel.eof_received:
                    logging.debug("client channel eof received")
                    self.server_channel.shutdown_write()
                if self.server_channel.eof_received:
                    logging.debug("server channel eof received")
                    self.client_channel.shutdown_write()

                time.sleep(0.1)
        except Exception:
            logging.exception("error processing netconf command")
            raise
