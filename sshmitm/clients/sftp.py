"""
SFTP Client Module

This module contains the implementation of the SFTP client.

.. moduleauthor:: OpenAI
"""

import logging
import os
from typing import TYPE_CHECKING, Any, Callable, List, Optional, Tuple, Union

import paramiko
from paramiko.pkey import PKey
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_file import SFTPFile

from sshmitm.clients.ssh import AuthenticationMethod, SSHClient

if TYPE_CHECKING:
    import sshmitm


class SFTPClient(SSHClient):
    """
    This class implements a simple SFTP client for transferring files
    to and from a remote server using SFTP protocol.

    :param host: hostname or IP address of the SFTP server
    :param username: username for authentication to the SFTP server
    :param password: password for authentication to the SFTP server
    :param port: port number to use for the connection (default is 22)

    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        host: str,
        port: int,
        method: AuthenticationMethod,
        password: Optional[str],
        user: str,
        key: Optional[PKey],
        session: "sshmitm.session.Session",
    ) -> None:
        super().__init__(host, port, method, password, user, key, session)
        self._sftp: Optional[paramiko.SFTPClient] = None
        self.subsystem_count = 0

    @classmethod
    def from_client(cls, ssh_client: Optional[SSHClient]) -> Optional["SFTPClient"]:
        """
        Create an SFTPClient instance from an SSHClient instance.

        :param ssh_client: The SSHClient instance.
        :return: An SFTPClient instance, or None if the SFTPClient could not be created.
        """
        if ssh_client is None:
            logging.error("error creating sftp client - no ssh client!")
            return None
        if not ssh_client.connected and ssh_client.connect():
            logging.error("error creating sftp client!")
            return None

        try:
            sftp = cls(
                ssh_client.host,
                ssh_client.port,
                ssh_client.method,
                ssh_client.password,
                ssh_client.user,
                ssh_client.key,
                ssh_client.session,
            )
            if ssh_client.transport is None:
                logging.debug("ssh_client does not have a transport")
                return None
            sftp._sftp = paramiko.SFTPClient.from_transport(ssh_client.transport)
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("error creating sftp client")
            return None
        sftp.connected = True
        return sftp

    @property
    def running(self) -> bool:
        """
        Indicate whether the SFTP client is running.

        :return: Whether the SFTP client is running.
        """
        return self.subsystem_count > 0

    def connect(self) -> bool:
        """
        Connect to the SFTP server.

        :return: Whether the connection was successful.
        """
        ret = super().connect()
        if not ret:
            return False
        if self._sftp is None:
            return False
        try:
            if self.transport is None:
                return False
            self._sftp = paramiko.SFTPClient.from_transport(self.transport)
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("error creating sftp client")
            return False
        return True

    def open(
        self, filename: Union[str, bytes], mode: str = "r", bufsize: int = -1
    ) -> SFTPFile:
        """
        Open a file on the SFTP server.

        :param filename: The file to open.
        :param mode: The mode in which to open the file.
        :param bufsize: The buffer size for the file.
        :return: An SFTPFile instance for the opened file.
        :raise paramiko.SFTPError: If the handle for the SFTP client is not available.
        """
        if self._sftp is None:
            msg = "Expected handle"
            raise paramiko.SFTPError(msg)
        return self._sftp.open(filename, mode, bufsize)

    def chmod(self, path: Union[str, bytes], mode: int) -> int:
        """
        Changes the mode (permission) of the specified path.

        :param path: The path of the file or directory whose permissions are to be changed.
        :param mode: The new permission mode, expressed as an integer (e.g. 0o755).
        :return: `paramiko.sftp.SFTP_OK` if the operation was successful, `paramiko.sftp.SFTP_FAILURE` otherwise.
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.chmod(path, mode)
        return paramiko.sftp.SFTP_OK

    def chown(self, path: Union[str, bytes], uid: int, gid: int) -> int:
        """
        Changes the owner and group of the specified path.

        :param path: The path of the file or directory whose ownership is to be changed.
        :param uid: The new user ID of the file or directory.
        :param gid: The new group ID of the file or directory.
        :return: `paramiko.sftp.SFTP_OK` if the operation was successful, `paramiko.sftp.SFTP_FAILURE` otherwise.
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.chown(path, uid, gid)
        return paramiko.sftp.SFTP_OK

    def get(
        self,
        remotepath: Union[str, bytes],
        localpath: Union[str, bytes],
        callback: Optional[Callable[[int, int], Any]] = None,
    ) -> int:
        """
        Downloads a file from the remote SFTP server and saves it to the local file system.

        :param remotepath: The path of the file on the remote SFTP server.
        :param localpath: The path of the file on the local file system.
        :param callback: An optional callback function that is called after each chunk of data has been transmitted.
            The function should accept two arguments: the number of bytes transmitted so far, and the total size of the
            file in bytes.
        :return: `paramiko.sftp.SFTP_OK` if the operation was successful, `paramiko.sftp.SFTP_FAILURE` otherwise.
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        try:
            self._sftp.get(remotepath, localpath, callback)
        except (IOError, OSError) as ex:
            logging.error(ex)
            os.remove(localpath)
            return paramiko.sftp.SFTP_FAILURE
        return paramiko.sftp.SFTP_OK

    def listdir_attr(self, path: str = ".") -> Union[int, List[SFTPAttributes]]:
        """
        This method returns the list of files and directories in the given path with their attributes.

        :param path: path to the directory to list the contents of. Default is current directory '.'
        :return: If successful, it returns a list of `SFTPAttributes` objects, else returns `paramiko.sftp.SFTP_FAILURE`
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.listdir_attr(path)

    def lstat(self, path: Union[str, bytes]) -> Union[int, SFTPAttributes]:
        """
        This method returns the attributes of the file/directory at the given path.

        :param path: path to the file/directory to get the attributes of.
        :return: If successful, it returns a `SFTPAttributes` object, else returns `paramiko.sftp.SFTP_FAILURE`
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.lstat(path)

    def mkdir(self, path: Union[str, bytes], mode: int = 511) -> int:
        """
        This method creates a new directory at the given path.

        :param path: path to the directory to be created.
        :param mode: mode of the directory to be created. Default is 511.
        :return: If successful, returns `paramiko.sftp.SFTP_OK`, else returns `paramiko.sftp.SFTP_FAILURE`
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.mkdir(path, mode)
        return paramiko.sftp.SFTP_OK

    def put(
        self,
        localpath: Union[str, bytes],
        remotepath: Union[str, bytes],
        callback: Any = None,
        confirm: bool = True,
    ) -> None:
        """
        This method is not implemented.

        :raises: NotImplementedError
        """
        del localpath
        del remotepath
        del callback
        del confirm
        msg = "put not implemented"
        raise NotImplementedError(msg)

    def readlink(self, path: Union[str, bytes]) -> Union[int, str]:
        """
        This method returns the target of the symbolic link or a failure code.

        :param path: The path of the symbolic link.
        :return: The target of the symbolic link or a failure code.
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.readlink(path) or paramiko.sftp.SFTP_FAILURE

    def remove(self, path: Union[str, bytes]) -> int:
        """
        This method removes the specified file.

        :param path: The path of the file to be removed.
        :return: A success code or a failure code.
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.remove(path)
        return paramiko.sftp.SFTP_OK

    def rename(self, oldpath: Union[str, bytes], newpath: Union[str, bytes]) -> int:
        """
        This method renames a file.

        :param oldpath: The current name of the file.
        :param newpath: The new name of the file.
        :return: A success code or a failure code.
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.rename(oldpath, newpath)
        return paramiko.sftp.SFTP_OK

    def rmdir(self, path: Union[str, bytes]) -> int:
        """
        This method removes the specified directory.

        :param path: The path of the directory to be removed.
        :return: A success code or a failure code.
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.rmdir(path)
        return paramiko.sftp.SFTP_OK

    def stat(self, path: Union[str, bytes]) -> Union[int, SFTPAttributes]:
        """
        This method returns the status of a file.

        :param path: The path of the file.
        :return: The status of the file or a failure code.
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.stat(path)

    def utime(self, path: Union[str, bytes], times: Tuple[float, float]) -> int:
        """
        Update the access and modification time of a file.

        :param path: The path to the file.
        :param times: Tuple of float representing the access and modification time.
        :return: returns `paramiko.sftp.SFTP_OK` on success, `paramiko.sftp.SFTP_FAILURE` on failure
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.utime(path, times)
        return paramiko.sftp.SFTP_OK

    def symlink(self, source: Union[str, bytes], dest: Union[str, bytes]) -> int:
        """
        Create a symbolic link pointing to `source` at `dest`.

        :param source: The target file of the symbolic link.
        :param dest: The path to the symbolic link.
        :return: returns `paramiko.sftp.SFTP_OK` on success, `paramiko.sftp.SFTP_FAILURE` on failure
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.symlink(source, dest)
        return paramiko.sftp.SFTP_OK

    def close(self) -> int:
        """
        Close the SFTP session.

        :return: returns `paramiko.sftp.SFTP_OK` on success, `paramiko.sftp.SFTP_FAILURE` on failure
        """
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        if not self.running:
            self._sftp.close()
            if self.session.sftp_channel is not None:
                self.session.sftp_channel.close()
        return paramiko.sftp.SFTP_OK
