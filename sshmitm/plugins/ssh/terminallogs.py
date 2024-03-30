import datetime
import os
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Union

import pytz


class TerminalLogFormat(ABC):
    def __init__(
        self, logdir: Union[str, os.PathLike[str]], prefix: str = "session"
    ) -> None:
        self.logdir = logdir
        self.prefix = prefix
        self.subdirectory = self.get_subdirectory()

    def get_subdirectory(self) -> Path:
        suffix = 1
        while True:
            subdirectory = self.logdir / Path(f"{self.prefix}_{suffix}")
            if not subdirectory.exists():
                return subdirectory
            suffix += 1

    @abstractmethod
    def stdin(self, buffer: bytes) -> None:
        pass

    @abstractmethod
    def stdout(self, buffer: bytes) -> None:
        pass

    @abstractmethod
    def stderr(self, buffer: bytes) -> None:
        pass

    @abstractmethod
    def close(self) -> None:
        pass


class ScriptLogFormat(TerminalLogFormat):
    def __init__(
        self, logdir: Union[str, os.PathLike[str]], prefix: str = "session"
    ) -> None:
        super().__init__(logdir, prefix)
        timecomponent = str(time.time()).split(".", maxsplit=1)[0]

        self.subdirectory.mkdir(parents=True, exist_ok=True)
        self.file_stdin = (
            self.subdirectory / Path(f"ssh_in_{timecomponent}.log")
        ).open("wb")
        self.file_stdout = (
            self.subdirectory / Path(f"ssh_out_{timecomponent}.log")
        ).open("wb")
        self.timeingfile = (
            self.subdirectory / Path(f"ssh_time_{timecomponent}.log")
        ).open("wb")
        self.timestamp: Optional[datetime.datetime] = None

        self.file_stdout.write(
            "Session started on {}\n".format(  # pylint: disable=consider-using-f-string
                datetime.datetime.now(tz=datetime.timezone.utc)
                .replace(tzinfo=pytz.utc)
                .strftime("%a %d %b %Y %H:%M:%S %Z")
            ).encode()
        )
        self.file_stdout.flush()

    def close(self) -> None:
        self.timeingfile.close()
        self.file_stdout.close()
        self.file_stdin.close()

    def stdin(self, buffer: bytes) -> None:
        self.file_stdin.write(buffer)
        self.file_stdin.flush()

    def stdout(self, buffer: bytes) -> None:
        self.file_stdout.write(buffer)
        self.file_stdout.flush()
        self.write_timingfile(buffer)

    def stderr(self, buffer: bytes) -> None:
        self.file_stdout.write(buffer)
        self.file_stdout.flush()
        self.write_timingfile(buffer)

    def write_timingfile(self, text: bytes) -> None:
        if not self.timestamp:
            self.timestamp = datetime.datetime.now(tz=datetime.timezone.utc)
        oldtime = self.timestamp
        self.timestamp = datetime.datetime.now(tz=datetime.timezone.utc)
        diff = self.timestamp - oldtime
        self.timeingfile.write(
            f"{diff.seconds}.{diff.microseconds} {len(text)}\n".encode()
        )
        self.timeingfile.flush()
