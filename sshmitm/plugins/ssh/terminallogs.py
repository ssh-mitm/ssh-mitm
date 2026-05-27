import datetime
import json
import os
import time as time_module
from abc import ABC, abstractmethod
from pathlib import Path

import pytz


class TerminalLogFormat(ABC):
    def __init__(self, logdir: str | os.PathLike[str], prefix: str = "session") -> None:
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
    def __init__(self, logdir: str | os.PathLike[str], prefix: str = "session") -> None:
        super().__init__(logdir, prefix)
        timecomponent = str(time_module.time()).split(".", maxsplit=1)[0]

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
        self.timestamp: datetime.datetime | None = None

        self.file_stdout.write(
            "Session started on {}\n".format(  # pylint: disable=consider-using-f-string
                datetime.datetime.now(tz=datetime.UTC)
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
            self.timestamp = datetime.datetime.now(tz=datetime.UTC)
        oldtime = self.timestamp
        self.timestamp = datetime.datetime.now(tz=datetime.UTC)
        diff = self.timestamp - oldtime
        self.timeingfile.write(
            f"{diff.seconds}.{diff.microseconds} {len(text)}\n".encode()
        )
        self.timeingfile.flush()


class AsciinemLogFormat(TerminalLogFormat):
    """Asciinema v2 format recording (single JSONL .cast file).

    Playback: ``asciinema play session_<ts>.cast``
    """

    def __init__(
        self,
        logdir: str | os.PathLike[str],
        prefix: str = "session",
        width: int = 80,
        height: int = 24,
    ) -> None:
        super().__init__(logdir, prefix)
        self._start = time_module.time()
        self.subdirectory.mkdir(parents=True, exist_ok=True)
        timecomponent = str(int(self._start))
        self._file = (self.subdirectory / f"session_{timecomponent}.cast").open(
            "w", encoding="utf-8"
        )
        header = {
            "version": 2,
            "width": width,
            "height": height,
            "timestamp": int(self._start),
        }
        self._file.write(json.dumps(header) + "\n")
        self._file.flush()

    def _elapsed(self) -> float:
        return time_module.time() - self._start

    def _write_event(self, event_type: str, data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")
        self._file.write(
            json.dumps([round(self._elapsed(), 6), event_type, text]) + "\n"
        )
        self._file.flush()

    def stdin(self, buffer: bytes) -> None:
        self._write_event("i", buffer)

    def stdout(self, buffer: bytes) -> None:
        self._write_event("o", buffer)

    def stderr(self, buffer: bytes) -> None:
        self._write_event("o", buffer)

    def close(self) -> None:
        self._file.close()
