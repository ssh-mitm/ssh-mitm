"""Tests for ExecHandlerBasePlugin and SCPBaseForwarder handler registry."""

from typing import ClassVar
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from sshmitm.forwarders.exec import ExecHandlerBasePlugin
from sshmitm.forwarders.scp import ExecHandlerEntry, SCPBaseForwarder


class _FakeHandler(ExecHandlerBasePlugin):
    """Minimal concrete ExecHandlerBasePlugin for testing."""

    command_prefix: ClassVar[bytes] = b"fake-cmd"
    disable_pty: ClassVar[bool] = True
    disable_ssh: ClassVar[bool] = False

    @property
    def client_channel(self) -> paramiko.Channel | None:
        return None

    @property
    def _forwarded_command(self) -> bytes:
        return self.command_prefix

    def forward(self) -> None:
        pass


class _AnotherHandler(ExecHandlerBasePlugin):
    command_prefix: ClassVar[bytes] = b"other-cmd"
    disable_pty: ClassVar[bool] = False
    disable_ssh: ClassVar[bool] = True

    @property
    def client_channel(self) -> paramiko.Channel | None:
        return None

    @property
    def _forwarded_command(self) -> bytes:
        return self.command_prefix

    def forward(self) -> None:
        pass


@pytest.fixture(autouse=True)
def clean_registry():
    """Isolate each test with a fresh handler registry."""
    original_handlers = SCPBaseForwarder._exec_handlers.copy()  # noqa: SLF001
    original_loaded = SCPBaseForwarder._handlers_loaded  # noqa: SLF001
    SCPBaseForwarder._exec_handlers = {}  # noqa: SLF001
    SCPBaseForwarder._handlers_loaded = True  # skip EP loading in tests
    yield
    SCPBaseForwarder._exec_handlers = original_handlers  # noqa: SLF001
    SCPBaseForwarder._handlers_loaded = original_loaded  # noqa: SLF001


class TestExecHandlerBasePlugin:
    def test_class_attributes(self) -> None:
        assert _FakeHandler.command_prefix == b"fake-cmd"
        assert _FakeHandler.disable_pty is True
        assert _FakeHandler.disable_ssh is False

    def test_is_subclass_of_exec_handler_base_plugin(self) -> None:
        assert issubclass(_FakeHandler, ExecHandlerBasePlugin)


class TestRegisterExecHandler:
    def test_registers_with_explicit_name(self) -> None:
        SCPBaseForwarder.register_exec_handler(
            b"fake-cmd", _FakeHandler, name="fake", disable_pty=True
        )
        entry = SCPBaseForwarder._exec_handlers.get(b"fake-cmd")  # noqa: SLF001
        assert entry is not None
        assert entry.name == "fake"
        assert entry.disable_pty is True
        assert entry.disable_ssh is False

    def test_falls_back_to_class_name_when_no_name_given(self) -> None:
        SCPBaseForwarder.register_exec_handler(b"fake-cmd", _FakeHandler)
        entry = SCPBaseForwarder._exec_handlers[b"fake-cmd"]  # noqa: SLF001
        assert entry.name == "_FakeHandler"


class TestGetExecHandler:
    def _register(self, name: str = "fake") -> None:
        SCPBaseForwarder._exec_handlers[b"fake-cmd"] = ExecHandlerEntry(  # noqa: SLF001
            handler=_FakeHandler, name=name, disable_pty=True, disable_ssh=False
        )

    def test_returns_entry_for_matching_prefix(self) -> None:
        self._register()
        entry = SCPBaseForwarder.get_exec_handler(b"fake-cmd /some/path")
        assert entry is not None
        assert entry.handler is _FakeHandler

    def test_returns_none_for_unknown_command(self) -> None:
        self._register()
        assert SCPBaseForwarder.get_exec_handler(b"scp -t /file") is None

    def test_enabled_all_disabled_none_returns_entry(self) -> None:
        self._register()
        assert SCPBaseForwarder.get_exec_handler(
            b"fake-cmd x", enabled=["ALL"], disabled=["NONE"]
        ) is not None

    def test_disabled_handler_returns_none(self) -> None:
        self._register()
        assert SCPBaseForwarder.get_exec_handler(
            b"fake-cmd x", enabled=["ALL"], disabled=["fake"]
        ) is None

    def test_disabled_all_with_enabled_override(self) -> None:
        self._register()
        assert SCPBaseForwarder.get_exec_handler(
            b"fake-cmd x", enabled=["fake"], disabled=["ALL"]
        ) is not None

    def test_disabled_all_without_enabled_override(self) -> None:
        self._register()
        assert SCPBaseForwarder.get_exec_handler(
            b"fake-cmd x", enabled=["other"], disabled=["ALL"]
        ) is None

    def test_enabled_none_returns_none(self) -> None:
        self._register()
        assert SCPBaseForwarder.get_exec_handler(
            b"fake-cmd x", enabled=["NONE"], disabled=["NONE"]
        ) is None


class TestLoadExecHandlers:
    def test_loads_exec_handler_base_plugin_subclass(self) -> None:
        fake_ep = MagicMock()
        fake_ep.name = "fake"
        fake_ep.value = "tests.test_exec_handler_registry:_FakeHandler"
        fake_ep.load.return_value = _FakeHandler

        SCPBaseForwarder._handlers_loaded = False  # noqa: SLF001

        with patch(
            "sshmitm.forwarders.scp.entry_points",
            return_value=[fake_ep],
        ):
            SCPBaseForwarder.load_exec_handlers()

        entry = SCPBaseForwarder._exec_handlers.get(b"fake-cmd")  # noqa: SLF001
        assert entry is not None
        assert entry.name == "fake"
        assert entry.handler is _FakeHandler
        assert entry.disable_pty is True
        assert entry.disable_ssh is False

    def test_skips_non_exec_handler_base_plugin_classes(self) -> None:
        class _Legacy:
            pass

        fake_ep = MagicMock()
        fake_ep.name = "legacy"
        fake_ep.load.return_value = _Legacy

        SCPBaseForwarder._handlers_loaded = False  # noqa: SLF001

        with patch(
            "sshmitm.forwarders.scp.entry_points",
            return_value=[fake_ep],
        ):
            SCPBaseForwarder.load_exec_handlers()

        assert b"fake-cmd" not in SCPBaseForwarder._exec_handlers  # noqa: SLF001

    def test_load_failure_is_logged_and_continues(self, caplog) -> None:
        broken_ep = MagicMock()
        broken_ep.name = "broken"
        broken_ep.load.side_effect = ImportError("missing module")

        good_ep = MagicMock()
        good_ep.name = "fake"
        good_ep.value = "tests.test_exec_handler_registry:_FakeHandler"
        good_ep.load.return_value = _FakeHandler

        SCPBaseForwarder._handlers_loaded = False  # noqa: SLF001

        with patch(
            "sshmitm.forwarders.scp.entry_points",
            return_value=[broken_ep, good_ep],
        ):
            SCPBaseForwarder.load_exec_handlers()

        assert SCPBaseForwarder._exec_handlers.get(b"fake-cmd") is not None  # noqa: SLF001
