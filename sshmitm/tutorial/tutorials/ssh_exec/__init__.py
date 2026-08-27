"""Tutorial: SSH Command Execution Interception."""

from typing import ClassVar

from sshmitm.tutorial._client_actions import SSHExecAction
from sshmitm.tutorial._conditions import TRUE, PortOpen, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial
from sshmitm.tutorial._requirements import RandomChoice, RandomPassword, Requirement
from sshmitm.tutorial.hosts.logfile_inc import LogfileIncScenario, MaxMorgan
from sshmitm.tutorial.hosts.logfile_inc.web01 import EXEC_COMMANDS, Web01


class SSHExecTutorial(Tutorial):
    id = "04-ssh-exec"
    title = "SSH Command Execution Interception"
    category = "Command Execution"
    description = (
        "Learn how SSH-MITM intercepts commands executed non-interactively via ssh."
    )
    tags: ClassVar[list[str]] = ["SSH Exec", "CI/CD"]
    docs: ClassVar[dict[str, str]] = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "Terminal Sessions": "https://docs.ssh-mitm.at/audit_guide/sessions.html",
    }
    lab_service_labels: ClassVar[dict[str, str]] = {
        "mock_port": "web01.logfileinc.internal"
    }

    scenario = LogfileIncScenario
    proxy_target = Web01
    victim = MaxMorgan
    requires: ClassVar[list[Requirement]] = [
        RandomPassword(MaxMorgan, Web01),
        RandomChoice("web01_exec_command", EXEC_COMMANDS),
    ]

    # Deliberately not ClassVar: see the comment on Tutorial.steps
    # in _definitions.py for why.
    steps = [  # noqa: RUF012
        Step(
            id="intro",
            title="What you will learn",
            condition=TRUE(),
            hint_done="Introduction read. ✓",
        ),
        Step(
            id="start-sshmitm",
            title="Start SSH-MITM",
            condition=PortOpen("sshmitm_port"),
            command=(
                "ssh-mitm server"
                " --remote-host {proxy_target_address}"
                " --remote-port {mock_port}"
                " --listen-port {sshmitm_port}"
            ),
            hint_waiting="Waiting for SSH-MITM to start on port {sshmitm_port}…",
            hint_done="SSH-MITM is running on port {sshmitm_port}. ✓",
        ),
        Step(
            id="intercept",
            title="Find the executed command",
            condition=UserInput(
                "web01_exec_command",
                prompt="Enter the command that was executed:",
            ),
            victim_action=SSHExecAction("web01_exec_command"),
            hint_waiting="A developer is running a command through SSH-MITM. Check the terminal and enter the command above.",
            hint_done="Correct! You intercepted the command execution. ✓",
        ),
    ]
