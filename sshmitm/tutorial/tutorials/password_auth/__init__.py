"""Tutorial: Password Authentication Interception."""

from typing import ClassVar

from sshmitm.tutorial._client_actions import SSHPasswordAction
from sshmitm.tutorial._conditions import TRUE, All, PortOpen, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial
from sshmitm.tutorial._requirements import RandomPassword, Requirement
from sshmitm.tutorial.hosts.logfile_inc import LogfileIncScenario, MaxMorgan
from sshmitm.tutorial.hosts.logfile_inc.web01 import Web01


class PasswordAuthTutorial(Tutorial):
    id = "01-password-auth"
    title = "Password Authentication"
    category = "Authentication"
    description = "Learn how SSH-MITM intercepts plaintext passwords."
    tags: ClassVar[list[str]] = ["Password Auth", "Credential Theft"]
    docs: ClassVar[dict[str, str]] = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "Authentication": "https://docs.ssh-mitm.at/audit_guide/authentication.html",
    }
    lab_service_labels: ClassVar[dict[str, str]] = {
        "mock_port": "web01.logfileinc.internal"
    }

    scenario = LogfileIncScenario
    proxy_target = Web01
    victim = MaxMorgan
    requires: ClassVar[list[Requirement]] = [RandomPassword(MaxMorgan, Web01)]

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
            title="Enter the intercepted credentials",
            condition=All(
                UserInput("password_user", prompt="Enter the intercepted username:"),
                UserInput("password_value", prompt="Enter the intercepted password:"),
            ),
            victim_action=SSHPasswordAction(),
            hint_waiting="Look at the SSH-MITM terminal and enter both values above.",
            hint_done="Correct! Tutorial complete. ✓",
        ),
    ]
