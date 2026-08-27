"""Tutorial: SFTP File Download Interception."""

from typing import ClassVar

from sshmitm.tutorial._client_actions import SFTPDownloadSessionAction
from sshmitm.tutorial._conditions import TRUE, PortOpen, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial
from sshmitm.tutorial._requirements import RandomChoice, RandomPassword, Requirement
from sshmitm.tutorial.hosts.logfile_inc import LogfileIncScenario, MaxMorgan
from sshmitm.tutorial.hosts.logfile_inc.files import FILENAMES, Files


class SFTPDownloadTutorial(Tutorial):
    id = "03-sftp-download"
    title = "SFTP File Download Interception"
    category = "File Transfer"
    description = "Learn how SSH-MITM intercepts SFTP downloads and reveals which files a client copies from a server."
    tags: ClassVar[list[str]] = ["SFTP", "File Interception"]
    docs: ClassVar[dict[str, str]] = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "File Transfers": "https://docs.ssh-mitm.at/audit_guide/file_transfer.html",
    }
    lab_service_labels: ClassVar[dict[str, str]] = {
        "mock_port": "files.logfileinc.internal"
    }

    scenario = LogfileIncScenario
    proxy_target = Files
    victim = MaxMorgan
    requires: ClassVar[list[Requirement]] = [
        RandomPassword(MaxMorgan, Files),
        RandomChoice("files_sftp_filename", FILENAMES),
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
            title="Find the downloaded filename",
            condition=UserInput(
                "files_sftp_filename",
                prompt="Enter the name of the file that was downloaded:",
            ),
            victim_action=SFTPDownloadSessionAction("files_sftp_filename"),
            hint_waiting="A developer is downloading a file through SSH-MITM. Check the terminal and enter the filename above.",
            hint_done="Correct! You intercepted the file transfer. ✓",
        ),
    ]
