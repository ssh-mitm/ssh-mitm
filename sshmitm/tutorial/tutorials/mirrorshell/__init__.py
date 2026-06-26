"""Tutorial: SSH Session Mirroring (mirrorshell)."""

from sshmitm.tutorial._client_actions import KeepAliveShellAction
from sshmitm.tutorial._conditions import PortOpen, TRUE, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial
from sshmitm.tutorial._requirements import RandomKeyPair, RandomSecret
from sshmitm.tutorial.hosts.logfile_inc import LogfileIncScenario, ThomasWebb
from sshmitm.tutorial.hosts.logfile_inc.router01 import Router01


class MirrorshellTutorial(Tutorial):
    id          = "05-mirrorshell"
    title       = "SSH Session Mirroring"
    category    = "Session Interception"
    description = (
        "Learn how SSH-MITM mirrors a live shell session to the attacker, "
        "allowing command injection into an unattended terminal."
    )
    tags = ["Mirrorshell", "Session Hijacking"]
    docs = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "Terminal Sessions":       "https://docs.ssh-mitm.at/audit_guide/sessions.html",
    }
    lab_service_labels = {"mock_port": "router01.logfileinc.internal"}

    scenario     = LogfileIncScenario
    proxy_target = Router01
    victim       = ThomasWebb
    requires     = [
        RandomKeyPair(ThomasWebb, "twebb_main", authorized_on=[Router01]),
        RandomSecret("router01_snmp_secret"),
    ]

    steps = [
        Step(
            id        = "intro",
            title     = "What you will learn",
            condition  = TRUE(),
            hint_done  = "Introduction read. ✓",
        ),
        Step(
            id        = "start-sshmitm",
            title     = "Start SSH-MITM",
            condition  = PortOpen("sshmitm_port"),
            command    = (
                "ssh-mitm server"
                " --remote-host {proxy_target_address}"
                " --remote-port {mock_port}"
                " --listen-port {sshmitm_port}"
            ),
            hint_waiting = "Waiting for SSH-MITM to start on port {sshmitm_port}…",
            hint_done    = "SSH-MITM is running on port {sshmitm_port}. ✓",
        ),
        Step(
            id        = "intercept",
            title     = "Connect to the mirrored session and find the SNMP secret",
            condition  = UserInput(
                "router01_snmp_secret",
                prompt="Enter the SNMP community string you found in the router config:",
            ),
            victim_action = KeepAliveShellAction(duration=600.0),
            hint_waiting  = (
                "The network admin's session is open. "
                "Check the SSH-MITM terminal for the mirrorshell port and connect. "
                "The terminal may appear blank — type 'help' to get started."
            ),
            hint_done = "Correct! You successfully extracted the SNMP community string. ✓",
        ),
    ]
