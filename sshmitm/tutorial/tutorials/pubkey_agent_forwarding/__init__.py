"""Tutorial: Public Key Auth & Agent Forwarding Interception."""

from sshmitm.tutorial._client_actions import SSHPublicKeyAction
from sshmitm.tutorial._conditions import PortOpen, TRUE, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial
from sshmitm.tutorial._requirements import RandomKeyPair
from sshmitm.tutorial.hosts.logfile_inc import LogfileIncScenario, SarahKing
from sshmitm.tutorial.hosts.logfile_inc.web01 import Web01


class PubkeyAgentForwardingTutorial(Tutorial):
    id          = "02-pubkey-agent-forwarding"
    title       = "Public Key Auth & Agent Forwarding"
    category    = "Authentication"
    description = "Learn what SSH-MITM can see when public key auth and agent forwarding are used."
    tags = ["Public Key", "Agent Forwarding", "Lateral Movement"]
    docs = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "Authentication":          "https://docs.ssh-mitm.at/audit_guide/authentication.html",
        "SSH Agent Forwarding":    "https://docs.ssh-mitm.at/audit_guide/sshagent.html",
    }
    lab_service_labels = {"mock_port": "web01.logfileinc.internal"}

    scenario     = LogfileIncScenario
    proxy_target = Web01
    victim       = SarahKing
    requires     = [RandomKeyPair(SarahKing, "sking_main", authorized_on=[Web01])]

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
            title     = "Enter the intercepted key fingerprint",
            condition  = UserInput(
                "pubkey_fingerprint",
                prompt="Enter the SHA256 fingerprint shown in the SSH-MITM terminal:",
            ),
            victim_action = SSHPublicKeyAction(),
            hint_waiting  = "Look at the SSH-MITM terminal and enter the key fingerprint above.",
            hint_done     = "Correct! Tutorial complete. ✓",
        ),
    ]
