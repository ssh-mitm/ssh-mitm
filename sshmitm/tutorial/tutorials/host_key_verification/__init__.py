"""Tutorial: Host Key Verification & CVE-2020-14145."""

from sshmitm.tutorial._client_actions import SimulatedCVE2020Action
from sshmitm.tutorial._conditions import All, FingerprintState, PortOpen, TRUE, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial
from sshmitm.tutorial._requirements import NoneAuthAccess
from sshmitm.tutorial.hosts.logfile_inc import LogfileIncScenario, MaxMorgan
from sshmitm.tutorial.hosts.logfile_inc.web01 import Web01


class HostKeyVerificationTutorial(Tutorial):
    id          = "00-host-key-verification"
    title       = "Host Key Verification"
    category    = "Fundamentals"
    description = (
        "Discover how SSH clients reveal their fingerprint state — "
        "and what CVE-2020-14145 exposes about first-time vs. returning connections."
    )
    tags = ["CVE-2020-14145", "Host Key", "TOFU", "Key Exchange"]
    docs = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "SSH Fingerprints":        "https://docs.ssh-mitm.at/audit_guide/fingerprint.html",
        "Client Audit":            "https://docs.ssh-mitm.at/audit_guide/client_audit.html",
        "CVE-2020-14145":          "https://docs.ssh-mitm.at/vulnerabilities/CVE-2020-14145.html",
        "Attack Scenarios":        "https://docs.ssh-mitm.at/audit_guide/attack_scenarios.html",
    }
    lab_service_labels = {"mock_port": "web01.logfileinc.internal"}

    scenario     = LogfileIncScenario
    proxy_target = Web01
    victim       = MaxMorgan
    requires     = [NoneAuthAccess(MaxMorgan, Web01)]

    steps = [
        Step(
            id       = "intro",
            title    = "What you will learn",
            condition = TRUE(),
            hint_done = "Introduction read. ✓",
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
            id        = "first-connection",
            title     = "First connection — unknown fingerprint",
            condition  = All(
                FingerprintState("new"),
                UserInput(
                    "preferred_algo_new",
                    prompt=(
                        "Enter the preferred server host key algorithm shown in"
                        " the SSH-MITM terminal:"
                    ),
                ),
            ),
            victim_action = SimulatedCVE2020Action(
                fingerprint_state = "new",
                algorithm_var     = "preferred_algo_new",
            ),
            hint_waiting = "Max is connecting… check the SSH-MITM terminal.",
            hint_done    = "Algorithm confirmed. ✓",
        ),
        Step(
            id        = "return-connection",
            title     = "Return connection — cached fingerprint",
            condition  = All(
                FingerprintState("cached"),
                UserInput(
                    "preferred_algo_cached",
                    prompt=(
                        "Enter the preferred server host key algorithm now"
                        " shown in the SSH-MITM terminal — has it changed?"
                    ),
                ),
            ),
            victim_action = SimulatedCVE2020Action(
                fingerprint_state = "cached",
                algorithm_var     = "preferred_algo_cached",
            ),
            hint_waiting = "Max is connecting again… check the algorithm in the SSH-MITM terminal.",
            hint_done    = "Tutorial complete. ✓",
        ),
    ]
