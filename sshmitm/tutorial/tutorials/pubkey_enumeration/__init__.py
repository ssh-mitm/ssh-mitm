"""Tutorial: SSH Key Enumeration — user validity oracle (CVE-2016-20012)."""

from typing import ClassVar

from sshmitm.tutorial._conditions import TRUE, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial
from sshmitm.tutorial._requirements import (
    RandomKeyPair,
    RegisterPublicKeys,
    Requirement,
)
from sshmitm.tutorial.hosts import Host
from sshmitm.tutorial.hosts.logfile_inc import LogfileIncScenario, MaxMorgan
from sshmitm.tutorial.hosts.logfile_inc.db01 import DB01
from sshmitm.tutorial.hosts.logfile_inc.files import Files
from sshmitm.tutorial.hosts.logfile_inc.logfilegit import LogfileGit
from sshmitm.tutorial.hosts.logfile_inc.web01 import Web01


class PubkeyEnumerationTutorial(Tutorial):
    id = "06-pubkey-enumeration"
    title = "SSH Key Enumeration"
    category = "Reconnaissance"
    description = (
        "Learn how to query the SSH user validity oracle (CVE-2016-20012) "
        "to discover which keys grant access to which servers "
        "using ssh-mitm check-publickey."
    )
    tags: ClassVar[list[str]] = ["CVE-2016-20012", "Public Key", "Lateral Movement"]
    docs: ClassVar[dict[str, str]] = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "Authentication": "https://docs.ssh-mitm.at/audit_guide/authentication.html",
        "CVE-2016-20012": "https://docs.ssh-mitm.at/vulnerabilities/CVE-2016-20012.html",
    }
    lab_service_labels: ClassVar[dict[str, str]] = {
        "git_server_url": "LogfileGit",
        "web_port": "web01.logfileinc.internal",
        "database_port": "db01.logfileinc.internal",
    }

    scenario = LogfileIncScenario
    proxy_target = None  # no SSH-MITM proxy — check-publickey connects directly
    victim = MaxMorgan
    direct_targets: ClassVar[dict[str, type[Host]]] = {
        "web": Web01,
        "database": DB01,
        "logfilegit": LogfileGit,
    }

    requires: ClassVar[list[Requirement]] = [
        # key1 — workstation key: valid on db01 only
        RandomKeyPair(MaxMorgan, "mmorgan_db", authorized_on=[DB01]),
        # key2 — laptop key: valid on web01
        RandomKeyPair(MaxMorgan, "mmorgan_web", authorized_on=[Web01]),
        # key3 — old laptop key: still valid on files (mmorgan never cleaned it up)
        RandomKeyPair(MaxMorgan, "mmorgan_old", authorized_on=[Files]),
        # register all three on LogfileGit
        RegisterPublicKeys(
            MaxMorgan,
            LogfileGit,
            [
                ("mmorgan@workstation", "mmorgan_db"),
                ("mmorgan@laptop", "mmorgan_web"),
                ("mmorgan@old-laptop", "mmorgan_old"),
            ],
        ),
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
            id="explore-gitlab",
            title="Explore LogfileGit",
            condition=TRUE(),
            hint_done="Profile explored. ✓",
        ),
        Step(
            id="enumerate",
            title="Find the key valid on the web server",
            condition=UserInput(
                "keypair_mmorgan_web_fingerprint",
                prompt="Enter the SHA256 fingerprint of the key accepted by the web server:",
            ),
            command=(
                "ssh-mitm check-publickey"
                " --host {web_address}"
                " --port {web_port}"
                " --username mmorgan"
                " --public-keys {git_server_url}/mmorgan.keys"
            ),
            hint_waiting=(
                "Run check-publickey and enter the SHA256 fingerprint"
                " of the valid key above."
            ),
            hint_done="Correct! You mapped mmorgan's access to the web server. ✓",
        ),
    ]
