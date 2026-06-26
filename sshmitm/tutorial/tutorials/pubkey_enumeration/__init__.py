"""Tutorial: SSH Key Enumeration — user validity oracle (CVE-2016-20012)."""

import base64
import hashlib

import paramiko

from sshmitm.tutorial._conditions import PortOpen, TRUE, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial
from sshmitm.tutorial._server_config import (
    MockServerConfig,
    PublicKeyAuth,
    TargetServerConfig,
    UserConfig,
)
from sshmitm.tutorial.gitserver import (
    GitCommit,
    GitRepo,
    GitServerConfig,
    GitUser,
)


def _fp(key: paramiko.PKey) -> str:
    """SHA256 fingerprint — matches SSHPubKey.hash_sha256()."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode()


def _publine(key: paramiko.PKey, comment: str) -> str:
    return f"{key.get_name()} {key.get_base64()} {comment}"


class PubkeyEnumerationTutorial(Tutorial):
    id          = "06-pubkey-enumeration"
    title       = "SSH Key Enumeration"
    category    = "Reconnaissance"
    lab_service_labels = {
        "git_server_url": "LogfileGit",
        "web_port":       "web01.logfileinc.internal",
        "database_port":  "db01.logfileinc.internal",
    }
    description = (
        "Learn how to query the SSH user validity oracle (CVE-2016-20012) "
        "to discover which keys grant access to which servers "
        "using ssh-mitm check-publickey."
    )
    tags = ["CVE-2016-20012", "Public Key", "Lateral Movement"]
    docs = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "Authentication": "https://docs.ssh-mitm.at/user_guide/authentication.html",
        "CVE-2016-20012": "https://docs.ssh-mitm.at/vulnerabilities/CVE-2016-20012.html",
    }

    steps = [
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
                "web_key_fingerprint",
                prompt="Enter the SHA256 fingerprint of the key accepted by the web server:",
            ),
            command=(
                "ssh-mitm check-publickey"
                " --host 127.0.0.1 --port {web_port}"
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

    # ------------------------------------------------------------------ #
    # Dynamic infrastructure — keys generated fresh for every run         #
    # ------------------------------------------------------------------ #

    def generate_tutorial_session_data(self) -> dict[str, object]:
        self._key1 = paramiko.ECDSAKey.generate()  # dev server + database
        self._key2 = paramiko.ECDSAKey.generate()  # web server
        self._key3 = paramiko.ECDSAKey.generate()  # registered but not authorized anywhere
        return {
            "key1_fingerprint": _fp(self._key1),
            "key2_fingerprint": _fp(self._key2),
            "web_key_fingerprint": _fp(self._key2),
            "db_key_fingerprint": _fp(self._key1),
        }

    def get_server(self) -> MockServerConfig:
        key1 = getattr(self, "_key1", None)
        return MockServerConfig(
            users=[UserConfig(username="mmorgan", auth=PublicKeyAuth(key=key1))],
        )

    def get_target_servers(self) -> list[TargetServerConfig]:
        key1 = getattr(self, "_key1", None)
        key2 = getattr(self, "_key2", None)
        return [
            TargetServerConfig(
                name="web",
                users=[UserConfig(username="mmorgan", auth=PublicKeyAuth(key=key2))],
            ),
            TargetServerConfig(
                name="database",
                users=[UserConfig(username="mmorgan", auth=PublicKeyAuth(key=key1))],
            ),
        ]

    def get_git_server(self) -> GitServerConfig | None:
        key1 = getattr(self, "_key1", None)
        key2 = getattr(self, "_key2", None)
        key3 = getattr(self, "_key3", None)
        pubkeys = []
        if key1:
            pubkeys.append(_publine(key1, "mmorgan@workstation"))
        if key2:
            pubkeys.append(_publine(key2, "mmorgan@laptop"))
        if key3:
            pubkeys.append(_publine(key3, "mmorgan@old-laptop"))

        return GitServerConfig(
            brand="LogfileGit",
            users=[
                GitUser(
                    username="mmorgan",
                    fullname="Max Morgan",
                    bio="Developer @ Logfile Inc.",
                    pubkeys=pubkeys,
                    repos=[
                        GitRepo(
                            name="dev-server-config",
                            description="Internal server configuration and deployment scripts",
                            language="YAML",
                            visibility="internal",
                            updated="Updated 3 days ago",
                            commits=[
                                GitCommit("Update SSH host keys after reinstall", "mmorgan", "3 days ago"),
                                GitCommit("Add Prometheus monitoring config", "sking", "1 week ago"),
                                GitCommit("Add SSH config template (ForwardAgent yes)", "lchen", "3 weeks ago"),
                                GitCommit("Initial commit", "mmorgan", "3 months ago"),
                            ],
                        ),
                        GitRepo(
                            name="web-app",
                            description="Customer portal (Django)",
                            language="Python",
                            visibility="internal",
                            updated="Updated 2 days ago",
                            commits=[
                                GitCommit("Fix login redirect after session timeout", "mmorgan", "2 days ago"),
                                GitCommit("Update Django to 4.2.9", "mmorgan", "5 days ago"),
                                GitCommit("Add rate limiting middleware", "mmorgan", "2 weeks ago"),
                            ],
                        ),
                        GitRepo(
                            name="database-scripts",
                            description="Backup and maintenance scripts",
                            language="Shell",
                            visibility="private",
                            updated="Updated 1 week ago",
                            commits=[
                                GitCommit("Add weekly snapshot job", "mmorgan", "1 week ago"),
                                GitCommit("Fix backup rotation", "mmorgan", "3 weeks ago"),
                            ],
                        ),
                    ],
                ),
            ],
        )
