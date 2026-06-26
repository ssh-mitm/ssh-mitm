"""Mock host: files.logfileinc.internal

Internal file server — SFTP only.  Holds deployment artefacts, configuration
backups, and company documents.  Max and Lisa access it regularly.
"""
from __future__ import annotations

import asyncio
import random

import paramiko

from sshmitm.tutorial.hosts import Host, SFTPService
from sshmitm.tutorial.hosts.logfile_inc import ApplicationServers, LisaChen, MaxMorgan

# Scenario-consistent files for Logfile Inc.
_FILES: dict[str, bytes] = {
    "deploy_keys_web01.tar.gz": (
        b"\x1f\x8b\x08\x00"
        b"# ssh_host_rsa_key, ssh_host_ecdsa_key (web01 reinstall backup)\n"
    ),
    "db_backup_2024-06-01.sql.gz": (
        b"\x1f\x8b\x08\x00"
        b"-- PostgreSQL database dump (production)\n"
        b"-- Logfile Inc. customer portal schema\n"
    ),
    "logfile_inc_policy_2024.pdf": (
        b"%PDF-1.4\n"
        b"% Logfile Inc. - IT Security Policy 2024 (INTERNAL)\n"
        b"% Drafted by lchen\n"
    ),
    "aws_credentials_prod.env": (
        b"[default]\n"
        b"aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"
        b"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        b"region=eu-central-1\n"
    ),
    "web01_nginx_config.conf": (
        b"server {\n"
        b"    listen 443 ssl;\n"
        b"    server_name logfileinc.internal;\n"
        b"    ssl_certificate /etc/ssl/logfileinc.crt;\n"
        b"    ssl_certificate_key /etc/ssl/private/server.key;\n"
        b"}\n"
    ),
    "ssh_config_template.txt": (
        b"Host *\n"
        b"    ForwardAgent yes\n"
        b"    StrictHostKeyChecking no\n"
        b"    UserKnownHostsFile=/dev/null\n"
    ),
    "gitlab_deploy_token.txt": (
        b"# LogfileGit Deploy Token - production registry\n"
        b"DEPLOY_TOKEN_USERNAME=gitlab+deploy-token-42\n"
        b"DEPLOY_TOKEN_VALUE=gldt-xYz9_Abc3-DeF1gHiJkL\n"
    ),
    "customer_data_export_2024-05.csv": (
        b"id,company,contact,contract_value\n"
        b"1001,Meridian GmbH,a.bauer@meridian.de,48000\n"
        b"1002,Solaris Systems,j.taylor@solaris.io,127000\n"
        b"1003,NordWerk AG,m.eriksson@nordwerk.de,63500\n"
    ),
}

FILENAMES = list(_FILES)


class Files(Host):
    """files.logfileinc.internal — internal SFTP file server."""

    label    = "files"
    hostname = "files.logfileinc.internal"
    address  = "127.2.0.2"
    segment  = ApplicationServers
    users    = [MaxMorgan, LisaChen]
    services = [
        SFTPService(port=20022),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._passwords: dict[str, str] = {}
        self._authorized_keys: dict[str, list[paramiko.PKey]] = {}
        self._sftp_filename: str | None = None

    def configure(self, session_data: dict) -> None:
        for user in self.__class__.users:
            pw_key   = f"files_{user.username}_password"
            auth_key = f"authorize_key_{user.username}"
            if pw_key in session_data:
                self._passwords[user.username] = str(session_data[pw_key])
            if auth_key in session_data:
                self._authorized_keys.setdefault(user.username, []).append(
                    session_data[auth_key]
                )
        if "files_sftp_filename" in session_data:
            self._sftp_filename = str(session_data["files_sftp_filename"])

    # ── behavior ────────────────────────────────────────────────────────

    def random_filename(self) -> str:
        return random.choice(FILENAMES)

    def sftp_files(self, session_data: dict) -> dict[str, bytes]:
        filename = str(session_data.get("files_sftp_filename", ""))
        if not filename:
            return {}
        content = _FILES.get(filename)
        return {filename: content} if content else {}

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, events: asyncio.Queue) -> None:
        await super().start(events)

    async def stop(self) -> None:
        pass
