"""Tutorial: SFTP File Download Interception."""

import random

from sshmitm.tutorial._client_actions import SFTPDownloadSessionAction
from sshmitm.tutorial._conditions import PortOpen, TRUE, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial

_FILES: dict[str, bytes] = {
    "employee_salaries_2024.csv": (
        b"Name,Department,Annual Salary,Bonus\n"
        b"Alice Morgan,Engineering,95000,12000\n"
        b"Bob Chen,Product,87000,9500\n"
        b"Carol Davis,HR,72000,6000\n"
        b"David Kim,Finance,91000,11000\n"
    ),
    "customer_database_export.csv": (
        b"id,email,full_name,credit_card\n"
        b"1001,alice@example.com,Alice Morgan,4111111111111111\n"
        b"1002,bob@example.com,Bob Chen,5500005555555559\n"
        b"1003,carol@example.com,Carol Davis,340000000000009\n"
    ),
    "aws_credentials_prod.env": (
        b"[default]\n"
        b"aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"
        b"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        b"region=eu-central-1\n"
    ),
    "private_key_backup.pem": (
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29P2rFj7tBPy2F\n"
        b"[...key data truncated for security...]\n"
        b"-----END RSA PRIVATE KEY-----\n"
    ),
    "vpn_config_internal.ovpn": (
        b"client\ndev tun\nproto udp\n"
        b"remote vpn.internal.example.com 1194\n"
        b"<ca>\n-----BEGIN CERTIFICATE-----\n"
        b"MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n"
        b"-----END CERTIFICATE-----\n</ca>\n"
    ),
    "gitlab_deploy_token.txt": (
        b"# GitLab Deploy Token - production registry\n"
        b"DEPLOY_TOKEN_NAME=prod-registry-pull\n"
        b"DEPLOY_TOKEN_USERNAME=gitlab+deploy-token-42\n"
        b"DEPLOY_TOKEN_VALUE=gldt-xYz9_Abc3-DeF1gHiJkL\n"
    ),
    "quarterly_financial_report.pdf": (
        b"%PDF-1.4\n"
        b"% Acme Corp - Q3 2024 Financial Report (CONFIDENTIAL)\n"
        b"% Revenue: $4,821,300  |  Net profit: $612,000\n"
    ),
    "ssh_host_keys_backup.tar.gz": (
        b"\x1f\x8b\x08\x00"  # gzip magic + flags
        b"# ssh_host_rsa_key, ssh_host_ecdsa_key, ssh_host_ed25519_key\n"
    ),
}

_FILENAMES = list(_FILES)


class SFTPDownloadTutorial(Tutorial):
    id          = "03-sftp-download"
    title       = "SFTP File Download Interception"
    category    = "File Transfer"
    description = "Learn how SSH-MITM intercepts SFTP downloads and reveals which files a client copies from a server."
    tags = ["SFTP", "File Interception"]
    docs = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "File Transfers": "https://docs.ssh-mitm.at/user_guide/file_transfer.html",
    }
    lab_service_labels = {"mock_port": "files.logfileinc.internal"}

    steps = [
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
                " --remote-host 127.0.0.1"
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
                "sftp_filename",
                prompt="Enter the name of the file that was downloaded:",
            ),
            victim_action=SFTPDownloadSessionAction("sftp_filename"),
            hint_waiting="A developer is downloading a file through SSH-MITM. Check the terminal and enter the filename above.",
            hint_done="Correct! You intercepted the file transfer. ✓",
        ),
    ]

    def generate_tutorial_session_data(self) -> dict[str, object]:
        return {"sftp_filename": random.choice(_FILENAMES)}

    def generate_sftp_files(self, session_data: dict[str, object]) -> dict[str, bytes]:
        filename = str(session_data.get("sftp_filename", ""))
        content = _FILES.get(filename)
        if content is None:
            return {}
        return {filename: content}
