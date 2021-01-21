# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

# read the contents of your README file
from os import path
import re

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = re.sub(r"## Give a Star.*?Thanks!", "", f.read(), 0, re.DOTALL)


setup(
    name='ssh-mitm',
    version='0.3.17',
    author='SSH-MITM Dev-Team',
    author_email='support@ssh-mitm.at',
    description='ssh mitm server for security audits supporting public key authentication, session hijacking and file manipulation',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords="ssh proxy mitm network security audit",
    packages=find_packages(),
    url="https://ssh-mitm.at",
    project_urls={
        'Documentation': 'https://docs.ssh-mitm.at',
        'Source': 'https://github.com/ssh-mitm/ssh-mitm',
        'Tracker': 'https://github.com/ssh-mitm/ssh-mitm/issues',
    },
    python_requires='>= 3.6',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Topic :: System :: Networking",
        "Development Status :: 4 - Beta"
    ],
    entry_points={
        'console_scripts': [
            'ssh-proxy-server = ssh_proxy_server.cli:main',
            'ssh-mitm = ssh_proxy_server.cli:main',
        ],
        'ssh_interface': [
            'base = ssh_proxy_server.forwarders.ssh:SSHForwarder',
            'injectorshell = ssh_proxy_server.plugins.ssh.injectorshell:SSHInjectableForwarder',
            'mirrorshell = ssh_proxy_server.plugins.ssh.mirrorshell:SSHMirrorForwarder',
            'noshell = ssh_proxy_server.plugins.ssh.noshell:NoShellForwarder',
            'sessionlogger = ssh_proxy_server.plugins.ssh.sessionlogger:SSHLogForwarder'
        ],
        'scp_interface': [
            'base = ssh_proxy_server.forwarders.scp:SCPForwarder',
            'inject_file = ssh_proxy_server.plugins.scp.inject_file:SCPInjectFile',
            'replace_file = ssh_proxy_server.plugins.scp.replace_file:SCPReplaceFile',
            'store_file = ssh_proxy_server.plugins.scp.store_file:SCPStorageForwarder'
        ],
        'sftp_interface': [
            'base = ssh_proxy_server.interfaces.sftp:SFTPProxyServerInterface'
        ],
        'sftp_handler': [
            'base = ssh_proxy_server.forwarders.sftp:SFTPHandlerPlugin',
            'replace_file = ssh_proxy_server.plugins.sftp.replace_file:SFTPProxyReplaceHandler',
            'store_file = ssh_proxy_server.plugins.sftp.store_file:SFTPHandlerStoragePlugin'
        ],
        'auth_interface': [
            'base = ssh_proxy_server.interfaces.server:ServerInterface'
        ],
        'authenticator': [
            'passthrough = ssh_proxy_server.authentication:AuthenticatorPassThrough'
        ]

    },
    install_requires=[
        'enhancements>=0.1.12',
        'tcp-proxy-server>=0.0.2',
        'paramiko',
        'pytz'
    ]
)
