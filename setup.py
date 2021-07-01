# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

# read the contents of your README file
from os import path
import re

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = re.sub(r"## Give a Star.*?Thanks!", "", f.read(), 0, re.DOTALL)
    long_description = re.sub(r"To install \*\*SSH-MITM.*?### Install as pip-package", "", long_description, 0, re.DOTALL)

def get_version():
    from ssh_proxy_server.__version__ import version
    return version

def get_entry_points():
    from ssh_proxy_server.__entrypoints__ import entry_points as ssh_entry_points
    return {
        **ssh_entry_points
    }


setup(
    name='ssh-mitm',
    version=get_version(),
    author='SSH-MITM Dev-Team',
    author_email='support@ssh-mitm.at',
    description='ssh mitm server for security audits supporting public key authentication, session hijacking and file manipulation',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords="ssh proxy mitm network security audit",
    packages=find_packages(),
    url="https://www.ssh-mitm.at",
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
    package_data={
        'ssh_proxy_server': [
            'data/*.*',
        ]
    },
    entry_points={
        **{
            'console_scripts': [
                'ssh-proxy-server = ssh_proxy_server.cli:main',
                'ssh-mitm = ssh_proxy_server.cli:main'
            ]
        },
        **get_entry_points()
    },
    install_requires=[
        'enhancements>=0.2.1',
        'paramiko',
        'pytz',
        'sshpubkeys',
        'pyyaml',
        'packaging'
    ],
    extras_require={
        'plugins': [
            'ssh-mitm-plugins'
        ],
    }
)
