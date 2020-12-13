# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

# read the contents of your README file
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='ssh-mitm',
    version='0.3.1',
    author='Manfred Kaiser, Simon Böhm',
    author_email='ssh-proxy-server@logfile.at',
    description='ssh proxy server to intercept ssh',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords="ssh proxy mitm network security audit",
    packages=find_packages(),
    url="https://ssh-mitm.logfile.at",
    project_urls={
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
        ]
    },
    install_requires=[
        'enhancements>=0.0.4',
        'paramiko',
        'pytz'
    ]
)
