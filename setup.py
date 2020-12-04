# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

# read the contents of your README file
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='ssh_proxy_server',
    version='0.2.5',
    author='Manfred Kaiser, Simon Böhm',
    author_email='ssh-proxy-server@logfile.at',
    description='ssh proxy server to intercept ssh',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords="ssh proxy mitm network security audit",
    packages=find_packages(),
    url="https://github.com/manfred-kaiser/ssh-proxy-server",
    project_urls={
        'Source': 'https://github.com/manfred-kaiser/ssh-proxy-server',
        'Tracker': 'https://github.com/manfred-kaiser/ssh-proxy-server/issues',
    },
    python_requires='>= 3.6',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: System :: Networking",
        "Development Status :: 4 - Beta"
    ],
    entry_points={
        'console_scripts': [
            'ssh-proxy-server = ssh_proxy_server.cli:main'
        ]
    },
    install_requires=[
        'enhancements>=0.0.4',
        'paramiko',
        'pytz'
    ]
)
