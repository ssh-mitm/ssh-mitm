# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

# read the contents of your README file
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='ssh_proxy_server',
    version='0.0.2',
    author='Manfred Kaiser',
    author_email='manfred.kaiser@logfile.at',
    description='ssh proxy server to intercept ssh',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages(),
    url="https://github.com/manfred-kaiser/ssh-proxy-server",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: System :: Networking"
    ],
    entry_points={
        'console_scripts': [
            'ssh-proxy-server = ssh_proxy_server.cli:main'
        ]
    },
    install_requires=[
        'enhancements',
        'paramiko',
        'pytz'
    ]
)
