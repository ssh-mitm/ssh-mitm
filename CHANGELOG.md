# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Changed

- better output for Flatpak

## [4.0.0] - 2023-09-14

### Added

- added configuration file to configure default values
- added info and PoC exploit for CVE-2023-25136
- mosh - added more information for decrypted packet
- added json logging format
- added client ip and port to client information #145

### Fixed

- added workarround for git to avoid unexpected session termination when EOF was reveived
- added fix for GitHub git operations
- fixes #136 - set paramiko version to >=3,<3.2 to fix private api changes in paramiko

### Changed

- set banner name only for server, not for client
- when output is piped to another application, the logformat is switched to json
- changed build system to hatch
- create AppImage with appimagetool instead of AppImage-Builder

### Removed

- removed support for Python 3.7
- removed official support for Windows


## [3.0.2] - 2023-02-14

### Added

- added requirements.txt which pins the tested packages

### Fixed

- fixed infinite loop when client closes connection during authentication
- fixed errors when too much connection attemps happen for the same server
- close transport in probe_host, which can publickey auth lead to fail


## [3.0.1] - 2022-12-18

### Fixed

- fixed requirements for installation

## [3.0.0] - 2022-12-18

### Added

- intercept MOSH connection and print decrypted data as hexdump
- added new function to get client information about used libraries
- added option to disable auth method lookup
- added indicator to docs, if vulnerability check is included in SSH-MITM
- added CVSS scores to vulnerability list in documentation
- added SHA512 fingerprint for server key
- added custom help formatter for cli arguments
- added option to disable auth method lookup

### Fixed

- fixed reace condition when tools like pyinfra are intercepted
- fixed documentation about port forwarding to match SSH-MITM v2
- fixed description of CVE-2022-29154
- updated  description of CVE-2020-15778

### Changed

- changed documentation folder structure
- if mosh is detected, pty will be disabled
- replaced typing.text with str
- removed support for Python 3.6

### Removed

- removed dependancy to python enhancements module
- remove unused methods and code
- removed unused update check


## [2.1.0] - 2022-08-05

### Added

- Test for CVE-2022-29154 (rsync file injection)
- Updated vulnerability database with new clients

### Fixed

- fixed a bug which shows an empty cve list
- fixed finding clients which are derived from other clients
- fix #95 - added workarround for MonaXterms SecureBlackbox SSH implementation

### Changed

- removed typecheck decorator



## [2.0.5] - 2022-06-17

### Fixed

- updated CVE-2020-14145 to match openSSH 8.9
- fixed client version check for vulnerabilities when using PuTTY
- fixed .bumpversion.cfg to work with original bump2version command (suggested by [@FredM](https://github.com/FredM))
- catch connection errors during authentication
- fixed scp message order from client to server to match OpenSSH's behavior (found by [@oddko](https://github.com/oddko))
- send server EOF and return code when closing scp channel (found by [@oddko](https://github.com/oddko), fixed by [@zoey-fux](https://github.com/zoey-fux))


## [2.0.4] - 2022-06-12

### Fixed

- close scp channel on EOF (found by [@oddko](https://github.com/oddko))

## [2.0.3] - 2022-05-22

### Fixed

- fixed appimage build script
- only show cve information if client has vulnerabilities
- catch error on closing mirror shell socket

## [2.0.2] - 2022-05-20

### Fixed

- fixed snapcaft.yaml build script
- fixed version numbers in man pages

## [2.0.1] - 2022-05-20

### Changed

- snap distribution - base image changed to core20

## [2.0.0] - 2022-04-01

### Changed

- changed license to GPLv3
- renamed module to "sshmitm" - old name "ssh_proxy_server"

## [1.0.0] - 2022-02-07

### Added

- added full support for trivial success authentication
- better documentation
- added typehints and typecheching
- added audit command, which tests publickey authentication with a specific private key

### Changed

- separate arguments for remote host and remote port
- changed logoutput format
- port forwarding: set injectable server tunnel forwarder as default forwarder
- replaced wxpython ssh-askpass implementation with tkinter

### Fixed

- added workarround for publickey lookup with OpenSSH 8.8

### Removed

- Gooey GUI
- removed SFTPHandle from SFTP replace_file plugin
- removed setup.cfg file


## [0.6.3] - 2021-11-04

- fixed hostname regex (error in regex)

## [0.6.2] - 2021-11-04

### Fixed

- fixed hostname regex (regex was to strict and not all hostnames were allowed)

## [0.6.1] - 2021-09-21

### Fixed

- missing environment variable in snap file
- fixed ssh-mitm-audit command

## [0.6.0] - 2021-09-13

### Added

- publickey authentication uses the same key as the destination server
- check if publickey authentication is possible
- updated vulnerability database
- added command to probe for known public keys
- save public keys to a file
- added simple gui
- added audit command
- added version check
- autodetect host key type

### Changed

- terminal logging changed to rich
- added terminal logging to mirror shell
- use same session log directory for all plugins
- use same icon for appimage and snap
- renamed cli argument '--disable-pubkey-auth' to '--disable-publickey-auth'
- removed arguments to request and forward agent (added autodetect of forwarded agent)

### Fixed

- bumpversion config file
- hide strg+c when shutting down server



## [0.5.13] - 2021-07-16

### Changed

- reorganized command line arguments - plugin args are now grouped

### Fixed

- fixed closing session when open channels exist

## [0.5.12] - 2021-07-13

### Fixed

- handle subsystem errors in sftp server
- ssh-mitm passes the return code of ssh commands to the client
- fixed error in sftp client, when ssh client does not exist

### Added

- pass env and window change requests to the server
- added asyncssh key negotiation vulnerability check
- added rubynetssh default key algorithms


## [0.5.11] - 2021-07-01

### Fixed

- fixed dropbear vulndb


## [0.5.10] - 2021-07-01

### Fixed

- missing python packages for snap and flatpak


## [0.5.9] - 2021-07-01

### Added

- print host key fingerprints on startup
- added client version check against known vulnerabilities
- added option to start ssh-mitm as module


## [0.5.8] - 2021-06-28

### Fixed

- use password cmd arg with all auth methods
- changed none auth to be rfc conform

### Added

- added keyboard-interactive authentication as alternative to password authentication


## [0.5.7] - 2021-06-10

### Fixed

- fixed "variable referenced before assignment" bug

### Added

- added '--version' cmd argument

### Changed

- Changed remote software name to 'SSHMITM_VERSIONSTRING'


## [0.5.6] - 2021-06-09

### Fixed

- fixed transparent mode in AppImage


## [0.5.5] - 2021-05-31


### Fixed

- fixed error when parsing converted IPv4 to IPv6 converted addresses


## [0.5.4] - 2021-05-12

### Added

- added new plugin to debug ssh command traffic

### Fixed

- increase buffer length to avoid broken connections with git
- do not close session on eof


## [0.5.3] - 2021-05-12

### Fixed

- fixed ssh command ``ssh -C <command>``
- ssh command now compatible with git


## [0.5.2] - 2021-05-07

### Added

- added default algorithms for OpenSSH 8.5 and 8.6 ([CVE-202014145](https://docs.ssh-mitm.at/CVE-2020-14145.html))

## [0.5.1] - 2021-05-03

### Changed

- sftp client is created only on sftp subsystem request


## [0.5.0] - 2021-03-26

### Added

- support remote port forwarding (ssh -R)
- support for proxyjump (ssh -W /-J) over the ssh-mitm server
- remote tunnel injection feature

### Changed

- handling of local port forwarding (passes through the tcpip stream to the remote)

## [0.4.3] - 2021-03-09

### Added

- compatibility with dropbear ssh clients


## [0.4.2] - 2021-03-05

### Added

- implemented CVE-2020-14002 (Putty information leak)
- option to use ed25519 host keys


## [0.4.1] - 2021-03-02

### Removed

- removed injectorshell because it will be integrated in [ssh-mitm-plugins](https://github.com/ssh-mitm/ssh-mitm-plugins) (maintained by @The5imon)

## [0.4.0] - 2021-02-12

### Added

- added port forwarding (only client to proxy at the moment)

### Fixed

- fixed pseudo terminal on exec command

[Unreleased]: https://github.com/ssh-mitm/ssh-mitm/compare/4.0.0...master
[4.0.0]: https://github.com/ssh-mitm/ssh-mitm/compare/3.0.2...4.0.0
[3.0.2]: https://github.com/ssh-mitm/ssh-mitm/compare/3.0.1...3.0.2
[3.0.1]: https://github.com/ssh-mitm/ssh-mitm/compare/3.0.0...3.0.1
[3.0.0]: https://github.com/ssh-mitm/ssh-mitm/compare/2.1.0...3.0.0
[2.1.0]: https://github.com/ssh-mitm/ssh-mitm/compare/2.0.5...2.1.0
[2.0.5]: https://github.com/ssh-mitm/ssh-mitm/compare/2.0.4...2.0.5
[2.0.4]: https://github.com/ssh-mitm/ssh-mitm/compare/2.0.3...2.0.4
[2.0.3]: https://github.com/ssh-mitm/ssh-mitm/compare/2.0.2...2.0.3
[2.0.2]: https://github.com/ssh-mitm/ssh-mitm/compare/2.0.1...2.0.2
[2.0.1]: https://github.com/ssh-mitm/ssh-mitm/compare/2.0.0...2.0.1
[2.0.0]: https://github.com/ssh-mitm/ssh-mitm/compare/1.0.0...2.0.0
[1.0.0]: https://github.com/ssh-mitm/ssh-mitm/compare/0.6.3...1.0.0
[0.6.3]: https://github.com/ssh-mitm/ssh-mitm/compare/0.6.2...0.6.3
[0.6.2]: https://github.com/ssh-mitm/ssh-mitm/compare/0.6.1...0.6.2
[0.6.1]: https://github.com/ssh-mitm/ssh-mitm/compare/0.6.0...0.6.1
[0.6.0]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.13...0.6.0
[0.5.13]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.12...0.5.13
[0.5.12]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.11...0.5.12
[0.5.11]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.10...0.5.11
[0.5.10]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.9...0.5.10
[0.5.9]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.8...0.5.9
[0.5.8]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.7...0.5.8
[0.5.7]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.6...0.5.7
[0.5.6]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.5...0.5.6
[0.5.5]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.4...0.5.5
[0.5.4]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.3...0.5.4
[0.5.3]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.2...0.5.3
[0.5.2]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.1...0.5.2
[0.5.1]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/ssh-mitm/ssh-mitm/compare/0.4.3...0.5.0
[0.4.3]: https://github.com/ssh-mitm/ssh-mitm/compare/0.4.2...0.4.3
[0.4.2]: https://github.com/ssh-mitm/ssh-mitm/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/ssh-mitm/ssh-mitm/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/ssh-mitm/ssh-mitm/releases/tag/0.4.0
