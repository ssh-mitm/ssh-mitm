# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased] - 2021-07-02

### Added

- pass env and window change requests to the server


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

[Unreleased]: https://github.com/ssh-mitm/ssh-mitm/compare/0.5.11...HEAD
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
