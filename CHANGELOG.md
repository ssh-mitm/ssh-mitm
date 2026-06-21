# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Fixed

- **CVE-2023-48795 (Terrapin) detection**: Fixed a bug where the vulnerability
  check incorrectly evaluated `supports_cbc_etm or supports_cbc_etm` instead of
  `supports_chacha20 or supports_cbc_etm`, causing ChaCha20-Poly1305 to never
  be considered when determining vulnerability status.

### Changed

- **CVE-2023-48795 (Terrapin) detection**: Improved reporting now lists the
  specific affected algorithms per direction (client-to-server / server-to-client),
  including the concrete CBC ciphers and ETM MACs involved.
  `rijndael-cbc@lysator.liu.se` is now also recognized as a CBC variant.
  Both `kex-strict-c-v00@openssh.com` and `kex-strict-s-v00@openssh.com`
  are checked when determining mitigation status.

### Added

- **Interactive tutorial system**: `ssh-mitm tutorial` opens a browser-based,
  step-by-step tutorial that demonstrates SSH-MITM's core capabilities without
  requiring an external target server. The tutorial spins up a built-in mock SSH
  server for each exercise and guides the learner through each scenario
  interactively. Five tutorials are included out of the box:
  password authentication interception, public-key auth and agent-forwarding
  interception, SFTP file-download interception, SSH command execution
  interception, and live session mirroring (mirror shell). Additional tutorials
  can be installed as Python packages via the `sshmitm.Tutorial` entry point.

- **Signal forwarding (RFC 4254 §6.9)**: Signals sent by the SSH client
  (e.g. `kill -TERM $SSH_TTY_PID`) are now forwarded to the remote server.
  Paramiko has no built-in support for the "signal" channel request type;
  SSH-MITM patches the transport dispatch table at startup to intercept it.

- **Terminal modes forwarding**: PTY terminal modes (e.g. `VINTR`, `ECHO`)
  sent by the client during `pty-req` are now passed through to the remote
  server unchanged. Previously paramiko's `get_pty()` silently discarded
  the modes bytes.

- **Asciinema session recording**: Terminal sessions can now be recorded in
  asciinema v2 format (`.cast` files) in addition to the existing scriptreplay
  format. Use `--ssh-terminal-log-formatter asciinema` when starting the
  server. MOSH sessions can also be recorded to disk for the first time via
  `--store-mosh-session` with the same format choice
  (`--mosh-terminal-log-formatter script|asciinema`).

- **None authentication is now forwarded to the remote server**: If the
  target server allows login without any credentials (none auth), SSH-MITM
  now forwards this to the client and establishes the session accordingly,
  instead of always rejecting it. The `--enable-none-auth` flag was renamed to
  `--force-none-auth` and continues to work for cases where you want to accept
  none auth regardless of what the remote server supports.

- **New `ssh-mitm mock-server` subcommand**: A lightweight built-in SSH server
  for testing and development. It accepts a single configurable user with
  password, public-key, keyboard-interactive, and none authentication, and
  executes commands directly on the host. Useful for testing SSH-MITM without
  setting up a full OpenSSH server. The mock server also supports an in-memory
  SFTP subsystem, allowing tutorials and tests to serve virtual files without
  touching the real filesystem.

- **Keyboard-interactive authentication is now intercepted by default**:
  SSH-MITM transparently forwards keyboard-interactive challenges from the
  target server to the client and returns the client's answers, so sessions
  using PAM, TOTP, or any other challenge-response mechanism are captured
  without any extra configuration. The previous opt-in flag
  `--enable-keyboard-interactive-auth` is no longer needed; use
  `--disable-keyboard-interactive-auth` to turn it off explicitly.

- **Clients with SSH agent host key restrictions can now be intercepted**:
  OpenSSH 8.9 introduced the ability to restrict which hosts an agent key may
  be used for (`ssh-add -h`). When such a restriction is in place, the agent
  refuses to sign unless the SSH session is cryptographically bound to the
  target host key. SSH-MITM now implements this binding correctly, so sessions
  from clients using host-bound agent keys no longer fail visibly at the MITM.
  Full documentation is available in the user guide.

- **Banner passthrough in both directions**: SSH-MITM now exchanges the real
  SSH version strings in both directions. Clients see the target server's
  actual version string, and the target server sees the connecting client's
  actual version string. Previously, the server always saw
  `SSH-2.0-paramiko_X.Y.Z` regardless of which client was used, which could
  reveal the interception in server logs or packet captures. The `--banner-name`
  option still works and takes precedence over the server-side passthrough.

- **MOSH session monitoring**: A new `ssh-mitm mosh client <host> <port>`
  subcommand lets you watch an active MOSH session in real time. The viewer
  renders a full VT100/ANSI terminal and replays the complete session history
  to any viewer that connects later.

- **Interactive plugin browser**: `ssh-mitm server --plugins` opens a
  terminal UI where you can explore all available plugins, their descriptions,
  and configuration options without having to read the docs.

- **Remote server fingerprint verification**: You can now pass expected
  fingerprints via `--remote-fingerprints` so SSH-MITM rejects connections
  to unexpected servers.

- **Credential-based remote authentication**: The new `AuthenticatorRemote`
  plugin lets you supply fixed credentials for the upstream server without
  using the passthrough authenticator.

- **Pinned production dependencies**: `pip install ssh-mitm[production]`
  installs a fully tested set of dependency versions suitable for production
  use.

- **PowerShell remoting (PSRP over SSH) interception**: SSH-MITM now intercepts
  PowerShell remoting sessions that use the SSH transport (`Enter-PSSession
  -HostName …`). The binary PSRP stream is relayed transparently between the
  client and the remote `pwsh -sshs` process. A new `--powershell-interface`
  CLI argument selects the forwarder plugin; the default is
  `PowerShellForwarder`. Custom plugins can subclass it and override
  `handle_client_data` / `handle_server_data` to inspect or modify the raw
  stream. Includes the new `sshmitm.clients.powershell.PowerShellClient` and
  `sshmitm.forwarders.powershell.PowerShellBaseForwarder` base classes.

- **PSRP session logging plugin** (`--powershell-interface log-session`):
  The new `PSRPLoggingForwarder` parses the PSRP-over-SSH wire format on the
  fly (MS-PSRP §2.2.4) and logs every protocol message — executed commands,
  pipeline output, errors, warnings, and runspace/pipeline state transitions.
  The stream is forwarded to the server unchanged. An optional
  `--psrp-transcript-dir` argument writes a human-readable per-session
  transcript file (one line per message). XML parsing uses `lxml` with all
  dangerous features disabled (no entity expansion, no DTD, no network access)
  to prevent XXE attacks.

- **Keyboard-interactive responses are now logged**: Each challenge round is
  captured as a structured log event (`auth_kbdint_response`) containing the
  prompt texts and the client's answers. The final outcome is logged separately
  as `auth_kbdint_result`. All captured prompt/response pairs are also stored
  in `session.auth.kbdint_responses` so custom plugins can access them.
  The `--auth-hide-credentials` flag suppresses the response values in both the
  log and the stored list. Closes #137 (partial — `AUTH_PARTIALLY_SUCCESSFUL`
  chaining for multi-method 2FA is still open).

### Fixed

- **Mirror shell**: connecting clients now see a brief status banner with their
  observed IP address. The connection loop was also hardened against channels
  that close mid-session, preventing a hang when the original session ends.

- Fixed broken SFTP file transfers and incorrect error responses for missing
  files.
- Fixed a connection drop that occurred when the remote side closed a command
  channel before all data was read.
- Terminal resize events (`SIGWINCH`) are now correctly forwarded to the
  remote server (#187).
- Subsystems (e.g. SFTP) are no longer started before the upstream connection
  is fully authenticated.
- **Connection limit (`--max-connections`)**: the server now rejects incoming
  connections once the configured limit is reached instead of spawning threads
  without bound. The default is 100 concurrent sessions; set to 0 for
  unlimited. Finished session threads are cleaned up automatically on each
  new connection so the count stays accurate. Closes #171.
- **Graceful server shutdown**: pressing Ctrl-C now waits up to 30 seconds
  for active session threads to finish before exiting. The listening socket
  is closed immediately so no new connections are accepted, and
  `session.running` becomes `False` for all sessions so their forwarding
  loops stop within one polling cycle (~100 ms). `os._exit()` is used only
  as a last resort if threads do not stop within the timeout. Closes #167.
- **Mosh fails to start on systems with old `cryptography` packages**: The
  `AESOCB3` cipher class required by Mosh support was introduced in
  `cryptography` 38.0.0 (September 2022), but the package was only constrained
  transitively via `paramiko` to `>=3.3`, allowing broken combinations on e.g.
  Ubuntu 22.04 LTS. `cryptography>=38.0.0` is now an explicit dependency.
  A `try/except` with a clear upgrade hint was added around the import so that
  users with an incompatible system-Python installation see an actionable error
  instead of a bare `ImportError`. Closes #195.

### Changed

- **Reduced connection footprint during public key lookup**: SSH-MITM
  previously opened a separate connection to the target server to check
  whether a client's public key is accepted, resulting in two log entries per
  intercepted session. The key check and the actual authentication now share
  one connection, leaving only a single log entry on the target server and
  reducing the risk of triggering OpenSSH's rate-limiting.

- **Python 3.11 or newer is now required.** Python 3.9 and 3.10 are no
  longer supported.

- DSS/DSA keys are no longer supported (OpenSSH has deprecated them as well).

- Updated paramiko dependency to version 4.0.


## [5.0.1] - 2025-01-22

### Added

- AppImage - added option to use extracted squashfs-root

### Fixed

- Rename logging.py to logger.py to avoid naming conflict in jsonlogger when in debug mode - fiexed by [francisfueconcillo](https://github.com/francisfueconcillo)
- fix connection call for IPv6 SSH servers - fixed by [ lmm-git](https://github.com/lmm-git)
- fixed typos by [Weltolk](https://github.com/Weltolk)


## [5.0.0] - 2024-06-29

### Changed

- easier plugin development
- SSH-MITM uses "appimage" module to start the AppImage
- merged SOCKS4 and SOCKS5 module in a single module
- prepend entry points with "sshmitm" to avoid name conflicts
- updated vulnerability db


## [4.1.1] - 2023-11-01

### Fixed

- fixed python source distribution - reported by [p-linnane ](https://github.com/p-linnane)


## [4.1.0] - 2023-10-31

### Fixed

- fixed AppImage build process

### Changed

- better output for Flatpak
- allow mkdir to work with default attr.st_mode (https://github.com/ssh-mitm/ssh-mitm/pull/152)
- Add new option to store output of non-interactive commands (https://github.com/ssh-mitm/ssh-mitm/pull/156)
- moved project dependencies to requirements.in file
- use command name of executable or link in help output


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

[Unreleased]: https://github.com/ssh-mitm/ssh-mitm/compare/5.0.1...master
[5.0.1]: https://github.com/ssh-mitm/ssh-mitm/compare/5.0.0...5.0.1
[5.0.0]: https://github.com/ssh-mitm/ssh-mitm/compare/4.1.1...5.0.0
[4.1.1]: https://github.com/ssh-mitm/ssh-mitm/compare/4.1.0...4.1.1
[4.1.0]: https://github.com/ssh-mitm/ssh-mitm/compare/4.0.0...4.1.0
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
