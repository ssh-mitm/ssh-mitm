:fas:`sitemap` Scenario Framework
===================================

The tutorial framework uses typed Python classes to declare everything that
appears in the lab: users, network segments, mock services, and complete
hosts.  A *scenario generator* combines these declarations with a tutorial's
requirements and produces a ready-to-run session.

This page explains how to read, write, and extend the framework.
For the story and infrastructure of the existing scenario see
:doc:`scenario`.


Overview
--------

.. mermaid::

   flowchart TD
       user["User\n(mmorgan, sking, …)"]
       segment["Segment\n(ApplicationServers, …)"]
       service["Service\n(SSHService, SFTPService, …)"]
       host["Host\n(Web01, Router01, …)"]
       scenario["Scenario\n(LogfileIncScenario)"]
       req["Requirement\n(RandomPassword, RandomKeyPair, …)"]
       gen["ScenarioGenerator.build()"]
       session["ScenarioSession"]

       user  --> host
       segment --> host
       service --> host
       host --> scenario
       req --> gen
       scenario --> gen
       gen --> session


Core concepts
-------------

**User**
    A person in the assessment scenario.  Carries ``username``,
    ``full_name``, and ``role``.  Used as a type (class reference), not as
    an instance.

**Segment**
    A network segment.  Provides ``name`` and ``subnet`` for documentation
    and topology validation.

**Service**
    A single network service on a host.  Built-in types: ``SSHService``,
    ``SFTPService``, ``HTTPService``, ``SNMPService``, ``PostgreSQLService``.
    Each carries a ``port`` and a ``protocol`` class variable.

**Host**
    A mock server.  Declares topology (``label``, ``hostname``, ``address``,
    ``segment``, ``users``, ``services``) and behaviour methods
    (``shell_outputs``, ``sftp_files``, ``exec_outputs``, ``shell_prompt``).
    Dynamic values are injected via ``configure(session_data)``.

**Scenario**
    Groups the hosts and users that belong to one engagement.

**Requirement**
    Describes what dynamic data a tutorial needs.  Has two phases:

    * ``generate()`` — produces values merged into the session data
    * ``apply(hosts, values)`` — pushes generated values into host instances

**ScenarioSession**
    The live, configured state for one tutorial run.  Holds host instances,
    the asyncio event queue, and all generated values.  Exposes
    ``template_vars()`` for step command/hint interpolation.

**ScenarioGenerator**
    ``build(scenario, host_aliases, requires, sshmitm_port)`` instantiates
    hosts, runs all requirements, and returns a ``ScenarioSession``.


Adding a new host
-----------------

Create a sub-package under
``sshmitm/tutorial/hosts/<scenario_name>/<hostname>/``:

.. code-block:: text

   sshmitm/tutorial/hosts/logfile_inc/
       new_server/
           __init__.py

Minimal ``__init__.py``:

.. code-block:: python

   from sshmitm.tutorial.hosts import Host, SSHService
   from sshmitm.tutorial.hosts.logfile_inc import ApplicationServers, MaxMorgan

   class NewServer(Host):
       label    = "newserver"
       hostname = "newserver.logfileinc.internal"
       address  = "127.2.0.10"
       segment  = ApplicationServers
       users    = [MaxMorgan]
       services = [SSHService(port=20022)]

       def configure(self, session_data: dict) -> None:
           # Accept session values like passwords or authorized keys
           pw = session_data.get(f"newserver_{MaxMorgan.username}_password")
           if pw:
               self._password = str(pw)

       def shell_outputs(self, session_data: dict) -> dict[str, bytes]:
           return {"whoami": b"mmorgan\r\n"}

Then add the host to ``LogfileIncScenario.all_hosts()`` and declare an
entry point in ``pyproject.toml``:

.. code-block:: toml

   [project.entry-points."sshmitm.Host"]
   newserver = "sshmitm.tutorial.hosts.logfile_inc.new_server:NewServer"


Requirement types
-----------------

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Class
     - Purpose
   * - ``RandomPassword(user, host)``
     - Generates a random password and stores it under
       ``"{host.label}_{user.username}_password"``.
   * - ``StaticPassword(user, host, password)``
     - Uses a fixed password.  Useful when step content must reference
       a known value.
   * - ``RandomKeyPair(user, name, authorized_on=[…])``
     - Generates a fresh ECDSA key pair.  Stores the private key under
       ``"keypair_{name}_private"`` and the fingerprint under
       ``"keypair_{name}_fingerprint"``.  Calls ``host.configure()``
       with the authorized-key entry for each host in ``authorized_on``.
   * - ``StaticKeyPair(user, name, key, authorized_on=[…])``
     - Same as ``RandomKeyPair`` but uses a pre-generated key.
   * - ``RandomSecret(name, length=8)``
     - A random hex string, not tied to any host.  Useful for SNMP
       community strings, OTP tokens, etc.
   * - ``RandomChoice(name, choices)``
     - Picks one value from a list at runtime.
   * - ``StaticValue(name, value)``
     - Stores any fixed value in the session data.


Writing a tutorial that uses the framework
------------------------------------------

A tutorial declares which hosts it needs and what dynamic data each host
requires.  The ``ScenarioGenerator`` does the rest.

Example — a tutorial that intercepts a password login to ``web01``:

.. code-block:: python

   from sshmitm.tutorial._definitions import Step, Tutorial
   from sshmitm.tutorial._conditions import PortOpen, UserInput, TRUE
   from sshmitm.tutorial._requirements import RandomPassword
   from sshmitm.tutorial._session import ScenarioGenerator
   from sshmitm.tutorial.hosts.logfile_inc import LogfileIncScenario, MaxMorgan
   from sshmitm.tutorial.hosts.logfile_inc.web01 import Web01

   class PasswordAuthTutorial(Tutorial):
       id          = "01-password-auth"
       title       = "Password Authentication"
       category    = "Authentication"
       description = "Intercept SSH password authentication via SSH-MITM."

       scenario     = LogfileIncScenario
       host_aliases = {"proxy_target": Web01}
       requires     = [RandomPassword(MaxMorgan, Web01)]

       steps = [
           Step("intro", "What you will learn", condition=TRUE()),
           Step("start-sshmitm", "Start SSH-MITM",
                condition=PortOpen("sshmitm_port"),
                command="ssh-mitm server --remote-host {proxy_target_address}"
                        " --remote-port {proxy_target_port}"
                        " --listen-port {sshmitm_port}"),
           Step("intercept", "Enter the intercepted password",
                condition=UserInput("web01_mmorgan_password",
                                    prompt="Enter the password from the terminal:")),
       ]


Session data keys
-----------------

``ScenarioSession.template_vars()`` exposes all values for step command
and hint interpolation.  The following keys are always available:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Key pattern
     - Value
   * - ``sshmitm_port``
     - Port on which the SSH-MITM proxy listens.
   * - ``{alias}_address``
     - IP address of the host (e.g. ``proxy_target_address``).
   * - ``{alias}_hostname``
     - DNS name of the host.
   * - ``{alias}_port``
     - Port of the first SSH-like service.
   * - ``{alias}_port_{protocol}``
     - Port for a specific protocol (e.g. ``proxy_target_port_ssh``).
   * - ``{host.label}_{user.username}_password``
     - Generated or static password (from ``RandomPassword`` /
       ``StaticPassword``).
   * - ``keypair_{name}_fingerprint``
     - SHA-256 fingerprint of a generated key pair.
   * - any ``RandomSecret`` / ``RandomChoice`` / ``StaticValue`` name
     - Passed through verbatim.


Event types
-----------

Mock hosts emit events into ``ScenarioSession.events`` (an
``asyncio.Queue``).  Condition classes can subscribe to this queue to
detect when a specific action has occurred.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Event class
     - When emitted
   * - ``AuthEvent``
     - A user attempts authentication (success or failure).
   * - ``FileTransferEvent``
     - An SFTP upload or download completes.
   * - ``ExecEvent``
     - A non-interactive SSH exec command is run.
   * - ``SessionEvent``
     - An SSH session is opened or closed.
   * - ``FingerprintEvent``
     - A host-key fingerprint check is observed (CVE-2020-14145).

All event classes live in ``sshmitm.tutorial._events``.


Existing scenario: Logfile Inc.
--------------------------------

All current tutorial chapters belong to ``LogfileIncScenario``.  The
declared hosts are:

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Class
     - Module
     - Role
   * - ``Web01``
     - ``hosts.logfile_inc.web01``
     - Django application server, SSH + HTTP.  Accepts password (mmorgan)
       and public-key (sking, lchen) auth.
   * - ``Files``
     - ``hosts.logfile_inc.files``
     - SFTP-only file server.  Holds deployment artefacts and company docs.
   * - ``Router01``
     - ``hosts.logfile_inc.router01``
     - Network router CLI (SSH, SNMP).  Shell outputs include the running
       configuration with the SNMP read-write community string.
   * - ``LogfileGit``
     - ``hosts.logfile_inc.logfilegit``
     - Self-hosted Git platform.  Exposes ``/<username>.keys`` without
       authentication.
   * - ``DB01``
     - ``hosts.logfile_inc.db01``
     - PostgreSQL database.  No SSH service — probed only via the
       user-validity oracle (CVE-2016-20012).

For topology, addresses, and story details see :doc:`scenario`.
