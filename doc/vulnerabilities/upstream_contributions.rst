.. _upstream-contributions:

:fas:`code-branch` Upstream Contributions
============================================

Not every result of this research is a vulnerability. Working through
OpenSSH's authentication and sandboxing code during the GSSAPI research
(see :doc:`CVE-2026-60000 </vulnerabilities/CVE-2026-60000>`) also produced
direct hardening contributions to OpenSSH itself, credited to Manfred Kaiser.

.. list-table::
   :header-rows: 1

   * - Commit
     - Change
   * - `4f4aeee6ed <https://github.com/openssh/openssh-portable/commit/4f4aeee6edaa248f1e7ce22ee3f35ce183eabf38>`__
     - ``sandbox-seccomp-filter``: removed a duplicate
       ``SC_ALLOW(__NR_clock_gettime64)`` entry — the syscall was already
       permitted under its own ``ifdef`` guard elsewhere in the filter.
       Authored directly by Manfred Kaiser.
   * - `7ab700f170 <https://github.com/openssh/openssh-portable/commit/7ab700f1706b154d4bc5cf66e19c05be6d9b1fc1>`__
     - Made a failure to set ``SECCOMP`` or ``NO_NEW_PRIVS`` fatal instead of
       silently continuing with a weaker sandbox. Credited as
       *"Prompted by manfred.kaiser@ssh-mitm.at"*.

Both changes tighten OpenSSH's privilege-separation sandbox rather than
fixing a reported vulnerability, and neither carries a CVE — they are listed
here for completeness alongside the CVE-2026-60000 research that surfaced
them.
