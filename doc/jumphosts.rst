Jump Hosts
==========

**SSH-MITM should not be used as a jump host for security reasons!**

It's intended to be used during security audits and not for separating networks.

When operating a jump host, security is one of the most important requirements.
This can not be achieved with SSH-MITM, because it has vulnerabilities which are needed
for exploiting clients and servers.

If you need a jump host with audit capabilities for security compliences, you should a product, which
is created for such a use case.

.. note::

    The listed products are not connected with SSH-MITM and are only listed
    as an alternative to SSH-MITM, when a jump host is needed.


There are many products, which can be used as a jump hosts. When choosing a product as a jump host,
the most important is security. Many jump hosts are able to create an audit log or can store sessions
for compliance reasons. Also authentication passthrough are required.

When compared with SSH-MITM, they share many features, but the use case is different.
For example, passwords should not be logged on a jump host or a forwarded agent should not be accessible, even by administrators.

**Note:** Some descriptions are taken from the product websites or github repos.

OpenSSH, Dropbear, ...
""""""""""""""""""""""

The most simple Jump Host is a ssh server like OpenSSH or Dropbear. They are available in nearly all
Linux distributions.

In most scenarios, when they are used as jump host, they should only not or only restriced shell access.
When accessing servers behind the jump host, the recommended method is "ProxyJump".

ContainerSSH
""""""""""""

* **Url:** https://github.com/ContainerSSH/ContainerSSH
* **License:** MIT License

ContainerSSH lets you dynamically create and destroy containers when your users connect. Authenticate against your existing user database and mount directories based on your existing permission matrix.

ContainerSSH is being used to provide dynamic console access to an environment with sensitive credentials. Use the authentication and configuration server to dynamically provision credentials in conjunction with secret management systems such as Hashicorp Vault.


Gravitational Teleport
""""""""""""""""""""""

* **Url:** https://github.com/gravitational/teleport
* **License:** Apache-2.0

Gravitational Teleport provides privileged access management (PAM) for cloud-native infrastructure.
Teleport is an access and authentication proxy for SSH and Kubernetes API access.
It's meant as a replacement for sshd and it works with existing OpenSSH clients and servers as-is.
It allows administrators to set up access for users and groups to groups of servers,
called clusters, and implements in the commercial version role-based access control (RBAC) to allow differing levels of
access to different clusters. Individual server credentials are not available to users,
reducing the administrative impact of rotating and removing credentials.

HashiCorp Boundary
""""""""""""""""""

* **Url:** https://github.com/hashicorp/boundary
* **License:** MPL-2.0

Boundary provides simple and secure access to hosts and services.

Traditional approaches like SSH bastion hosts or VPNs require distributing and managing credentials, configuring network controls like firewalls, and exposing the private network. Boundary provides a secure way to access hosts and critical systems without having to manage credentials or expose your network, and is entirely open source.

Boundary is designed to be straightforward to understand, highly scalable, and resilient. It can run in clouds, on-prem, secure enclaves and more, and does not require an agent to be installed on every end host.

Unlike firewalls, Boundary performs per-access authentication and authorization checks, allowing for much higher level mappings of users to services or hosts than at network layers. Although complementary to secrets managers (like HashiCorp's own Vault), Boundary fills a different niche, allowing the credential that is eventually used to be hidden entirely from the user.
