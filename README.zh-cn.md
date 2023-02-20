[![en](https://img.shields.io/badge/lang-en-red.svg)](https://github.com/ssh-mitm/ssh-mitm/blob/master/README.md)

<div id="top" align="center">
<img src="https://github.com/ssh-mitm/ssh-mitm/raw/master/doc/images/ssh-mitm-logo.png" width="200"><br/>
</div>
<h1 align="center"> SSH-MITM - 简单的SSH审计 </h1>
<p align="center">
  <a href="https://docs.ssh-mitm.at">
    <img alt="SSH-MITM intercepting password login" title="SSH-MITM" src="https://docs.ssh-mitm.at/_images/ssh-mitm-password.png#20230214" >
  </a>
  <p align="center">用于安全审计的ssh中间人（ssh-mitm）服务器支持 公钥认证、会话劫持和文件操纵</b></p>
  <p align="center">
   <a href="https://snapcraft.io/ssh-mitm">
     <img alt="Get it from the Snap Store" src="https://snapcraft.io/static/images/badges/en/snap-store-black.svg" />
   </a>
   <br />
   <br />
   <a href="https://docs.ssh-mitm.at"><img src="https://read-the-docs-guidelines.readthedocs-hosted.com/_downloads/d9606423d87d78fcceae4ee2af883b12/logo-wordmark-dark.png" title="阅读文档" width="256"></a>
  </p>
</p>


<h3 align="center">撰稿人</h3>
<p align="center">
<a href="https://github.com/ssh-mitm/ssh-mitm/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=ssh-mitm/ssh-mitm" />
</a>
</p>

##目录

- [简介](#introduction)
- [特点](#特点)
- [安装](#installation)
- [快速启动](#quickstart)
- [会话劫持](#session-hijacking)
- [钓鱼式FIDO令牌](#Phishing-fido-tokens)
- [贡献](#contributing)
- [联系](#contact)

## Introduction

[![下载](https://pepy.tech/badge/ssh-mitm)](https://pepy.tech/project/ssh-mitm)
[![代码因素](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm/badge)](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm)
[![文件状态](https://readthedocs.org/projects/ssh-mitm/badge/?version=latest)](https://docs.ssh-mitm.at/?badge=latest)
[![GitHub](https://img.shields.io/github/license/ssh-mitm/ssh-mitm?color=%23434ee6)](https://github.com/ssh-mitm/ssh-mitm/blob/master/LICENSE)
[![欢迎公关人员](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
<a rel="me" href="https://defcon.social/@sshmitm"><img src="https://img.shields.io/mastodon/follow/109597663767801251?color=%236364FF&domain=https%3A%2F%2Fdefcon.social&label=Mastodon&style=plastic"></a>


**SSH-MITM**是一个用于安全审计和恶意软件分析的中间人SSH服务器。

支持密码和公钥认证，SSH-MITM能够检测到，如果一个用户能够在远程服务器上用公钥认证登录。这允许SSH-MITM接受与目标服务器相同的密钥。如果公钥认证是不可能的，认证将退回到密码认证。

当公钥认证是可能的，需要一个转发的代理来登录到远程服务器。在没有代理被转发的情况下，SSH-MITM可以将会话重定向到一个蜜罐。


<p align="right">(<a href="#top">回到顶部</a>)</p>

##功能

*公钥认证
   *接受与目标服务器相同的密钥
   * 钓鱼式FIDO令牌（[来自OpenSSH的信息](https://www.openssh.com/agent-restrict.html))
* 劫持和记录终端会话
* 在SCP/SFTP文件传输过程中存储和替换文件
* 端口转发
  * 支持SOCKS 4/5的动态端口转发
* 拦截MOSH连接
* 针对已知的漏洞审计客户
* 支持插件

<p align="right">(<a href="#top">回到顶部</a>)</p>

## 安装

**SSH-MITM**可以作为[Ubuntu Snap](https://snapcraft.io/ssh-mitm)、[PIP-Package](https://pypi.org/project/ssh-mitm/)、[AppImage](https://github.com/ssh-mitm/ssh-mitm/releases/latest)、[Nix](https://search.nixos.org/packages?channel=unstable&show=ssh-mitm&type=packages&query=ssh-mitm)安装，甚至可以运行在[Android设备](https://github.com/ssh-mitm/ssh-mitm/discussions/83#discussioncomment-1531873)

    # 将 ssh-mitm 安装为 snap 包
    $ sudo snap install ssh-mitm

    # 将 ssh-mitm 安装为 python pip 包
    $ python3 -m pip install ssh-mitm

    # 安装为 Nix 包
    $ nix-env -iA nixos.ssh-mitm

<p align="right">(<a href="#top">回到顶部</a>)</p>

## 快速启动

要启动SSH-MITM，你所要做的就是在你选择的终端中运行这个命令。

    $ ssh-mitm server --remote-host 192.168.0.x

现在让我们试着连接一下。SSH-MITM在10022端口上监听。

    $ ssh -p 10022 testuser@proxyserver

你将在日志输出中看到凭证。

    INFO     Remote authentication succeeded
        Remote Address: 127.0.0.1:22
        Username: testuser
        Password: secret
        Agent: no agent
        
<p align="right">(<a href="#top">回到顶部</a>)</p>

## 会话劫持

获得纯文本凭证只是乐趣的一半。
当客户端连接时，ssh-mitm会启动一个新的服务器，用于会话劫持。

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1
    
为了劫持会话，你可以使用你喜欢的ssh客户端。

    $ ssh -p 34463 127.0.0.1

尝试在被劫持的会话或原会话中执行一些命令。

输出将显示在两个会话中。

<p align="right">(<a href="#top">回到顶部</a>)</p>

## 钓鱼式FIDO令牌

SSH-MITM能够伪造FIDO2令牌，该令牌可用于双因素认证。

该攻击被称为 [trivial authentication](https://docs.ssh-mitm.at/trivialauth.html) ([CVE-2021-36367](https://docs.ssh-mitm.at/CVE-2021-36367.html), [CVE-2021-36368](https://docs.ssh-mitm.at/CVE-2021-36368.html))，可以通过命令行参数`--enable-trivial-auth`来启用。

  ssh-mitm server --enable-trivial-auth

使用琐碎的认证攻击不会破坏密码认证，因为该攻击只在公钥登录可能时进行。

<p align="center">
  <b>解释网络钓鱼攻击的视频。</b><br/>
  <i>点击查看vimeo.com上的视频</i><br/>
  <a href="https://vimeo.com/showcase/9059922/video/651517195">
  <img src="https://github.com/ssh-mitm/ssh-mitm/raw/master/doc/images/ds2021-video.png" alt="点击查看vimeo.com上的视频">
  </a>
</p>

<p align="center">
  <b><a href="https://github.com/ssh-mitm/ssh-mitm/files/7568291/deepsec.pdf">下载演讲幻灯片</a></b>
</p>

<p align="right">(<a href="#top">回到顶部</a>)</p>

## 贡献

贡献是使开源社区成为一个学习、激励和创造的奇妙场所的原因。我们非常感谢你的任何贡献。

如果你有什么建议可以让它变得更好，请fork这个 repo并创建一个pull request。你也可以简单地打开一个带有 "增强 "标签的问题。
不要忘了给这个项目打一颗星! 再次感谢!

1. 叉开项目
2. 创建你的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交你的修改（`git commit -m 'Add some AmazingFeature''）。
4. 推送到分支（`git push origin feature/AmazingFeature`）。
5. 打开一个拉动请求

另请参见参与本项目的[贡献者](https://github.com/ssh-mitm/ssh-mitm/graphs/contributors)的名单。

<p align="right">(<a href="#top">回到顶部</a>)</p>

## 联系

- 电子邮件：support@ssh-mitm.at
- [问题追踪](https://github.com/ssh-mitm/ssh-mitm/issues)

<p align="right">(<a href="#top">回到顶部</a>)</p>
