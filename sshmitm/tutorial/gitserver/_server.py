"""aiohttp web application for the fake Git hosting server."""

from __future__ import annotations

import base64
import hashlib
import html
import struct
from typing import TYPE_CHECKING

from aiohttp import web

if TYPE_CHECKING:
    from sshmitm.tutorial.gitserver import GitServerConfig, GitUser, GitRepo

# ---------------------------------------------------------------------------
# Colour palette for avatar circles (GitLab-like)
# ---------------------------------------------------------------------------

_AVATAR_COLOURS = [
    "#6e49cb", "#1f75cb", "#0e8c6c", "#c5483c", "#c97a20",
    "#5f6a7d", "#d44d8c", "#387d41", "#8e6b3e", "#1f78a3",
]


def _esc(text: str) -> str:
    """HTML-escape *text*."""
    return html.escape(str(text), quote=True)


def _avatar_color(username: str) -> str:
    """Return a deterministic colour from *_AVATAR_COLOURS* for *username*."""
    idx = sum(ord(c) for c in username) % len(_AVATAR_COLOURS)
    return _AVATAR_COLOURS[idx]


def _key_fingerprint(pubkey_line: str) -> str:
    """Return ``SHA256:...`` fingerprint for a raw SSH public key line."""
    try:
        parts = pubkey_line.strip().split()
        if len(parts) < 2:
            return "invalid key"
        raw = base64.b64decode(parts[1])
        digest = hashlib.sha256(raw).digest()
        b64 = base64.b64encode(digest).decode().rstrip("=")
        return f"SHA256:{b64}"
    except Exception:  # noqa: BLE001
        return "invalid key"


def _key_type(pubkey_line: str) -> str:
    """Extract the algorithm name from a public key line."""
    parts = pubkey_line.strip().split()
    return parts[0] if parts else "unknown"


def _key_bits(pubkey_line: str) -> str:
    """Extract bit size from an RSA or DSA public key line; return empty string for EC/Ed keys."""
    parts = pubkey_line.strip().split()
    if len(parts) < 2:
        return ""
    algo = parts[0].lower()
    # Only RSA/DSA keys have a meaningful bit length derivable from the raw key
    if algo not in ("ssh-rsa", "ssh-dss"):
        return ""
    try:
        data = base64.b64decode(parts[1])
        # Skip the algorithm name length-prefix, then read the first MPI (modulus for RSA)
        pos = 0
        # Read algo name
        name_len = struct.unpack(">I", data[pos:pos+4])[0]
        pos += 4 + name_len
        # For RSA: next MPI is exponent, then modulus
        # For DSA: next is p
        exp_len = struct.unpack(">I", data[pos:pos+4])[0]
        pos += 4 + exp_len
        mod_len = struct.unpack(">I", data[pos:pos+4])[0]
        # modulus in bytes → bits (first byte may be 0x00 padding)
        bits = (mod_len - 1) * 8 if data[pos+4] == 0 else mod_len * 8
        return str(bits)
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #f0f0f0; color: #333; font-size: 14px; }
a { color: #1f75cb; text-decoration: none; }
a:hover { text-decoration: underline; }

/* Navbar */
.navbar {
  background: #292961; color: #fff; display: flex; align-items: center;
  padding: 0 16px; height: 48px; gap: 12px;
}
.navbar .brand { font-size: 16px; font-weight: 700; color: #fff; letter-spacing: .5px; }
.navbar .brand a { color: inherit; }
.navbar .spacer { flex: 1; }
.navbar .nav-link { color: rgba(255,255,255,.8); font-size: 13px; padding: 4px 8px; border-radius: 4px; }
.navbar .nav-link:hover { background: rgba(255,255,255,.12); text-decoration: none; }

/* Layout */
.container { max-width: 960px; margin: 0 auto; padding: 24px 16px; }

/* Profile header */
.profile-header {
  display: flex; gap: 24px; align-items: flex-start;
  background: #fff; border: 1px solid #ddd; border-radius: 6px;
  padding: 24px; margin-bottom: 20px;
}
.profile-avatar {
  width: 96px; height: 96px; border-radius: 50%; display: flex;
  align-items: center; justify-content: center; font-size: 36px;
  font-weight: 700; color: #fff; flex-shrink: 0;
}
.profile-info h1 { font-size: 22px; font-weight: 700; margin-bottom: 4px; }
.profile-info .username { color: #666; font-size: 15px; margin-bottom: 8px; }
.profile-info .bio { color: #444; font-size: 14px; }

/* Tabs */
.tab-nav {
  display: flex; border-bottom: 1px solid #ddd;
  background: #fff; border-radius: 6px 6px 0 0; border: 1px solid #ddd;
  border-bottom: none; overflow: hidden; margin-bottom: 0;
}
.tab-nav a {
  padding: 10px 18px; font-size: 13px; color: #555; border-bottom: 2px solid transparent;
  display: flex; align-items: center; gap: 6px;
}
.tab-nav a:hover { background: #f5f5f5; text-decoration: none; color: #222; }
.tab-nav a.active { color: #1f75cb; border-bottom-color: #1f75cb; font-weight: 600; }
.tab-count {
  background: #eee; border-radius: 10px; padding: 1px 7px;
  font-size: 11px; font-weight: 600; color: #555;
}

/* Tab content wrapper */
.tab-content {
  background: #fff; border: 1px solid #ddd; border-top: none;
  border-radius: 0 0 6px 6px; padding: 16px;
}

/* Repo cards */
.repo-list { display: flex; flex-direction: column; gap: 12px; }
.repo-card {
  border: 1px solid #e0e0e0; border-radius: 6px; padding: 16px;
}
.repo-card:hover { border-color: #bbb; }
.repo-card .repo-name { font-size: 16px; font-weight: 700; }
.repo-card .repo-name a { color: #1f75cb; }
.repo-card .repo-desc { color: #555; font-size: 13px; margin-top: 4px; }
.repo-card .repo-meta {
  display: flex; gap: 16px; margin-top: 10px; color: #666; font-size: 12px;
  align-items: center;
}
.repo-card .lang-dot {
  width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 4px;
}
.badge-visibility {
  font-size: 11px; padding: 2px 6px; border-radius: 3px; border: 1px solid;
}
.badge-public { color: #387d41; border-color: #387d41; }
.badge-internal { color: #c97a20; border-color: #c97a20; }
.badge-private { color: #666; border-color: #999; }

/* SSH Keys table */
.key-table { width: 100%; border-collapse: collapse; }
.key-table th {
  text-align: left; padding: 8px 12px; background: #f5f5f5;
  border-bottom: 2px solid #e0e0e0; font-size: 12px; color: #555;
}
.key-table td { padding: 10px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
.key-table tr:last-child td { border-bottom: none; }
.key-title { font-weight: 600; color: #222; margin-bottom: 2px; }
.key-fingerprint { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 12px; color: #555; }
.key-algo { font-size: 11px; color: #888; margin-top: 2px; }
.no-keys { padding: 32px; text-align: center; color: #888; }

/* Repo page */
.repo-header {
  background: #fff; border: 1px solid #ddd; border-radius: 6px;
  padding: 20px 24px; margin-bottom: 16px;
}
.repo-header .breadcrumb { font-size: 13px; color: #888; margin-bottom: 8px; }
.repo-header h1 { font-size: 22px; font-weight: 700; }
.repo-header .repo-desc-header { color: #555; margin-top: 6px; }
.repo-header .repo-badges { margin-top: 10px; display: flex; gap: 12px; align-items: center; }

/* Commit list */
.commit-list { background: #fff; border: 1px solid #ddd; border-radius: 6px; overflow: hidden; }
.commit-list-header {
  padding: 10px 16px; border-bottom: 1px solid #eee;
  font-size: 13px; color: #555; background: #fafafa;
}
.commit-row { display: flex; align-items: center; padding: 12px 16px; border-bottom: 1px solid #eee; }
.commit-row:last-child { border-bottom: none; }
.commit-row:hover { background: #fafafa; }
.commit-avatar {
  width: 28px; height: 28px; border-radius: 50%; display: flex;
  align-items: center; justify-content: center; font-size: 11px;
  font-weight: 700; color: #fff; flex-shrink: 0; margin-right: 12px;
}
.commit-body { flex: 1; min-width: 0; }
.commit-message { font-size: 13px; color: #222; font-weight: 500;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.commit-meta { font-size: 12px; color: #888; margin-top: 2px; }
.commit-sha {
  font-family: 'SFMono-Regular', Consolas, monospace; font-size: 12px;
  color: #1f75cb; background: #f0f4ff; border: 1px solid #d0daf5;
  padding: 2px 8px; border-radius: 3px; margin-left: 16px; flex-shrink: 0;
}

/* Home page user list */
.user-list { display: flex; flex-direction: column; gap: 12px; }
.user-card {
  background: #fff; border: 1px solid #ddd; border-radius: 6px;
  padding: 16px; display: flex; align-items: center; gap: 16px;
}
.user-card:hover { border-color: #bbb; }
.user-card .info { flex: 1; }
.user-card .info h3 { font-size: 16px; font-weight: 700; }
.user-card .info h3 a { color: #222; }
.user-card .info .uname { color: #1f75cb; font-size: 13px; }
.user-card .info .ubio { color: #666; font-size: 13px; margin-top: 4px; }
.user-card .avatar-sm {
  width: 48px; height: 48px; border-radius: 50%; display: flex;
  align-items: center; justify-content: center; font-size: 18px;
  font-weight: 700; color: #fff; flex-shrink: 0;
}

/* Section heading */
.section-header { display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 12px; }
.section-header h2 { font-size: 16px; font-weight: 700; }

/* Empty state */
.empty-state { padding: 48px; text-align: center; color: #888; }
.empty-state .icon { font-size: 32px; margin-bottom: 12px; }

/* Responsive */
@media (max-width: 600px) {
  .profile-header { flex-direction: column; }
  .commit-sha { display: none; }
}
"""

_LANG_COLOURS: dict[str, str] = {
    "python": "#3572A5",
    "shell": "#89e051",
    "bash": "#89e051",
    "ruby": "#701516",
    "go": "#00ADD8",
    "javascript": "#f1e05a",
    "typescript": "#2b7489",
    "java": "#b07219",
    "c": "#555555",
    "c++": "#f34b7d",
    "rust": "#dea584",
    "yaml": "#cb171e",
    "dockerfile": "#384d54",
    "html": "#e34c26",
    "css": "#563d7c",
}


def _lang_color(lang: str) -> str:
    return _LANG_COLOURS.get(lang.lower(), "#999")


def _base(brand: str, title: str, content: str) -> web.Response:
    """Return a full HTML page Response."""
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)} \xb7 {_esc(brand)}</title>
<style>{_CSS}</style>
</head>
<body>
<nav class="navbar">
  <span class="brand"><a href="/">{_esc(brand)}</a></span>
  <span class="spacer"></span>
  <a class="nav-link" href="/">Explore</a>
</nav>
{content}
</body>
</html>"""
    return web.Response(text=page, content_type="text/html", charset="utf-8")


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

def _handle_home(config: "GitServerConfig") -> web.Response:
    """Home page: list all users."""
    if not config.users:
        cards = '<div class="empty-state"><div class="icon">&#x1F3E0;</div><p>No users yet.</p></div>'
    else:
        items = []
        for user in config.users:
            initial = (user.fullname or user.username)[0].upper()
            color = _avatar_color(user.username)
            fullname = user.fullname or user.username
            bio_html = f'<div class="ubio">{_esc(user.bio)}</div>' if user.bio else ""
            items.append(f"""
<a href="/{_esc(user.username)}" style="text-decoration:none">
  <div class="user-card">
    <div class="avatar-sm" style="background:{color}">{_esc(initial)}</div>
    <div class="info">
      <h3><a href="/{_esc(user.username)}">{_esc(fullname)}</a></h3>
      <div class="uname">@{_esc(user.username)}</div>
      {bio_html}
    </div>
    <span style="color:#888;font-size:13px">{len(user.repos)} repo{"s" if len(user.repos) != 1 else ""}</span>
  </div>
</a>""")
        cards = '<div class="user-list">' + "".join(items) + "</div>"

    content = f"""
<div class="container">
  <div class="section-header"><h2>Users</h2></div>
  {cards}
</div>"""
    return _base(config.brand, "Users", content)


def _handle_user(config: "GitServerConfig", user: "GitUser", tab: str) -> web.Response:
    """User profile page with Repositories or SSH Keys tab."""
    initial = (user.fullname or user.username)[0].upper()
    color = _avatar_color(user.username)
    fullname = user.fullname or user.username

    # Profile header
    bio_html = f'<p class="bio">{_esc(user.bio)}</p>' if user.bio else ""
    profile_header = f"""
<div class="profile-header">
  <div class="profile-avatar" style="background:{color}">{_esc(initial)}</div>
  <div class="profile-info">
    <h1>{_esc(fullname)}</h1>
    <div class="username">@{_esc(user.username)}</div>
    {bio_html}
  </div>
</div>"""

    # Tab navigation
    base_url = f"/{_esc(user.username)}"
    repos_active = "active" if tab == "repos" else ""
    keys_active  = "active" if tab == "ssh_keys" else ""
    tab_nav = f"""
<div class="tab-nav">
  <a href="{base_url}" class="{repos_active}">
    &#x1F4C1; Repositories <span class="tab-count">{len(user.repos)}</span>
  </a>
  <a href="{base_url}?tab=ssh_keys" class="{keys_active}">
    &#x1F511; SSH Keys <span class="tab-count">{len(user.pubkeys)}</span>
  </a>
</div>"""

    # Tab content
    if tab == "ssh_keys":
        tab_content = _render_ssh_keys(user)
    else:
        tab_content = _render_repos(user)

    content = f"""
<div class="container">
  {profile_header}
  {tab_nav}
  <div class="tab-content">{tab_content}</div>
</div>"""

    title = fullname
    return _base(config.brand, title, content)


def _render_repos(user: "GitUser") -> str:
    if not user.repos:
        return '<div class="empty-state"><div class="icon">&#x1F4C1;</div><p>No repositories yet.</p></div>'
    items = []
    for repo in user.repos:
        vis_cls = f"badge-{repo.visibility}"
        vis_label = repo.visibility.capitalize()
        lang_dot = ""
        if repo.language:
            lc = _lang_color(repo.language)
            lang_dot = f'<span class="lang-dot" style="background:{lc}"></span>{_esc(repo.language)}'
        stars_html = f"&#11088; {repo.stars}" if repo.stars else ""
        forks_html = f"&#x1F374; {repo.forks}" if repo.forks else ""
        updated_html = _esc(repo.updated) if repo.updated else ""
        desc_html = f'<div class="repo-desc">{_esc(repo.description)}</div>' if repo.description else ""
        items.append(f"""
<div class="repo-card">
  <div class="repo-name">
    <a href="/{_esc(user.username)}/{_esc(repo.name)}">{_esc(repo.name)}</a>
    <span class="badge-visibility {vis_cls}" style="margin-left:8px">{vis_label}</span>
  </div>
  {desc_html}
  <div class="repo-meta">
    {lang_dot}
    {stars_html}
    {forks_html}
    <span style="flex:1"></span>
    <span style="color:#999">{updated_html}</span>
  </div>
</div>""")
    return '<div class="repo-list">' + "".join(items) + "</div>"


def _render_ssh_keys(user: "GitUser") -> str:
    if not user.pubkeys:
        return '<div class="no-keys">No SSH keys registered.</div>'
    rows = []
    for i, key_line in enumerate(user.pubkeys):
        key_line = key_line.strip()
        parts = key_line.split()
        comment = parts[2] if len(parts) >= 3 else f"key-{i+1}"
        algo = _key_type(key_line)
        fp = _key_fingerprint(key_line)
        bits = _key_bits(key_line)
        algo_label = f"{algo} {bits}".strip() if bits else algo
        rows.append(f"""
<tr>
  <td>
    <div class="key-title">{_esc(comment)}</div>
    <div class="key-fingerprint">{_esc(fp)}</div>
    <div class="key-algo">{_esc(algo_label)}</div>
  </td>
</tr>""")
    return f"""
<table class="key-table">
  <thead><tr><th>Key</th></tr></thead>
  <tbody>{"".join(rows)}</tbody>
</table>"""


def _handle_repo(
    config: "GitServerConfig", user: "GitUser", repo: "GitRepo"
) -> web.Response:
    """Repository page with fake commit history."""
    vis_cls = f"badge-{repo.visibility}"
    vis_label = repo.visibility.capitalize()
    lang_html = ""
    if repo.language:
        lc = _lang_color(repo.language)
        lang_html = (
            f'<span class="lang-dot" style="background:{lc}"></span>'
            f"{_esc(repo.language)}"
        )
    repo_header = f"""
<div class="repo-header">
  <div class="breadcrumb">
    <a href="/{_esc(user.username)}">{_esc(user.username)}</a> /
  </div>
  <h1>{_esc(repo.name)}</h1>
  {'<div class="repo-desc-header">' + _esc(repo.description) + '</div>' if repo.description else ''}
  <div class="repo-badges">
    <span class="badge-visibility {vis_cls}">{vis_label}</span>
    {lang_html}
    {f"&#11088; {repo.stars}" if repo.stars else ""}
    {f"&#x1F374; {repo.forks}" if repo.forks else ""}
  </div>
</div>"""

    if not repo.commits:
        commits_html = '<div class="empty-state"><p>No commits yet.</p></div>'
    else:
        rows = []
        for commit in repo.commits:
            initial = commit.author[0].upper() if commit.author else "?"
            color = _avatar_color(commit.author)
            rows.append(f"""
<div class="commit-row">
  <div class="commit-avatar" style="background:{color}">{_esc(initial)}</div>
  <div class="commit-body">
    <div class="commit-message">{_esc(commit.message)}</div>
    <div class="commit-meta">{_esc(commit.author)} &middot; {_esc(commit.age)}</div>
  </div>
  <span class="commit-sha">{_esc(commit.sha)}</span>
</div>""")
        commits_html = f"""
<div class="commit-list">
  <div class="commit-list-header">{len(repo.commits)} commit{"s" if len(repo.commits) != 1 else ""}</div>
  {"".join(rows)}
</div>"""

    content = f"""
<div class="container">
  {repo_header}
  {commits_html}
</div>"""
    return _base(config.brand, f"{user.username}/{repo.name}", content)


def _handle_keys_txt(user: "GitUser") -> web.Response:
    """Plain-text public keys endpoint (GitHub/GitLab format)."""
    body = "\n".join(k.strip() for k in user.pubkeys if k.strip())
    if body:
        body += "\n"
    return web.Response(text=body, content_type="text/plain", charset="utf-8")


def _handle_404(config: "GitServerConfig", message: str = "Not found") -> web.Response:
    content = f'<div class="container"><div class="empty-state"><p>{_esc(message)}</p></div></div>'
    resp = _base(config.brand, "404 Not Found", content)
    resp.set_status(404)
    return resp


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def make_app(config: "GitServerConfig") -> web.Application:
    """Create and return the aiohttp Application."""
    _user_map: dict[str, "GitUser"] = {u.username: u for u in config.users}

    async def handle_home(_req: web.Request) -> web.Response:
        return _handle_home(config)

    async def handle_user(req: web.Request) -> web.Response:
        username = req.match_info["username"]
        # Strip .keys suffix
        if username.endswith(".keys"):
            uname = username[:-5]
            user = _user_map.get(uname)
            if user is None:
                return _handle_404(config, f"User {uname!r} not found")
            return _handle_keys_txt(user)
        user = _user_map.get(username)
        if user is None:
            return _handle_404(config, f"User {username!r} not found")
        tab = req.rel_url.query.get("tab", "repos")
        return _handle_user(config, user, tab)

    async def handle_repo(req: web.Request) -> web.Response:
        username = req.match_info["username"]
        reponame = req.match_info["repo"]
        user = _user_map.get(username)
        if user is None:
            return _handle_404(config, f"User {username!r} not found")
        repo = next((r for r in user.repos if r.name == reponame), None)
        if repo is None:
            return _handle_404(config, f"Repository {username}/{reponame} not found")
        return _handle_repo(config, user, repo)

    app = web.Application()
    app.router.add_get("/", handle_home)
    app.router.add_get("/{username}", handle_user)
    app.router.add_get("/{username}/{repo}", handle_repo)
    return app
