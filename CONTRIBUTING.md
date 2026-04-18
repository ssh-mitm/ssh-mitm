# Contributing to SSH-MITM

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

**Legal notice:** SSH-MITM is a security tool intended for authorized audits and research only. Please ensure your contributions do not enable unauthorized access to systems.

## Table of Contents

- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)
- [Documentation](#documentation)
- [Contact](#contact)

## Development Setup

**Requirements:** Python 3.11 or newer, [hatch](https://hatch.pypa.io/)

```bash
git clone https://github.com/ssh-mitm/ssh-mitm.git
cd ssh-mitm
pip install hatch
```

## Code Style

This project uses the following tools to enforce consistent code quality:

| Tool | Purpose |
|------|---------|
| [black](https://github.com/psf/black) | Code formatting |
| [ruff](https://github.com/astral-sh/ruff) | Fast linting |
| [flake8](https://flake8.pycqa.org/) | Style checks |
| [pylint](https://pylint.org/) | Static analysis |
| [mypy](https://mypy-lang.org/) | Type checking (strict mode) |
| [bandit](https://bandit.readthedocs.io/) | Security scanning |

All checks can be run at once:

```bash
hatch run lint:check
```

Please make sure your code passes all checks before opening a PR.

## Submitting a Pull Request

1. **Fork** the repository on GitHub and clone your fork locally
2. **Create a branch** for your change: `git checkout -b feature/my-feature`
3. **Make your changes** and ensure all linters pass (`hatch run lint:check`)
4. **Commit** your changes with a descriptive message: `git commit -m 'Add my feature'`
5. **Push** to your fork: `git push origin feature/my-feature`
6. **Open a Pull Request** on GitHub — describe what your PR does and why

For larger changes, consider opening an issue first to discuss your approach.

## Reporting Bugs

Please use the [GitHub Issue Tracker](https://github.com/ssh-mitm/ssh-mitm/issues) to report bugs. Include:

- SSH-MITM version (`ssh-mitm --version`)
- Python version
- Operating system
- Steps to reproduce
- Expected vs. actual behavior

**Reporting security vulnerabilities:** Please do not open public issues for security-related bugs. Instead, follow the responsible disclosure process described in [SECURITY.md](SECURITY.md).

## Plugin & Feature Development

SSH-MITM is built around a plugin system — most functionality is implemented as exchangeable plugins. If you want to extend SSH-MITM or contribute a new feature, the developer documentation covers the architecture, available base classes, and examples:

[https://docs.ssh-mitm.at/develop/index.html](https://docs.ssh-mitm.at/develop/index.html)

## Documentation

The documentation is built with [Sphinx](https://www.sphinx-doc.org/) and lives in the `doc/` directory.

```bash
hatch run docs:build
```

The output will be in `build/html/`.

## Contact

- E-Mail: [support@ssh-mitm.at](mailto:support@ssh-mitm.at)
- Issue Tracker: [github.com/ssh-mitm/ssh-mitm/issues](https://github.com/ssh-mitm/ssh-mitm/issues)
