"""Detect the system package manager and build install commands.

Lets the agent install missing CLI tools (nmap, whois, ...) instead of giving
up when a command is not found. Detection is by probing for known managers on
PATH; the install command is templated per-manager and root-prefixed only when
needed (non-root + sudo present), so it works on macOS (brew), Debian/Ubuntu
(apt), Termux (pkg), and the common Linux families.
"""
from __future__ import annotations

import os
import shlex
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class PackageManager:
    """A detected package manager and how to install a package with it."""

    name: str
    install_template: str  # contains a single ``{pkg}`` placeholder

    def install_command(self, package: str) -> str:
        """Full shell command to install ``package`` (shell-quoted)."""
        return self.install_template.format(pkg=shlex.quote(package))


def _root_prefix(which) -> str:
    """``"sudo "`` when elevation is needed and available, else ``""``."""
    try:
        is_root = os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:  # non-POSIX
        is_root = False
    if not is_root and which("sudo"):
        return "sudo "
    return ""


def detect_package_manager(which=shutil.which) -> PackageManager | None:
    """Return the first available package manager, or ``None`` if none found.

    ``which`` is injectable for testing. Order matters: ``brew`` and ``pkg``
    (Termux/BSD) need no root, so they win over the Debian/RHEL families that do.
    """
    root = _root_prefix(which)
    candidates = [
        ("brew", "brew install {pkg}"),
        ("pkg", "pkg install -y {pkg}"),
        ("apt-get", f"{root}apt-get install -y {{pkg}}"),
        ("dnf", f"{root}dnf install -y {{pkg}}"),
        ("yum", f"{root}yum install -y {{pkg}}"),
        ("pacman", f"{root}pacman -S --noconfirm {{pkg}}"),
        ("apk", f"{root}apk add {{pkg}}"),
        ("zypper", f"{root}zypper install -y {{pkg}}"),
    ]
    for name, template in candidates:
        if which(name):
            return PackageManager(name=name, install_template=template)
    return None
