"""Tests for package-manager detection and install-command templating."""
from __future__ import annotations

from muhgpt.packages import PackageManager, detect_package_manager


def test_install_command_is_shell_quoted():
    pm = PackageManager(name="brew", install_template="brew install {pkg}")
    assert pm.install_command("nmap") == "brew install nmap"
    # injection attempt gets quoted, not interpreted
    assert pm.install_command("a; rm -rf /") == "brew install 'a; rm -rf /'"


def test_detect_prefers_brew_over_apt():
    available = {"brew", "apt-get", "sudo"}
    pm = detect_package_manager(which=lambda name: name if name in available else None)
    assert pm is not None
    assert pm.name == "brew"
    assert pm.install_command("nmap") == "brew install nmap"


def test_detect_termux_pkg():
    pm = detect_package_manager(which=lambda name: name if name == "pkg" else None)
    assert pm is not None and pm.name == "pkg"
    assert pm.install_command("nmap") == "pkg install -y nmap"


def test_detect_apt_falls_back_when_no_brew():
    available = {"apt-get"}
    pm = detect_package_manager(which=lambda name: name if name in available else None)
    assert pm is not None and pm.name == "apt-get"
    # no sudo present in this fake env -> no sudo prefix
    assert pm.install_command("nmap") == "apt-get install -y nmap"


def test_detect_returns_none_when_nothing_available():
    assert detect_package_manager(which=lambda name: None) is None
