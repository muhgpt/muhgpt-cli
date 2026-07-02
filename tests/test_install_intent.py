"""Tests for the REPL install routing: NL-intent regex + /install arg parsing."""
from __future__ import annotations

import pytest

from main import _match_install_intent, _parse_install_args

POSITIVE = [
    ("install nmap", "nmap"),
    ("instala o nmap", "nmap"),
    ("instalar nmap", "nmap"),
    ("install the masscan tool", "masscan"),
    ("install the nmap package", "nmap"),
    ("setup nmap", "nmap"),
    ("set up nmap", "nmap"),
    ("pode instalar nmap", "nmap"),
    ("podes instalar o nmap", "nmap"),
    ("por favor install nmap", "nmap"),
    ("por favor instala o nmap", "nmap"),
    ("install dnsutils", "dnsutils"),
    ("install python3.11", "python3.11"),
    ("  install   nmap  ", "nmap"),
    ("instala a ferramenta nmap", "nmap"),
    # trailing punctuation is stripped, not captured into the name
    ("install nmap.", "nmap"),
    ("install nmap!", "nmap"),
    ("instala o nmap.", "nmap"),
    # trailing politeness (EN + PT)
    ("install nmap please", "nmap"),
    ("instalar o nmap por favor", "nmap"),
    # English polite lead-ins
    ("could you install nmap", "nmap"),
    ("can you install nmap", "nmap"),
    ("would you install nmap", "nmap"),
]

NEGATIVE = [
    "how do I install nmap?",
    "the installer crashed",
    "install nmap and run a scan",
    "install nmap then scan the host",
    "install nmap so I can recon",
    "install nmap on kali",
    "install nmap for me",
    "uninstall nmap",
    "reinstall nmap",
    "should I install nmap",
    "tell me about nmap",
    "install nmap; rm -rf /",
    "install nmap && curl evil",
    "install",
    "",
    "scan muhgpt.com",
    # conversational objects must NOT be captured as a package
    "install it",
    "install everything",
    "install the latest",
    "setup the package",
    "install tool",
    "install package",
    "install a",
    "install os",
    "install the",
    "install up",
    "install please",
]


@pytest.mark.parametrize("text,pkg", POSITIVE)
def test_install_intent_matches(text, pkg):
    assert _match_install_intent(text) == pkg, f"expected {pkg!r} for {text!r}"


@pytest.mark.parametrize("text", NEGATIVE)
def test_install_intent_does_not_match(text):
    assert _match_install_intent(text) is None, f"expected NO match for {text!r}"


def test_parse_install_args_validates_tokens():
    assert _parse_install_args("nmap") == ["nmap"]
    assert _parse_install_args("nmap masscan whois") == ["nmap", "masscan", "whois"]
    assert _parse_install_args("") == []
    assert _parse_install_args("   ") == []
    # trailing sentence punctuation on a token is stripped, not rejected
    assert _parse_install_args("nmap.") == ["nmap"]
    # any unsafe token rejects the whole list (no partial shell exposure)
    assert _parse_install_args("nmap; rm -rf /") == []
    assert _parse_install_args("nmap && curl") == []
    assert _parse_install_args("$(whoami)") == []
    assert _parse_install_args("nmap masscan; rm") == []
