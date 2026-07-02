"""Tests for the autonomous-mode safety guard: classify, secret paths, budget."""
from __future__ import annotations

import pytest
from guard_corpus import (
    EXTRA_RECON_ALLOW,
    EXTRA_RECON_STILL_BLOCK,
    EXTRA_RECON_STILL_CONFIRM,
    MUST_ALLOW,
    MUST_BLOCK,
    MUST_CONFIRM,
    SANITIZE_ACCEPT,
    SANITIZE_REJECT,
)

from muhgpt.guard import (
    _NEVER_RECON,
    SAFE_RECON,
    Budget,
    BudgetExceeded,
    Verdict,
    classify,
    classify_mcp,
    is_secret_path,
    make_classifier,
    mcp_targets_out_of_scope,
    sanitize_extra_recon,
    targets_out_of_scope,
)


@pytest.mark.parametrize("cmd", MUST_BLOCK)
def test_block(cmd):
    verdict, _ = classify(cmd)
    assert verdict is Verdict.BLOCK, f"expected BLOCK for {cmd!r}, got {verdict}"


@pytest.mark.parametrize("cmd", MUST_ALLOW)
def test_allow(cmd):
    verdict, _ = classify(cmd)
    assert verdict is Verdict.ALLOW, f"expected ALLOW for {cmd!r}, got {verdict}"


@pytest.mark.parametrize("cmd", MUST_CONFIRM)
def test_confirm(cmd):
    verdict, _ = classify(cmd)
    assert verdict is Verdict.CONFIRM, f"expected CONFIRM for {cmd!r}, got {verdict}"


# --- operator-extensible recon allowlist -----------------------------------
@pytest.mark.parametrize("cmd,extra", EXTRA_RECON_ALLOW)
def test_extra_recon_allows_sanitized_tool(cmd, extra):
    accepted, _ = sanitize_extra_recon(extra)
    assert classify(cmd, accepted)[0] is Verdict.ALLOW


@pytest.mark.parametrize("cmd,extra", EXTRA_RECON_STILL_BLOCK)
def test_extra_recon_never_beats_denylist(cmd, extra):
    # RAW (unsanitized) extra_recon passed straight to classify still cannot
    # escalate a denylisted/chained command — the gates run before the allowlist.
    assert classify(cmd, frozenset(extra))[0] is Verdict.BLOCK


@pytest.mark.parametrize("cmd,extra", EXTRA_RECON_STILL_CONFIRM)
def test_extra_recon_never_beats_metachar_or_unlisted(cmd, extra):
    assert classify(cmd, frozenset(extra))[0] is Verdict.CONFIRM


@pytest.mark.parametrize("name", sorted(_NEVER_RECON))
def test_sanitize_rejects_every_never_recon_binary(name):
    accepted, rejected = sanitize_extra_recon([name])
    assert accepted == frozenset(), f"{name!r} must never be allowlistable"
    assert name in rejected


@pytest.mark.parametrize("name", SANITIZE_REJECT)
def test_sanitize_rejects_dangerous_and_malformed(name):
    accepted, _ = sanitize_extra_recon([name])
    assert accepted == frozenset(), f"{name!r} must not be accepted"


@pytest.mark.parametrize("name", SANITIZE_ACCEPT)
def test_sanitize_accepts_wellformed_recon_names(name):
    accepted, rejected = sanitize_extra_recon([name])
    assert name.lower() in accepted
    assert name not in rejected


def test_sanitize_lowercases_dedupes_and_ignores_builtins():
    accepted, rejected = sanitize_extra_recon(["NMAP", "TheHarvester", "gobuster", "gobuster"])
    assert accepted == frozenset({"gobuster"})  # NMAP/theharvester already builtin -> ignored
    assert rejected == ()
    # mixed path/metachar/space tokens are rejected, only the clean one survives
    acc, rej = sanitize_extra_recon(["../bin/rm", "foo;bar", "a b", "tool"])
    assert acc == frozenset({"tool"})
    assert set(rej) == {"../bin/rm", "foo;bar", "a b"}


def test_make_classifier_binds_set_and_preserves_ordering():
    clf = make_classifier(("shodan-cli", "bash", "cat", "curl"))  # dangerous ones dropped
    assert clf("shodan-cli host 1.1.1.1")[0] is Verdict.ALLOW
    assert clf("rm -rf /")[0] is Verdict.BLOCK          # denylist beats the closure
    assert clf("bash -c id")[0] is Verdict.CONFIRM       # bash was never allowlisted
    assert clf("cat /etc/shadow")[0] is Verdict.CONFIRM  # cat dropped by sanitize (end-to-end)
    assert clf("curl http://x")[0] is Verdict.CONFIRM    # curl dropped by sanitize
    assert clf("shodan-cli host x | tee f")[0] is Verdict.CONFIRM  # metachar gate wins


def test_extra_recon_does_not_unblock_denylisted_flag():
    # Adding an already-allowlisted tool via extra_recon must not un-block its
    # denylisted dangerous flags.
    assert classify("nuclei -u https://t -code", frozenset({"nuclei"}))[0] is Verdict.BLOCK


def test_never_recon_is_disjoint_from_safe_recon_and_lowercase():
    assert _NEVER_RECON.isdisjoint(SAFE_RECON)
    assert all(t == t.lower() for t in SAFE_RECON)
    assert all(t == t.lower() for t in _NEVER_RECON)


def test_obfuscated_destructive_never_auto_allows():
    # Even if a payload dodges the denylist, an unlisted binary / metachar keeps it
    # out of ALLOW — the load-bearing allowlist-first property.
    for cmd in ["X=rm; $X -rf /", "python3 -c 'import os;os.system(\"x\")'", "eval $(echo rm)"]:
        assert classify(cmd)[0] is not Verdict.ALLOW


def test_secret_paths():
    assert is_secret_path("/home/u/.ssh/id_rsa")
    assert is_secret_path("~/.aws/credentials")
    assert is_secret_path("/etc/shadow")
    assert is_secret_path("./prod.pem")
    assert not is_secret_path("/var/log/nginx/access.log")
    assert not is_secret_path("./reports/scan.txt")


def test_budget_caps():
    b = Budget(max_rounds=2, max_commands=1, max_installs=0, max_blocks=1, wall_clock_s=9999)
    b.start()
    b.charge("round")
    b.charge("round")
    with pytest.raises(BudgetExceeded):
        b.charge("round")  # 3rd round over cap of 2


def test_budget_command_and_block_caps():
    b = Budget(max_commands=1, max_blocks=1, wall_clock_s=9999)
    b.start()
    b.charge("command")
    with pytest.raises(BudgetExceeded):
        b.charge("command")
    b2 = Budget(max_blocks=1, wall_clock_s=9999)
    b2.start()
    b2.charge("block")
    with pytest.raises(BudgetExceeded):
        b2.charge("block")


# --- soft scope check ------------------------------------------------------
def test_in_scope_targets_are_not_flagged():
    assert targets_out_of_scope("nmap -sV example.com", "example.com") is False
    assert targets_out_of_scope("dig sub.example.com", "example.com") is False  # subdomain
    assert targets_out_of_scope("nmap 10.0.0.5", "10.0.0.0/24") is False        # CIDR member
    assert targets_out_of_scope("httpx -u https://example.com/a", "example.com") is False


def test_out_of_scope_targets_are_flagged():
    assert targets_out_of_scope("nmap -sV 10.0.0.5", "example.com") is True     # IP pivot
    assert targets_out_of_scope("dig evil.com", "example.com") is True
    assert targets_out_of_scope("nmap 192.168.1.1", "10.0.0.0/24") is True


def test_scope_check_disabled_when_unenforceable():
    # unrestricted / non-host scope, or no host in the command -> never flagged
    assert targets_out_of_scope("nmap evil.com", "unrestricted") is False
    assert targets_out_of_scope("nmap evil.com", "Acme Corp engagement") is False
    assert targets_out_of_scope("nmap --help", "example.com") is False


def test_arsenal_additions_are_active_recon_only():
    # The expansion stays within the invariant: no file readers, interpreters,
    # fuzzers, or the Swiss-army tools crept into the allowlist.
    forbidden = {"cat", "grep", "awk", "sed", "python", "python3", "sh", "bash",
                 "curl", "wget", "openssl", "gobuster", "ffuf", "dirb", "feroxbuster"}
    assert SAFE_RECON.isdisjoint(forbidden)


# --- MCP tool classification ----------------------------------------------
def test_classify_mcp_defaults_to_confirm():
    assert classify_mcp("mcp__shodan__host", "shodan", "host", frozenset())[0] is Verdict.CONFIRM


def test_classify_mcp_allows_only_explicit_allowlist():
    name = "mcp__shodan__host"
    assert classify_mcp(name, "shodan", "host", {name})[0] is Verdict.ALLOW
    assert classify_mcp(name, "shodan", "host", {"other"})[0] is Verdict.CONFIRM


def test_classify_mcp_blocks_weaponized_even_if_allowlisted():
    # Denylist-first: an allowlisted weaponized tool still BLOCKS, across families.
    weaponized = [
        ("msf", "run_exploit"), ("x", "reverse-shell"), ("y", "os_command"),
        ("z", "password_spray"), ("x", "sqlmap_dump"), ("x", "lfi_read"),
        ("x", "rce_exec"), ("x", "mimikatz"), ("x", "dos_flood"), ("x", "ssrf_probe"),
        ("x", "hashdump"), ("x", "kerberoast"), ("cobalt", "beacon"), ("x", "xss_inject"),
        # reversed / word-order-flipped compounds must also BLOCK (under-match guard)
        ("x", "shell_reverse"), ("x", "spray_password"), ("x", "dump_hash"),
        ("x", "dump_secrets"), ("x", "spoof_arp"), ("x", "spoof_dns"), ("x", "stuff_creds"),
    ]
    for server, tool in weaponized:
        name = f"mcp__{server}__{tool}"
        assert classify_mcp(name, server, tool, {name})[0] is Verdict.BLOCK, tool


def test_classify_mcp_does_not_overblock_benign_data_tools():
    # Common read-only data-source tools must NOT be caught by the deny families.
    for server, tool in [("shodan", "host_info"), ("virustotal", "url_report"),
                         ("censys", "search"), ("dns", "lookup"), ("whois", "query")]:
        name = f"mcp__{server}__{tool}"
        assert classify_mcp(name, server, tool, set())[0] is Verdict.CONFIRM
        assert classify_mcp(name, server, tool, {name})[0] is Verdict.ALLOW


def test_mcp_scope_check():
    assert mcp_targets_out_of_scope({"host": "10.0.0.5"}, "example.com") is True
    assert mcp_targets_out_of_scope({"q": {"target": "sub.example.com"}}, "example.com") is False
    assert mcp_targets_out_of_scope({"host": "10.0.0.5"}, "unrestricted") is False
    assert mcp_targets_out_of_scope({"limit": 5}, "example.com") is False  # no host arg
