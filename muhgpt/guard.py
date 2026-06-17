"""Command-safety classifier and run budget for autonomous mode.

Pure stdlib. ``classify(command)`` returns ALLOW / CONFIRM / BLOCK, evaluated
allowlist-first:

1. destructive / irreversible / weaponized patterns -> BLOCK (never run, never
   even prompts — the operator must drop back to HITL to run such a command);
2. any shell metacharacter (so a second command can't ride along) -> CONFIRM;
3. only a curated set of read-only recon binaries -> ALLOW (auto-run unattended);
4. everything else -> CONFIRM (defer to a human).

The verdict is computed on the literal command string at the side-effect
boundary, so it holds even if the model is fully prompt-injected by hostile
target output. The allowlist-first design is load-bearing: a destructive command
that evades the denylist still cannot auto-run unless its *leading binary* is an
allowlisted recon tool AND it contains no shell metacharacters.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shlex
import time
from dataclasses import dataclass, field
from enum import Enum


class Verdict(Enum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    BLOCK = "block"


# Destructive / irreversible / exfil / weaponized commands. Matched as substrings
# anywhere in the command, so a payload buried in a wrapper is still caught.
_DENYLIST = [
    # lookbehind excludes word chars/dots (so "perform"/"x.rm" don't match) but
    # allows a leading path ("/bin/rm") and whitespace.
    r"(?<![\w.-])rm\s+(?:-[a-zA-Z0-9]*\s+)*-[a-zA-Z0-9]*[rf][a-zA-Z0-9]*[rf]?(?:\s|$)",
    r"(?<![\w.-])rm\s+(?:-[a-zA-Z0-9]+\s+)*(?:/|~|\$HOME|\*|/\*)(?:\s|$)",
    r"--no-preserve-root",
    r"\bmkfs(?:\.[a-z0-9]+)?\b|\bmke2fs\b|\bnewfs\b|\bformat\b",
    r"\bdd\b[^\n|;&]*\bof=\s*(?:/dev/|/)",
    r"\b(?:shred|wipefs|blkdiscard|sgdisk|fdisk|gdisk|parted)\b",
    r"\bdiskutil\s+(?:erase\w*|reformat|partitionDisk|secureErase)\b",
    r">\s*/dev/(?:sd|nvme|hd|disk|mmcblk|vd|null|zero|random|urandom)[a-z0-9]*",
    r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
    r"\b(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b",
    r"\bsystemctl\s+(?:poweroff|reboot|halt|isolate|kexec)\b",
    r"\b(?:curl|wget|fetch|aria2c)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|t?c|a)?sh\b",
    r"\b(?:curl|wget|fetch)\b[^\n]*\|\s*(?:sudo\s+)?(?:python[0-9.]*|perl|ruby|node|php)\b",
    r"(?:ba|z)?sh\s+<\(\s*(?:curl|wget|fetch)",
    r"\b(?:base64\s+(?:-d|-D|--decode)|xxd\s+-r|openssl\s+enc\s+-d)\b[^\n]*\|\s*(?:ba|z)?sh\b",
    r"\bchmod\s+(?:-[a-zA-Z]*\s+)*0?[0-7]*7{2,}[0-7]*\s+(?:-R\s+)?/(?:\s|$|\w)",
    r"\bchmod\s+-R\b[^\n]*\s/(?:\s|$|\w)",
    r"\bchown\s+-R\b[^\n]*\s/(?:\s|$|\w)",
    r"\b(?:mv|cp)\b[^\n]*\s/(?:etc|usr|bin|sbin|boot|sys|dev|lib|System|Library)(?:/|\b)",
    r">\s*/(?:etc|usr|bin|sbin|boot|sys|dev|lib|System|Library)/",
    r"(?:>>?|tee(?:\s+-a)?)\s*[^\n|;&]*(?:\.ssh/|authorized_keys|\.bash_history|/etc/sudoers|crontab)",
    # curl/wget writing a downloaded file to a sensitive path (no shell redirect)
    r"\b(?:curl|wget)\b[^\n]*(?:-o|-O|--output|--remote-name)\b[^\n]*"
    r"(?:\.ssh/|authorized_keys|/etc/|\.bashrc|\.zshrc|\.profile|crontab|\.aws/)",
    r"\b(?:scp|rsync|sftp)\b[^\n]*\s[^\n]*@[^\n]*:",
    r"\b(?:curl|wget)\b[^\n]*(?:--upload-file|\s-T\s|--data-binary\s+@|\s-d\s+@|-F\s+[^\n]*@)",
    r"\b(?:nc|ncat|netcat)\b[^\n]*\s-[a-zA-Z]*e\b|\bncat\b[^\n]*--exec",
    r"\b(?:iptables|ip6tables|nft|pfctl|ufw)\b[^\n]*(?:-F|--flush|flush|disable|delete)",
    r"\bkill\s+-9\s+-1\b|\bkillall\s+-9\b|\b(?:kill|pkill)\b[^\n]*\s(?:-9\s+)?1\b",
    r"\b(?:apt|apt-get|dnf|yum|brew|apk|pkg|zypper)\b[^\n]*"
    r"\b(?:remove|purge|uninstall|autoremove|erase)\b|\bpacman\b[^\n]*\s-R",
    r"\bnpm\s+(?:install|i|add)\b[^\n]*(?:-g\b|--global)",
    r"\bgit\b[^\n]*\b(?:push|reset\s+--hard|clean\s+-[a-zA-Z]*f)\b",
    r"\bsqlmap\b[^\n]*--(?:os-shell|os-cmd|os-pwn|file-write|sql-shell)",
    r"\b(?:msfconsole|msfvenom|metasploit|responder|ettercap|bettercap|arpspoof)\b",
    r"\b(?:hydra|medusa|patator|ncrack|hashcat|john)\b",
    r"\bhping3\b[^\n]*--flood|\b(?:masscan|zmap)\b[^\n]*--rate[=\s]*[1-9][0-9]{4,}",
    r"\bping\b[^\n]*(?:\s-f\b|--flood|\s-i\s*0*\.0)",  # ping flood / sub-decisecond interval
    r"\bnmap\b[^\n]*--script[=\s][^\n]*(?:exploit|dos|brute|malware|intrusive)",
    # openssl enc can encrypt/overwrite local files (ransomware primitive) — block it
    # even though `openssl s_client` (TLS recon) stays allowlisted.
    r"\bopenssl\s+enc\b",
    r"\b(?:sudo|su|doas)\b",
]
_BLOCK_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _DENYLIST]

# Any of these means a second command could be smuggled in -> defer to a human.
_META = re.compile(r"[;&|<>`]|\$\(|\$\{|>>|\|\||\n|\r")

# Single-purpose recon tools that may auto-run unattended. Deliberately EXCLUDES
# the general-purpose Swiss-army tools curl / wget / openssl: their flags are full
# file read/write/exfil + remote-config-execution primitives (curl -K/--config,
# --upload-file, --data @file, -o/--output-dir/--write-out, --netrc-file; wget
# --use-askpass runs a program; openssl genrsa/req/rsautl overwrite key files) that
# no denylist can fully chase — in auto mode they fall to CONFIRM (one approval).
# Also excludes local file readers (cat/grep/sort/strings/head/tail/jq dump file
# contents, bypassing read_file's secret guard), RCE-capable interpreters (awk/sed/
# find/xargs/perl/python/sh/eval), and active fuzzers (gobuster/ffuf/dirb). The tools
# here only emit their own scan output; they cannot download attacker payloads to a
# path, exfiltrate arbitrary files, or execute a program.
SAFE_RECON = frozenset({
    "nmap", "whois", "dig", "host", "nslookup", "httpx", "whatweb", "wafw00f",
    "dnsrecon", "dnsenum", "sublist3r", "amass", "subfinder", "assetfinder",
    "theharvester", "waybackurls", "gau", "ping", "traceroute", "tracert",
    "sslscan", "testssl.sh", "nikto",
})

_WRAPPERS = {"sudo", "command", "env", "exec", "time", "nice", "nohup", "doas", "stdbuf"}

# Files that must never be auto-read even inside the read-root.
_SECRET_PATH = re.compile(
    r"(?:\.ssh/|/\.ssh$|authorized_keys|id_[rd]sa|id_ecdsa|id_ed25519|\.pem$|\.key$|"
    r"\.aws/|\.env(?:\.|$)|\.netrc|/etc/shadow|/etc/sudoers|\.bash_history|"
    r"\.git-credentials|\.npmrc|\.pypirc)",
    re.IGNORECASE,
)


def _leading_binary(command: str) -> str:
    """The base name of the first real binary, skipping VAR= and wrapper words."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for token in tokens:
        if "=" in token.split("/")[0] or token in _WRAPPERS:
            continue
        return os.path.basename(token)
    return ""


def classify(command: str) -> tuple[Verdict, str]:
    """Classify a shell command into a verdict plus a short reason string."""
    command = command.strip()
    if not command:
        return Verdict.CONFIRM, "empty"
    for pattern in _BLOCK_PATTERNS:
        if pattern.search(command):
            return Verdict.BLOCK, pattern.pattern
    if _META.search(command):
        return Verdict.CONFIRM, "shell-metacharacter"
    binary = _leading_binary(command)
    if binary in SAFE_RECON:
        return Verdict.ALLOW, binary
    return Verdict.CONFIRM, f"unlisted:{binary or '?'}"


def is_secret_path(path: str) -> bool:
    """Whether a file path looks like a credential/secret that must not auto-read."""
    return bool(_SECRET_PATH.search(path))


# --- soft scope check -----------------------------------------------------
_HOST_RE = re.compile(
    r"\b(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE)


def _scope_tokens(scope: str) -> list[str]:
    return [t.strip().lower() for t in re.split(r"[\s,;]+", scope or "") if t.strip()]


def _as_ip(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _as_net(text: str):
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _scope_is_enforceable(tokens: list[str]) -> bool:
    """True only if the scope contains a domain / IP / CIDR we can compare against."""
    return any(
        _DOMAIN_RE.fullmatch(t) or _as_ip(t) or ("/" in t and _as_net(t)) for t in tokens
    )


def _host_in_scope(host: str, tokens: list[str]) -> bool:
    host = host.lower()
    host_ip = _as_ip(host)
    for token in tokens:
        if _DOMAIN_RE.fullmatch(token):
            if host == token or host.endswith("." + token):
                return True
        elif "/" in token:
            net = _as_net(token)
            if net is not None and host_ip is not None and host_ip in net:
                return True
        else:
            token_ip = _as_ip(token)
            if token_ip is not None and host_ip is not None and host_ip == token_ip:
                return True
    return False


def targets_out_of_scope(command: str, scope: str) -> bool:
    """Heuristic: does the command target a host that isn't in the declared scope?

    Conservative on purpose — only fires when the scope is a recognizable
    domain/IP/CIDR set AND the command names at least one host, none of which
    match. Returns False (in scope) when scope is unrestricted/unparseable or no
    host appears, so normal recon is never second-guessed. Used to downgrade an
    otherwise-auto-approved command to a human CONFIRM, never to BLOCK.
    """
    tokens = _scope_tokens(scope)
    if not tokens or "unrestricted" in tokens or not _scope_is_enforceable(tokens):
        return False
    hosts = [h.lower() for h in _HOST_RE.findall(command)]
    if not hosts:
        return False
    return not any(_host_in_scope(h, tokens) for h in hosts)


class BudgetExceeded(Exception):
    """Raised when an autonomous run hits one of its resource caps."""


@dataclass
class Budget:
    """Resource caps for a single autonomous objective."""

    max_rounds: int = 40
    max_commands: int = 60
    max_installs: int = 8
    wall_clock_s: int = 1200
    max_blocks: int = 5
    max_idle_rounds: int = 3  # consecutive unproductive rounds before halting
    rounds: int = 0
    commands: int = 0
    installs: int = 0
    blocks: int = 0
    _start: float | None = field(default=None, repr=False)

    def start(self) -> None:
        """Reset all counters and the wall clock for a fresh objective."""
        self._start = time.monotonic()
        self.rounds = self.commands = self.installs = self.blocks = 0

    def charge(self, kind: str) -> None:
        """Account for one unit of work; raise :class:`BudgetExceeded` past a cap."""
        if kind == "round":
            self.rounds += 1
            if self.rounds > self.max_rounds:
                raise BudgetExceeded(f"round budget ({self.max_rounds}) reached")
        elif kind == "command":
            self.commands += 1
            if self.commands > self.max_commands:
                raise BudgetExceeded(f"command budget ({self.max_commands}) reached")
        elif kind == "install":
            self.installs += 1
            if self.installs > self.max_installs:
                raise BudgetExceeded(f"install budget ({self.max_installs}) reached")
        elif kind == "block":
            self.blocks += 1
            if self.blocks > self.max_blocks:
                raise BudgetExceeded(f"too many blocked commands ({self.max_blocks})")
        if self._start is not None and (time.monotonic() - self._start) > self.wall_clock_s:
            raise BudgetExceeded(f"wall-clock budget ({self.wall_clock_s}s) reached")
