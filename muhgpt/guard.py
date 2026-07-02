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
from collections.abc import Callable
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
    # nuclei is allowlisted for read-only detection, but several flags turn it
    # active/RCE: -code runs code-protocol templates (arbitrary code execution),
    # -dast sends live injection payloads, and -headless/-system-chrome/-sandbox
    # drive a real browser executing page JS. Block them all — dash-count- and
    # separator-agnostic (goflags treats -flag and --flag identically), so neither
    # `--code` nor `-code=true` can slip past.
    r"\bnuclei\b[^\n]*(?<![\w-])--?"
    r"(?:code|dast|headless|hl|system-chrome|sc|sandbox|sb|show-browser|cdp-endpoint|cdpe)(?:=|\b)",
    # katana is allowlisted for crawling, but its headless-browser modes execute
    # page JavaScript / attach to a Chrome instance — block those active modes.
    r"\bkatana\b[^\n]*(?<![\w-])--?(?:headless|hl|system-chrome|no-sandbox|chrome-ws-url|cwu)(?:=|\b)",
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
    # Expanded read-only recon arsenal (the guard-safe subset of HexStrike's
    # toolset): each only emits its own scan/lookup output — it cannot read
    # arbitrary local files, write downloaded payloads to a path, or exec a
    # program. Active fuzzers (gobuster/ffuf/dirb), file readers, interpreters,
    # and the Swiss-army tools (curl/wget/openssl) are deliberately still absent.
    "dnsx", "naabu", "tlsx", "asnmap", "cdncheck", "mapcidr", "httprobe",
    "katana", "hakrawler", "gospider", "cero", "nuclei",
})

# Binaries the operator may NEVER add to the recon allowlist via MUHGPT_EXTRA_SAFE_RECON.
# Even with no shell metacharacter and while dodging the denylist, each of these is a
# file-read / file-write / exfil / code-execution primitive (the denylist only catches
# *specific* weaponized invocations, not a bare `cat /etc/shadow` or `python3 evil.py`).
# This is a backstop against operator foot-guns: absence from this set does NOT auto-allow
# a tool — the operator still has to name it explicitly — it only bounds what CAN be named.
# Keep this list broad; over-inclusion only blocks a marginal operator addition (safe way).
_NEVER_RECON = frozenset({
    # shells / command interpreters -> direct RCE
    "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "ash", "busybox",
    # language interpreters -> arbitrary code execution
    "python", "python2", "python3", "perl", "ruby", "php", "node", "nodejs", "deno",
    "bun", "lua", "luajit", "tclsh", "rscript", "r", "osascript", "pwsh", "powershell",
    "groovy", "gdb", "java", "jshell",
    # eval-capable / in-place text + process tools (own -e/-i/system() = RCE or FS write)
    "awk", "gawk", "mawk", "sed", "find", "xargs", "expect",
    "vi", "vim", "nvim", "view", "nano", "emacs", "ed", "ex",
    # swiss-army network tools -> fetch-to-file / exfil / remote-config-exec / tunnels
    "curl", "wget", "fetch", "aria2c", "openssl", "nc", "ncat", "netcat", "socat",
    "telnet", "ssh", "sshpass", "scp", "sftp", "rsync", "ftp", "tftp", "smbclient",
    # file read / write / copy / archive -> arbitrary FS read or overwrite
    "cat", "tac", "head", "tail", "less", "more", "dd", "tee", "cp", "mv", "rm", "ln",
    "install", "truncate", "shred", "touch", "mktemp", "split", "xxd", "od", "hexdump",
    "strings", "base64", "base32", "uuencode", "uudecode", "tar", "zip", "unzip",
    "gzip", "gunzip", "bzip2", "7z", "7za", "cpio", "ar",
    # content readers that bypass read_file's secret guard
    "grep", "egrep", "fgrep", "rg", "ag", "sort", "uniq", "cut", "paste", "jq", "yq",
    "xmllint",
    # package / privilege / build / orchestration -> install or run arbitrary code
    "sudo", "doas", "su", "pkexec", "apt", "apt-get", "dnf", "yum", "brew", "pip",
    "pip3", "pipx", "npm", "npx", "yarn", "pnpm", "gem", "cargo", "go", "make", "cmake",
    "gcc", "cc", "clang", "ld", "git", "docker", "kubectl", "ansible", "terraform",
    "systemctl", "crontab", "at",
})

# A well-formed bare tool-name token (no path, no metachar, no spaces).
_RECON_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,30}$")

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


def classify(
    command: str, extra_recon: frozenset[str] = frozenset()
) -> tuple[Verdict, str]:
    """Classify a shell command into a verdict plus a short reason string.

    ``extra_recon`` is an optional operator-supplied set of extra read-only recon
    binaries that may auto-run (see :func:`sanitize_extra_recon` /
    :func:`make_classifier`). It ONLY widens step 3 — the denylist (step 1) and
    the shell-metacharacter gate (step 2) run first and unchanged, so no
    destructive or chained command can escalate to ALLOW through it. The leading
    binary is lowercased before the allowlist check, so mixed-case tool names like
    ``theHarvester`` match their lowercase allowlist entry.
    """
    command = command.strip()
    if not command:
        return Verdict.CONFIRM, "empty"
    for pattern in _BLOCK_PATTERNS:
        if pattern.search(command):
            return Verdict.BLOCK, pattern.pattern
    if _META.search(command):
        return Verdict.CONFIRM, "shell-metacharacter"
    binary = _leading_binary(command).lower()
    if binary in SAFE_RECON:
        return Verdict.ALLOW, f"recon:{binary}"
    if binary in extra_recon:
        return Verdict.ALLOW, f"extra-recon:{binary}"
    return Verdict.CONFIRM, f"unlisted:{binary or '?'}"


def sanitize_extra_recon(names) -> tuple[frozenset[str], tuple[str, ...]]:
    """Filter an operator-supplied extra-recon list into a safe allowlist.

    Lowercases and dedupes, keeps only well-formed bare tool-name tokens, and
    drops anything in :data:`_NEVER_RECON` (shells, interpreters, swiss-army net
    tools, file read/write utils, package/priv/build binaries). Returns
    ``(accepted, rejected)`` where ``rejected`` preserves the operator's original
    spelling of every dropped entry so the CLI can warn about it.
    """
    accepted: set[str] = set()
    rejected: list[str] = []
    for raw in names or ():
        name = str(raw).strip()
        if not name:
            continue
        low = name.lower()
        if _RECON_TOKEN.match(low) and low not in _NEVER_RECON and low not in SAFE_RECON:
            accepted.add(low)
        elif low in SAFE_RECON:
            continue  # already allowlisted; silently ignore (not a rejection)
        else:
            rejected.append(name)
    return frozenset(accepted), tuple(rejected)


def make_classifier(extra_recon=()) -> Callable[[str], tuple[Verdict, str]]:
    """Return a ``classify``-compatible closure that binds a sanitized extra allowlist.

    The returned callable has the same ``(command) -> (Verdict, reason)`` signature
    as :func:`classify`, so it drops into ``ToolRegistry(classifier=...)`` and the
    test seam unchanged. The extra allowlist is sanitized ONCE here; the denylist
    and metacharacter gates still run first inside :func:`classify`.
    """
    clean, _rejected = sanitize_extra_recon(extra_recon)

    def _classify(command: str) -> tuple[Verdict, str]:
        return classify(command, clean)

    return _classify


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


# --- MCP tool classification ----------------------------------------------
# MCP tools are invoked by name with structured JSON args, not a shell string, so
# the shell denylist/metacharacter/allowlist pipeline above does not apply to
# them. They get their own, equally model-independent policy: weaponized tools
# are BLOCKED, an explicit operator allowlist may auto-run a tool, and EVERYTHING
# else defaults to a human CONFIRM (MCP tools are out-of-process side-effect
# engines — treated as conservatively as curl/wget, never auto-run by default).
# Broad on purpose: a BLOCK only bites in autonomous mode (HITL still lets the
# operator run the tool with a confirm), so over-matching merely forces a human
# approval — the safe direction. MCP tool names are far less standardized than
# shell binaries, so we cover whole weaponized families, not just exact names.
# Short acronym tokens (rce, lfi, xss, dos, …) use letter-boundary lookarounds
# instead of \b, because \b treats '_' as a word char and would miss the common
# underscore-separated tool naming ("rce_exec", "ssrf_probe", "dos_flood").
# Where a family is normally written as an order-sensitive compound (reverse_shell,
# password_spray, hash_dump, arp_spoof, cred_stuff) we match the DISTINCTIVE token
# alone (shell/spray/spoof) or both orders, so a reversed name (shell_reverse,
# spray_password, dump_hash, spoof_arp, stuff_creds) cannot slip past — over-match
# is the safe direction here (a BLOCK only bites in --auto; HITL still confirms).
_MCP_DENY = re.compile(
    r"(?:exploit|payload|metasploit|msf(?:console|venom)?|meterpreter|sliver|"
    r"cobalt|empire|backdoor|rootkit|implant|(?<![a-z])c2(?![a-z])|"
    r"shell|os[_-]?(?:cmd|command)|"
    r"sqlmap|sqli|injection|"
    r"(?<![a-z])rce(?![a-z])|(?<![a-z])lfi(?![a-z])|(?<![a-z])rfi(?![a-z])|"
    r"(?<![a-z])ssrf(?![a-z])|(?<![a-z])xxe(?![a-z])|(?<![a-z])xss(?![a-z])|"
    r"mimikatz|kerberoast|lsass|"
    r"(?:hash|secret|sam|ntds|cred)[_-]?dump|dump[_-]?(?:hash|secret|sam|ntds|cred|lsass)|"
    r"brute[_-]?force|spray|cred(?:ential)?[_-]?stuff|stuff[_-]?cred|"
    r"hashcat|(?<![a-z])john(?![a-z])|crack|phish|keylog|"
    r"(?<![a-z])d?dos(?![a-z])|flood|deauth|spoof|exfil|ransom)",
    re.IGNORECASE,
)


def classify_mcp(
    name: str, server: str, raw_tool: str, auto_tools: set[str] | frozenset[str] = frozenset()
) -> tuple[Verdict, str]:
    """Classify an MCP tool call into a verdict, independent of the model.

    Denylist-first, mirroring :func:`classify`: a weaponized tool name (or
    server name) is BLOCKED even if the operator allowlisted it; a tool whose
    namespaced name is in ``auto_tools`` may ALLOW (auto-run in autonomous mode);
    everything else defers to a human CONFIRM.
    """
    blob = f"{server} {raw_tool}".lower()
    if _MCP_DENY.search(blob):
        return Verdict.BLOCK, f"mcp-weaponized:{raw_tool}"
    if name in auto_tools:
        return Verdict.ALLOW, "mcp-auto-allowed"
    return Verdict.CONFIRM, "mcp-default-confirm"


def _iter_str_values(obj: object):
    """Yield every string value nested anywhere inside a JSON-like structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _iter_str_values(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _iter_str_values(value)


def mcp_targets_out_of_scope(args: dict, scope: str) -> bool:
    """Like :func:`targets_out_of_scope`, but reads structured MCP arguments.

    Scans every string value in the argument tree for hosts and, when the scope
    is an enforceable domain/IP/CIDR set, returns True if a named host falls
    outside it. Conservative: returns False when scope is unrestricted/unparseable
    or no host appears, so it only ever downgrades ALLOW -> CONFIRM.
    """
    tokens = _scope_tokens(scope)
    if not tokens or "unrestricted" in tokens or not _scope_is_enforceable(tokens):
        return False
    hosts: list[str] = []
    for value in _iter_str_values(args):
        hosts.extend(h.lower() for h in _HOST_RE.findall(value))
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
