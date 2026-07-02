"""Recon arsenal: a static tool catalog + attack-chain playbooks.

This is MuhGPT's guard-compatible take on HexStrike's "intelligent decision
engine". HexStrike's engine is not AI — it's a hand-written table of tool
effectiveness plus ordered attack-chain playbooks. We port that idea as PURE
DATA that shapes the model's planning, granting **no new execution power**: the
tool index and chaining methodology are injected into the system prompt, and the
playbooks expand into objectives the agent runs through the existing guard.

The catalog is cross-checked against :data:`guard.SAFE_RECON` at render time, so
the "auto-runs vs. asks-for-approval" annotation can never drift from the actual
guard policy — there is one source of truth for what auto-runs.
"""
from __future__ import annotations

from . import guard

# Ordered recon arsenal grouped by engagement phase. Every name is matched
# against guard.SAFE_RECON to decide whether it auto-runs; tools NOT in the
# allowlist (masscan, the fuzzers) are kept here so the model knows they exist,
# but they are flagged as approval-gated.
_ARSENAL: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("DNS & subdomains",
     ("dig", "host", "nslookup", "dnsx", "dnsrecon", "dnsenum",
      "subfinder", "amass", "assetfinder", "sublist3r", "cero")),
    ("Network & ports",
     ("nmap", "naabu", "masscan", "traceroute", "asnmap", "mapcidr", "cdncheck")),
    ("TLS & certificates",
     ("sslscan", "testssl.sh", "tlsx")),
    ("HTTP & web",
     ("httpx", "httprobe", "whatweb", "wafw00f", "nikto", "nuclei")),
    ("Crawl & content discovery",
     ("katana", "hakrawler", "gospider", "gau", "waybackurls",
      "gobuster", "ffuf", "feroxbuster")),
    ("OSINT & enrichment",
     ("whois", "theharvester")),
)

CHAINING_METHODOLOGY = (
    "CHAINING METHODOLOGY — pick tools by target type, least-intrusive first, and "
    "feed each step's output into the next:\n"
    "- Domain: subdomain enum (subfinder, amass, assetfinder) -> resolve (dnsx) -> "
    "live-probe (httpx) -> fingerprint (whatweb, nuclei) -> crawl (katana, gau) -> "
    "per-live-host nmap -sV.\n"
    "- IP / CIDR: expand (mapcidr, asnmap) -> port scan (naabu, then nmap -sV on the "
    "open ports) -> TLS (tlsx, sslscan) -> HTTP fingerprint (httpx, whatweb).\n"
    "- URL / web app: httpx -> whatweb -> nuclei -> crawl (katana, hakrawler) -> note "
    "missing security headers and exposed paths.\n"
    "Don't re-run a tool that already answered; stop when the surface is mapped."
)


# Scan-depth presets (ported from Strix's scan_modes) — pure prompt shaping.
SCAN_MODES = {
    "quick": (
        "QUICK scan — time-box it: breadth over depth. Hit the obvious, high-impact issues and "
        "the main entry points, skip exhaustive enumeration, and finish fast."
    ),
    "standard": (
        "STANDARD scan — balanced: map the full attack surface, understand the target before "
        "probing, and cover the main vulnerability classes methodically."
    ),
    "deep": (
        "DEEP scan — exhaustive: probe every parameter, endpoint, and edge case; load the "
        "relevant vulnerability playbooks (load_skill) before each class; and CHAIN findings "
        "for maximum demonstrated impact. Thoroughness over speed."
    ),
}


def scan_mode_briefing(mode: str) -> str:
    """The prompt fragment describing the requested scan depth."""
    return "SCAN MODE — " + SCAN_MODES.get(mode, SCAN_MODES["standard"])


def auto_run_tools() -> frozenset[str]:
    """The tools that auto-run unattended (the live guard allowlist)."""
    return guard.SAFE_RECON


def tool_index() -> str:
    """A compact, phase-grouped arsenal listing; ``*`` marks approval-gated tools."""
    lines: list[str] = []
    for phase, tools in _ARSENAL:
        marked = [t if t in guard.SAFE_RECON else f"{t}*" for t in tools]
        lines.append(f"- {phase}: " + ", ".join(marked))
    return "\n".join(lines)


def arsenal_briefing(autonomous: bool = True) -> str:
    """The prompt fragment that teaches the model its arsenal and how to chain it."""
    if autonomous:
        head = (
            "RECON ARSENAL — tools marked * PAUSE for operator approval; every other "
            "tool AUTO-RUNS unattended, so prefer them for hands-off recon:"
        )
    else:
        head = (
            "RECON ARSENAL — recon/OSINT tools available to you (each runs only after "
            "operator approval); tools marked * are general-purpose or active and should "
            "be used sparingly:"
        )
    return f"{head}\n{tool_index()}\n\n{CHAINING_METHODOLOGY}"


# Attack-chain playbooks exposed as recon skills. Each maps a name to
# (one-line description, objective template) — pure data the agent runs through
# the guard, exactly like the built-in recon skills. {target} is the operator's
# validated target token.
PLAYBOOKS: dict[str, tuple[str, str]] = {
    "pentest": (
        "Full attack-surface recon chain",
        "Run a full, methodical recon chain against {target}, passive-first then active: "
        "subdomain enumeration, DNS mapping, host resolution and live-probing, TLS "
        "inspection, an nmap -sV service scan of open ports, HTTP fingerprinting, a nuclei "
        "vulnerability scan (low/medium/high severity, no intrusive or code templates), and "
        "light content crawling. Correlate findings across phases, save each to the report "
        "as you go, then write a prioritized summary of the attack surface.",
    ),
    "osint": (
        "Passive OSINT profile (no active scan)",
        "Perform PASSIVE OSINT on {target} only — do not actively scan the target's "
        "infrastructure. Gather whois/registration data, theHarvester results (emails, "
        "hosts, subdomains from public sources), certificate-transparency subdomains, "
        "wayback/gau historical URLs, and ASN/netblock mapping (asnmap). Save a consolidated "
        "OSINT profile to the report.",
    ),
    "cloud": (
        "Internet-facing cloud footprint",
        "Enumerate the internet-facing cloud footprint of {target}: resolve hosts and "
        "identify cloud/CDN providers (cdncheck, dnsx, asnmap), find cloud-hosted subdomains "
        "and storage endpoints, fingerprint exposed services (httpx, whatweb), and flag "
        "non-destructively detectable misconfigurations (open buckets, exposed metadata, "
        "dangling DNS). Save findings to the report. Credentialed cloud-config audits "
        "(prowler, scoutsuite) require operator approval.",
    ),
    "api": (
        "Map and probe an API surface",
        "Map the API surface at {target}: discover API hosts/paths (httpx, katana, gau, "
        "waybackurls), identify the API style (REST/GraphQL/gRPC) and version, fingerprint "
        "the stack (whatweb), inspect TLS, run nuclei exposure/misconfiguration templates, "
        "and flag missing authentication, verbose errors, and exposed docs (swagger/openapi). "
        "Save findings to the report.",
    ),
    "vulns": (
        "Non-destructive vulnerability scan",
        "Run a focused, NON-DESTRUCTIVE vulnerability scan of {target}: live-probe with "
        "httpx, fingerprint with whatweb, then run nuclei across cve/vulnerability/"
        "misconfiguration/exposure templates (low through high severity; never intrusive or "
        "code templates) plus nikto for the web server. Correlate results and save each "
        "confirmed issue with severity, evidence, and remediation; end with a prioritized "
        "summary.",
    ),
}
