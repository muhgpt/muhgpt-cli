# MuhGPT

A modular, human-in-the-loop CLI assistant for **authorized** penetration testing
and OSINT. It talks to your OpenAI-compatible `muh-chat` endpoint, lets the model
drive predefined local tools via **native function calling**, requires explicit
operator approval before any command runs, and exports a clean Markdown report.

## Project structure

```text
muhgpt_cli/
├── main.py                  # CLI loop, banner, authorization gate, report export
├── pyproject.toml           # packaging + `muhgpt` console entry point + pytest config
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── muhgpt/
│   ├── __init__.py
│   ├── config.py            # .env loading -> immutable Settings
│   ├── api_client.py        # resilient HTTP client (retries, backoff, error types)
│   ├── tools.py             # tool schemas + dispatcher + human-in-the-loop
│   ├── guard.py             # autonomous-mode safety classifier + run budget
│   ├── mcp.py               # Model Context Protocol client (stdio + HTTP), pure stdlib
│   ├── arsenal.py           # recon tool catalog + attack-chain playbooks
│   ├── research.py          # OSINT research sub-agent (relace-search-style delegate)
│   ├── packages.py          # package-manager detection + install commands
│   ├── session.py           # JSONL audit log + Markdown report
│   ├── render.py            # terminal Markdown renderer
│   ├── bidi.py              # display-only RTL (Arabic) fix
│   ├── ui.py                # ANSI color theme
│   └── agent.py             # multi-step tool-use feedback loop
└── tests/                   # pytest suite (no network — model + HTTP are faked)
```

## Install

**Requirements:** Python ≥ 3.9 (macOS, Linux, or Termux) — just two dependencies
(`requests`, `python-dotenv`). Install the `muhgpt` command straight from GitHub:

```bash
pipx install git+https://github.com/muhgpt/muhgpt-cli.git    # recommended (isolated)
# or:
pip install git+https://github.com/muhgpt/muhgpt-cli.git
muhgpt --version
```

Prefer to clone (to read or hack on it)?

```bash
git clone https://github.com/muhgpt/muhgpt-cli.git
cd muhgpt-cli
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Get an API key

MuhGPT talks to the **MUHGPT API** (`https://api.muhgpt.com/v1`, OpenAI-compatible).

1. Sign up at **<https://muhgpt.com>** and open your account.
2. Create an **API key** — it looks like `mghp_...`.

**Easiest — just run it.** On first launch with no key configured, MuhGPT asks
for it and saves it for you:

```text
$ muhgpt
  No API key set yet — quick one-time setup.
  Paste your MUHGPT API key: mghp_…
  ✓ Saved to ~/.config/muhgpt/.env  — future runs pick it up automatically.
```

The key is written to `~/.config/muhgpt/.env` (owner-only, `0600`) so every future
run — from any directory — just works. No file editing, no touching the code.

Prefer to set it yourself? Any of these work (checked in this order — first wins):
`MUHGPT_API_KEY` in your environment → a `.env` in the current folder →
`~/.config/muhgpt/.env`.

```ini
MUHGPT_API_KEY=mghp_your_key_here
MUHGPT_BASE_URL=https://api.muhgpt.com/v1
MUHGPT_MODEL=muh-chat
```

Once running, `/models` lists the models your key can use and `/balance` shows your
remaining credits. `.env.example` documents every optional knob (timeouts, retries,
`MUHGPT_TEMPERATURE=none` for reasoning models, autonomous/MCP/research settings, …).

## Step-by-step quick start

From zero to a finished recon report. Use only against systems you are
**authorized** to test (the examples use `scanme.nmap.org`, which Nmap provides
for exactly this).

### 1. Install and configure

```bash
git clone <repo> && cd muhgpt_cli
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # then edit .env and set MUHGPT_API_KEY
```

### 2. Start a session (manual mode — the safe default)

```bash
python main.py
```

You get a `[you@muhgpt] ❯` prompt. Type `/help` any time. **Every** command the
model wants to run shows up in a box and waits for your `[y/N]` — nothing executes
without your approval.

### 3. Run your first recon

Type a **skill** followed by an authorized target:

```text
/recon scanme.nmap.org
```

The agent plans and proposes commands (whois → dig → nmap → httpx …); press `y`
to run each. Findings are saved as it goes. Single-purpose skills: `/subdomains`,
`/dns`, `/tls`, `/ports`, `/web`. Bigger attack-chain playbooks: `/pentest`,
`/osint`, `/cloud`, `/api`, `/vulns`.

> Declare the target as the scope so the agent knows it's authorized:
> `python main.py --scope scanme.nmap.org`. The agent will refuse hosts that are
> clearly outside the confirmed scope.

### 4. Use the vulnerability playbooks (skills)

MuhGPT ships a knowledge base of per-class playbooks (find → **validate** →
report). List and preview them:

```text
/skills              # xss, sqli, ssrf, idor, ssti, xxe, rce, auth-jwt, …
/skills sqli         # preview the SQL-injection playbook
```

During a run the agent loads the right one itself (the `load_skill` tool) before
hunting a bug class — that's where its techniques, payloads, and the
"no PoC, no finding" validation method come from. Add your own by dropping a
Markdown file into `muhgpt/skills/`.

### 5. Choose how deep to go (scan modes)

```bash
python main.py --scan-mode quick      # fast, breadth, high-impact only
python main.py --scan-mode standard   # balanced (default)
python main.py --scan-mode deep       # exhaustive + vulnerability chaining
```

When the agent confirms a real, **proven** vulnerability it files it with
`report_vulnerability` — which requires a proof of concept and auto-computes a
**CVSS 3.1** score. It also keeps a scratchpad (`note` / `recall_notes`). All of
this lands in the exported report (a severity-sorted *Vulnerabilities* section,
plus *Notes & Methodology*).

### 6. Ask it anything (no target needed)

Assistant skills run a one-off in a dedicated role:

```text
/explain how TLS session resumption works
/code a python script that parses nmap -oX output
/security  <paste a code snippet to review>
```

### 7. Add web search + OSINT (free MCP servers, no API key)

Requires Node/`npx`. Just add `--mcp` — a curated free set loads automatically
(DuckDuckGo search, fetch, Wikipedia, sequential-thinking):

```bash
python main.py --mcp
```

Check what's connected with `/mcp`, then let the model search the web:

```text
search the web for recent nginx CVEs and summarize them
```

Make it always-on by adding `MUHGPT_MCP_ENABLED=1` to `.env` (then plain
`python main.py` already has MCP).

### 8. Deep OSINT research (a search sub-agent)

Turn on a dedicated **research sub-agent** that the main agent can hand a question
to. It runs its own focused search loop (best with `--mcp` for web search) and
returns a tight, **sourced** brief — instead of cluttering the main chat with raw
results. Inspired by [Relace Search](https://docs.relace.ai/docs/fast-agentic-search/agent)'s
"sub-agent → oracle" pattern.

Use the main model:

```bash
python main.py --mcp --research
```

Or point it at a dedicated search model (any OpenAI-compatible endpoint — e.g.
`relace/relace-search` or a Perplexity model via OpenRouter):

```bash
python main.py --mcp --research-model relace/relace-search
# separate provider? set these in .env:
#   MUHGPT_RESEARCH_BASE_URL=https://openrouter.ai/api/v1
#   MUHGPT_RESEARCH_API_KEY=sk-or-...
```

Then ask directly, or let the agent delegate on its own:

```text
/research breach history and exposed infrastructure of example.com
```

The sub-agent reuses the **same safety guard**: in manual mode each of its
commands still asks `[y/N]`; in `--auto` its read-only recon auto-runs. Because it
ingests untrusted web pages, it **does not inherit YOLO** — its CONFIRM-tier
primitives (curl/wget) stay gated even in a `--yolo` session. It runs on its own
bounded budget (`MUHGPT_RESEARCH_MAX_ROUNDS` / `_MAX_COMMANDS` / `_WALLCLOCK_S`)
and **cannot recurse into itself**. Make it always-on with
`MUHGPT_RESEARCH_ENABLED=1` in `.env`.

### 9. Plug in your own MCP servers (optional)

Create `mcp.json` (the standard `mcpServers` shape) and keep API keys in `.env`,
not in the file:

```json
{ "mcpServers": { "shodan": { "command": "npx", "args": ["-y", "shodan-mcp"] } } }
```

```bash
python main.py --mcp --mcp-config mcp.json
```

Your servers are **merged on top** of the bundled free ones. Use
`--no-mcp-defaults` to load only yours.

### 10. Go hands-off (autonomous mode)

Give one objective and let it run read-only recon end-to-end without approving
each step (you acknowledge the scope once at launch; destructive commands stay
blocked, installs still ask):

```bash
python main.py --auto --scope scanme.nmap.org
```

### 11. Maximum hands-off (YOLO)

Auto-approves everything **except** the destructive denylist and secret-file
reads. Only against targets you fully trust:

```bash
python main.py --yolo --scope your-lab.example.com
```

### 12. One-shot (for cron / CI)

Run a single objective, export the report, and exit — no prompts:

```bash
python main.py --auto --objective "/recon scanme.nmap.org" --scope scanme.nmap.org
```

### 13. Get your report

Inside a session type `/report` (and you're offered an export on exit). Reports
are written to `reports/report-*.md`, with a full JSONL audit log next to them.

## Run

```bash
python main.py
```

The session starts immediately. In-session commands: `/help`, `/install <pkg>`,
`/mcp`, `/models`, `/balance`, `/skills`, `/scope`, `/report`, `/exit`. The operator handle defaults to your login name and
the report scope label defaults to `unrestricted`; override either with
`--operator NAME` / `--scope "target(s)"`. Run `python main.py --version` to
print the version.

**Recon skills.** Built-in `/<skill> <target>` commands expand into a ready-made
recon playbook and run it through the agent (hands-off under `--auto`,
step-approved otherwise): `/recon`, `/subdomains`, `/dns`, `/tls`, `/ports`,
`/web`. For example `/recon example.com` runs WHOIS → DNS → subdomains → TLS →
nmap → HTTP fingerprinting and saves findings to the report.

**Attack-chain playbooks.** Larger HexStrike-style multi-tool objectives that
chain the recon arsenal end-to-end (also `/<skill> <target>`): `/pentest` (full
attack-surface chain), `/osint` (passive profile, no active scan), `/cloud`
(internet-facing cloud footprint), `/api` (map + probe an API), `/vulns`
(non-destructive nuclei/nikto vulnerability scan). They run through the same
guard as everything else — nothing in a playbook can bypass approval or the
denylist.

**Assistant skills.** General-purpose `/<skill> <your text>` commands run your
request under a dedicated role — its own system prompt, isolated from the pentest
context — so the model answers in-character: `/code`, `/analyze`, `/debug`,
`/explain`, `/write`, `/optimize`, `/security`. For example `/security review this
login handler …` runs a focused security review. `/help` lists everything.

Output is colorized (gradient banner, highlighted command-approval box, dimmed
model reasoning). Colors auto-disable when output isn't a terminal, and can be
turned off with `--no-color` or the `NO_COLOR` / `MUHGPT_NO_COLOR` env vars —
audit logs and Markdown reports are always written plain.

Replies **stream token-by-token** as the model produces them. On a terminal,
once a reply finishes it is re-rendered in place as Markdown: pipe tables drawn
with box borders and aligned columns, plus headings, bullet/numbered lists,
blockquotes, fenced code blocks, and inline bold/italic/code. (If the reply is
taller than the screen, or output is piped, the raw stream is kept as-is.) Use
`--no-stream` (or `MUHGPT_STREAM=false`) to buffer the whole reply and render it
in one shot. Rendering is display-only — raw Markdown is what gets logged and
saved to reports.

**Right-to-left (Arabic) replies.** Most terminals lay text out left-to-right and
don't implement the Unicode BiDi algorithm or Arabic shaping, so an Arabic reply
shows up with its letters mirrored and disconnected. MuhGPT fixes this at the
display layer: lines containing RTL text are reshaped (contextual Arabic forms +
lam-alef ligatures) and reordered so they read correctly even on a non-BiDi
terminal. It's pure-stdlib and **display-only** — audit logs and saved reports
stay in logical order. Controlled by `MUHGPT_BIDI` (`auto` default / `on` / `off`);
set it to `off` if your terminal already does BiDi, to avoid double-reversal.

When the API reports token usage, a dim `↑prompt ↓completion · session total`
line is printed after each turn, and a **Token Usage** section is appended to
the exported report. Set `MUHGPT_PRICE_PROMPT_PER_1M` / `MUHGPT_PRICE_COMPLETION_PER_1M`
(USD per 1M tokens) to also show an estimated `~$cost` per turn and per session.

**Real credits & models.** Beyond that local estimate, MuhGPT reads your **actual
account** from the API (same key, no extra setup): `/models` lists the models your
key can use, and `/balance` shows your **real remaining credits** plus a usage
breakdown (`/balance 2026-06-01 2026-06-30` for a date range). Your live credit
balance is also shown once at session start (disable with `--no-balance` /
`MUHGPT_SHOW_BALANCE=0`). And API failures are actionable: an out-of-credits `402`,
a wrong-model `403/404`, or a bad key `401` print a specific next step instead of a
generic error. These use the muh `/v1/models` + `/v1/usage` endpoints; against a
plain OpenAI-compatible endpoint that lacks them, `/balance` just degrades quietly.

## Reference — every option, skill & command (with examples)

A complete, copy-pasteable cheat sheet. Replace `example.com` with a target you
are **authorized** to test.

### CLI flags

| Flag | What it does | Example |
|---|---|---|
| `--scope "LABEL"` | Authorized scope; the agent refuses clearly out-of-scope hosts | `python main.py --scope example.com` |
| `--operator NAME` | Operator handle on the report (default: your login) | `python main.py --operator alice` |
| `--auto` | Autonomous: auto-runs read-only recon, blocks destructive, still prompts unknowns/installs | `python main.py --auto --scope example.com` |
| `--yolo` | High-trust: auto-approves everything **except** the denylist + secret-file reads (implies `--auto`) | `python main.py --yolo --scope lab.local` |
| `--objective "TEXT"` | Run one objective (free text or `/skill target`) non-interactively, export, exit | `python main.py --auto --objective "/recon example.com"` |
| `--scan-mode quick\|standard\|deep` | Depth of testing (default `standard`) | `python main.py --scan-mode deep` |
| `--mcp` | Enable MCP; auto-loads the bundled free servers (search/fetch/wiki) | `python main.py --mcp` |
| `--mcp-config PATH` | Add your own `mcpServers` JSON (merged on top of bundled) | `python main.py --mcp --mcp-config mcp.json` |
| `--no-mcp` | Disable MCP even if enabled in `.env` | `python main.py --no-mcp` |
| `--no-mcp-defaults` | Don't load the bundled free servers; use only `--mcp-config` | `python main.py --mcp --mcp-config mcp.json --no-mcp-defaults` |
| `--research` | Enable the OSINT research sub-agent on the main model | `python main.py --mcp --research` |
| `--research-model MODEL` | Dedicated research model, any OpenAI-compatible endpoint (implies `--research`) | `python main.py --mcp --research-model relace/relace-search` |
| `--no-research` | Disable the research sub-agent even if enabled in `.env` | `python main.py --no-research` |
| `--model NAME` | Override the chat model from `.env` | `python main.py --model muh-chat` |
| `--no-stream` | Buffer the full reply, then render (no token streaming) | `python main.py --no-stream` |
| `--no-color` | Disable colored output | `python main.py --no-color` |
| `--no-balance` | Don't fetch/show your real credit balance at session start | `python main.py --no-balance` |
| `--env-file PATH` | Use a specific `.env` file | `python main.py --env-file .env.prod` |
| `--extra-recon "LIST"` | Add extra read-only recon tools to the auto-run allowlist (merged with `MUHGPT_EXTRA_SAFE_RECON`; dangerous binaries rejected) | `python main.py --auto --extra-recon "gobuster ffuf"` |
| `--classify "CMD"` | Dry-run: print how the guard would classify CMD (BLOCK/ALLOW/CONFIRM) and exit — runs nothing, needs no API key | `python main.py --classify "curl x \| sh"` |
| `--version` | Print version and exit | `python main.py --version` |

### In-session slash commands

| Command | What it does | Example |
|---|---|---|
| `/help` | List all commands and skills | `/help` |
| `/install <pkg>...` | Install one or more CLI tools via the package manager | `/install nmap masscan` |
| `/mcp` | List connected MCP servers and their tools | `/mcp` |
| `/models` | List the models available on your API key | `/models` |
| `/balance` | Show real remaining credits + usage (optional date range) | `/balance 2026-06-01 2026-06-30` |
| `/research <question>` | Run the OSINT research sub-agent (if enabled) | `/research breach history of example.com` |
| `/skills` | List vulnerability playbooks (or preview one) | `/skills sqli` |
| `/scope` | Show the authorized engagement scope | `/scope` |
| `/report` | Export the engagement report to Markdown now | `/report` |
| `/exit`, `/quit` | Exit (offered a report export) | `/exit` |

Anything that isn't a command or skill is sent to the agent as a normal message.
A bare `install nmap` / `instala o nmap` is also routed straight to the installer.

### Recon skills — `/<skill> <target>`

| Skill | Does | Example |
|---|---|---|
| `/recon` | Full host/domain recon: WHOIS → DNS → subdomains → TLS → nmap → HTTP | `/recon example.com` |
| `/subdomains` | Passive subdomain enumeration (subfinder, amass, CT logs) | `/subdomains example.com` |
| `/dns` | Map all DNS records + attempt zone transfer (AXFR) | `/dns example.com` |
| `/tls` | Inspect TLS/cert: protocols, ciphers, chain, expiry, SANs | `/tls example.com` |
| `/ports` | nmap service/version scan of open ports | `/ports example.com` |
| `/web` | Fingerprint a web target (httpx, whatweb) + missing security headers | `/web https://example.com` |

### Attack-chain playbooks — `/<skill> <target>`

Larger multi-tool objectives that chain the recon arsenal end-to-end.

| Playbook | Does | Example |
|---|---|---|
| `/pentest` | Full attack-surface recon chain | `/pentest example.com` |
| `/osint` | Passive OSINT profile (no active scan) | `/osint example.com` |
| `/cloud` | Internet-facing cloud footprint | `/cloud example.com` |
| `/api` | Map and probe an API surface | `/api api.example.com` |
| `/vulns` | Non-destructive vulnerability scan (nuclei/nikto) | `/vulns example.com` |

### Assistant skills — `/<skill> <free text>`

General-purpose helpers that answer in a dedicated role, isolated from the
pentest persona (no target needed).

| Skill | Role | Example |
|---|---|---|
| `/code` | Senior engineer — writes clean code | `/code a python script that parses nmap -oX output` |
| `/analyze` | Sharp analyst — deep breakdown | `/analyze tradeoffs of JWT vs session cookies` |
| `/debug` | Bug hunter — root-cause + fix | `/debug why does this regex catch newlines? ...` |
| `/explain` | Teacher — explain simply | `/explain how TLS session resumption works` |
| `/write` | Pro writer/editor | `/write a clear summary of this finding for a client` |
| `/optimize` | Perf/clarity refactor | `/optimize <paste a slow function>` |
| `/security` | Security review with severities | `/security review this login handler <paste code>` |

### Vulnerability playbooks (skills KB)

Preview with `/skills <name>`; the agent loads the right one itself while hunting
a bug class (`load_skill` tool). The 12 bundled playbooks:

```text
auth-jwt   csrf   idor   nosqli   open-redirect   path-traversal
rce        sqli   ssrf   ssti     xss             xxe
```

```text
/skills           # list them all
/skills sqli      # preview the SQL-injection playbook
```

Add your own by dropping a Markdown file into `muhgpt/skills/`.

### Key environment variables (`.env`)

Full list with defaults is in [`.env.example`](.env.example). Most-used:

```ini
MUHGPT_API_KEY=mghp_...            # required
MUHGPT_BASE_URL=https://api.muhgpt.com/v1
MUHGPT_MODEL=muh-chat
MUHGPT_AUTO=1                      # autonomous by default (same as --auto)
MUHGPT_AUTO_YOLO=1                 # YOLO by default (same as --yolo)
MUHGPT_SCAN_MODE=deep              # default depth (same as --scan-mode)
MUHGPT_EXTRA_SAFE_RECON=gobuster ffuf   # extra auto-run recon tools (same as --extra-recon)
MUHGPT_MCP_ENABLED=1               # MCP on by default (same as --mcp)
MUHGPT_MCP_AUTO_TOOLS=mcp__ddg__web-search   # MCP tools allowed to auto-run in --auto
MUHGPT_RESEARCH_ENABLED=1          # research sub-agent on by default
MUHGPT_RESEARCH_MODEL=relace/relace-search
MUHGPT_RESEARCH_BASE_URL=https://openrouter.ai/api/v1
MUHGPT_RESEARCH_API_KEY=sk-or-...
MUHGPT_BIDI=off                    # RTL/Arabic display fix: auto | on | off
MUHGPT_SHOW_BALANCE=0              # don't fetch real credits at startup (same as --no-balance)
MUHGPT_PRICE_PROMPT_PER_1M=0       # local ~$cost estimate (separate from real credits)
```

Every `--flag` has an `MUHGPT_*` equivalent (CLI flags win over `.env`).

### Common recipes (full command lines)

```bash
# 1. Manual recon with web search (every command asks [y/N])
python main.py --mcp --scope example.com

# 2. Hands-off recon one-shot, auto-exports the report (cron/CI friendly)
python main.py --auto --objective "/recon example.com" --scope example.com

# 3. Deep autonomous full-pentest chain
python main.py --auto --scan-mode deep \
  --objective "/pentest example.com" --scope example.com

# 4. Zero prompts (YOLO) OSINT with MCP web search + research sub-agent
python main.py --yolo --mcp --research \
  --objective "/osint example.com" --scope example.com

# 5. Passive OSINT profile only (no active scanning)
python main.py --auto --objective "/osint example.com" --scope example.com

# 6. Research using a dedicated model via OpenRouter
python main.py --mcp --research-model relace/relace-search --scope example.com

# 7. Quick non-destructive vuln scan, no color, buffered (logs/CI)
python main.py --auto --no-color --no-stream --scan-mode quick \
  --objective "/vulns example.com" --scope example.com

# 8. Assistant one-shot, no target needed
python main.py --objective "/code a python nmap -oX parser"
```

## How it works

- **Native tool calling.** Instead of parsing ```` ```bash ```` blocks out of prose,
  the model is given four tools — `execute_terminal_command`, `install_package`,
  `read_file`, `save_report` — and invokes them through the standard `tool_calls`
  interface. The agent feeds each tool's output back as a `tool` message, so the
  model can interpret results and pick the next step. That round-trip is the
  feedback loop; it is capped per turn by `MUHGPT_MAX_TOOL_ROUNDS`. Any reasoning
  the model narrates alongside its tool calls is printed before each approval
  prompt, so you see *why* a command is proposed.
- **Installs missing tools.** When a command fails because its tool isn't
  installed (exit 127 / "command not found"), the runtime identifies the missing
  binary, offers to install it via the detected package manager — `brew`,
  `apt-get`, `pkg` (Termux), `dnf`, `yum`, `pacman`, `apk`, or `zypper` (choosing
  the right command, with `sudo` only when needed) — and, on approval, installs
  it and **re-runs the original command automatically**. This recovery is
  deterministic, so it works even with models that are weak at tool-calling. The
  model can also call `install_package` directly. Either way the install is shown
  and approved like any other command before it runs.
- **Operator-driven installs.** You can also install tools yourself without the
  model: `/install nmap` (or `/install nmap masscan`), or simply typing a bare
  request like `install nmap` / `instala o nmap`. These route straight to the
  package manager through the same `[y/N]` approval — bypassing the model so a
  weak tool-caller can't refuse. Package names are validated against a strict
  allowlist before they reach the shell.
- **Bounded context.** The running conversation is trimmed to the most recent
  `MUHGPT_MAX_HISTORY_MESSAGES` (default 40, `0` to disable) so long engagements
  don't silently blow the model's context window or cost. Trimming only cuts on
  turn boundaries, never splitting a tool call from its result.
- **Human-in-the-loop (default).** Both command execution and file reads route
  through a confirmation prompt and only proceed on an explicit `y`. The model
  cannot cause a side effect on its own.
- **Autonomous mode (opt-in, `--auto`).** Give one objective and the agent plans,
  runs read-only recon, installs missing tools, maps the target, and writes the
  report end-to-end without approving each step. A safety guard classifies every
  command at the execution boundary — **independently of the model**, so it holds
  even if scanned output prompt-injects it:
  - **BLOCK** — destructive/irreversible/weaponized commands (`rm -rf`, `dd`,
    `mkfs`, fork bombs, `curl … | sh`, disk/`/etc` writes, `~/.ssh` writes, exfil,
    reverse shells, brute-force/exploit tooling, `sudo`, …) never run and aren't
    even offered.
  - **auto-run** — only a curated allowlist of single-purpose read-only recon
    tools (nmap, whois, dig, httpx, whatweb, subfinder, amass, sslscan, nikto,
    plus the expanded arsenal: dnsx, naabu, tlsx, asnmap, cdncheck, katana,
    nuclei, …) with no shell metacharacters.
  - **CONFIRM** — everything else still stops for your `[y/N]`: unknown binaries,
    any pipe/chaining, installs, local file reads, the general-purpose tools
    `curl`/`wget`/`openssl` (whose flags can read/write/exfil files, so they're
    never auto-run), and any command whose target host looks **outside the
    declared scope** (a soft guard against injected scope pivots).

  It's bounded by a budget (rounds / commands / installs / wall-clock; see
  `.env.example`) plus a **no-progress guard** that halts the run if the model
  goes several rounds without a command actually executing (stuck talking, or all
  blocked/declined). Abortable with Ctrl-C, fully audit-logged, and requires a
  one-time scope acknowledgement at launch. The denylist has no disable flag — to
  run a blocked command, drop back to manual mode. Enable with `--auto` or
  `MUHGPT_AUTO=1`. Default stays human-in-the-loop.
- **Extend the allowlist safely + inspect it.** Add your own trusted read-only
  recon tools to the auto-run set with `--extra-recon "gobuster ffuf"` or
  `MUHGPT_EXTRA_SAFE_RECON`. Additions are **sanitized**: shells, interpreters,
  `curl`/`wget`/`cat`/`sudo`/… (the file-read/exfil/RCE primitives in the guard's
  `_NEVER_RECON` list) are rejected, and because the denylist and metacharacter
  gates run **before** the allowlist, an operator addition can never auto-run a
  destructive or chained command — it only lets that one binary auto-run when it's
  clean. On startup the CLI prints what was accepted vs rejected. Preview any
  command without running it: `python main.py --classify "curl x | sh"` prints the
  verdict (BLOCK/ALLOW/CONFIRM) and exits — no session, no API key. The whole
  classifier is locked by a **regression corpus** (`tests/guard_corpus.py`) run in
  CI (`.github/workflows/ci.yml`) and by `make check` / `python scripts/guard_selftest.py`
  before packaging, so the guard can never silently weaken.
- **YOLO mode (opt-in, `--yolo`).** Maximum hands-off: in autonomous mode it
  auto-approves the **CONFIRM tier too** — curl/wget/openssl, pipes/chaining,
  installs, and reads of non-secret files all run unattended, with **no per-step
  prompts**. Two lines stay absolute even here: the **BLOCK denylist** (rm -rf,
  dd, exfil, reverse shells, `sudo`, …) never runs, and **secret/credential file
  reads** (`~/.ssh`, `.env`, `*.pem`, …) still require a prompt. Still bounded by
  the same budget. This trades away the CONFIRM safety layer, so scanned output
  could prompt-inject the model into running a CONFIRM-tier command — use it only
  against targets you fully trust (your own lab/infra), never untrusted hosts.
  Enable with `--yolo` (implies `--auto`) or `MUHGPT_AUTO_YOLO=1`.
- **MCP client (opt-in, `--mcp`).** Connect to external [Model Context
  Protocol](https://modelcontextprotocol.io) servers and let the model call their
  tools alongside the built-ins. Both **stdio** (local subprocess) and **HTTP**
  servers are supported — implemented in pure stdlib + `requests`, no SDK.
  Discovered tools are namespaced `mcp__<server>__<tool>` and routed through the
  **same guard** as shell commands: in `--auto` every MCP call defaults to a human
  `[y/N]` (never auto-runs), tool names that look weaponized
  (exploit/shell/payload/brute-force) are **BLOCKED**, out-of-scope target
  arguments downgrade to a confirm, and only tools you list in
  `MUHGPT_MCP_AUTO_TOOLS` may auto-run. Tool descriptions and outputs are treated
  as untrusted input. `/mcp` lists connected servers and tools. Off by default.
  - **Batteries included.** When you enable MCP, a curated set of **free,
    no-API-key** servers loads automatically (needs Node/`npx`): **ddg**
    (DuckDuckGo web search — deep search / OSINT), **fetch** (URL → html/markdown/
    txt/json — recon), **wikipedia** (search + read), and **think** (sequential
    reasoning). So `python main.py --mcp` works out of the box with no config.
    Versions are pinned; disable the bundle with `--no-mcp-defaults` /
    `MUHGPT_MCP_DEFAULTS=0`.
  - **Add your own.** Point `--mcp-config mcp.json` (or `MUHGPT_MCP_CONFIG`) at a
    standard `{"mcpServers": {…}}` file; your servers are **merged on top** of the
    bundled ones (a same-named entry overrides the default). Great for keyed
    OSINT/recon servers (Shodan, VirusTotal, Brave, a pinned nmap/nuclei wrapper,
    …) — put the API keys in `.env`, not in the JSON. MuhGPT never auto-installs a
    server; review and pin them yourself.
- **Research sub-agent (opt-in, `--research`).** A focused OSINT search delegate
  the lead agent hands a single question to — the "sub-agent → oracle" pattern
  popularized by [Relace Search](https://docs.relace.ai/docs/fast-agentic-search/agent)
  (it does this for code; here it's for web/OSINT). The sub-agent runs its own
  bounded search loop (best with `--mcp`) and returns a distilled, **sourced**
  brief, so raw search output never floods the lead's context. It runs on the main
  model by default, or on a dedicated one via `--research-model MODEL` (any
  OpenAI-compatible endpoint — `relace/relace-search`, Perplexity, … — with
  optional `MUHGPT_RESEARCH_BASE_URL` / `MUHGPT_RESEARCH_API_KEY` for a separate
  provider). It reuses the **same model-independent guard**: it inherits `auto`
  (HITL → each command still prompts; `--auto` → read-only recon auto-runs) but
  **never inherits YOLO** — since it browses untrusted web content, its CONFIRM-tier
  primitives (curl/wget) stay gated even under `--yolo`. It runs on its own bounded
  budget (`MUHGPT_RESEARCH_MAX_ROUNDS`/`_MAX_COMMANDS`/`_WALLCLOCK_S`), each
  delegation also costs one unit of the engagement command budget, and it
  **cannot recurse into itself**. Call it directly with `/research <question>`, or
  let the model delegate. Off by default.
- **One-shot / scripting (`--objective`).** Run a single objective and exit,
  exporting the report automatically: `python main.py --auto --objective "/recon
  example.com"`. Non-interactive (no prompts; `--auto` is the consent) — for cron
  or CI.
- **Auditing + reporting.** Every message, proposed command (approved or not), and
  finding is appended to `reports/session-*.jsonl` as it happens. `save_report`
  builds the human-facing report, exported to `reports/report-*.md`.
- **Vulnerability playbooks (skills).** A bundled knowledge base of per-class
  playbooks (XSS, SQLi, SSRF, IDOR, SSTI, XXE, RCE, JWT/auth, path-traversal,
  CSRF, open-redirect, NoSQLi) — each with where-to-look, detection, **validation
  ("no PoC, no finding")**, payloads, and remediation. The model loads one on
  demand via the `load_skill` tool; browse them with `/skills` (or `/skills xss`
  to preview). The available names are injected into the system prompt so even a
  weak model knows what it can pull in. Pure prompt data — grants no new execution
  power. (Inspired by [Strix](https://github.com/usestrix/strix)'s skills.)
- **Scratchpad memory.** `note` / `recall_notes` give the agent durable
  engagement memory (leads, plan, in-scope creds) that survives history trimming —
  rendered in the report under *Notes & Methodology*.
- **Validated reporting + CVSS.** `report_vulnerability` files a structured
  finding that **requires a proof of concept** and computes a real **CVSS 3.1**
  base score/severity/vector (pure stdlib, no dependency), de-duplicating by
  title. Vulnerabilities render in their own severity-sorted report section.
- **Scan modes.** `--scan-mode quick|standard|deep` (or `MUHGPT_SCAN_MODE`) shapes
  the agent's depth — `quick` (breadth, fast), `standard` (balanced), `deep`
  (exhaustive + vulnerability chaining).

### A note on `shell=True`

`execute_terminal_command` runs through the shell so real recon one-liners (pipes,
redirects, globs) work. The safety boundary is the mandatory approval prompt: you
see the exact command string before it can run. Review each command before
approving — only run this against systems you are authorized to test.

## Tests

The suite fakes the model and the HTTP layer, so it runs offline and fast:

```bash
pip install -e ".[dev]"   # or: pip install pytest ruff
python -m pytest
ruff check .              # lint (config in pyproject.toml)
```

## Termux / Android

Works under Termux. If `python` is missing: `pkg install python`. The optional
`MUHGPT_COMMAND_TIMEOUT` is handy on mobile to stop long scans. Everything else is
pure-Python with two small dependencies.

## License

Released under the [MIT License](LICENSE). For **authorized** security testing
only — you are responsible for having permission to test any target.
