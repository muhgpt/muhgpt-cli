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
│   ├── session.py           # JSONL audit log + Markdown report
│   └── agent.py             # multi-step tool-use feedback loop
└── tests/                   # pytest suite (no network — model + HTTP are faked)
```

## Setup

```bash
cd muhgpt_cli
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env and set MUHGPT_API_KEY
```

`.env` format:

```ini
MUHGPT_API_KEY=mghp_your_key_here
MUHGPT_BASE_URL=https://api.muhgpt.com/v1
MUHGPT_MODEL=muh-chat
```

The API key is read from the environment only; nothing is hardcoded. See
`.env.example` for the full set of optional tuning variables (timeouts, retries,
`MUHGPT_MAX_HISTORY_MESSAGES`, and `MUHGPT_TEMPERATURE=none` to omit the field
for reasoning models that reject it).

Optionally install it as the `muhgpt` command:

```bash
pip install -e .
muhgpt --version
```

## Run

```bash
python main.py
```

The session starts immediately. In-session commands: `/help`, `/install <pkg>`,
`/scope`, `/report`, `/exit`. The operator handle defaults to your login name and
the report scope label defaults to `unrestricted`; override either with
`--operator NAME` / `--scope "target(s)"`. Run `python main.py --version` to
print the version.

**Recon skills.** Built-in `/<skill> <target>` commands expand into a ready-made
recon playbook and run it through the agent (hands-off under `--auto`,
step-approved otherwise): `/recon`, `/subdomains`, `/dns`, `/tls`, `/ports`,
`/web`. For example `/recon example.com` runs WHOIS → DNS → subdomains → TLS →
nmap → HTTP fingerprinting and saves findings to the report.

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

When the API reports token usage, a dim `↑prompt ↓completion · session total`
line is printed after each turn, and a **Token Usage** section is appended to
the exported report. Set `MUHGPT_PRICE_PROMPT_PER_1M` / `MUHGPT_PRICE_COMPLETION_PER_1M`
(USD per 1M tokens) to also show an estimated `~$cost` per turn and per session.

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
    tools (nmap, whois, dig, httpx, whatweb, subfinder, amass, sslscan, nikto, …)
    with no shell metacharacters.
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
- **One-shot / scripting (`--objective`).** Run a single objective and exit,
  exporting the report automatically: `python main.py --auto --objective "/recon
  example.com"`. Non-interactive (no prompts; `--auto` is the consent) — for cron
  or CI.
- **Auditing + reporting.** Every message, proposed command (approved or not), and
  finding is appended to `reports/session-*.jsonl` as it happens. `save_report`
  builds the human-facing report, exported to `reports/report-*.md`.

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
