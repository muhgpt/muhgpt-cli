# CLAUDE.md

Guidance for working in this repo. Read once at session start.

## What this is

**MuhGPT** — a human-in-the-loop pentest/OSINT CLI assistant. It talks to an
OpenAI-compatible chat endpoint (`muh-chat` model), lets the model drive a small
set of local tools via native function calling, and exports a Markdown
engagement report. It is **for authorized testing only**.

Hard constraints (do not break):
- **Pure stdlib + two deps** (`requests`, `python-dotenv`). No new runtime
  dependencies. Must run on macOS, Linux, and Termux.
- **Python ≥ 3.9.** Code uses `from __future__ import annotations`, so `X | None`
  in annotations is fine, but don't use 3.10+ runtime features.
- Every module has docstrings and tests. Add/adjust tests with any change;
  `python3 -m pytest` must stay green.

## Layout

```
main.py            CLI entry: arg parsing, REPL, slash commands, skills, install
                   routing, autonomous gate, one-shot mode, stream view
muhgpt/
  config.py        env -> immutable Settings (MUHGPT_* vars); chat_completions_url /
                   models_url / usage_url derived from base_url; show_balance
  api_client.py    resilient HTTP client; chat_completion + stream_chat_completion
                   (SSE) + accumulate_stream(); retries/backoff on 429/5xx/network;
                   list_models() (GET /v1/models) + get_usage() (GET /v1/usage, real
                   credit balance) via shared _request_json(); typed errors carry
                   APIStatusError.error_type (insufficient_quota/model_not_allowed/…)
  agent.py         the model<->tool feedback loop; SYSTEM_PROMPT + AUTONOMOUS_SYSTEM_PROMPT
                   (+ arsenal briefing injected into the system prompt)
  tools.py         ToolRegistry: execute_terminal_command, install_package, read_file,
                   save_report, load_skill, note/recall_notes, report_vulnerability;
                   HITL confirm + auto-approve + exit-127 auto-recovery; MCP dispatch
  knowledge.py     vuln-playbook KB loader (load_skill/list_skills/skills_index) over muhgpt/skills/
  skills/          markdown vuln playbooks (xss/sqli/ssrf/idor/… — Strix-style "skills"); package data
  cvss.py          CVSS 3.1 base score/severity/vector — pure stdlib (no `cvss` dep)
  guard.py         autonomous-mode safety: classify(cmd, extra_recon) + Budget
                   + classify_mcp() + mcp_targets_out_of_scope() for MCP calls;
                   operator-extensible allowlist: _NEVER_RECON, sanitize_extra_recon(),
                   make_classifier() (binds a sanitized extra-recon set)
  scripts/guard_selftest.py  standalone red-team gate (make guard-selftest / CI)
  mcp.py           Model Context Protocol client (stdio + Streamable HTTP), McpManager,
                   config parsing + default_config_path()/merge_mcp_configs() — stdlib + requests
  mcp_defaults.json  bundled curated FREE no-key servers (ddg/fetch/wikipedia/think),
                   auto-loaded when MCP is on; pinned npx versions (package data)
  arsenal.py       recon tool catalog -> tool_index()/arsenal_briefing() + PLAYBOOKS
                   (the HexStrike "decision engine" as static, guard-safe data)
  research.py      OSINT research sub-agent: RESEARCH_SYSTEM_PROMPT + run_research()
                   (relace-search-style "sub-agent -> oracle"; reuses the guard)
  packages.py      detect_package_manager() (brew/apt/pkg/dnf/…) + install command
  session.py       JSONL audit log + Markdown report + token-usage accounting
  render.py        terminal Markdown renderer (tables, headings, code, wrapping)
  bidi.py          display-only RTL fix: Arabic shaping + BiDi reorder (MUHGPT_BIDI)
  ui.py            ANSI color theme with TTY / NO_COLOR detection
tests/             pytest suite (network + model are faked; runs offline)
```

## Two modes

**HITL (default).** Every command/install/file-read routes through a `[y/N]`
confirm (`tools.console_confirm`). The model cannot cause a side effect alone.
The guard is **bypassed** in this mode — behavior is exactly as before autonomous
mode existed (this is why all the original tests pass untouched).

**Autonomous (`--auto` or `MUHGPT_AUTO=1`).** The agent plans and runs read-only
recon end-to-end without per-step approval. A safety guard ([guard.py](muhgpt/guard.py))
classifies every command **at the execution boundary, independent of the model**,
so it holds even under prompt injection from scanned output:
- **BLOCK** — destructive/irreversible/weaponized/`sudo` (denylist regexes). Never
  runs, never prompts. No disable flag — to run one, drop to HITL.
- **ALLOW** — only `guard.SAFE_RECON` single-purpose recon tools (nmap, dig, httpx,
  sslscan, subfinder, nikto, plus the expanded arsenal: dnsx, naabu, tlsx, asnmap,
  cdncheck, katana, nuclei, …) with **no shell metacharacters**. Auto-runs.
- **CONFIRM** — everything else still prompts: unknown binaries, any pipe/chaining,
  installs, local file reads, and the Swiss-army tools `curl`/`wget`/`openssl`
  (their flags are file read/write/exfil/RCE primitives, so they're never
  auto-run — see the red-team note below).

**MCP tools (opt-in, `--mcp`).** When an MCP client is attached, discovered tools
(`mcp__<server>__<tool>`) are NOT shell strings, so they bypass `classify()` and get
their own model-independent verdict via `guard.classify_mcp()`: weaponized tool/server
names (exploit/shell/payload/brute-force regex) → **BLOCK**; only names the operator
listed in `MUHGPT_MCP_AUTO_TOOLS` → **ALLOW**; everything else → **CONFIRM** (the safe
default — treated as conservatively as curl/wget, never auto-run). `mcp_targets_out_of_scope()`
downgrades an ALLOW to CONFIRM when a structured argument names an out-of-scope host.
Every MCP call still flows through `tools._approve_and_run_mcp` (HITL confirm or auto
classification + budget + `mcp_call` audit event). MuhGPT never auto-installs/launches a
server; tool descriptions/outputs are untrusted.

Bounded by a `guard.Budget` (rounds/commands/installs/wall-clock/blocks) and a
**no-progress guard**: after `auto_max_idle` consecutive rounds with no command
actually executed (stuck talking, or all blocked/declined/failed), the run halts.
Autonomous turns loop until the model replies `DONE`, the budget runs out, or
no-progress triggers.

**YOLO (`--yolo` or `MUHGPT_AUTO_YOLO=1`, implies `--auto`).** Auto-approves the
CONFIRM tier too — only the **BLOCK denylist** and **secret-file reads**
(`guard.is_secret_path`) stay gated. Centralized in `ToolRegistry._auto_approves`
(ALLOW always auto-runs; CONFIRM auto-runs only under yolo; BLOCK never). `_read_file`
auto-reads any non-secret file in yolo. `self._yolo = yolo and auto` (inert without
auto). Budget still bounds the run. High-trust, trusted-targets-only — the CONFIRM
tier exists precisely because those commands (curl/wget/openssl/pipes) are exfil/RCE
primitives, so yolo accepts injection risk by design.

### Guard invariants (don't regress these)
- The verdict is computed inside `ToolRegistry._approve_and_run` from the literal
  command string — never trust the model's framing.
- **Allowlist-first is load-bearing:** a destructive command that dodges the
  denylist still can't auto-run unless its leading binary is in `SAFE_RECON` and
  it has no metacharacters. Keep `SAFE_RECON` to network/recon tools that only
  emit their own output — never add file readers (cat/grep/…), interpreters
  (awk/sed/python/sh), fuzzers, or the Swiss-army tools (curl/wget/openssl).
- **The allowlist match is case-insensitive** (`_leading_binary(cmd).lower()`), so
  `theHarvester` matches the lowercase `theharvester` entry. Keep every `SAFE_RECON`
  and `_NEVER_RECON` entry lowercase (a test enforces this).
- **Operator-extensible allowlist stays bounded:** `MUHGPT_EXTRA_SAFE_RECON` /
  `--extra-recon` widen ONLY step 3, and only through `sanitize_extra_recon()` —
  which drops anything in `_NEVER_RECON` (shells/interpreters/curl/wget/cat/sudo/…)
  and any non-tool-name token. The denylist + metacharacter gates still run first,
  so an operator addition can never auto-run a destructive/chained command. Thread
  it via `make_classifier(extra)` (a closure keeping the `(cmd)->verdict` signature)
  passed as `ToolRegistry(classifier=…)`; never make `classify()` read Settings —
  it must stay a pure function. When adding to `_NEVER_RECON`, err toward inclusion.
- **The guard is gated by a regression corpus.** `tests/guard_corpus.py` is the
  single source of truth (MUST_BLOCK/ALLOW/CONFIRM + EXTRA_RECON_* + SANITIZE_*);
  `scripts/guard_selftest.py`, `make check`, and `.github/workflows/ci.yml` run it.
  After ANY guard change, extend the corpus and re-run the red-team pass — a
  silently-weakened guard must fail CI.
- BLOCK reasons (raw regex) go to the audit log only; the model/operator see a
  generic message (don't reveal the rule to a possibly-injected model).
- `guard.targets_out_of_scope()` softly downgrades an ALLOW to CONFIRM when a
  command names a host outside `session.scope` (defense against injected scope
  pivots). Conservative: only fires for parseable domain/IP/CIDR scopes.
- **MCP keeps the same invariants on its own track:** `classify_mcp()` is
  denylist-first (BLOCK beats the operator allowlist) and defaults to CONFIRM;
  never widen the auto-run set except via the operator's `MUHGPT_MCP_AUTO_TOOLS`.
  When expanding `SAFE_RECON`, only add tools that emit their own output — the
  arsenal additions (dnsx/naabu/tlsx/asnmap/cdncheck/mapcidr/httprobe/katana/
  hakrawler/gospider/cero/nuclei) were chosen on that rule; `nuclei -code`
  (code-template RCE) is denylisted. Re-run the red-team pass after any change.

## Skills & routing (main.py)

- **Recon skills:** `/recon /subdomains /dns /tls /ports /web <target>` expand a
  playbook objective (`_SKILLS`) and run it through the agent. Targets are
  validated for hygiene but only reach the prompt; the guard governs actual shell.
- **Attack-chain playbooks:** `/pentest /osint /cloud /api /vulns <target>` are
  sourced from `arsenal.PLAYBOOKS` and merged into `_SKILLS` at import, so they
  resolve through the same `_expand_skill` path — pure data, no new code path.
- **MCP:** `--mcp` (or `MUHGPT_MCP_ENABLED`) builds an `McpManager` (`_build_mcp`,
  failures are non-fatal warnings) passed to `ToolRegistry(mcp=…)`; `/mcp` lists
  servers/tools; subprocesses closed in `try/finally`. The agent needs no change —
  it only reads `tools.schemas`/`dispatch`. When enabled, `_build_mcp` loads the
  bundled curated free servers (`mcp_defaults.json` via `default_config_path()`)
  unless `--no-mcp-defaults`/`MUHGPT_MCP_DEFAULTS=0`, then `merge_mcp_configs`
  layers the operator's `--mcp-config` on top (same name → user overrides). Keep
  bundled servers to READ-ONLY data sources with pinned versions; they still route
  through `classify_mcp` (CONFIRM default). Never bundle exploit kitchen-sinks.
- **Assistant skills:** `/code /analyze /debug /explain /write /optimize /security
  <free text>` (`_PROMPT_SKILLS`) run as an isolated one-off via `Agent.ask_once`:
  the skill's role is the SYSTEM prompt (NOT the pentest persona) on a fresh,
  tool-free `[system, user]` context never appended to the engagement history —
  so a weak model reliably adopts the role instead of being dominated by the
  pentest persona. Recon skills resolve in `_expand_skill`; assistant skills in
  `_expand_prompt_skill`. `_drive` runs either (a `run_turn` or `ask_once` thunk).
- **Install routing:** `/install <pkg>` and bare "install X" / "instala o X"
  (`_match_install_intent`) route straight to `install_package`, bypassing the
  model (which is weak at tool-calling). Plus deterministic auto-recovery: a
  command that exits 127 triggers an offer to install the missing tool and re-run.

## Knowledge, memory & validated reporting (Strix-inspired)

Ported as guard-safe, stdlib-only ideas from usestrix/strix — its *brains*, not its
weight (no Docker/multi-agent/browser/proxy):

- **Skills KB:** `muhgpt/skills/*/*.md` vuln playbooks loaded on demand via the
  `load_skill` tool (`knowledge.py`). `knowledge.skills_index()` is injected into the
  system prompt so the model knows what it can pull; `/skills [name]` lists/previews.
  Pure prompt data — no new execution power. New playbooks = drop a `.md` file in.
- **Scratchpad:** `note` / `recall_notes` tools → `session.notes` (durable across
  history trim). `load_skill`/`note`/`recall_notes` return `executed=False` so they
  never reset the autonomous no-progress guard (they're prep, not progress).
- **Validated reporting:** `report_vulnerability` REQUIRES a PoC ("no PoC, no finding"),
  dedups by title, and computes a real CVSS 3.1 score via `cvss.py` (stdlib). Stored in
  `session.vulnerabilities`, rendered severity-sorted in the report.
- **Scan modes:** `--scan-mode quick|standard|deep` / `MUHGPT_SCAN_MODE` →
  `arsenal.scan_mode_briefing()` injected into the prompt via `Agent(scan_mode=…)`.

## Research sub-agent (relace-search-style OSINT delegate)

A second model the lead agent delegates a single OSINT question to — the
"sub-agent → oracle" pattern (Relace Search does this for *code*; here it's for
*web/OSINT*). It runs its own bounded search loop and hands back a distilled,
sourced brief, keeping raw search output out of the lead's context.

- **Off by default.** Active when `--research` / `MUHGPT_RESEARCH_ENABLED=1`, or
  implicitly when a model is named via `--research-model` / `MUHGPT_RESEARCH_MODEL`.
  When active, `ToolRegistry` advertises the `research` tool and `/research <q>`
  runs the sub-agent directly. Best paired with `--mcp` (web search/fetch).
- **Configurable model.** `config.research_client_settings()` clones `Settings`
  with `research_model` / `research_base_url` / `research_api_key`, each falling
  back to the main endpoint — so it works on the main model out of the box, or you
  point it at relace/relace-search (OpenRouter), Perplexity, etc.
- **[research.py](muhgpt/research.py):** `run_research(query, *, client, tools,
  session, budget, scan_mode)` builds a quiet `autonomous=True` `Agent` on
  `RESEARCH_SYSTEM_PROMPT`, `stream=False`, and runs it. Returns the brief string.
- **Dedicated sub-registry (not a view).** `tools._research` builds a SEPARATE
  `ToolRegistry` sharing the engagement's `session`/`mcp`/`classifier`/package
  manager, with `research_client=None` (so it advertises **no `research` tool** →
  can't recurse) and a fresh `Budget` from `research_max_rounds`/`_max_commands`/
  `_wall_clock_s` shared with the sub-`Agent` (so round AND command AND wall-clock
  caps are all genuinely enforced — mirrors how `main.py` pairs the lead Agent +
  registry on one budget). `tools._research` lazily imports `research` to avoid the
  `tools → research → agent` import cycle.
- **Guard invariants preserved, with one hardening.** Every sub-agent command
  still flows through `classify()`/`classify_mcp()` (model-independent) and the
  parent's approval policy: it **inherits `auto`** (HITL → each command prompts;
  `--auto` → ALLOW recon auto-runs) but **never inherits `yolo`** (`yolo=False` on
  the sub-registry) — the researcher ingests untrusted web content, so its
  CONFIRM-tier primitives (curl/wget/non-allowlisted MCP) stay gated even in a YOLO
  session. Each delegation also charges one unit of the engagement command budget,
  so the number of research calls per run is bounded too. BLOCK and scope
  downgrades apply unchanged.

## One-shot mode

`--objective "TEXT"` (or `--objective "/recon target"`) runs a single objective
non-interactively then exits, exporting the report automatically. With `--auto`
the flag itself is the autonomous consent (no interactive `[y/N]`). For cron/CI.

## Real API integration (account, models, credits)

Grounded in the actual backend (a PHP server; the CLI only ever READS it — never
edits `api.muhgpt.com/`). Only the **`/v1/*` endpoints use the Bearer API key** the
CLI holds: `chat/completions`, `models`, `usage`. Everything else (TTS, image-gen,
upload, chats, key management) is **web session + CSRF** only, so it's deliberately
out of scope (would need a different auth model).

- `/models` → `client.list_models()` (GET `/v1/models`), lists the real model IDs
  (`muh-chat` is an alias → `google/gemini-2.5-flash-lite`; plus gemini/qwen/gpt-4o).
- `/balance` (alias `/usage`, optional date range) + a best-effort startup line →
  `client.get_usage()` (GET `/v1/usage`): REAL remaining credits + a token/request
  breakdown. This is separate from the LOCAL `MUHGPT_PRICE_*` cost estimate. Gated by
  `show_balance` / `--no-balance`; degrades silently on a non-muh endpoint.
- Typed errors: `api_client._error_info()` parses `{error:{type,message}}`;
  `APIStatusError.error_type` drives `main._error_hint()` → actionable next steps for
  402 insufficient_quota / 403 model_not_allowed / 404 model_not_found / 401 bad key.
  Both `/models`/`/balance` and startup balance are best-effort (never abort the session).

## Run & test

```bash
python3 main.py                                   # interactive HITL
python3 main.py --auto                            # interactive autonomous
python3 main.py --auto --objective "/recon x"     # one-shot, exports report
python3 main.py --mcp --mcp-config mcp.json       # with MCP servers attached
python3 -m pytest -q                              # full suite (offline)
python3 -m pytest tests/test_guard.py -q          # one file
```

Config: copy `.env.example` to `.env`, set `MUHGPT_API_KEY`. All knobs are
`MUHGPT_*` env vars (see `.env.example`), also settable as CLI flags where shown.

## Testing conventions

- Network and the model are faked — tests never hit a real endpoint. Use the
  fakes in `tests/conftest.py` (`FakeSession`, `FakeResponse`, `FakeTools`,
  scripted clients). Drive SSE with `data:`-prefixed line lists.
- The guard's classifier is injectable (`ToolRegistry(classifier=…)`) and the
  budget is constructable — test wiring with deterministic verdicts, and test the
  denylist/allowlist content separately in `tests/test_guard.py`.
- When you touch the guard, re-run a red-team pass: feed candidate destructive
  commands through `guard.classify()` and confirm none return `ALLOW` except
  legitimate read-only recon. Do the MCP equivalent through `guard.classify_mcp()`.
- MCP is tested with a real stdio server in `tests/test_mcp.py` (`FAKE_SERVER`
  script launched as a subprocess) and a fake `requests` session for HTTP;
  `tests/test_tools.py` has a `FakeMcp` manager to exercise `_approve_and_run_mcp`
  without spawning a process. Keep the pure-stdlib constraint: no `mcp` SDK.

## Reporting / output

- All output styling is at the `print` layer (`ui`, `render`); the audit log
  (`reports/session-*.jsonl`) and the Markdown report (`reports/report-*.md`) are
  always plain. Colors auto-disable off-TTY and with `--no-color` / `NO_COLOR`.
- Model replies are streamed token-by-token and re-rendered as Markdown in place
  on a TTY; `--no-stream` buffers then renders.
- RTL (Arabic) replies pass through `bidi.to_display()` at the render call sites
  (stream re-render + `--no-stream` print), TTY-only so piped/saved output stays
  logical. Like colors, it's display-only — never feed its result back into logic
  or reports. `MUHGPT_BIDI=off` disables it for terminals that already do BiDi.
