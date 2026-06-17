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
  config.py        env -> immutable Settings (MUHGPT_* vars)
  api_client.py    resilient HTTP client; chat_completion + stream_chat_completion
                   (SSE) + accumulate_stream(); retries/backoff on 429/5xx/network
  agent.py         the model<->tool feedback loop; SYSTEM_PROMPT + AUTONOMOUS_SYSTEM_PROMPT
  tools.py         ToolRegistry: execute_terminal_command, install_package, read_file,
                   save_report; HITL confirm + auto-approve + exit-127 auto-recovery
  guard.py         autonomous-mode safety: classify() (ALLOW/CONFIRM/BLOCK) + Budget
  packages.py      detect_package_manager() (brew/apt/pkg/dnf/…) + install command
  session.py       JSONL audit log + Markdown report + token-usage accounting
  render.py        terminal Markdown renderer (tables, headings, code, wrapping)
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
  sslscan, subfinder, nikto, …) with **no shell metacharacters**. Auto-runs.
- **CONFIRM** — everything else still prompts: unknown binaries, any pipe/chaining,
  installs, local file reads, and the Swiss-army tools `curl`/`wget`/`openssl`
  (their flags are file read/write/exfil/RCE primitives, so they're never
  auto-run — see the red-team note below).

Bounded by a `guard.Budget` (rounds/commands/installs/wall-clock/blocks) and a
**no-progress guard**: after `auto_max_idle` consecutive rounds with no command
actually executed (stuck talking, or all blocked/declined/failed), the run halts.
Autonomous turns loop until the model replies `DONE`, the budget runs out, or
no-progress triggers.

### Guard invariants (don't regress these)
- The verdict is computed inside `ToolRegistry._approve_and_run` from the literal
  command string — never trust the model's framing.
- **Allowlist-first is load-bearing:** a destructive command that dodges the
  denylist still can't auto-run unless its leading binary is in `SAFE_RECON` and
  it has no metacharacters. Keep `SAFE_RECON` to network/recon tools that only
  emit their own output — never add file readers (cat/grep/…), interpreters
  (awk/sed/python/sh), fuzzers, or the Swiss-army tools (curl/wget/openssl).
- BLOCK reasons (raw regex) go to the audit log only; the model/operator see a
  generic message (don't reveal the rule to a possibly-injected model).
- `guard.targets_out_of_scope()` softly downgrades an ALLOW to CONFIRM when a
  command names a host outside `session.scope` (defense against injected scope
  pivots). Conservative: only fires for parseable domain/IP/CIDR scopes.

## Skills & routing (main.py)

- **Recon skills:** `/recon /subdomains /dns /tls /ports /web <target>` expand a
  playbook objective (`_SKILLS`) and run it through the agent. Targets are
  validated for hygiene but only reach the prompt; the guard governs actual shell.
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

## One-shot mode

`--objective "TEXT"` (or `--objective "/recon target"`) runs a single objective
non-interactively then exits, exporting the report automatically. With `--auto`
the flag itself is the autonomous consent (no interactive `[y/N]`). For cron/CI.

## Run & test

```bash
python3 main.py                                   # interactive HITL
python3 main.py --auto                            # interactive autonomous
python3 main.py --auto --objective "/recon x"     # one-shot, exports report
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
  legitimate read-only recon.

## Reporting / output

- All output styling is at the `print` layer (`ui`, `render`); the audit log
  (`reports/session-*.jsonl`) and the Markdown report (`reports/report-*.md`) are
  always plain. Colors auto-disable off-TTY and with `--no-color` / `NO_COLOR`.
- Model replies are streamed token-by-token and re-rendered as Markdown in place
  on a TTY; `--no-stream` buffers then renders.
