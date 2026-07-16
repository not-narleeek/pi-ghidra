# pi-ghidra

> **Drive [Ghidra](https://ghidra-sre.org/) from [pi](https://pi.dev).** Let your AI coding agent decompile, disassemble, search, and cross-reference binaries during CTF reverse-engineering — no GUI, no copy-paste, no manual Jython setup. Just point it at a binary and ask.

`pi-ghidra` is a [pi package](https://pi.dev/packages) that exposes Ghidra's headless analyzer as ten first-class agent tools plus a `/ghidra` command and a live status footer. It manages a **PyGhidra venv** (CPython 3 + JPype — what Ghidra 12.x uses for Python postScripts) and a **cached analysis project** for you, so the first run just works and every later query is fast. One TypeScript extension, one Python postScript, nothing else.

---

## Table of contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Install](#install)
- [First-run setup](#first-run-setup)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Standalone usage](#standalone-usage)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## What it does

Point the agent at a binary (ELF, PE, Mach-O, firmware, …) and it can, without ever leaving the conversation:

- **import & auto-analyze** it once, then **cache** the project so repeat queries are instant,
- **decompile** functions to readable C pseudocode,
- **disassemble** at any address with raw bytes and operands,
- **list / search** functions, symbols, and defined strings,
- **find cross-references** to and from any address (who calls this? what does it reference?),
- **search memory** for byte patterns (find `flag{`, magic numbers, opcodes),
- **dump raw memory** as a hex+ASCII dump,
- **map the call graph** from a function,
- and read **metadata** — architecture, endianness, segments, entry points.

The package gives the agent these tools:

| Tool | What the agent uses it for |
|------|----------------------------|
| `ghidra_analyze` | Import & auto-analyze a binary. **Always the first step** — it caches the project and returns metadata. |
| `ghidra_decompile` | C pseudocode of one function (by name or address), or many. |
| `ghidra_functions` | List all functions or filter by name substring (`main`, `check`, `flag`…). |
| `ghidra_disasm` | Raw disassembly with bytes + operands at an address or function. |
| `ghidra_xrefs` | Cross-references **to** (who references this) or **from** (what it references) an address. |
| `ghidra_strings` | Defined strings, optionally filtered. Great for finding flags & messages. |
| `ghidra_info` | Architecture, endianness, address size, image base, entry points, segments. |
| `ghidra_search` | Byte-pattern search across all initialized memory (`deadbeef`, `48 8b c4`). |
| `ghidra_data` | Hex+ASCII dump of raw memory at an address. |
| `ghidra_calls` | Functions called from a given function. |

And a `/ghidra` command for you:

```
/ghidra                        status (install path · venv · analyzed binaries)
/ghidra path                   show Ghidra root + PyGhidra venv paths
/ghidra venv                   set up / verify the PyGhidra venv
/ghidra clean                  delete the cached analysis projects
/ghidra decompile <bin> [func] quick decompile (defaults to main)
```

A live footer (🔬 `ghidra · 3 binary(ies)`) shows readiness at a glance.

---

## Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| **pi** | any recent | the agent that loads this package — `npm i -g @earendil-works/pi-coding-agent` |
| **Ghidra** | **12.x** | must be the PyGhidra era (Ghidra 12 dropped Jython). Install from <https://ghidra-sre.org/> or `apt install ghidra` on Kali. |
| **Python** | 3.8+ | `python3` and `pip` on `PATH`. A **dedicated venv** is auto-created — your system Python is untouched. |
| **JDK** | 21+ | required by Ghidra itself (bundled or via `apt install default-jdk`). |
| **Node** | 18+ | for the TypeScript extension |

No `pip install` is needed by you. The extension creates the venv and installs
the `pyghidra` wheel **bundled inside your Ghidra install** on first use.

---

## Install

Pick **one** of the three sources. `pi install` writes to user settings
(`~/.pi/agent/settings.json`) by default; add `-l` for project-local settings.

### 1. From git (recommended — always latest)

```bash
pi install git:github.com/not-narleeek/pi-ghidra
```

Pin a tag/commit if you want reproducibility:

```bash
pi install git:github.com/not-narleeek/pi-ghidra@v0.1.0
```

### 2. From npm (once published)

```bash
pi install npm:pi-ghidra
```

### 3. From a local clone (for development)

```bash
git clone https://github.com/not-narleeek/pi-ghidra
cd pi-ghidra
npm install        # installs TypeScript peer deps for local type-checking
pi install .       # or: pi install ./pi-ghidra  (absolute or relative path)
```

Verify it loaded:

```bash
pi list                 # pi-ghidra should appear under packages
/ghidra status          # inside a pi session
```

Try it without committing it to settings:

```bash
pi -e git:github.com/not-narleeek/pi-ghidra     # ephemeral, current run only
```

> **Updating:** `pi update --extensions` reconciles git packages to their
> pinned ref; `pi update npm:pi-ghidra` updates a single package.
> `pi remove npm:pi-ghidra` (or the git: spec) uninstalls.

---

## First-run setup

1. **Install Ghidra 12.x** (the PyGhidra era). On Kali: `apt install ghidra`.
   Otherwise download from <https://ghidra-sre.org/> and extract it. If it's
   not in a standard location, export it:
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```
2. **Confirm `python3` + `pip` work** — that's the only other prerequisite.

That's it. On the first `ghidra_analyze` call (or `/ghidra venv`) the
extension will:

1. create `~/.pi/ghidra-venv`,
2. locate the `pyghidra-*.whl` bundled inside your Ghidra install
   (`<ghidra>/Ghidra/Features/PyGhidra/pypkg/dist/`), and
3. install it into the venv.

From then on, every headless command launches through that venv.

---

## Quick start

Inside a pi session, anywhere you have a binary:

```text
> analyze ./challenge and figure out what the main function does

# The agent calls ghidra_analyze (imports + auto-analyzes, caches the project),
# then ghidra_decompile main, and explains the logic in plain English.
```

Hunt for the flag the lazy way:

```text
> does this binary contain any interesting strings? look for a flag format

# Agent runs ghidra_strings --filter flag and highlights matches.
```

Trace data flow:

```text
> who calls the decrypt function, and what does it pass in?

# Agent uses ghidra_xrefs --to decrypt, then decompiles each caller.
```

Find a byte signature across the whole binary:

```text
> search for 48 8b c4 (mov rax,rsp) and tell me where it appears

# Agent runs ghidra_search with the pattern; results include block + function.
```

The footer updates live: 🔬 `ghidra · 1 binary(ies)`.

---

## Architecture

Three layers, no hidden moving parts. (Full deep-dive:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).)

```
┌──────────────────────────────────────────────────────────────────────┐
│                              pi (the agent)                           │
│   ┌────────────────────────────────────────────────────────────────┐ │
│   │  extensions/ghidra.ts   ←── this package (TypeScript)           │ │
│   │   • 10 tools + /ghidra command + live footer                    │ │
│   │   • Ghidra discovery · PyGhidra venv · analysis-project cache   │ │
│   └───────────────────┬────────────────────────────────────────────┘ │
│                       │ spawnSync(venv-python,                        │
│                       │   ["-m","pyghidra.ghidra_launch", …])         │
│   ┌───────────────────▼────────────────────────────────────────────┐ │
│   │  scripts/ghidra_query.py  ←── this package (PyGhidra postScript) │ │
│   │   • 14 operations · emits JSON between unique markers           │ │
│   └───────────────────┬────────────────────────────────────────────┘ │
└───────────────────────┼────────────────────────────────────────────────┘
                        │  JVM + JPype bridge (launched by pyghidra)
┌───────────────────────▼────────────────────────────────────────────────┐
│            Ghidra headless analyzer (AnalyzeHeadless)                   │
│   -import (analyze)  ·  -process (query cached project, -readOnly)      │
└────────────────────────────────────────────────────────────────────────┘
```

**Why this split?**

- **`ghidra.ts`** is the *agent surface*: it defines the tools, renders their
  call/result in the TUI, runs the `/ghidra` command, and owns all the
  orchestration — finding Ghidra, building the venv, caching projects, and
  parsing results. It contains **no** RE logic; it shells out and formats JSON.
- **`ghidra_query.py`** is the *Ghidra surface*: it runs **inside** Ghidra as a
  postScript, talks to the live `currentProgram` via the Ghidra/PyGhidra API,
  and returns one JSON blob per call. Being one auditable file also means you
  can run it standalone (see [Standalone usage](#standalone-usage)).
- **Ghidra** is the *engine*: the real analysis, decompilation, and memory
  model live there, so what the agent reports is always ground truth.

### File layout

```
pi-ghidra/
├── extensions/
│   └── ghidra.ts          # pi extension: tools, /ghidra command, footer
├── scripts/
│   └── ghidra_query.py    # PyGhidra postScript (runs inside Ghidra)
├── docs/
│   └── ARCHITECTURE.md    # lifecycle, data flow, operation reference
├── package.json           # pi manifest (pi.extensions) + npm metadata
├── tsconfig.json          # local type-checking only (pi compiles the extension)
├── README.md
├── CHANGELOG.md
└── LICENSE
```

---

## How it works

### 1. Ghidra discovery

On first use the extension looks for Ghidra in order: `$GHIDRA_INSTALL_DIR`,
then `/usr/share/ghidra`, `/usr/local/share/ghidra`, `/opt/ghidra`, then
`which ghidra` resolved through its symlink. A directory counts only if it
contains `Ghidra/application.properties`. The result is cached for the session.

### 2. PyGhidra venv bootstrap

Ghidra 12.x runs Python postScripts through **PyGhidra** (CPython 3 bridged to
the JVM via JPype) — Jython is gone. Rather than touch your system Python, the
extension maintains a dedicated venv at `~/.pi/ghidra-venv`:

1. `python3 -m venv ~/.pi/ghidra-venv` (once).
2. Probe `import pyghidra`; if it fails, find the wheel bundled at
   `<ghidra>/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl` and `pip install` it.

Every headless invocation is then launched as:

```
~/.pi/ghidra-venv/bin/python3 -m pyghidra.ghidra_launch \
    --install-dir <ghidra-root> ghidra.app.util.headless.AnalyzeHeadless ...
```

### 3. Cached analysis (`ghidra_analyze`)

Analysis is the expensive part (10–60 s), so it is done **once** and cached:

- Each binary gets a project dir under `~/ghidra-work/<sha256[:16]>/`
  (keyed by the absolute path — Ghidra rejects dotted directory names, so the
  cache lives in `~/ghidra-work`, not `~/.pi`).
- An `index.json` records `{binaryPath, projectDir, mtime, analyzedAt}`.
- On a later `ghidra_analyze`, if the path matches **and** the file's mtime is
  unchanged **and** the project dir exists, the cached entry is reused and the
  function returns instantly (it still emits fresh `info` metadata).

The analyze call itself:

```
… AnalyHeadless <projectDir> proj -import <binary> -overwrite \
    -analysisTimeoutPerFile 600
```

### 4. Fast queries (every other `ghidra_*` tool)

Repeat queries load the **already-analyzed** program with `-process` instead
of re-importing, which is what makes them fast:

```
… AnalyHeadless <projectDir> proj -process <programName> -readOnly \
    -scriptPath <script-dir> -postScript ghidra_query.py <operation> [args…]
```

`-readOnly` prevents queries from writing back to the cache.

### 5. Reliable result extraction

Ghidra's headless mode is noisy. To stay robust across log levels and
versions, the postScript wraps its JSON between two unique markers:

```
___PI_GHIDRA_RESULT_START___
{"name":"main","decompiled":"…"}
___PI_GHIDRA_RESULT_END___
```

The extension scans for `START`, parses up to `END`, and (on parse failure)
falls back to scanning every `START`-delimited segment in reverse, so a stray
early emit can't corrupt the final result.

---

## Configuration

All optional. Sensible defaults mean zero config for most setups.

| Env var | Default | Purpose |
|---------|---------|---------|
| `GHIDRA_INSTALL_DIR` | *(auto-discovered)* | Path to your Ghidra install root (the dir containing `Ghidra/`). Set this if Ghidra isn't in a standard location. |
| `GHIDRA_QUERY` | *(bundled)* | Override the path to `ghidra_query.py` (dev/debugging). Falls back to the bundled script, then `~/.pi/scripts/ghidra_query.py`. |

Generated state (not committed, created on first use):

```
~/.pi/ghidra-venv/        # PyGhidra venv (CPython 3 + JPype + pyghidra wheel)
~/ghidra-work/            # cached analysis projects
├── index.json            #   path → {projectDir, mtime, analyzedAt}
└── <sha256[:16]>/        #   one Ghidra project per analyzed binary
```

> Add `export GHIDRA_INSTALL_DIR=/path/to/ghidra` to your shell rc if Ghidra
> lives somewhere non-standard.

---

## Standalone usage

`scripts/ghidra_query.py` is a normal Ghidra postScript — you can run it
without pi, directly through the PyGhidra launcher or even the Ghidra GUI's
Script Manager:

```bash
VENV=~/.pi/ghidra-venv/bin/python3
GHIDRA=${GHIDRA_INSTALL_DIR:-/usr/share/ghidra}

# Analyze once
$VENV -m pyghidra.ghidra_launch --install-dir $GHIDRA \
    ghidra.app.util.headless.AnalyzeHeadless \
    /tmp/proj proj -import ./target.elf -overwrite

# Query the cached project — decompile main
$VENV -m pyghidra.ghidra_launch --install-dir $GHIDRA \
    ghidra.app.util.headless.AnalyzeHeadless \
    /tmp/proj proj -process target.elf -readOnly \
    -scriptPath ./scripts -postScript ghidra_query.py decompile main
```

Grab the `___PI_GHIDRA_RESULT_START___` … `___PI_GHIDRA_RESULT_END___` block
and parse the JSON between them. Operations:
`info · functions · decompile · decompile_all · disasm · xrefs_to · xrefs_from ·
strings · symbols · segments · data · search · calls · graph`.

---

## Security notes

- **Runs with your permissions.** Like all pi packages, this extension executes
  code (`python3`, the JVM via pyghidra, and whatever Ghidra does during
  analysis). Review the source before installing — there are only two files
  (`extensions/ghidra.ts`, `scripts/ghidra_query.py`).
- **Local-only.** Nothing leaves your machine. No network calls are made by the
  package itself; analysis runs entirely through the local Ghidra install.
- **The venv is isolated.** JPype/pyghidra are installed into
  `~/.pi/ghidra-venv`, not your system or user Python.
- **Analyzing untrusted binaries** still carries the usual RE risk (though
  Ghidra's analysis is generally safe). Use a sandbox/VM for genuinely
  malicious samples, as you would with any RE tool.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `⚠ Ghidra error: Ghidra installation not found` | Install Ghidra 12.x, or `export GHIDRA_INSTALL_DIR=/path/to/ghidra`. Verify with `/ghidra path`. |
| `PyGhidra venv setup failed` | Run `/ghidra venv` for a focused attempt. Ensure `python3` + `pip` work and your user can write `~/.pi/ghidra-venv`. The bundled wheel must exist at `<ghidra>/Ghidra/Features/PyGhidra/pypkg/dist/`. |
| Analysis hangs / times out | Large or obfuscated binaries can exceed the per-file cap. Re-run, or raise `DEFAULT_ANALYSIS_TIMEOUT` in `extensions/ghidra.ts`. |
| `Ghidra query "…" produced no result` | Usually means the postScript crashed before emitting. Check the stderr/stdout tail in the error message; common cause is a Jython-vs-PyGhidra mismatch (need Ghidra 12.x). |
| `Function not found` | The name may differ post-analysis. Run `ghidra_functions --filter <substring>` to discover the exact symbol, or pass an address. |
| JDK errors on launch | Ghidra needs JDK 21+. `apt install default-jdk` on Debian/Kali. |
| Want a fresh analysis | `/ghidra clean` deletes the cache, or delete `~/ghidra-work/<hash>/`. The next `ghidra_analyze` re-imports. |
| Stale results after editing a binary | The cache is keyed on file **mtime**; `touch`-ing or recompiling invalidates it automatically. |

---

## License

[MIT](LICENSE) — free to use, modify, and distribute. Attribution appreciated but not required.
