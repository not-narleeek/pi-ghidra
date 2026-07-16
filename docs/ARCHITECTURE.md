# Architecture

A deeper dive into how `pi-ghidra` is structured, how the pieces communicate,
and where state lives. For usage, see the [README](../README.md).

## Design goals

- **No GUI needed.** Reverse-engineering from an AI agent should be fully
  scriptable. Nothing here requires opening the Ghidra GUI.
- **No manual JVM/Jython setup.** Ghidra 12.x dropped Jython in favour of
  PyGhidra (CPython 3 + JPype). This package bootstraps a dedicated venv and
  installs the bundled `pyghidra` wheel automatically.
- **Fast on repeat queries.** Analysis is expensive (10–60 s); querying a
  cached project is cheap. The extension caches aggressively and never
  re-analyzes an unchanged binary.
- **Thin TypeScript, rich Python.** The extension only orchestrates; all
  Ghidra-specific logic lives in the postScript so it can also be used
  standalone.
- **Self-contained & portable.** Ships its own script; resolves the bundled
  copy first, then a legacy global install.

## The three layers

```
┌──────────────────────────────────────────────────────────────────────┐
│                              pi (the agent)                           │
│                                                                       │
│   ┌────────────────────────────────────────────────────────────────┐ │
│   │  extensions/ghidra.ts   ←── this package (TypeScript)           │ │
│   │   • 10 tools: ghidra_analyze · ghidra_decompile · ghidra_*     │ │
│   │   • /ghidra command   • live status footer                      │ │
│   │   • Ghidra discovery · PyGhidra venv bootstrap · project cache  │ │
│   └───────────────────┬────────────────────────────────────────────┘ │
│                       │ spawnSync(venv-python,                        │
│                       │   ["-m","pyghidra.ghidra_launch", …])         │
│   ┌───────────────────▼────────────────────────────────────────────┐ │
│   │  scripts/ghidra_query.py  ←── this package (PyGhidra postScript) │ │
│   │   • 14 operations dispatched by name                            │ │
│   │   • emits JSON between ___PI_GHIDRA_RESULT_* markers            │ │
│   └───────────────────┬────────────────────────────────────────────┘ │
└───────────────────────┼────────────────────────────────────────────────┘
                        │  JVM + JPype bridge (launched by pyghidra)
┌───────────────────────▼────────────────────────────────────────────────┐
│            Ghidra headless analyzer (AnalyzeHeadless)                   │
│   -import (analyze)  ·  -process (query cached project, -readOnly)      │
│   decompiler · disassembler · memory · references · symbol table        │
└────────────────────────────────────────┬───────────────────────────────┘
                                         │
                       ┌─────────────────▼─────────────────┐
                       │   the binary under analysis        │
                       │   (ELF / PE / Mach-O / firmware)   │
                       └────────────────────────────────────┘
```

### Why the split?

- **`ghidra.ts`** is the *agent surface*: it defines the tools (names, schemas,
  prompt guidance, call/result rendering), the `/ghidra` command, and the
  footer. It also owns Ghidra installation discovery, the PyGhidra venv, and
  the analysis-project cache. It performs **no** decompilation logic itself —
  it shells out to the headless launcher and parses the JSON the postScript
  emits.
- **`ghidra_query.py`** is the *Ghidra surface*: it receives one operation plus
  arguments, talks to the live `currentProgram` via the Ghidra/PyGhidra API,
  and returns structured JSON. Being a single CPython file means it is trivial
  to audit and can also be run standalone (see below).
- **Ghidra** is the *engine*: it owns the actual analysis, decompilation, and
  memory model. Everything the agent reports is ground truth from Ghidra.

## State on disk

```
~/.pi/
├── scripts/
│   └── ghidra_query.py          # legacy global install (fallback only)
└── ghidra-venv/                 # PyGhidra venv (auto-created)
    └── bin/python3              #  → used to launch every headless command

~/ghidra-work/                   # analysis-project cache
├── index.json                   #   abs-path → {projectDir, mtime, ...}
└── <sha256[:16]>/               #   one project dir per binary
    ├── proj.rep/                #   Ghidra project files
    └── proj.gpr
```

> **Why `~/ghidra-work` and not `~/.pi/ghidra-work`?** Ghidra rejects project
> paths containing dotted directory names (it interprets the `.rep`/`.gpr`
> suffixes). The script and venv have no such restriction and live under
> `~/.pi`.

## Execution flow

### 1. Ghidra discovery (`findGhidraRoot`)

Checked in order, first hit wins:

1. `$GHIDRA_INSTALL_DIR`
2. `/usr/share/ghidra`, `/usr/local/share/ghidra`, `/opt/ghidra`
3. `which ghidra` → resolve symlink → parent dir

A directory is valid only if it contains `Ghidra/application.properties`.
The result is cached for the session.

### 2. PyGhidra venv bootstrap (`ensureVenv`)

On the first headless call (or `/ghidra venv`):

1. Create `~/.pi/ghidra-venv` via `python3 -m venv` if missing.
2. Probe `import pyghidra`. If it fails, locate the bundled wheel at
   `<ghidra-root>/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl` and
   `pip install` it.
3. Mark the venv ready for the rest of the session.

This isolates the JPype dependency from your system Python.

### 3. Analyze (`ensureAnalyzed` → `ghidra_analyze`)

1. Resolve the binary to an absolute path; bail if it doesn't exist.
2. Stat it for mtime. If the index has a matching entry **and** the mtime is
   unchanged **and** the project dir still exists → reuse it (instant).
3. Otherwise run:
   ```
   <venv-python> -m pyghidra.ghidra_launch --install-dir <root> \
       ghidra.app.util.headless.AnalyzeHeadless \
       <projectDir> proj -import <binary> -overwrite \
       -analysisTimeoutPerFile 600
   ```
4. On success, record `{binaryPath, projectDir, programName, mtime, analyzedAt}`
   in `index.json` and return the entry.

`ghidra_analyze` then immediately runs the `info` query so the first call
returns useful metadata (architecture, segments, entry points, function count).

### 4. Query (`queryBinary` → every other `ghidra_*` tool)

For a cached project:

```
<venv-python> -m pyghidra.ghidra_launch --install-dir <root> \
    ghidra.app.util.headless.AnalyzeHeadless \
    <projectDir> proj -process <programName> -readOnly \
    -scriptPath <script-dir> -postScript ghidra_query.py \
    <operation> [arg1] [arg2] ...
```

Key flags:

- `-process <programName>` loads the already-analyzed program instead of
  re-importing — this is what makes repeat queries fast.
- `-readOnly` prevents the query from writing back to the cached project.
- `-postScript` runs `ghidra_query.py` with the operation and its arguments
  passed as Ghidra script args (`getScriptArgs()`).

### 5. Result extraction (`extractJson`)

Ghidra's headless mode prints a lot of log noise. To stay robust across Ghidra
versions and log levels, the postScript wraps its JSON between two unique
markers:

```
___PI_GHIDRA_RESULT_START___
{"name":"main","decompiled":"..."}
___PI_GHIDRA_RESULT_END___
```

`extractJson` finds the first `START`, then parses up to the matching `END`.
If that parse fails it falls back to scanning every `START`-delimited segment
in reverse — this handles cases where a stray early emit is later overwritten.

## The postScript operation set

`scripts/ghidra_query.py` dispatches on its first argument via a `HANDLERS`
table. Each handler reads further positional args, calls into the
`currentProgram` API, and calls `emit({...})` once:

| Operation        | Args                          | Returns                                       |
|------------------|-------------------------------|-----------------------------------------------|
| `info`           | —                             | arch, endian, segments, entry points, counts  |
| `functions`      | `[filter] [limit]`            | name · address · size · ext/thunk flags        |
| `decompile`      | `<name\|addr>`                | C pseudocode for one function                  |
| `decompile_all`  | `[limit] [filter]`            | many decompiled functions                      |
| `disasm`         | `<addr\|name> [count]`        | instructions with bytes + operands             |
| `xrefs_to`       | `<addr\|name>`                | who references this address                    |
| `xrefs_from`     | `<addr\|name>`                | what this address references                   |
| `strings`        | `[filter] [limit]`            | defined string data                            |
| `symbols`        | `[filter] [limit]`            | symbol table                                   |
| `segments`       | —                             | memory blocks + permissions                    |
| `data`           | `<addr> <size>`               | hex + ASCII dump                               |
| `search`         | `<hex-pattern> [limit]`       | byte-pattern matches with block/function       |
| `calls`          | `<name\|addr>`                | functions called from target                   |
| `graph`          | `<name\|addr> [depth]`        | call-graph nodes + edges                       |

Addresses accept hex (`0x401000`), decimal, function names (exact then
case-insensitive), and labels from the symbol table.

## Standalone usage

`scripts/ghidra_query.py` is a normal Ghidra postScript — you can run it
without pi, directly through the PyGhidra launcher or the Ghidra GUI's
Script Manager. Example:

```bash
VENV=~/.pi/ghidra-venv/bin/python3
GHIDRA=/usr/share/ghidra

# Analyze (once)
$VENV -m pyghidra.ghidra_launch --install-dir $GHIDRA \
    ghidra.app.util.headless.AnalyzeHeadless \
    /tmp/proj proj -import ./target.elf -overwrite

# Query the cached project
$VENV -m pyghidra.ghidra_launch --install-dir $GHIDRA \
    ghidra.app.util.headless.AnalyzeHeadless \
    /tmp/proj proj -process target.elf -readOnly \
    -scriptPath ./scripts -postScript ghidra_query.py decompile main
```

Look for the `___PI_GHIDRA_RESULT_START___` … `___PI_GHIDRA_RESULT_END___`
block in the output and parse the JSON between them.

## Timeouts

| Phase   | Constant                  | Default     |
|---------|---------------------------|-------------|
| Analyze | `DEFAULT_ANALYSIS_TIMEOUT`| 700 s       |
| Query   | `DEFAULT_QUERY_TIMEOUT`   | 180 s       |

Per-file analysis is additionally capped at 600 s via
`-analysisTimeoutPerFile`. Very large or heavily obfuscated binaries may need
these raised; the constants live at the top of `extensions/ghidra.ts`.
