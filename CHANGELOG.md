# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-07-16

### Added
- Initial release as a standalone, distributable pi package.
- `extensions/ghidra.ts` — pi extension exposing ten tools
  (`ghidra_analyze`, `ghidra_decompile`, `ghidra_functions`, `ghidra_disasm`,
  `ghidra_xrefs`, `ghidra_strings`, `ghidra_info`, `ghidra_search`,
  `ghidra_data`, `ghidra_calls`), a `/ghidra` command (status / path / venv /
  clean / decompile), and a live status footer.
- Automatic Ghidra installation discovery (`GHIDRA_INSTALL_DIR` or standard
  paths) and PyGhidra venv bootstrap (`~/.pi/ghidra-venv`, installs the bundled
  `pyghidra` wheel on first use) — no manual JVM/Jython setup needed.
- Cached headless analysis: binaries are imported + auto-analyzed once into a
  project under `~/ghidra-work/` (keyed by a SHA-256 of the absolute path,
  validated by mtime); subsequent queries load the project with `-process`
  and are fast.
- `scripts/ghidra_query.py` — PyGhidra (CPython 3 + JPype) postScript that runs
  inside Ghidra's headless analyzer, supporting 14 operations
  (`info`, `functions`, `decompile`, `decompile_all`, `disasm`, `xrefs_to`,
  `xrefs_from`, `strings`, `symbols`, `segments`, `data`, `search`, `calls`,
  `graph`) and emitting JSON between dedicated markers for reliable extraction
  from Ghidra's verbose console output.
- Self-contained script resolution: `$GHIDRA_QUERY` → bundled
  `scripts/ghidra_query.py` → legacy `~/.pi/scripts/ghidra_query.py`.
- Config via `GHIDRA_INSTALL_DIR` and `GHIDRA_QUERY`.
- `package.json` pi manifest (`pi.extensions`), `tsconfig.json` for local
  type-checking, MIT license, README, and architecture docs.

[Unreleased]: https://github.com/not-narleeek/pi-ghidra/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/not-narleeek/pi-ghidra/releases/tag/v0.1.0
