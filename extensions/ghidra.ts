/**
 * Ghidra extension for pi.
 *
 * Wraps Ghidra's headless analyzer (via PyGhidra — Ghidra 12.x dropped Jython)
 * so the agent can seamlessly decompile, disassemble, and query binaries during
 * CTF reverse-engineering challenges — no manual Ghidra GUI needed.
 *
 * The extension manages a PyGhidra venv (~/.pi/ghidra-venv) and Ghidra projects
 * automatically:
 *   1. ghidra_analyze imports & auto-analyzes the binary (cached in a project).
 *   2. Subsequent ghidra_* queries load the cached project with -process
 *      (fast — no re-analysis).
 *
 * Tools (for the LLM):
 *   ghidra_analyze      — import & auto-analyze a binary (first step)
 *   ghidra_decompile    — C pseudocode of a function (or all functions)
 *   ghidra_functions    — list / search functions
 *   ghidra_disasm       — disassemble at an address or function
 *   ghidra_xrefs        — cross-references to/from an address
 *   ghidra_strings      — defined strings
 *   ghidra_info         — binary metadata + segments + entry points
 *   ghidra_search       — byte-pattern search across memory
 *   ghidra_data         — dump raw memory as hex
 *   ghidra_calls        — functions called from a target function
 *
 * Command (for the user): /ghidra [status|clean|path|decompile <bin> <func>]
 *
 * Prerequisites: Ghidra installed (apt install ghidra on Kali).
 * The extension auto-creates a PyGhidra venv on first use.
 * Set GHIDRA_INSTALL_DIR if Ghidra is in a non-standard location.
 */

import { spawnSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	readFileSync,
	writeFileSync,
	statSync,
	rmSync,
	readdirSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, basename, resolve, dirname } from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { StringEnum } from "@earendil-works/pi-ai";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// NOTE: Ghidra rejects project paths with dotted directory names (e.g. .pi),
// so we use ~/ghidra-work instead of ~/.pi/ghidra-work for the project cache.
// The script and venv can live under .pi (no Ghidra path restriction there).
//
// The query script is shipped in this package at scripts/ghidra_query.py.
// It is resolved in this order so the package is self-contained while staying
// backwards-compatible with a legacy global install:
//   1. $GHIDRA_QUERY               — explicit override (handy for dev / debugging)
//   2. <package>/scripts/ghidra_query.py — bundled script (default for pi packages)
//   3. ~/.pi/scripts/ghidra_query.py    — legacy global install
const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const BUNDLED_SCRIPT = join(PKG_ROOT, "scripts", "ghidra_query.py");
const LEGACY_SCRIPT = join(homedir(), ".pi", "scripts", "ghidra_query.py");
const WORK_DIR = join(homedir(), "ghidra-work");
const INDEX_FILE = join(WORK_DIR, "index.json");

function resolveScript(): string {
	if (process.env.GHIDRA_QUERY) return process.env.GHIDRA_QUERY;
	if (existsSync(BUNDLED_SCRIPT)) return BUNDLED_SCRIPT;
	if (existsSync(LEGACY_SCRIPT)) return LEGACY_SCRIPT;
	// Fall through to the bundled path; the spawn error will be informative.
	return BUNDLED_SCRIPT;
}

// Ghidra 12.x requires PyGhidra (CPython 3 + JPype) for Python postScripts.
// We maintain a dedicated venv so the system Python is untouched.
const VENV_DIR = join(homedir(), ".pi", "ghidra-venv");
const VENV_PYTHON = join(VENV_DIR, "bin", "python3");

const RESULT_START = "___PI_GHIDRA_RESULT_START___";
const RESULT_END = "___PI_GHIDRA_RESULT_END___";

const MAX_OUTPUT = 60_000;
const DEFAULT_ANALYSIS_TIMEOUT = 700_000;
const DEFAULT_QUERY_TIMEOUT = 180_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ProjectEntry {
	binaryPath: string;
	projectDir: string;
	programName: string;
	binaryMtime: number;
	analyzedAt: number;
}

type Index = Record<string, ProjectEntry>;

// ---------------------------------------------------------------------------
// Ghidra installation + PyGhidra venv management
// ---------------------------------------------------------------------------

let _ghidraRoot: string | null = null;
let _venvReady = false;

function findGhidraRoot(): string {
	if (_ghidraRoot) return _ghidraRoot;

	const candidates: (string | null)[] = [
		process.env.GHIDRA_INSTALL_DIR || null,
		"/usr/share/ghidra",
		"/usr/local/share/ghidra",
		"/opt/ghidra",
	];

	for (const p of candidates) {
		if (p && existsSync(join(p, "Ghidra", "application.properties"))) {
			_ghidraRoot = p;
			return p;
		}
	}

	const which = spawnSync("which", ["ghidra"], { encoding: "utf8" });
	if (which.status === 0 && which.stdout.trim()) {
		const resolved = spawnSync("readlink", ["-f", which.stdout.trim()], { encoding: "utf8" });
		const target = resolved.stdout.trim() || which.stdout.trim();
		const root = resolve(dirname(target), "..");
		if (existsSync(join(root, "Ghidra", "application.properties"))) {
			_ghidraRoot = root;
			return root;
		}
	}

	throw new Error(
		"Ghidra installation not found. Set GHIDRA_INSTALL_DIR or install Ghidra (apt install ghidra on Kali).",
	);
}

/** Find the pyghidra wheel bundled with the Ghidra install. */
function findPyghidraWheel(root: string): string | null {
	const distDir = join(root, "Ghidra", "Features", "PyGhidra", "pypkg", "dist");
	if (!existsSync(distDir)) return null;
	try {
		for (const f of readdirSync(distDir)) {
			if (f.endsWith(".whl") && f.includes("pyghidra")) {
				return join(distDir, f);
			}
		}
	} catch {
		// ignore
	}
	return null;
}

/** Ensure the PyGhidra venv exists and pyghidra is installed. */
function ensureVenv(): boolean {
	if (_venvReady) return true;

	try {
		findGhidraRoot(); // throws if not found

		if (!existsSync(VENV_PYTHON)) {
			mkdirSync(VENV_DIR, { recursive: true });
			const create = spawnSync("python3", ["-m", "venv", VENV_DIR], {
				encoding: "utf8",
				timeout: 60_000,
			});
			if (create.status !== 0 || !existsSync(VENV_PYTHON)) {
				return false;
			}
		}

		const check = spawnSync(VENV_PYTHON, ["-c", "import pyghidra"], { encoding: "utf8" });
		if (check.status !== 0) {
			const wheel = findPyghidraWheel(findGhidraRoot());
			if (!wheel) return false;
			const install = spawnSync(VENV_PYTHON, ["-m", "pip", "install", wheel], {
				encoding: "utf8",
				timeout: 120_000,
			});
			if (install.status !== 0) return false;
		}

		_venvReady = true;
		return true;
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------
// Project index management
// ---------------------------------------------------------------------------

function readIndex(): Index {
	try {
		return JSON.parse(readFileSync(INDEX_FILE, "utf8"));
	} catch {
		return {};
	}
}

function writeIndex(index: Index): void {
	mkdirSync(WORK_DIR, { recursive: true });
	writeFileSync(INDEX_FILE, JSON.stringify(index, null, 2));
}

function getProjectDir(binaryPath: string): string {
	const abs = resolve(binaryPath);
	const hash = createHash("sha256").update(abs).digest("hex").slice(0, 16);
	return join(WORK_DIR, hash);
}

// ---------------------------------------------------------------------------
// Headless execution
// ---------------------------------------------------------------------------

interface ExecResult {
	stdout: string;
	stderr: string;
	code: number;
}

/**
 * Run a Ghidra headless command through the PyGhidra launcher.
 *
 * The launcher starts the JVM with the JPype bridge, enabling Python
 * postScripts. The actual arguments are the same as analyzeHeadless.
 */
function runHeadless(args: string[], timeout: number): ExecResult {
	if (!ensureVenv()) {
		return {
			stdout: "",
			stderr:
				"PyGhidra venv setup failed. Run: python3 -m venv ~/.pi/ghidra-venv && ~/.pi/ghidra-venv/bin/pip install <ghidra>/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl",
			code: -1,
		};
	}
	const root = findGhidraRoot();
	const launcherArgs = [
		"-m",
		"pyghidra.ghidra_launch",
		"--install-dir",
		root,
		"ghidra.app.util.headless.AnalyzeHeadless",
		...args,
	];
	const r = spawnSync(VENV_PYTHON, launcherArgs, {
		encoding: "utf8",
		timeout,
		maxBuffer: 128 * 1024 * 1024,
		env: { ...process.env },
	});
	return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", code: r.status ?? -1 };
}

function extractJson(stdout: string): any | null {
	const startIdx = stdout.indexOf(RESULT_START);
	if (startIdx === -1) return null;

	const jsonStart = startIdx + RESULT_START.length;
	const endIdx = stdout.indexOf(RESULT_END, jsonStart);
	const endPos = endIdx === -1 ? undefined : endIdx;
	const jsonStr = stdout.slice(jsonStart, endPos).trim();

	if (!jsonStr) return null;

	try {
		return JSON.parse(jsonStr);
	} catch {
		const allMatches = stdout.split(RESULT_START);
		for (let i = allMatches.length - 1; i >= 0; i--) {
			const seg = allMatches[i];
			const end = seg.indexOf(RESULT_END);
			const candidate = (end === -1 ? seg : seg.slice(0, end)).trim();
			if (candidate) {
				try {
					return JSON.parse(candidate);
				} catch {
					continue;
				}
			}
		}
		return null;
	}
}

// ---------------------------------------------------------------------------
// Analyze & query
// ---------------------------------------------------------------------------

function ensureAnalyzed(binaryPath: string, timeout: number = DEFAULT_ANALYSIS_TIMEOUT): ProjectEntry {
	const abs = resolve(binaryPath);
	if (!existsSync(abs)) throw new Error(`Binary not found: ${abs}`);

	const stat = statSync(abs);
	const index = readIndex();
	const existing = index[abs];

	if (existing && existing.binaryMtime === stat.mtimeMs && existsSync(existing.projectDir)) {
		return existing;
	}

	const projectDir = getProjectDir(abs);
	mkdirSync(projectDir, { recursive: true });

	const importResult = runHeadless(
		[projectDir, "proj", "-import", abs, "-overwrite", "-analysisTimeoutPerFile", "600"],
		timeout,
	);

	// Ghidra logs errors to stdout via its logger (not stderr). Check both.
	if (importResult.code !== 0) {
		const combined = (importResult.stdout + importResult.stderr).toLowerCase();
		// Extract the most relevant error line for the message
		const errorLines = (importResult.stdout + importResult.stderr)
			.split("\n")
			.filter((l) => /^error/i.test(l.trim()) || /exception/i.test(l))
			.slice(0, 5)
			.join("\n");
		const detail = errorLines || importResult.stdout.slice(-1500);
		throw new Error(
			`Ghidra analysis failed (exit ${importResult.code}).\n${detail}`,
		);
	}

	const entry: ProjectEntry = {
		binaryPath: abs,
		projectDir,
		programName: basename(abs),
		binaryMtime: stat.mtimeMs,
		analyzedAt: Date.now(),
	};

	index[abs] = entry;
	writeIndex(index);
	return entry;
}

function queryBinary(
	entry: ProjectEntry,
	operation: string,
	args: string[] = [],
	timeout: number = DEFAULT_QUERY_TIMEOUT,
): any {
	const script = resolveScript();
	const result = runHeadless(
		[
			entry.projectDir,
			"proj",
			"-process",
			entry.programName,
			"-readOnly",
			"-scriptPath",
			dirname(script),
			"-postScript",
			script,
			operation,
			...args,
		],
		timeout,
	);

	const json = extractJson(result.stdout);
	if (json === null) {
		const stderr = result.stderr.slice(0, 2000);
		const stdoutTail = result.stdout.slice(-2000);
		throw new Error(
			`Ghidra query "${operation}" produced no result. Exit ${result.code}.\n--- stderr ---\n${stderr}\n--- stdout tail ---\n${stdoutTail}`,
		);
	}

	return json;
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

function truncate(text: string, max: number = MAX_OUTPUT): string {
	if (text.length <= max) return text;
	return text.slice(0, max) + `\n\n[... truncated, ${text.length} total chars ...]`;
}

function formatInfo(data: any): string {
	const lines: string[] = [];
	lines.push(`=== Binary Info ===`);
	lines.push(`Name:        ${data.name}`);
	lines.push(`Path:        ${data.executable_path}`);
	lines.push(`Processor:   ${data.processor}`);
	lines.push(`Language:    ${data.language_id}`);
	lines.push(`Endian:      ${data.endian}`);
	lines.push(`Addr size:   ${data.address_size} bits`);
	lines.push(`Compiler:    ${data.compiler}`);
	lines.push(`Image base:  ${data.image_base}`);
	lines.push(`Functions:   ${data.function_count}`);
	if (data.entry_points && data.entry_points.length > 0) {
		lines.push(`Entry pts:   ${data.entry_points.join(", ")}`);
	}
	lines.push("");
	lines.push(`=== Segments (${data.segment_count}) ===`);
	for (const seg of data.segments || []) {
		const perms = (seg.read ? "r" : "-") + (seg.write ? "w" : "-") + (seg.execute ? "x" : "-");
		lines.push(
			`  ${seg.start}-${seg.end}  ${String(seg.size).padStart(10)}  ${perms}  ${seg.name}`,
		);
	}
	return lines.join("\n");
}

function formatFunctions(data: any): string {
	const lines: string[] = [];
	lines.push(
		`Functions (${data.count}${data.filtered ? " filtered" : ""} / ${data.total_functions} total)`,
	);
	lines.push("");
	for (const f of data.functions || []) {
		const ext = f.is_external ? " [ext]" : "";
		const thunk = f.is_thunk ? " [thunk]" : "";
		lines.push(`  ${f.address}  ${f.name}${ext}${thunk}  (${f.size} bytes)`);
	}
	if (data.total_functions > data.count) {
		lines.push("");
		lines.push(`Showing ${data.count} of ${data.total_functions}. Use filter to narrow down.`);
	}
	return lines.join("\n");
}

function formatDecompiled(data: any): string {
	if (data.functions) {
		const lines: string[] = [];
		lines.push(`Decompiled ${data.decompiled_count} of ${data.total_non_external} functions.`);
		lines.push("");
		for (const f of data.functions) {
			lines.push(`// ===== ${f.name} @ ${f.address} =====`);
			lines.push(f.decompiled);
			lines.push("");
		}
		return lines.join("\n");
	}
	return data.decompiled || "(no output)";
}

function formatDisasm(data: any): string {
	if (data.instructions) {
		const lines: string[] = [];
		for (const inst of data.instructions) {
			lines.push(
				`  ${inst.address}  ${String(inst.bytes).padEnd(20)} ${String(inst.mnemonic).padEnd(8)} ${inst.operands}`,
			);
		}
		return lines.join("\n");
	}
	if (data.type === "data") {
		return `  ${data.address}  data (${data.data_type})\n  value: ${data.value || "(none)"}\n  bytes: ${data.bytes}`;
	}
	return JSON.stringify(data, null, 2);
}

function formatXrefs(data: any): string {
	const refs = data.references || [];
	if (refs.length === 0) {
		return `No cross-references to ${data.address || "?"}.`;
	}
	const lines: string[] = [];
	lines.push(`Cross-references (${refs.length}):`);
	lines.push("");
	for (const ref of refs) {
		const fn = ref.from_function ? ` <${ref.from_function}>` : "";
		lines.push(`  ${ref.from || "?"}${fn}  --[${ref.type}]-->  ${data.address}`);
	}
	return lines.join("\n");
}

function formatStrings(data: any): string {
	const strs = data.strings || [];
	if (strs.length === 0) return "No defined strings found.";
	const lines: string[] = [];
	lines.push(`Strings (${data.count}):`);
	lines.push("");
	for (const s of strs) {
		const val = s.value.length > 120 ? s.value.slice(0, 120) + "..." : s.value;
		lines.push(`  ${s.address}  "${val}"`);
	}
	return lines.join("\n");
}

function formatSymbols(data: any): string {
	const syms = data.symbols || [];
	if (syms.length === 0) return "No symbols found.";
	const lines: string[] = [];
	lines.push(`Symbols (${data.count}):`);
	lines.push("");
	for (const s of syms) {
		lines.push(`  ${s.address}  ${String(s.type).padEnd(12)} ${s.name}`);
	}
	return lines.join("\n");
}

function formatSearch(data: any): string {
	const matches = data.matches || [];
	if (matches.length === 0) return `No matches for pattern: ${data.pattern}`;
	const lines: string[] = [];
	lines.push(`Pattern "${data.pattern}" — ${data.count} match(es):`);
	lines.push("");
	for (const m of matches) {
		const fn = m.function ? ` <${m.function}>` : "";
		lines.push(`  ${m.address}  [${m.block}]${fn}`);
	}
	return lines.join("\n");
}

function formatData(data: any): string {
	const hex = data.hex || "";
	const lines: string[] = [];
	lines.push(`Memory at ${data.address} (${data.size} bytes):`);
	lines.push("");
	for (let i = 0; i < hex.length; i += 32) {
		const chunk = hex.slice(i, i + 32);
		const offset = (i / 2).toString(16).padStart(8, "0");
		const hexParts: string[] = [];
		for (let j = 0; j < chunk.length; j += 2) {
			hexParts.push(chunk.slice(j, j + 2));
		}
		const ascii = (data.ascii || "").slice(i / 2, i / 2 + 16);
		lines.push(`  ${offset}  ${hexParts.join(" ").padEnd(48)}  |${ascii}|`);
	}
	return lines.join("\n");
}

function formatCalls(data: any): string {
	const calls = data.calls || [];
	if (calls.length === 0) return `${data.function} makes no calls.`;
	const lines: string[] = [];
	lines.push(`${data.function} @ ${data.address} calls ${calls.length} function(s):`);
	lines.push("");
	for (const c of calls) {
		lines.push(`  ${c.from}  ->  ${c.to}  ${c.name || "(unknown)"}`);
	}
	return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

function toolError(e: unknown) {
	const msg = e instanceof Error ? e.message : String(e);
	return {
		content: [{ type: "text" as const, text: `⚠ Ghidra error: ${msg}` }],
		details: { error: msg },
		isError: true,
	};
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

export default function ghidraExtension(pi: ExtensionAPI) {
	function checkGhidra(): boolean {
		try {
			findGhidraRoot();
			return true;
		} catch {
			return false;
		}
	}

	// =========================================================================
	// Tools
	// =========================================================================

	pi.registerTool({
		name: "ghidra_analyze",
		label: "Ghidra Analyze",
		description:
			"Import and auto-analyze a binary with Ghidra's headless analyzer. Must be called once before any other ghidra_* tool on the same binary — subsequent calls are cached and instant if the binary hasn't changed. Returns binary metadata (architecture, entry points, segments, function count). This is the first step for reverse-engineering a binary with Ghidra.",
		promptSnippet: "Import & auto-analyze a binary with Ghidra (first step for RE)",
		promptGuidelines: [
			"Use ghidra_analyze as the FIRST step when reverse-engineering any binary — it imports and auto-analyzes it with Ghidra and caches the project.",
			"After ghidra_analyze, use ghidra_decompile for C pseudocode, ghidra_functions to list/search functions, ghidra_disasm for disassembly, ghidra_xrefs for cross-references, ghidra_strings for defined strings, ghidra_info for metadata, and ghidra_search for byte patterns.",
			"Ghidra analysis is cached — the first ghidra_analyze call on a binary takes 10-60s; repeated calls on the same (unchanged) binary return instantly.",
		],
		parameters: Type.Object({
			binary: Type.String({ description: "Path to the binary file (ELF, PE, Mach-O, etc.)" }),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx) {
			if (!checkGhidra()) {
				return toolError(new Error("Ghidra installation not found."));
			}
			try {
				const entry = ensureAnalyzed(params.binary);
				const info = queryBinary(entry, "info", [], DEFAULT_QUERY_TIMEOUT);
				if (info.error) throw new Error(info.error);
				const text = formatInfo(info);
				return {
					content: [{ type: "text" as const, text: truncate(text) }],
					details: { ...info, project_dir: entry.projectDir, binary: entry.binaryPath },
				};
			} catch (e) {
				return toolError(e);
			}
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ghidra_analyze ")) + theme.fg("dim", String(args.binary ?? "")), 0, 0);
		},
		renderResult(result, _opts, theme) {
			const d = (result.details || {}) as any;
			if (d.error) return new Text(theme.fg("error", "✖ " + d.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("accent", d.processor || "?") + theme.fg("dim", " · " + (d.function_count ?? "?") + " funcs"), 0, 0);
		},
	});

	pi.registerTool({
		name: "ghidra_decompile",
		label: "Ghidra Decompile",
		description:
			"Decompile a function (or multiple functions) to C pseudocode using Ghidra's decompiler. Pass a function name or address for a single function, or omit target to decompile all functions (up to limit). This is the most powerful Ghidra tool for understanding binary logic.",
		promptSnippet: "Decompile binary functions to C pseudocode with Ghidra",
		parameters: Type.Object({
			binary: Type.String({ description: "Path to the (previously analyzed) binary" }),
			target: Type.Optional(Type.String({
				description: "Function name or hex address to decompile. Omit to decompile all functions.",
			})),
			limit: Type.Optional(Type.Number({
				description: "Max functions when decompiling all (default 50). Ignored when target is specified.",
			})),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx) {
			try {
				const entry = ensureAnalyzed(params.binary);
				let result: any;
				if (params.target) {
					result = queryBinary(entry, "decompile", [params.target]);
				} else {
					result = queryBinary(entry, "decompile_all", [String(params.limit ?? 50)]);
				}
				if (result.error) throw new Error(result.error);
				if (result.suggestions) {
					const lines = [`Function "${params.target}" not found. Did you mean:`];
					for (const s of result.suggestions) {
						lines.push(`  ${s.address}  ${s.name}`);
					}
					return { content: [{ type: "text" as const, text: lines.join("\n") }], details: result };
				}
				const text = formatDecompiled(result);
				return {
					content: [{ type: "text" as const, text: truncate(text) }],
					details: result,
				};
			} catch (e) {
				return toolError(e);
			}
		},
		renderCall(args, theme) {
			const target = args.target || "(all)";
			return new Text(theme.fg("toolTitle", theme.bold("ghidra_decompile ")) + theme.fg("accent", target) + theme.fg("dim", " " + (basename(String(args.binary ?? "")) || "")), 0, 0);
		},
		renderResult(result, _opts, theme) {
			const d = (result.details || {}) as any;
			if (d.error) return new Text(theme.fg("error", "✖ " + d.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("dim", d.name || `${d.decompiled_count ?? "?"} funcs`), 0, 0);
		},
	});

	pi.registerTool({
		name: "ghidra_functions",
		label: "Ghidra Functions",
		description:
			"List all functions in the binary with their addresses and sizes, or filter by name substring. Use this to find functions like main, check_flag, encrypt, etc.",
		promptSnippet: "List or search functions in a Ghidra-analyzed binary",
		parameters: Type.Object({
			binary: Type.String({ description: "Path to the analyzed binary" }),
			filter: Type.Optional(Type.String({
				description: "Case-insensitive name filter substring (e.g. 'main', 'check', 'flag')",
			})),
			limit: Type.Optional(Type.Number({ description: "Max results (default 500)" })),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx) {
			try {
				const entry = ensureAnalyzed(params.binary);
				const opArgs: string[] = [];
				if (params.filter) opArgs.push(params.filter);
				else opArgs.push("*");
				if (params.limit) opArgs.push(String(params.limit));
				const result = queryBinary(entry, "functions", opArgs);
				if (result.error) throw new Error(result.error);
				const text = formatFunctions(result);
				return {
					content: [{ type: "text" as const, text: truncate(text) }],
					details: result,
				};
			} catch (e) {
				return toolError(e);
			}
		},
		renderCall(args, theme) {
			const f = args.filter ? theme.fg("accent", args.filter) : theme.fg("dim", "(all)");
			return new Text(theme.fg("toolTitle", theme.bold("ghidra_functions ")) + f, 0, 0);
		},
		renderResult(result, _opts, theme) {
			const d = (result.details || {}) as any;
			if (d.error) return new Text(theme.fg("error", "✖ " + d.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("dim", `${d.count}/${d.total_functions} funcs`), 0, 0);
		},
	});

	pi.registerTool({
		name: "ghidra_disasm",
		label: "Ghidra Disassemble",
		description:
			"Disassemble instructions at a function or hex address. Shows raw assembly with bytes. Use this when you need exact instruction details that the decompiler abstracts away.",
		promptSnippet: "Disassemble at an address or function with Ghidra",
		parameters: Type.Object({
			binary: Type.String({ description: "Path to the analyzed binary" }),
			target: Type.String({
				description: "Function name or hex address to start disassembly at (e.g. 'main' or '0x401000')",
			}),
			count: Type.Optional(Type.Number({ description: "Number of instructions (default 50, max 500)" })),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx) {
			try {
				const entry = ensureAnalyzed(params.binary);
				const opArgs = [params.target];
				if (params.count) opArgs.push(String(params.count));
				const result = queryBinary(entry, "disasm", opArgs);
				if (result.error) throw new Error(result.error);
				const text = formatDisasm(result);
				return {
					content: [{ type: "text" as const, text: truncate(text) }],
					details: result,
				};
			} catch (e) {
				return toolError(e);
			}
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ghidra_disasm ")) + theme.fg("accent", String(args.target ?? "")), 0, 0);
		},
		renderResult(result, _opts, theme) {
			const d = (result.details || {}) as any;
			if (d.error) return new Text(theme.fg("error", "✖ " + d.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("dim", `${d.count ?? "?"} instructions`), 0, 0);
		},
	});

	pi.registerTool({
		name: "ghidra_xrefs",
		label: "Ghidra Xrefs",
		description:
			"Find cross-references (xrefs) to or from an address or function. 'to' shows who calls/references this; 'from' shows what this references. Essential for understanding data flow and control flow.",
		promptSnippet: "Cross-references to/from an address in Ghidra",
		parameters: Type.Object({
			binary: Type.String({ description: "Path to the analyzed binary" }),
			target: Type.String({
				description: "Function name or hex address (e.g. 'main', '0x401000', or 'printf')",
			}),
			direction: StringEnum(["to", "from"] as const, {
				description: "'to' = who references this address; 'from' = what this address references (default 'to')",
			}),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx) {
			try {
				const entry = ensureAnalyzed(params.binary);
				const direction = params.direction || "to";
				const op = direction === "from" ? "xrefs_from" : "xrefs_to";
				const result = queryBinary(entry, op, [params.target]);
				if (result.error) throw new Error(result.error);
				const text = formatXrefs(result);
				return {
					content: [{ type: "text" as const, text: truncate(text) }],
					details: result,
				};
			} catch (e) {
				return toolError(e);
			}
		},
		renderCall(args, theme) {
			const dir = args.direction || "to";
			return new Text(theme.fg("toolTitle", theme.bold("ghidra_xrefs ")) + theme.fg("dim", dir + " ") + theme.fg("accent", String(args.target ?? "")), 0, 0);
		},
		renderResult(result, _opts, theme) {
			const d = (result.details || {}) as any;
			if (d.error) return new Text(theme.fg("error", "✖ " + d.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("dim", `${d.count ?? 0} refs`), 0, 0);
		},
	});

	pi.registerTool({
		name: "ghidra_strings",
		label: "Ghidra Strings",
		description:
			"List defined strings found by Ghidra's analysis, optionally filtered by substring. Useful for finding flag strings, error messages, format strings, and other text data embedded in the binary.",
		promptSnippet: "Defined strings in a Ghidra-analyzed binary",
		parameters: Type.Object({
			binary: Type.String({ description: "Path to the analyzed binary" }),
			filter: Type.Optional(Type.String({
				description: "Case-insensitive filter (e.g. 'flag', 'password', 'error')",
			})),
			limit: Type.Optional(Type.Number({ description: "Max results (default 500)" })),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx) {
			try {
				const entry = ensureAnalyzed(params.binary);
				const opArgs: string[] = [];
				if (params.filter) opArgs.push(params.filter);
				else opArgs.push("*");
				if (params.limit) opArgs.push(String(params.limit));
				const result = queryBinary(entry, "strings", opArgs);
				if (result.error) throw new Error(result.error);
				const text = formatStrings(result);
				return {
					content: [{ type: "text" as const, text: truncate(text) }],
					details: result,
				};
			} catch (e) {
				return toolError(e);
			}
		},
		renderCall(args, theme) {
			const f = args.filter ? theme.fg("accent", args.filter) : theme.fg("dim", "(all)");
			return new Text(theme.fg("toolTitle", theme.bold("ghidra_strings ")) + f, 0, 0);
		},
		renderResult(result, _opts, theme) {
			const d = (result.details || {}) as any;
			if (d.error) return new Text(theme.fg("error", "✖ " + d.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("dim", `${d.count ?? 0} strings`), 0, 0);
		},
	});

	pi.registerTool({
		name: "ghidra_info",
		label: "Ghidra Info",
		description:
			"Get binary metadata: architecture, endianness, address size, compiler spec, image base, entry points, and memory segments/blocks. Use this to understand the binary layout.",
		promptSnippet: "Binary metadata and segments from Ghidra",
		parameters: Type.Object({
			binary: Type.String({ description: "Path to the analyzed binary" }),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx) {
			try {
				const entry = ensureAnalyzed(params.binary);
				const result = queryBinary(entry, "info");
				if (result.error) throw new Error(result.error);
				const text = formatInfo(result);
				return {
					content: [{ type: "text" as const, text: truncate(text) }],
					details: result,
				};
			} catch (e) {
				return toolError(e);
			}
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ghidra_info ")) + theme.fg("dim", String(args.binary ?? "")), 0, 0);
		},
		renderResult(result, _opts, theme) {
			const d = (result.details || {}) as any;
			if (d.error) return new Text(theme.fg("error", "✖ " + d.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("accent", d.processor || "?") + theme.fg("dim", " · " + (d.endian ?? "?")), 0, 0);
		},
	});

	pi.registerTool({
		name: "ghidra_search",
		label: "Ghidra Search",
		description:
			"Search for a byte pattern across all initialized memory blocks. Returns addresses, containing blocks, and containing functions. Pattern can be hex with or without spaces (e.g. 'deadbeef', '48 8b c4').",
		promptSnippet: "Byte-pattern search across memory with Ghidra",
		parameters: Type.Object({
			binary: Type.String({ description: "Path to the analyzed binary" }),
			pattern: Type.String({
				description: "Hex byte pattern, with or without spaces (e.g. 'deadbeef', '48 8b c4', '666c6167')",
			}),
			limit: Type.Optional(Type.Number({ description: "Max matches (default 100)" })),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx) {
			try {
				const entry = ensureAnalyzed(params.binary);
				const opArgs = [params.pattern];
				if (params.limit) opArgs.push(String(params.limit));
				const result = queryBinary(entry, "search", opArgs);
				if (result.error) throw new Error(result.error);
				const text = formatSearch(result);
				return {
					content: [{ type: "text" as const, text: truncate(text) }],
					details: result,
				};
			} catch (e) {
				return toolError(e);
			}
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ghidra_search ")) + theme.fg("accent", String(args.pattern ?? "")), 0, 0);
		},
		renderResult(result, _opts, theme) {
			const d = (result.details || {}) as any;
			if (d.error) return new Text(theme.fg("error", "✖ " + d.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("dim", `${d.count ?? 0} matches`), 0, 0);
		},
	});

	pi.registerTool({
		name: "ghidra_data",
		label: "Ghidra Data Dump",
		description:
			"Dump raw memory at an address as a hex dump (hex + ASCII). Useful for inspecting data sections, stack strings, or custom structures.",
		promptSnippet: "Dump raw memory as hex from Ghidra",
		parameters: Type.Object({
			binary: Type.String({ description: "Path to the analyzed binary" }),
			address: Type.String({ description: "Hex address to read from (e.g. '0x401000')" }),
			size: Type.Optional(Type.Number({ description: "Bytes to read (default 256, max 8192)" })),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx) {
			try {
				const entry = ensureAnalyzed(params.binary);
				const result = queryBinary(entry, "data", [params.address, String(params.size ?? 256)]);
				if (result.error) throw new Error(result.error);
				const text = formatData(result);
				return {
					content: [{ type: "text" as const, text: truncate(text) }],
					details: result,
				};
			} catch (e) {
				return toolError(e);
			}
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ghidra_data ")) + theme.fg("accent", String(args.address ?? "")) + theme.fg("dim", " +" + (args.size ?? 256) + "B"), 0, 0);
		},
		renderResult(result, _opts, theme) {
			const d = (result.details || {}) as any;
			if (d.error) return new Text(theme.fg("error", "✖ " + d.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("dim", `${d.size ?? "?"} bytes`), 0, 0);
		},
	});

	pi.registerTool({
		name: "ghidra_calls",
		label: "Ghidra Call Graph",
		description:
			"List all functions called from a given function. Useful for understanding what a function does without reading its full decompilation.",
		promptSnippet: "Functions called from a target function",
		parameters: Type.Object({
			binary: Type.String({ description: "Path to the analyzed binary" }),
			target: Type.String({ description: "Function name or address (e.g. 'main')" }),
		}),
		async execute(_id, params, _signal, _onUpdate, _ctx) {
			try {
				const entry = ensureAnalyzed(params.binary);
				const result = queryBinary(entry, "calls", [params.target]);
				if (result.error) throw new Error(result.error);
				const calls = result.calls || [];
				const lines: string[] = [];
				lines.push(`${result.function} @ ${result.address} calls ${calls.length} function(s):`);
				lines.push("");
				for (const c of calls) {
					lines.push(`  ${c.from}  ->  ${c.to}  ${c.name || "(unknown)"}`);
				}
				return {
					content: [{ type: "text" as const, text: truncate(lines.join("\n")) }],
					details: result,
				};
			} catch (e) {
				return toolError(e);
			}
		},
		renderCall(args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("ghidra_calls ")) + theme.fg("accent", String(args.target ?? "")), 0, 0);
		},
		renderResult(result, _opts, theme) {
			const d = (result.details || {}) as any;
			if (d.error) return new Text(theme.fg("error", "✖ " + d.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("dim", `${d.count ?? 0} calls`), 0, 0);
		},
	});

	// =========================================================================
	// /ghidra command
	// =========================================================================

	pi.registerCommand("ghidra", {
		description: "Ghidra status, cache management, and quick queries",
		handler: async (args, ctx) => {
			const parts = (args || "").trim().split(/\s+/);
			const sub = parts[0] || "status";

			if (!checkGhidra()) {
				ctx.ui.notify("Ghidra not found. Install it (apt install ghidra) or set GHIDRA_INSTALL_DIR.", "error");
				return;
			}

			if (sub === "path" || sub === "root") {
				ctx.ui.notify(`Ghidra root: ${findGhidraRoot()}\nPyGhidra venv: ${VENV_DIR}`, "info");
				return;
			}

			if (sub === "venv") {
				ctx.ui.setStatus("ghidra", "🔬 setting up venv...");
				const ok = ensureVenv();
				ctx.ui.setStatus("ghidra", undefined);
				ctx.ui.notify(ok ? `PyGhidra venv ready at ${VENV_DIR}` : "PyGhidra venv setup failed", ok ? "info" : "error");
				return;
			}

			if (sub === "status") {
				const index = readIndex();
				const count = Object.keys(index).length;
				const venvOk = ensureVenv();
				const venvStatus = venvOk ? "ready" : "not set up";
				if (count === 0) {
					ctx.ui.notify(`Ghidra: ${findGhidraRoot()}\nPyGhidra: ${venvStatus}\nNo binaries analyzed yet.`, "info");
				} else {
					const lines: string[] = [];
					for (const [path, entry] of Object.entries(index)) {
						const age = Math.round((Date.now() - entry.analyzedAt) / 60000);
						lines.push(`  ${basename(path)} (${age}m ago)`);
					}
					ctx.ui.notify(`Ghidra: ${findGhidraRoot()}\nPyGhidra: ${venvStatus}\n${count} analyzed binary(ies):\n${lines.join("\n")}`, "info");
				}
				return;
			}

			if (sub === "clean") {
				try {
					rmSync(WORK_DIR, { recursive: true, force: true });
					ctx.ui.notify("Ghidra project cache cleared.", "info");
				} catch (e) {
					ctx.ui.notify(`Failed to clean: ${e}`, "error");
				}
				return;
			}

			if (sub === "decompile" || sub === "d") {
				const binary = parts[1];
				const func = parts[2] || "main";
				if (!binary) {
					ctx.ui.notify("Usage: /ghidra decompile <binary> [function]", "error");
					return;
				}
				ctx.ui.setStatus("ghidra", "🔬 analyzing...");
				try {
					const entry = ensureAnalyzed(binary);
					const result = queryBinary(entry, "decompile", [func]);
					if (result.error) {
						ctx.ui.notify(`Error: ${result.error}`, "error");
					} else {
						ctx.ui.notify(`Decompiled ${result.name || func}:\n\n${(result.decompiled || "").slice(0, 500)}`, "info");
					}
				} catch (e) {
					ctx.ui.notify(`Error: ${e}`, "error");
				}
				ctx.ui.setStatus("ghidra", undefined);
				return;
			}

			ctx.ui.notify(
				`Usage: /ghidra [status|path|venv|clean|decompile <binary> [function]]\n\n` +
				`  status       - show analyzed binaries\n` +
				`  path         - show Ghidra + venv paths\n` +
				`  venv         - set up / verify PyGhidra venv\n` +
				`  clean        - clear project cache\n` +
				`  decompile b f - decompile function f from binary b`,
				"info",
			);
		},
	});

	// =========================================================================
	// Footer status on session start
	// =========================================================================

	pi.on("session_start", async (_event, ctx) => {
		if (!ctx.hasUI) return;
		const th = ctx.ui.theme;
		if (!checkGhidra()) {
			ctx.ui.setStatus("ghidra", th.fg("dim", "🔬 ghidra (not found)"));
		} else {
			const index = readIndex();
			const count = Object.keys(index).length;
			if (count > 0) {
				ctx.ui.setStatus(
					"ghidra",
					th.fg("accent", "🔬 ") + th.fg("text", "ghidra") + th.fg("dim", ` · ${count} binary(ies)`),
				);
			} else {
				ctx.ui.setStatus("ghidra", th.fg("dim", "🔬 ghidra ready"));
			}
		}
	});
}
