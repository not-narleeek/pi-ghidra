#!/usr/bin/env jython
# -*- coding: utf-8 -*-
"""
Ghidra query script for the pi CTF extension.

Runs as a postScript inside Ghidra's headless analyzer (analyzeHeadless).
Outputs JSON between dedicated markers so the TypeScript extension can
extract it reliably from Ghidra's verbose console output.

Operations (passed as script args):
    info                                    Binary metadata, entry points, segments
    functions [filter] [limit]              List/search functions
    decompile <name_or_addr>                Decompile one function
    decompile_all [limit] [filter]          Decompile many functions
    disasm <addr_or_name> [count]           Disassemble instructions
    xrefs_to <addr_or_name>                 Who references this address
    xrefs_from <addr_or_name>               What this address references
    strings [filter] [limit]                Defined strings
    symbols [filter] [limit]                Symbol table
    segments                                Memory blocks
    data <addr> <size>                      Dump memory as hex
    search <hex_pattern> [limit]            Search for byte pattern (e.g. "deadbeef")
    calls <name_or_addr>                    Functions called from target
    graph <name_or_addr> [depth]            Call graph from a function

Runs in PyGhidra (CPython 3 + JPype) which Ghidra 12.x uses for Python scripts.
"""

# @category Pi.CTF

import json
import sys
import traceback

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

RESULT_START = "___PI_GHIDRA_RESULT_START___"
RESULT_END = "___PI_GHIDRA_RESULT_END___"


def emit(data):
    """Print JSON between markers for reliable parsing."""
    print(RESULT_START)
    print(json.dumps(data, default=str))
    print(RESULT_END)


def fail(msg):
    """Emit an error result and return."""
    emit({"error": msg, "traceback": traceback.format_exc()})


# ---------------------------------------------------------------------------
# Ghidra utility helpers
# ---------------------------------------------------------------------------

def get_args():
    """Retrieve script arguments from Ghidra."""
    try:
        return list(getScriptArgs())
    except Exception:
        return []


def parse_int(s):
    """Parse an integer from hex (0x...) or decimal string."""
    s = str(s).strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        return None


def try_parse_addr(s):
    """Attempt to parse *s* as a program address."""
    s = str(s).strip()
    af = currentProgram.getAddressFactory()

    # Hex / decimal numeric
    val = parse_int(s)
    if val is not None:
        try:
            return af.getDefaultAddressSpace().getAddress(val)
        except Exception:
            pass

    # Raw address string (e.g. "0x401000" or "ram:401000")
    try:
        addr = af.getAddress(s)
        if addr is not None:
            return addr
    except Exception:
        pass

    return None


def resolve_addr(s):
    """Resolve *s* to an address. Handles hex, decimal, function names, labels."""
    addr = try_parse_addr(s)
    if addr is not None:
        return addr

    # Function name
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        if func.getName() == s:
            return func.getEntryPoint()

    # Case-insensitive function name
    for func in fm.getFunctions(True):
        if func.getName().lower() == str(s).lower():
            return func.getEntryPoint()

    # Symbol / label
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getSymbols(s):
            return sym.getAddress()
    except Exception:
        pass

    return None


def get_function(s):
    """Find a function by name, address, or address-within-function."""
    fm = currentProgram.getFunctionManager()

    addr = try_parse_addr(s)
    if addr is not None:
        func = fm.getFunctionAt(addr)
        if func is not None:
            return func
        func = fm.getFunctionContaining(addr)
        if func is not None:
            return func

    # Exact name match
    for func in fm.getFunctions(True):
        if func.getName() == s:
            return func

    # Case-insensitive
    for func in fm.getFunctions(True):
        if func.getName().lower() == str(s).lower():
            return func

    # Symbol table
    st = currentProgram.getSymbolTable()
    try:
        for sym in st.getSymbols(s):
            if str(sym.getSymbolType()) == "Function":
                f = fm.getFunctionAt(sym.getAddress())
                if f is not None:
                    return f
    except Exception:
        pass

    return None


def find_func_matches(name_sub):
    """Return functions whose name contains *name_sub* (case-insensitive)."""
    name_sub = str(name_sub).lower()
    fm = currentProgram.getFunctionManager()
    matches = []
    for func in fm.getFunctions(True):
        if func.isExternal():
            continue
        if name_sub in func.getName().lower():
            matches.append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
            })
    return matches


def get_or_create_decompiler():
    """Create and open a DecompInterface on the current program."""
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    decomp = DecompInterface()
    opts = DecompileOptions()
    decomp.setOptions(opts)
    decomp.toggleCCode(True)
    decomp.toggleSyntaxTree(True)
    decomp.setSimplificationStyle("decompile")
    decomp.openProgram(currentProgram)
    return decomp


def decompile_single(decomp, func, timeout=120):
    """Decompile a single function. Returns C string or None."""
    try:
        result = decomp.decompileFunction(func, timeout, monitor)
        if result is not None and result.decompileCompleted():
            df = result.getDecompiledFunction()
            if df is not None:
                return df.getC()
    except Exception:
        pass
    return None


def bytes_to_hex(java_bytes):
    """Convert a Java byte array to a hex string."""
    try:
        return ''.join('%02x' % (b & 0xff) for b in java_bytes)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def op_info(args):
    prog = currentProgram
    lang = prog.getLanguage()
    cs = prog.getCompilerSpec()
    mem = prog.getMemory()
    fm = prog.getFunctionManager()

    # Endian / address size
    endian = "unknown"
    addr_size = 0
    try:
        lang_desc = lang.getLanguageDescription()
        endian = str(lang_desc.getEndian())
        addr_size = lang_desc.getSize()
    except Exception:
        pass

    # Function count
    func_count = 0
    for _f in fm.getFunctions(True):
        func_count += 1

    # Entry points
    entry_points = []
    try:
        for ep in prog.getSymbolTable().getExternalEntryPointIterator():
            entry_points.append(str(ep))
    except Exception:
        pass
    if not entry_points:
        try:
            # Fallback: look for _start / entry symbol
            for sym in prog.getSymbolTable().getSymbolIterator("_start"):
                entry_points.append(str(sym.getAddress()))
                break
        except Exception:
            pass

    # Segments
    segments = []
    for block in mem.getBlocks():
        segments.append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "read": block.isRead(),
            "write": block.isWrite(),
            "execute": block.isExecute(),
            "initialized": block.isInitialized(),
        })

    info = {
        "name": prog.getName(),
        "executable_path": str(prog.getExecutablePath()),
        "language_id": str(lang.getLanguageID()),
        "processor": str(lang.getProcessor()),
        "endian": endian,
        "address_size": addr_size,
        "compiler": str(cs.getCompilerSpecID()),
        "image_base": str(prog.getImageBase()),
        "entry_points": entry_points,
        "function_count": func_count,
        "segment_count": len(segments),
        "segments": segments,
    }
    emit(info)


def op_functions(args):
    filt = None
    limit = 500

    if len(args) >= 1 and args[0] != "*":
        filt = args[0].lower()
    if len(args) >= 2:
        parsed = parse_int(args[1])
        if parsed is not None:
            limit = parsed

    fm = currentProgram.getFunctionManager()
    result = []
    total = 0

    for func in fm.getFunctions(True):
        total += 1
        name = func.getName()
        if filt is not None and filt not in name.lower():
            continue
        result.append({
            "name": name,
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses(),
            "is_external": func.isExternal(),
            "is_thunk": func.isThunk(),
        })
        if len(result) >= limit:
            break

    emit({
        "functions": result,
        "count": len(result),
        "total_functions": total,
        "limit": limit,
        "filtered": filt is not None,
    })


def op_decompile(args):
    if not args:
        fail("decompile requires a function name or address")
        return

    target = args[0]
    func = get_function(target)

    if func is None:
        matches = find_func_matches(target)
        if matches:
            emit({
                "error": "Function not found exactly: " + target,
                "suggestions": matches[:20],
            })
        else:
            emit({"error": "Function not found: " + target})
        return

    if func.isExternal():
        emit({"error": "Function is external (imported, no body): " + func.getName()})
        return

    decomp = get_or_create_decompiler()
    code = decompile_single(decomp, func)
    decomp.dispose()

    if code is None:
        emit({"error": "Decompilation failed for: " + func.getName()})
        return

    emit({
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses(),
        "decompiled": code,
    })


def op_decompile_all(args):
    limit = 50
    filt = None

    if len(args) >= 1:
        parsed = parse_int(args[0])
        if parsed is not None:
            limit = parsed
        elif args[0] != "*":
            filt = args[0].lower()
    if len(args) >= 2:
        if args[1] != "*":
            filt = args[1].lower()

    decomp = get_or_create_decompiler()
    fm = currentProgram.getFunctionManager()

    result = []
    total = 0

    for func in fm.getFunctions(True):
        if func.isExternal():
            continue
        total += 1
        name = func.getName()
        if filt is not None and filt not in name.lower():
            continue
        code = decompile_single(decomp, func, timeout=60)
        if code is not None:
            result.append({
                "name": name,
                "address": str(func.getEntryPoint()),
                "decompiled": code,
            })
        if len(result) >= limit:
            break

    decomp.dispose()

    emit({
        "functions": result,
        "decompiled_count": len(result),
        "total_non_external": total,
        "limit": limit,
    })


def op_disasm(args):
    if not args:
        fail("disasm requires an address or function name")
        return

    target = args[0]
    count = 50
    if len(args) >= 2:
        parsed = parse_int(args[1])
        if parsed is not None:
            count = min(parsed, 500)

    # Resolve starting address
    addr = try_parse_addr(target)
    if addr is None:
        func = get_function(target)
        if func is not None:
            addr = func.getEntryPoint()
        else:
            emit({"error": "Cannot find address or function: " + target})
            return

    listing = currentProgram.getListing()
    inst = listing.getInstructionAt(addr)
    if inst is None:
        inst = listing.getInstructionContaining(addr)

    if inst is None:
        # Maybe it's data
        data = listing.getDataAt(addr)
        if data is not None:
            try:
                dlen = min(data.getLength(), 64)
                import jpype
                ba = jpype.JArray(jpype.JByte)([0] * dlen)
                data.getBytes(ba)
                emit({
                    "type": "data",
                    "address": str(addr),
                    "data_type": str(data.getDataType()),
                    "value": str(data.getValue()) if data.getValue() else None,
                    "bytes": bytes_to_hex(ba),
                })
            except Exception:
                emit({"type": "data", "address": str(addr), "value": str(data.getValue())})
            return
        emit({"error": "No instruction or data at: " + str(addr)})
        return

    result = []
    for _i in range(count):
        if inst is None:
            break
        try:
            ba = inst.getBytes()
            bhex = bytes_to_hex(ba)
        except Exception:
            bhex = ""
        rep = str(inst)
        parts = rep.split(" ", 1)
        mnemonic = parts[0]
        operands = parts[1] if len(parts) > 1 else ""

        result.append({
            "address": str(inst.getAddress()),
            "bytes": bhex,
            "mnemonic": inst.getMnemonicString(),
            "operands": operands,
            "representation": rep,
        })
        inst = inst.getNext()

    emit({"instructions": result, "count": len(result)})


def op_xrefs_to(args):
    if not args:
        fail("xrefs_to requires an address or function name")
        return

    addr = resolve_addr(args[0])
    if addr is None:
        emit({"error": "Cannot resolve: " + args[0]})
        return

    rm = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()
    refs = rm.getReferencesTo(addr)

    result = []
    for ref in refs:
        from_addr = ref.getFromAddress()
        func = None
        if from_addr is not None:
            func = fm.getFunctionContaining(from_addr)
        try:
            op_idx = ref.getOperandIndex()
        except Exception:
            op_idx = -1
        result.append({
            "from": str(from_addr) if from_addr else None,
            "from_function": func.getName() if func else None,
            "type": str(ref.getReferenceType()),
            "operand_index": op_idx,
        })

    emit({
        "address": str(addr),
        "references": result,
        "count": len(result),
    })


def op_xrefs_from(args):
    if not args:
        fail("xrefs_from requires an address or function name")
        return

    addr = resolve_addr(args[0])
    if addr is None:
        emit({"error": "Cannot resolve: " + args[0]})
        return

    rm = currentProgram.getReferenceManager()
    refs = rm.getReferencesFrom(addr)

    result = []
    for ref in refs:
        to_addr = ref.getToAddress()
        result.append({
            "to": str(to_addr) if to_addr else None,
            "type": str(ref.getReferenceType()),
        })

    emit({
        "address": str(addr),
        "references": result,
        "count": len(result),
    })


def op_strings(args):
    filt = None
    limit = 500

    if len(args) >= 1 and args[0] != "*":
        filt = args[0].lower()
    if len(args) >= 2:
        parsed = parse_int(args[1])
        if parsed is not None:
            limit = parsed

    result = []
    listing = currentProgram.getListing()
    for data in listing.getDefinedData(True):
        dt = data.getDataType()
        if dt is None:
            continue
        # Check if it's a string data type (works across Ghidra versions)
        cls_name = dt.getClass().getName()
        if "String" not in cls_name:
            continue
        val = data.getValue()
        if val is None:
            continue
        val_str = str(val)
        if filt is not None and filt not in val_str.lower():
            continue
        result.append({
            "address": str(data.getAddress()),
            "value": val_str,
            "length": len(val_str),
        })
        if len(result) >= limit:
            break

    emit({"strings": result, "count": len(result), "limit": limit})


def op_symbols(args):
    filt = None
    limit = 500

    if len(args) >= 1 and args[0] != "*":
        filt = args[0].lower()
    if len(args) >= 2:
        parsed = parse_int(args[1])
        if parsed is not None:
            limit = parsed

    st = currentProgram.getSymbolTable()
    result = []
    count = 0

    for sym in st.getAllSymbols(True):
        name = sym.getName()
        if filt is not None and filt not in name.lower():
            continue
        result.append({
            "name": name,
            "address": str(sym.getAddress()),
            "type": str(sym.getSymbolType()),
            "source": str(sym.getSource()),
        })
        count += 1
        if count >= limit:
            break

    emit({"symbols": result, "count": count, "limit": limit})


def op_segments(args):
    mem = currentProgram.getMemory()
    result = []
    for block in mem.getBlocks():
        result.append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "read": block.isRead(),
            "write": block.isWrite(),
            "execute": block.isExecute(),
            "initialized": block.isInitialized(),
        })
    emit({"segments": result, "count": len(result)})


def op_data(args):
    if len(args) < 2:
        fail("data requires <address> <size>")
        return

    addr = resolve_addr(args[0])
    if addr is None:
        emit({"error": "Cannot resolve address: " + args[0]})
        return

    size = parse_int(args[1])
    if size is None or size <= 0:
        emit({"error": "Invalid size: " + args[1]})
        return

    size = min(size, 8192)

    import jpype
    ba = jpype.JArray(jpype.JByte)([0] * size)

    try:
        currentProgram.getMemory().getBytes(addr, ba)
    except Exception as e:
        emit({"error": "Failed to read memory: " + str(e)})
        return

    hex_str = bytes_to_hex(ba)

    # Also build an ASCII preview
    ascii_str = ""
    for b in ba:
        c = b & 0xff
        if 32 <= c <= 126:
            ascii_str += chr(c)
        else:
            ascii_str += "."

    emit({
        "address": str(addr),
        "size": size,
        "hex": hex_str,
        "ascii": ascii_str,
    })


def op_search(args):
    if not args:
        fail("search requires a hex pattern (e.g. 'deadbeef' or '48 8b')")
        return

    pattern = args[0]
    limit = 100
    if len(args) >= 2:
        parsed = parse_int(args[1])
        if parsed is not None:
            limit = parsed

    # Parse hex pattern
    clean = pattern.replace(" ", "").replace("\t", "").replace("\n", "")
    if clean.lower().startswith("0x"):
        clean = clean[2:]

    try:
        byte_values = [int(clean[i:i + 2], 16) for i in range(0, len(clean), 2)]
    except Exception:
        emit({"error": "Invalid hex pattern: " + pattern})
        return

    if not byte_values:
        emit({"error": "Empty byte pattern"})
        return

    import jpype
    ba = jpype.JArray(jpype.JByte)([v if v < 128 else v - 256 for v in byte_values])

    mem = currentProgram.getMemory()
    fm = currentProgram.getFunctionManager()

    result = []
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        if len(result) >= limit:
            break
        search_addr = block.getStart()
        end_addr = block.getEnd()
        while search_addr is not None and search_addr.compareTo(end_addr) <= 0:
            try:
                found = mem.findBytes(search_addr, end_addr, ba, None, True, monitor)
            except Exception:
                found = None
            if found is None:
                break
            func = fm.getFunctionContaining(found)
            result.append({
                "address": str(found),
                "block": block.getName(),
                "function": func.getName() if func else None,
            })
            if len(result) >= limit:
                break
            search_addr = found.add(1)

    emit({"pattern": pattern, "matches": result, "count": len(result)})


def op_calls(args):
    """List functions called from a given function."""
    if not args:
        fail("calls requires a function name or address")
        return

    func = get_function(args[0])
    if func is None:
        emit({"error": "Function not found: " + args[0]})
        return

    result = []
    seen = set()
    body = func.getBody()
    listing = currentProgram.getListing()
    rm = currentProgram.getReferenceManager()

    # Iterate instructions in function body
    inst_iter = listing.getInstructions(body, True)
    for inst in inst_iter:
        refs = rm.getReferencesFrom(inst.getAddress())
        for ref in refs:
            if str(ref.getReferenceType()).lower() in ("call", "unconditional_call", "conditional_call"):
                to_addr = ref.getToAddress()
                to_key = str(to_addr)
                if to_key in seen:
                    continue
                seen.add(to_key)
                called = currentProgram.getFunctionManager().getFunctionAt(to_addr)
                result.append({
                    "to": to_key,
                    "name": called.getName() if called else None,
                    "from": str(inst.getAddress()),
                })

    emit({
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "calls": result,
        "count": len(result),
    })


def op_graph(args):
    """Build a call graph from a function up to *depth* levels."""
    if not args:
        fail("graph requires a function name or address")
        return

    depth = 2
    if len(args) >= 2:
        parsed = parse_int(args[1])
        if parsed is not None:
            depth = min(parsed, 5)

    start_func = get_function(args[0])
    if start_func is None:
        emit({"error": "Function not found: " + args[0]})
        return

    visited = set()
    edges = []

    def walk(func, current_depth):
        if current_depth > depth:
            return
        key = str(func.getEntryPoint())
        if key in visited:
            return
        visited.add(key)

        body = func.getBody()
        listing = currentProgram.getListing()
        rm = currentProgram.getReferenceManager()
        fm = currentProgram.getFunctionManager()

        inst_iter = listing.getInstructions(body, True)
        for inst in inst_iter:
            refs = rm.getReferencesFrom(inst.getAddress())
            for ref in refs:
                if "call" in str(ref.getReferenceType()).lower():
                    to_addr = ref.getToAddress()
                    called = fm.getFunctionAt(to_addr)
                    if called is not None and not called.isExternal():
                        edges.append({
                            "from": func.getName(),
                            "to": called.getName(),
                            "from_addr": str(func.getEntryPoint()),
                            "to_addr": str(called.getEntryPoint()),
                        })
                        walk(called, current_depth + 1)

    walk(start_func, 0)

    nodes = []
    fm = currentProgram.getFunctionManager()
    for key in visited:
        try:
            addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(
                int(key, 16) if key.startswith("0x") or key.startswith("00") else int(key)
            ) if not key.startswith("0x") else currentProgram.getAddressFactory().getAddress(key)
            f = fm.getFunctionAt(addr) if addr else None
            nodes.append({"name": f.getName() if f else key, "address": key})
        except Exception:
            nodes.append({"name": key, "address": key})

    emit({
        "root": start_func.getName(),
        "depth": depth,
        "nodes": nodes,
        "edges": edges,
    })


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

HANDLERS = {
    "info": op_info,
    "functions": op_functions,
    "decompile": op_decompile,
    "decompile_all": op_decompile_all,
    "disasm": op_disasm,
    "xrefs_to": op_xrefs_to,
    "xrefs_from": op_xrefs_from,
    "strings": op_strings,
    "symbols": op_symbols,
    "segments": op_segments,
    "data": op_data,
    "search": op_search,
    "calls": op_calls,
    "graph": op_graph,
}


def main():
    args = get_args()
    if not args:
        emit({"error": "No operation specified"})
        return

    op = args[0]
    rest = args[1:]

    handler = HANDLERS.get(op)
    if handler is None:
        emit({"error": "Unknown operation: " + op,
              "available": list(HANDLERS.keys())})
        return

    try:
        handler(rest)
    except Exception as e:
        emit({"error": str(e), "traceback": traceback.format_exc()})


main()
