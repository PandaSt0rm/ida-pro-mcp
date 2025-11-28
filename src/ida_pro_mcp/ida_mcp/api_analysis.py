from typing import Annotated, Literal, Optional, get_args
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_funcs
import idaapi
import idautils
import idc
import ida_typeinf
import ida_nalt
import ida_bytes
import ida_ida
import ida_entry
import ida_search
import ida_idaapi
import ida_xref
import ida_problems
import ida_tryblks
import ida_fixup
from .rpc import tool
from .sync import idaread, is_window_active
from .utils import (
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    parse_struct_field_query,
    parse_path_query,
    parse_insn_pattern,
    parse_string_filter,
    get_function,
    get_prototype,
    get_stack_frame_variables_internal,
    decompile_checked,
    decompile_function_safe,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    get_callees,
    get_callers,
    get_xrefs_from_internal,
    extract_function_strings,
    extract_function_constants,
    Function,
    Argument,
    DisassemblyFunction,
    Xref,
    FunctionAnalysis,
    BasicBlock,
    PathQuery,
    StructFieldQuery,
    StringFilter,
    InsnPattern,
)

# ============================================================================
# String Cache
# ============================================================================

# Cache for idautils.Strings() to avoid rebuilding on every call
_strings_cache: Optional[list[dict]] = None
_strings_cache_md5: Optional[str] = None


def _get_cached_strings_dict() -> list[dict]:
    """Get cached strings as dicts, rebuilding if IDB changed"""
    global _strings_cache, _strings_cache_md5

    # Get current IDB modification hash
    current_md5 = ida_nalt.retrieve_input_file_md5()

    # Rebuild cache if needed
    if _strings_cache is None or _strings_cache_md5 != current_md5:
        _strings_cache = []
        for s in idautils.Strings():
            try:
                _strings_cache.append(
                    {
                        "addr": hex(s.ea),
                        "length": s.length,
                        "string": str(s),
                        "type": s.strtype,
                    }
                )
            except Exception:
                pass
        _strings_cache_md5 = current_md5

    return _strings_cache


# ============================================================================
# Code Analysis & Decompilation
# ============================================================================


@tool
@idaread
def decompile(
    addrs: Annotated[list[str] | str, "Function addresses to decompile"],
) -> list[dict]:
    """Decompile functions to pseudocode"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            start = parse_address(addr)
            cfunc = decompile_checked(start)
            if is_window_active():
                ida_hexrays.open_pseudocode(start, ida_hexrays.OPF_REUSE)
            sv = cfunc.get_pseudocode()
            code = ""
            for i, sl in enumerate(sv):
                sl: ida_kernwin.simpleline_t
                item = ida_hexrays.ctree_item_t()
                ea = None if i > 0 else cfunc.entry_ea
                if cfunc.get_line_item(sl.line, 0, False, None, item, None):
                    dstr: str | None = item.dstr()
                    if dstr:
                        ds = dstr.split(": ")
                        if len(ds) == 2:
                            try:
                                ea = int(ds[0], 16)
                            except ValueError:
                                pass
                line = ida_lines.tag_remove(sl.line)
                if len(code) > 0:
                    code += "\n"
                if not ea:
                    code += f"/* line: {i} */ {line}"
                else:
                    code += f"/* line: {i}, address: {hex(ea)} */ {line}"

            results.append({"addr": addr, "code": code})
        except Exception as e:
            results.append({"addr": addr, "code": None, "error": str(e)})

    return results


@tool
@idaread
def disasm(
    addrs: Annotated[list[str] | str, "Function addresses to disassemble"],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 5000, max: 50000)"
    ] = 5000,
    offset: Annotated[int, "Skip first N instructions (default: 0)"] = 0,
) -> list[dict]:
    """Disassemble functions to assembly instructions"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_instructions <= 0 or max_instructions > 50000:
        max_instructions = 50000

    results = []

    for start_addr in addrs:
        try:
            start = parse_address(start_addr)
            func = idaapi.get_func(start)

            if is_window_active():
                ida_kernwin.jumpto(start)

            # Get segment info
            seg = idaapi.getseg(start)
            if not seg:
                results.append(
                    {
                        "addr": start_addr,
                        "asm": None,
                        "error": "No segment found",
                        "cursor": {"done": True},
                    }
                )
                continue

            segment_name = idaapi.get_segm_name(seg) if seg else "UNKNOWN"

            # Collect instructions
            all_instructions = []

            if func:
                # Function exists: disassemble function items starting from requested address
                func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
                header_addr = start  # Use requested address, not function start

                for ea in idautils.FuncItems(func.start_ea):
                    if ea == idaapi.BADADDR:
                        continue
                    # Skip instructions before the requested start address
                    if ea < start:
                        continue

                    # Use generate_disasm_line to get full line with comments
                    line = idc.generate_disasm_line(ea, 0)
                    instruction = ida_lines.tag_remove(line) if line else ""
                    all_instructions.append((ea, instruction))
            else:
                # No function: disassemble sequentially from start address
                func_name = f"<no function>"
                header_addr = start

                ea = start
                while ea < seg.end_ea and len(all_instructions) < max_instructions + offset:
                    if ea == idaapi.BADADDR:
                        break

                    insn = idaapi.insn_t()
                    if idaapi.decode_insn(insn, ea) == 0:
                        break

                    # Use generate_disasm_line to get full line with comments
                    line = idc.generate_disasm_line(ea, 0)
                    instruction = ida_lines.tag_remove(line) if line else ""
                    all_instructions.append((ea, instruction))

                    ea = idc.next_head(ea, seg.end_ea)

            # Apply pagination
            total_insns = len(all_instructions)
            paginated_insns = all_instructions[offset : offset + max_instructions]
            has_more = offset + max_instructions < total_insns

            # Build disassembly string from paginated instructions
            lines_str = f"{func_name} ({segment_name} @ {hex(header_addr)}):"
            for ea, instruction in paginated_insns:
                lines_str += f"\n{ea:x}  {instruction}"

            rettype = None
            args: Optional[list[Argument]] = None
            stack_frame = None

            if func:
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
                    ftd = ida_typeinf.func_type_data_t()
                    if tif.get_func_details(ftd):
                        rettype = str(ftd.rettype)
                        args = [
                            Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                            for i, a in enumerate(ftd)
                        ]
                stack_frame = get_stack_frame_variables_internal(func.start_ea, False)

            out: DisassemblyFunction = {
                "name": func_name,
                "start_ea": hex(header_addr),
                "lines": lines_str,
            }
            if stack_frame:
                out["stack_frame"] = stack_frame
            if rettype:
                out["return_type"] = rettype
            if args is not None:
                out["arguments"] = args

            results.append(
                {
                    "addr": start_addr,
                    "asm": out,
                    "instruction_count": len(paginated_insns),
                    "total_instructions": total_insns,
                    "cursor": (
                        {"next": offset + max_instructions}
                        if has_more
                        else {"done": True}
                    ),
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": start_addr,
                    "asm": None,
                    "error": str(e),
                    "cursor": {"done": True},
                }
            )

    return results


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


@tool
@idaread
def xrefs_to(
    addrs: Annotated[list[str] | str, "Addresses to find cross-references to"],
) -> list[dict]:
    """Get all cross-references to specified addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(parse_address(addr)):
                xrefs += [
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                ]
            results.append({"addr": addr, "xrefs": xrefs})
        except Exception as e:
            results.append({"addr": addr, "xrefs": None, "error": str(e)})

    return results


@tool
@idaread
def xrefs_to_field(
    queries: Annotated[
        list[StructFieldQuery] | StructFieldQuery | str,
        "Field xref queries. Accepts list of {struct, field} dicts or string shortcut: 'struct.field;struct2.field2'",
    ],
) -> list[dict]:
    """Get cross-references to structure fields"""
    queries = normalize_dict_list(queries, parse_struct_field_query)

    results = []
    til = ida_typeinf.get_idati()
    if not til:
        return [
            {
                "struct": q.get("struct"),
                "field": q.get("field"),
                "xrefs": [],
                "error": "Failed to retrieve type library",
            }
            for q in queries
        ]

    for query in queries:
        struct_name = query.get("struct", "")
        field_name = query.get("field", "")

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(
                til, struct_name, ida_typeinf.BTF_STRUCT, True, False
            ):
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
            if idx == -1:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Field '{field_name}' not found in '{struct_name}'",
                    }
                )
                continue

            tid = tif.get_udm_tid(idx)
            if tid == ida_idaapi.BADADDR:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": "Unable to get tid",
                    }
                )
                continue

            xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(tid):
                xrefs += [
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                ]
            results.append({"struct": struct_name, "field": field_name, "xrefs": xrefs})
        except Exception as e:
            results.append(
                {
                    "struct": struct_name,
                    "field": field_name,
                    "xrefs": [],
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Call Graph Analysis
# ============================================================================


@tool
@idaread
def callees(
    addrs: Annotated[list[str] | str, "Function addresses to get callees for"],
) -> list[dict]:
    """Get all functions called by the specified functions"""
    addrs = normalize_list_input(addrs)
    results = []

    for fn_addr in addrs:
        try:
            func_start = parse_address(fn_addr)
            func = idaapi.get_func(func_start)
            if not func:
                results.append(
                    {"addr": fn_addr, "callees": None, "error": "No function found"}
                )
                continue
            func_end = idc.find_func_end(func_start)
            callees: list[dict[str, str]] = []
            current_ea = func_start
            while current_ea < func_end:
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, current_ea)
                if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    target = idc.get_operand_value(current_ea, 0)
                    target_type = idc.get_operand_type(current_ea, 0)
                    if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                        func_type = (
                            "internal"
                            if idaapi.get_func(target) is not None
                            else "external"
                        )
                        func_name = idc.get_name(target)
                        if func_name is not None:
                            callees.append(
                                {
                                    "addr": hex(target),
                                    "name": func_name,
                                    "type": func_type,
                                }
                            )
                current_ea = idc.next_head(current_ea, func_end)

            unique_callee_tuples = {tuple(callee.items()) for callee in callees}
            unique_callees = [dict(callee) for callee in unique_callee_tuples]
            results.append({"addr": fn_addr, "callees": unique_callees})
        except Exception as e:
            results.append({"addr": fn_addr, "callees": None, "error": str(e)})

    return results


@tool
@idaread
def callers(
    addrs: Annotated[list[str] | str, "Function addresses to get callers for"],
) -> list[dict]:
    """Get all functions that call the specified functions"""
    addrs = normalize_list_input(addrs)
    results = []

    for fn_addr in addrs:
        try:
            callers = {}
            for caller_addr in idautils.CodeRefsTo(parse_address(fn_addr), 0):
                func = get_function(caller_addr, raise_error=False)
                if not func:
                    continue
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, caller_addr)
                if insn.itype not in [
                    idaapi.NN_call,
                    idaapi.NN_callfi,
                    idaapi.NN_callni,
                ]:
                    continue
                callers[func["addr"]] = func

            results.append({"addr": fn_addr, "callers": list(callers.values())})
        except Exception as e:
            results.append({"addr": fn_addr, "callers": None, "error": str(e)})

    return results


@tool
@idaread
def entrypoints() -> list[Function]:
    """Get entry points"""
    result = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        addr = ida_entry.get_entry(ordinal)
        func = get_function(addr, raise_error=False)
        if func is not None:
            result.append(func)
    return result


# ============================================================================
# Comprehensive Function Analysis
# ============================================================================


@tool
@idaread
def analyze_funcs(
    addrs: Annotated[list[str] | str, "Function addresses to comprehensively analyze"],
) -> list[FunctionAnalysis]:
    """Comprehensive function analysis: decompilation, xrefs, callees, strings, constants, blocks"""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)

            if not func:
                results.append(
                    FunctionAnalysis(
                        addr=addr,
                        name=None,
                        code=None,
                        asm=None,
                        xto=[],
                        xfrom=[],
                        callees=[],
                        callers=[],
                        strings=[],
                        constants=[],
                        blocks=[],
                        error="Function not found",
                    )
                )
                continue

            # Get basic blocks
            flowchart = idaapi.FlowChart(func)
            blocks = []
            for block in flowchart:
                blocks.append(
                    {
                        "start": hex(block.start_ea),
                        "end": hex(block.end_ea),
                        "type": block.type,
                    }
                )

            result = FunctionAnalysis(
                addr=addr,
                name=ida_funcs.get_func_name(func.start_ea),
                code=decompile_function_safe(ea),
                asm=get_assembly_lines(ea),
                xto=[
                    Xref(
                        addr=hex(x.frm),
                        type="code" if x.iscode else "data",
                        fn=get_function(x.frm, raise_error=False),
                    )
                    for x in idautils.XrefsTo(ea, 0)
                ],
                xfrom=get_xrefs_from_internal(ea),
                callees=get_callees(addr),
                callers=get_callers(addr),
                strings=extract_function_strings(ea),
                constants=extract_function_constants(ea),
                blocks=blocks,
                error=None,
            )
            results.append(result)
        except Exception as e:
            results.append(
                FunctionAnalysis(
                    addr=addr,
                    name=None,
                    code=None,
                    asm=None,
                    xto=[],
                    xfrom=[],
                    callees=[],
                    callers=[],
                    strings=[],
                    constants=[],
                    blocks=[],
                    error=str(e),
                )
            )
    return results


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


@tool
@idaread
def find_bytes(
    patterns: Annotated[
        list[str] | str, "Byte patterns to search for (e.g. '48 8B ?? ??')"
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for byte patterns in the binary (supports wildcards with ??)"""
    patterns = normalize_list_input(patterns)

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in patterns:
        all_matches = []
        try:
            # Parse the pattern
            compiled = ida_bytes.compiled_binpat_vec_t()
            err = ida_bytes.parse_binpat_str(
                compiled, ida_ida.inf_get_min_ea(), pattern, 16
            )
            if err:
                results.append(
                    {
                        "pattern": pattern,
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                    }
                )
                continue

            # Search for all matches
            ea = ida_ida.inf_get_min_ea()
            while ea != idaapi.BADADDR:
                ea = ida_bytes.bin_search(
                    ea, ida_ida.inf_get_max_ea(), compiled, ida_bytes.BIN_SEARCH_FORWARD
                )
                if ea != idaapi.BADADDR:
                    all_matches.append(hex(ea))
                    ea += 1
        except Exception:
            pass

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )
    return results


@tool
@idaread
def find_insns(
    sequences: Annotated[
        list[list[str]] | list[str], "Instruction mnemonic sequences to search for"
    ],
    limit: Annotated[
        int, "Max matches per sequence (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for sequences of instruction mnemonics in the binary"""
    # Handle single sequence vs array of sequences
    if sequences and isinstance(sequences[0], str):
        sequences = [sequences]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    for sequence in sequences:
        if not sequence:
            results.append(
                {
                    "sequence": sequence,
                    "matches": [],
                    "count": 0,
                    "cursor": {"done": True},
                }
            )
            continue

        all_matches = []
        # Scan all code segments
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                continue

            ea = seg.start_ea
            while ea < seg.end_ea:
                # Try to match sequence starting at ea
                match_ea = ea
                matched = True

                for expected_mnem in sequence:
                    insn = idaapi.insn_t()
                    if idaapi.decode_insn(insn, match_ea) == 0:
                        matched = False
                        break

                    actual_mnem = idc.print_insn_mnem(match_ea)
                    if actual_mnem != expected_mnem:
                        matched = False
                        break

                    match_ea = idc.next_head(match_ea, seg.end_ea)
                    if match_ea == idaapi.BADADDR:
                        matched = False
                        break

                if matched:
                    all_matches.append(hex(ea))

                ea = idc.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "sequence": sequence,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )

    return results


# ============================================================================
# Control Flow Analysis
# ============================================================================


@tool
@idaread
def basic_blocks(
    addrs: Annotated[list[str] | str, "Function addresses to get basic blocks for"],
    max_blocks: Annotated[
        int, "Max basic blocks per function (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N blocks (default: 0)"] = 0,
) -> list[dict]:
    """Get control flow graph basic blocks for functions"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_blocks <= 0 or max_blocks > 10000:
        max_blocks = 10000

    results = []
    for fn_addr in addrs:
        try:
            ea = parse_address(fn_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        "error": "Function not found",
                        "blocks": [],
                        "cursor": {"done": True},
                    }
                )
                continue

            flowchart = idaapi.FlowChart(func)
            all_blocks = []

            for block in flowchart:
                all_blocks.append(
                    BasicBlock(
                        start=hex(block.start_ea),
                        end=hex(block.end_ea),
                        size=block.end_ea - block.start_ea,
                        type=block.type,
                        successors=[hex(succ.start_ea) for succ in block.succs()],
                        predecessors=[hex(pred.start_ea) for pred in block.preds()],
                    )
                )

            # Apply pagination
            total_blocks = len(all_blocks)
            blocks = all_blocks[offset : offset + max_blocks]
            has_more = offset + max_blocks < total_blocks

            results.append(
                {
                    "addr": fn_addr,
                    "blocks": blocks,
                    "count": len(blocks),
                    "total_blocks": total_blocks,
                    "cursor": (
                        {"next": offset + max_blocks} if has_more else {"done": True}
                    ),
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": fn_addr,
                    "error": str(e),
                    "blocks": [],
                    "cursor": {"done": True},
                }
            )
    return results


@tool
@idaread
def find_paths(
    queries: Annotated[
        list[PathQuery] | PathQuery | str,
        "Path queries. Accepts list of {source, target} dicts or string shortcut: 'source->target;source2->target2'",
    ],
) -> list[dict]:
    """Find execution paths between source and target addresses"""
    queries = normalize_dict_list(queries, parse_path_query)
    results = []

    for query in queries:
        source = parse_address(query["source"])
        target = parse_address(query["target"])

        # Get containing function
        func = idaapi.get_func(source)
        if not func:
            results.append(
                {
                    "source": query["source"],
                    "target": query["target"],
                    "paths": [],
                    "reachable": False,
                    "error": "Source not in a function",
                }
            )
            continue

        # Build flow graph
        flowchart = idaapi.FlowChart(func)

        # Find source and target blocks
        source_block = None
        target_block = None
        for block in flowchart:
            if block.start_ea <= source < block.end_ea:
                source_block = block
            if block.start_ea <= target < block.end_ea:
                target_block = block

        if not source_block or not target_block:
            results.append(
                {
                    "source": query["source"],
                    "target": query["target"],
                    "paths": [],
                    "reachable": False,
                    "error": "Could not find basic blocks",
                }
            )
            continue

        # Simple BFS to find paths
        paths = []
        queue = [([source_block], {source_block.id})]

        while queue and len(paths) < 10:  # Limit paths
            path, visited = queue.pop(0)
            current = path[-1]

            if current.id == target_block.id:
                paths.append([hex(b.start_ea) for b in path])
                continue

            for succ in current.succs():
                if succ.id not in visited and len(path) < 20:  # Limit depth
                    queue.append((path + [succ], visited | {succ.id}))

        results.append(
            {
                "source": query["source"],
                "target": query["target"],
                "paths": paths,
                "reachable": len(paths) > 0,
                "error": None,
            }
        )

    return results


# ============================================================================
# Search Operations
# ============================================================================

SearchType = Literal["string", "immediate", "data_ref", "code_ref"]


@tool
@idaread
def search(
    type: Annotated[SearchType, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"],
    targets: Annotated[
        list[str | int] | str | int, "Search targets (strings, integers, or addresses)"
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for patterns in the binary (strings, immediate values, or references)"""
    if not isinstance(targets, list):
        targets = [targets]

    # Enforce max limit to prevent token overflow
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    if type == "string":
        # Search for strings containing pattern
        all_strings = _get_cached_strings_dict()
        for pattern in targets:
            pattern_str = str(pattern)
            all_matches = [
                s["addr"]
                for s in all_strings
                if pattern_str.lower() in s["string"].lower()
            ]

            # Apply pagination
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)

            results.append(
                {
                    "query": pattern_str,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if has_more else {"done": True},
                    "error": None,
                }
            )

    elif type == "immediate":
        # Search for immediate values
        for value in targets:
            if isinstance(value, str):
                try:
                    value = int(value, 0)
                except ValueError:
                    value = 0

            all_matches = []
            try:
                ea = ida_ida.inf_get_min_ea()
                while ea < ida_ida.inf_get_max_ea():
                    result = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, value)
                    if result[0] == idaapi.BADADDR:
                        break
                    all_matches.append(hex(result[0]))
                    ea = result[0] + 1
            except Exception:
                pass

            # Apply pagination
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)

            results.append(
                {
                    "query": value,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if has_more else {"done": True},
                    "error": None,
                }
            )

    elif type == "data_ref":
        # Find all data references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                all_matches = [hex(xref) for xref in idautils.DataRefsTo(target)]

                # Apply pagination
                if limit > 0:
                    matches = all_matches[offset : offset + limit]
                    has_more = offset + limit < len(all_matches)
                else:
                    matches = all_matches[offset:]
                    has_more = False

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if has_more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    elif type == "code_ref":
        # Find all code references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                all_matches = [hex(xref) for xref in idautils.CodeRefsTo(target, 0)]

                # Apply pagination
                if limit > 0:
                    matches = all_matches[offset : offset + limit]
                    has_more = offset + limit < len(all_matches)
                else:
                    matches = all_matches[offset:]
                    has_more = False

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if has_more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    else:
        results.append(
            {
                "query": None,
                "matches": [],
                "count": 0,
                "cursor": {"done": True},
                "error": f"Unknown search type: {type}. Valid types: {', '.join(get_args(SearchType))}",
            }
        )

    return results


@tool
@idaread
def find_insn_operands(
    patterns: Annotated[
        list[InsnPattern] | InsnPattern | str,
        "Instruction patterns. Accepts list of {mnem, op0, op1, op2, op_any} dicts or string shortcut: 'call op_any=0x401000' or 'mov op0=0x10;ret'",
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Find instructions with specific mnemonics and operand values"""
    patterns = normalize_dict_list(patterns, parse_insn_pattern)

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in patterns:
        all_matches = _find_insn_pattern(pattern)

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )
    return results


def _find_insn_pattern(pattern: dict) -> list[str]:
    """Internal helper to find instructions matching a pattern"""
    mnem = pattern.get("mnem", "").lower()
    op0_val = pattern.get("op0")
    op1_val = pattern.get("op1")
    op2_val = pattern.get("op2")
    any_val = pattern.get("op_any")

    matches = []

    # Scan all executable segments
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
            continue

        ea = seg.start_ea
        while ea < seg.end_ea:
            # Check mnemonic
            if mnem and idc.print_insn_mnem(ea).lower() != mnem:
                ea = idc.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            # Check specific operand positions
            match = True
            if op0_val is not None:
                if idc.get_operand_value(ea, 0) != op0_val:
                    match = False

            if op1_val is not None:
                if idc.get_operand_value(ea, 1) != op1_val:
                    match = False

            if op2_val is not None:
                if idc.get_operand_value(ea, 2) != op2_val:
                    match = False

            # Check any operand
            if any_val is not None and match:
                found_any = False
                for i in range(8):
                    if idc.get_operand_type(ea, i) == idaapi.o_void:
                        break
                    if idc.get_operand_value(ea, i) == any_val:
                        found_any = True
                        break
                if not found_any:
                    match = False

            if match:
                matches.append(hex(ea))

            ea = idc.next_head(ea, seg.end_ea)
            if ea == idaapi.BADADDR:
                break

    return matches


# ============================================================================
# Export Operations
# ============================================================================

ExportFormat = Literal["json", "c_header", "prototypes"]


@tool
@idaread
def export_funcs(
    addrs: Annotated[list[str] | str, "Function addresses to export"],
    format: Annotated[ExportFormat, "Export format: json (default), c_header, or prototypes"] = "json",
) -> dict:
    """Export function data in various formats"""
    if format not in get_args(ExportFormat):
        return {"error": f"Unknown format: {format}. Valid formats: {', '.join(get_args(ExportFormat))}"}

    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"addr": addr, "error": "Function not found"})
                continue

            func_data = {
                "addr": addr,
                "name": ida_funcs.get_func_name(func.start_ea),
                "prototype": get_prototype(func),
                "size": hex(func.end_ea - func.start_ea),
                "comments": get_all_comments(ea),
            }

            if format == "json":
                func_data["asm"] = get_assembly_lines(ea)
                func_data["code"] = decompile_function_safe(ea)
                func_data["xrefs"] = get_all_xrefs(ea)

            results.append(func_data)

        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    if format == "c_header":
        # Generate C header file
        lines = ["// Auto-generated by IDA Pro MCP", ""]
        for func in results:
            if "prototype" in func and func["prototype"]:
                lines.append(f"{func['prototype']};")
        return {"format": "c_header", "content": "\n".join(lines)}

    elif format == "prototypes":
        # Just prototypes
        prototypes = []
        for func in results:
            if "prototype" in func and func["prototype"]:
                prototypes.append(
                    {"name": func.get("name"), "prototype": func["prototype"]}
                )
        return {"format": "prototypes", "functions": prototypes}

    return {"format": "json", "functions": results}


# ============================================================================
# Graph Operations
# ============================================================================


@tool
@idaread
def callgraph(
    roots: Annotated[
        list[str] | str, "Root function addresses to start call graph traversal from"
    ],
    max_depth: Annotated[int, "Maximum depth for call graph traversal"] = 5,
) -> list[dict]:
    """Build call graph starting from root functions"""
    roots = normalize_list_input(roots)
    results = []

    for root in roots:
        try:
            ea = parse_address(root)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "root": root,
                        "error": "Function not found",
                        "nodes": [],
                        "edges": [],
                    }
                )
                continue

            nodes = {}
            edges = []
            visited = set()

            def traverse(addr, depth):
                if depth > max_depth or addr in visited:
                    return
                visited.add(addr)

                f = idaapi.get_func(addr)
                if not f:
                    return

                func_name = ida_funcs.get_func_name(f.start_ea)
                nodes[hex(addr)] = {
                    "addr": hex(addr),
                    "name": func_name,
                    "depth": depth,
                }

                # Get callees
                for item_ea in idautils.FuncItems(f.start_ea):
                    for xref in idautils.CodeRefsFrom(item_ea, 0):
                        callee_func = idaapi.get_func(xref)
                        if callee_func:
                            edges.append(
                                {
                                    "from": hex(addr),
                                    "to": hex(callee_func.start_ea),
                                    "type": "call",
                                }
                            )
                            traverse(callee_func.start_ea, depth + 1)

            traverse(ea, 0)

            results.append(
                {
                    "root": root,
                    "nodes": list(nodes.values()),
                    "edges": edges,
                    "max_depth": max_depth,
                    "error": None,
                }
            )

        except Exception as e:
            results.append({"root": root, "error": str(e), "nodes": [], "edges": []})

    return results


# ============================================================================
# Cross-Reference Matrix
# ============================================================================


@tool
@idaread
def xref_matrix(
    entities: Annotated[
        list[str] | str, "Addresses to build cross-reference matrix for"
    ],
) -> dict:
    """Build matrix showing cross-references between entities"""
    entities = normalize_list_input(entities)
    matrix = {}

    for source in entities:
        try:
            source_ea = parse_address(source)
            matrix[source] = {}

            for target in entities:
                if source == target:
                    continue

                target_ea = parse_address(target)

                # Count references from source to target
                count = 0
                for xref in idautils.XrefsFrom(source_ea, 0):
                    if xref.to == target_ea:
                        count += 1

                if count > 0:
                    matrix[source][target] = count

        except Exception:
            matrix[source] = {"error": "Failed to process"}

    return {"matrix": matrix, "entities": entities}


# ============================================================================
# String Analysis
# ============================================================================


@tool
@idaread
def analyze_strings(
    filters: Annotated[
        list[StringFilter] | StringFilter | str,
        "String filters. Accepts list of {pattern, min_length} dicts or string shortcut: 'error' or 'http,min_length=5'",
    ],
    limit: Annotated[int, "Max matches per filter (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Analyze and filter strings in the binary"""
    filters = normalize_dict_list(filters, parse_string_filter)

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    # Use cached strings to avoid rebuilding on every call
    all_strings = _get_cached_strings_dict()

    results = []

    for filt in filters:
        pattern = filt.get("pattern", "").lower()
        min_length = filt.get("min_length", 0)

        # Find all matching strings
        all_matches = []
        for s in all_strings:
            if len(s["string"]) < min_length:
                continue
            if pattern and pattern not in s["string"].lower():
                continue

            # Add xref info
            s_ea = parse_address(s["addr"])
            xrefs = [hex(x.frm) for x in idautils.XrefsTo(s_ea, 0)]
            all_matches.append({**s, "xrefs": xrefs, "xref_count": len(xrefs)})

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "filter": filt,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )

    return results


# ============================================================================
# Cross-References (from)
# ============================================================================


@tool
@idaread
def xrefs_from(
    addrs: Annotated[list[str] | str, "Addresses to find cross-references from"],
) -> list[dict]:
    """Get all cross-references from specified addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            xrefs = get_xrefs_from_internal(ea)
            results.append({
                "addr": addr,
                "xrefs": [
                    {
                        "to": x["addr"],
                        "type": x["type"],
                        "function": x.get("fn"),
                    }
                    for x in xrefs
                ],
                "count": len(xrefs),
                "error": None,
            })
        except Exception as e:
            results.append({"addr": addr, "xrefs": [], "count": 0, "error": str(e)})

    return results


# ============================================================================
# Problems List
# ============================================================================

# Problem type constants with descriptions
_PROBLEM_TYPES = {
    ida_problems.PR_NOBASE: ("PR_NOBASE", "The segment for the address cannot be determined"),
    ida_problems.PR_NONAME: ("PR_NONAME", "A name in the instruction has no resolution"),
    ida_problems.PR_NOFOP: ("PR_NOFOP", "A function operand has no resolution"),
    ida_problems.PR_NOCMT: ("PR_NOCMT", "A comment operand has no resolution"),
    ida_problems.PR_NOXREFS: ("PR_NOXREFS", "Address has no references - possibly orphaned code"),
    ida_problems.PR_JUMP: ("PR_JUMP", "Jump or call to an illegal address"),
    ida_problems.PR_DISASM: ("PR_DISASM", "Can't disassemble"),
    ida_problems.PR_HEAD: ("PR_HEAD", "Can't make data at address (probably code)"),
    ida_problems.PR_ILLADDR: ("PR_ILLADDR", "Illegal address used in instruction operand"),
    ida_problems.PR_MANYLINES: ("PR_MANYLINES", "Too many lines generated (>= 128K)"),
    ida_problems.PR_BADSTACK: ("PR_BADSTACK", "Stack analysis problems"),
    ida_problems.PR_ATTN: ("PR_ATTN", "Attention! Probably erroneous situation"),
    ida_problems.PR_FINAL: ("PR_FINAL", "Not used for problem types - end marker"),
    ida_problems.PR_ROLLED: ("PR_ROLLED", "Instruction has rolled back analysis"),
    ida_problems.PR_COLLISION: ("PR_COLLISION", "Names collision (already exists)"),
    ida_problems.PR_DECIMP: ("PR_DECIMP", "Decompiler/plugin notification"),
}


@tool
@idaread
def problems(
    problem_type: Annotated[
        str | None,
        "Optional filter: PR_JUMP, PR_DISASM, PR_NOBASE, PR_BADSTACK, PR_ATTN, etc. (None=all)",
    ] = None,
) -> list[dict]:
    """List all analysis problems found by IDA.

    Problems indicate areas where IDA had difficulty during analysis,
    such as invalid jumps, disassembly errors, or stack analysis issues.
    """
    results = []

    # Determine which problem types to query
    if problem_type:
        # Look up the constant by name
        type_map = {name: val for val, (name, _) in _PROBLEM_TYPES.items()}
        if problem_type not in type_map:
            valid = ", ".join(sorted(type_map.keys()))
            return [{"error": f"Unknown problem type '{problem_type}'. Valid types: {valid}"}]
        types_to_check = [type_map[problem_type]]
    else:
        # Check all types except PR_FINAL
        types_to_check = [t for t in _PROBLEM_TYPES.keys() if t != ida_problems.PR_FINAL]

    for pr_type in types_to_check:
        type_name, type_desc = _PROBLEM_TYPES.get(pr_type, (f"UNKNOWN_{pr_type}", "Unknown"))

        # Iterate through all problems of this type
        ea = ida_problems.get_problem(pr_type, ida_ida.inf_get_min_ea())
        while ea != idaapi.BADADDR:
            # Get problem description if available
            desc = ida_problems.get_problem_desc(pr_type, ea)

            # Get function context if available
            func = idaapi.get_func(ea)
            func_name = ida_funcs.get_func_name(func.start_ea) if func else None

            results.append({
                "addr": hex(ea),
                "type": type_name,
                "type_desc": type_desc,
                "description": desc if desc else None,
                "function": func_name,
            })

            # Get next problem
            ea = ida_problems.get_problem(pr_type, ea + 1)

    return results


# ============================================================================
# Switch/Jump Tables
# ============================================================================


@tool
@idaread
def switch_info(
    addrs: Annotated[list[str] | str, "Addresses of switch instructions to analyze"],
) -> list[dict]:
    """Get switch/jump table information at specified addresses.

    Use this to understand switch statement structure including:
    - Jump table location and entries
    - Default case address
    - Case values and their targets
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)

            si = ida_nalt.switch_info_t()
            if ida_nalt.get_switch_info(si, ea) is None:
                results.append({
                    "addr": addr,
                    "is_switch": False,
                    "error": None,
                })
                continue

            # Extract jump table entries
            jtable = []
            elem_size = si.get_jtable_element_size()
            for i in range(si.get_jtable_size()):
                entry_ea = si.jumps + (i * elem_size)
                target_offset = int.from_bytes(
                    ida_bytes.get_bytes(entry_ea, elem_size),
                    'little' if not ida_ida.inf_is_be() else 'big'
                )
                target = target_offset + si.elbase
                jtable.append({
                    "index": i,
                    "entry_addr": hex(entry_ea),
                    "target": hex(target),
                })

            results.append({
                "addr": addr,
                "is_switch": True,
                "switch_addr": hex(si.startea),
                "jump_table_addr": hex(si.jumps),
                "jump_table_size": si.get_jtable_size(),
                "element_size": elem_size,
                "default_case": hex(si.defjump) if si.defjump != idaapi.BADADDR else None,
                "lowcase": si.lowcase,
                "cases": si.ncases,
                "elbase": hex(si.elbase),
                "entries": jtable,
                "error": None,
            })

        except Exception as e:
            results.append({"addr": addr, "is_switch": False, "error": str(e)})

    return results


# ============================================================================
# Exception Handling / Try-Catch Blocks
# ============================================================================


@tool
@idaread
def tryblks(
    addrs: Annotated[list[str] | str, "Function addresses to get try/catch blocks for"],
) -> list[dict]:
    """Get exception handling try/catch block information.

    Returns SEH (Structured Exception Handling) and C++ exception handling
    information for functions. Useful for understanding exception flow.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)

            # Get function containing this address
            func = idaapi.get_func(ea)
            if not func:
                results.append({
                    "addr": addr,
                    "tryblks": [],
                    "count": 0,
                    "error": "Address not in a function",
                })
                continue

            # Get try blocks for the function range
            blocks = []

            # Create a range_t for the function
            func_range = idaapi.range_t(func.start_ea, func.end_ea)

            # Create a tryblks_t vector to receive results
            tbv = ida_tryblks.tryblks_t()

            # Get try blocks - returns number of blocks found
            count = ida_tryblks.get_tryblks(tbv, func_range)

            # Iterate through try blocks
            for i in range(count):
                tb = tbv[i]

                block_info = {
                    "level": tb.level if hasattr(tb, "level") else 0,
                    "try_start": hex(tb.start_ea),
                    "try_end": hex(tb.end_ea),
                    "handlers": [],
                }

                # Get catch handlers for this try block
                # tryblk_t can contain catch_t entries
                if hasattr(tb, "size"):
                    for j in range(tb.size()):
                        handler = tb.at(j) if hasattr(tb, "at") else None
                        if handler:
                            handler_info = {}

                            # Check handler type
                            if hasattr(handler, "disp") and handler.disp != 0:
                                handler_info["type"] = "seh"
                                handler_info["filter_addr"] = hex(handler.disp)
                            else:
                                handler_info["type"] = "cpp"

                            if hasattr(handler, "ea"):
                                handler_info["handler_addr"] = hex(handler.ea)

                            block_info["handlers"].append(handler_info)

                blocks.append(block_info)

            results.append({
                "addr": addr,
                "function": ida_funcs.get_func_name(func.start_ea),
                "tryblks": blocks,
                "count": len(blocks),
                "error": None,
            })

        except Exception as e:
            results.append({"addr": addr, "tryblks": [], "count": 0, "error": str(e)})

    return results


# ============================================================================
# Fixups / Relocations
# ============================================================================

# Fixup type constants - built dynamically to handle IDA version differences
def _build_fixup_types():
    types = {}
    for name in ['FIXUP_OFF8', 'FIXUP_OFF16', 'FIXUP_SEG16', 'FIXUP_PTR16',
                 'FIXUP_PTR32', 'FIXUP_OFF32', 'FIXUP_HI8', 'FIXUP_HI16',
                 'FIXUP_LOW8', 'FIXUP_LOW16', 'FIXUP_OFF64', 'FIXUP_CUSTOM']:
        if hasattr(ida_fixup, name):
            types[getattr(ida_fixup, name)] = name.replace('FIXUP_', '')
    return types

_FIXUP_TYPES = _build_fixup_types()


@tool
@idaread
def fixups(
    start: Annotated[str | None, "Start address (default: image base)"] = None,
    end: Annotated[str | None, "End address (default: image end)"] = None,
    limit: Annotated[int, "Maximum number of fixups to return (default: 1000)"] = 1000,
) -> list[dict]:
    """List fixups/relocations in the specified address range.

    Fixups indicate places in the binary that need relocation when loaded
    at a different base address. Useful for understanding position-independent code.
    """
    # Parse address range
    if start:
        start_ea = parse_address(start)
    else:
        start_ea = ida_ida.inf_get_min_ea()

    if end:
        end_ea = parse_address(end)
    else:
        end_ea = ida_ida.inf_get_max_ea()

    results = []
    count = 0
    ea = ida_fixup.get_first_fixup_ea()

    while ea != idaapi.BADADDR and count < limit:
        if ea >= start_ea and ea < end_ea:
            fd = ida_fixup.fixup_data_t()
            if ida_fixup.get_fixup(fd, ea):
                fixup_type = _FIXUP_TYPES.get(fd.get_type(), f"TYPE_{fd.get_type()}")

                result_entry = {
                    "addr": hex(ea),
                    "type": fixup_type,
                    "type_id": fd.get_type(),
                    "target": hex(fd.off) if fd.off != idaapi.BADADDR else None,
                    "base": hex(fd.get_base()) if fd.get_base() != idaapi.BADADDR else None,
                }
                # Add displacement if available
                if hasattr(fd, 'displacement'):
                    result_entry["displacement"] = fd.displacement
                results.append(result_entry)
                count += 1

        ea = ida_fixup.get_next_fixup_ea(ea)

    return {
        "fixups": results,
        "count": len(results),
        "has_more": ea != idaapi.BADADDR,
    }
