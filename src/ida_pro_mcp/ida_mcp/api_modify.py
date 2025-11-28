from typing import Annotated

import idaapi
import idautils
import idc
import ida_auto
import ida_funcs
import ida_hexrays
import ida_bytes
import ida_nalt
import ida_segment
import ida_typeinf
import ida_frame

from .rpc import tool
from .sync import idawrite, IDAError
from .utils import (
    parse_address,
    decompile_checked,
    refresh_decompiler_ctext,
    normalize_dict_list,
    normalize_list_input,
    parse_comment_op,
    parse_asm_patch_op,
    CommentOp,
    AsmPatchOp,
    FunctionRename,
    GlobalRename,
    LocalRename,
    StackRename,
    RenameBatch,
)


# ============================================================================
# Modification Operations
# ============================================================================


@tool
@idawrite
def make_function(
    addrs: Annotated[list[str] | str, "Address(es) where functions should be created"],
) -> list[dict]:
    """Create functions at specified addresses. IDA will auto-detect function boundaries.

    Use this when decompilation fails because an address is not inside a function.
    After creating a function, you can decompile it.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)

            # Check if already inside a function
            existing_func = idaapi.get_func(ea)
            if existing_func:
                results.append({
                    "addr": addr_str,
                    "ok": True,
                    "start": hex(existing_func.start_ea),
                    "end": hex(existing_func.end_ea),
                    "name": ida_funcs.get_func_name(existing_func.start_ea),
                    "note": "Address is already inside an existing function",
                })
                continue

            # Check if the address contains valid code
            if not idaapi.is_code(idaapi.get_flags(ea)):
                # Try to convert to code first
                if not idc.create_insn(ea):
                    results.append({
                        "addr": addr_str,
                        "ok": False,
                        "error": f"Address {hex(ea)} does not contain valid code. "
                                 "It may be data or undefined bytes.",
                    })
                    continue

            # Create the function (BADADDR = auto-detect end)
            if not ida_funcs.add_func(ea, idaapi.BADADDR):
                # add_func failed - try to get more info
                flags = idaapi.get_flags(ea)
                if idaapi.is_tail(flags):
                    results.append({
                        "addr": addr_str,
                        "ok": False,
                        "error": f"Address {hex(ea)} is in the middle of another item. "
                                 "Use a different start address.",
                    })
                else:
                    results.append({
                        "addr": addr_str,
                        "ok": False,
                        "error": f"Failed to create function at {hex(ea)}. "
                                 "IDA could not determine valid function boundaries.",
                    })
                continue

            # Get the created function's info
            new_func = idaapi.get_func(ea)
            if new_func:
                results.append({
                    "addr": addr_str,
                    "ok": True,
                    "start": hex(new_func.start_ea),
                    "end": hex(new_func.end_ea),
                    "name": ida_funcs.get_func_name(new_func.start_ea),
                })
            else:
                results.append({
                    "addr": addr_str,
                    "ok": False,
                    "error": "Function was created but could not be retrieved",
                })

        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    return results


@tool
@idawrite
def delete_function(
    addrs: Annotated[list[str] | str, "Address(es) of functions to delete"],
) -> list[dict]:
    """Delete functions at specified addresses.

    This removes the function definition but preserves the underlying code/data.
    Useful for fixing incorrectly defined function boundaries.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)
            func = idaapi.get_func(ea)

            if not func:
                results.append({
                    "addr": addr_str,
                    "ok": False,
                    "error": f"No function at address {hex(ea)}",
                })
                continue

            func_name = ida_funcs.get_func_name(func.start_ea)
            func_start = func.start_ea
            func_end = func.end_ea

            if ida_funcs.del_func(func_start):
                results.append({
                    "addr": addr_str,
                    "ok": True,
                    "deleted": {
                        "name": func_name,
                        "start": hex(func_start),
                        "end": hex(func_end),
                    },
                })
            else:
                results.append({
                    "addr": addr_str,
                    "ok": False,
                    "error": f"Failed to delete function {func_name}",
                })

        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    return results


@tool
@idawrite
def set_comments(
    items: Annotated[
        list[CommentOp] | CommentOp | str,
        "Comment operations. Accepts list of {addr, comment} dicts or string shortcut: 'addr=comment;addr2=comment2'",
    ],
):
    """Set comments at addresses (both disassembly and decompiler views)"""
    items = normalize_dict_list(items, parse_comment_op)

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        comment = item.get("comment", "")

        try:
            ea = parse_address(addr_str)

            if not idaapi.set_cmt(ea, comment, False):
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set disassembly comment at {hex(ea)}",
                    }
                )
                continue

            if not ida_hexrays.init_hexrays_plugin():
                results.append({"addr": addr_str, "ok": True})
                continue

            try:
                cfunc = decompile_checked(ea)
            except IDAError:
                results.append({"addr": addr_str, "ok": True})
                continue

            if ea == cfunc.entry_ea:
                idc.set_func_cmt(ea, comment, True)
                cfunc.refresh_func_ctext()
                results.append({"addr": addr_str, "ok": True})
                continue

            eamap = cfunc.get_eamap()
            if ea not in eamap:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": True,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
                continue
            nearest_ea = eamap[ea][0].ea

            if cfunc.has_orphan_cmts():
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()

            tl = idaapi.treeloc_t()
            tl.ea = nearest_ea
            for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                tl.itp = itp
                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()
                if not cfunc.has_orphan_cmts():
                    results.append({"addr": addr_str, "ok": True})
                    break
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": True,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@tool
@idawrite
def patch_asm(
    items: Annotated[
        list[AsmPatchOp] | AsmPatchOp | str,
        "Assembly patch operations. Accepts list of {addr, asm} dicts or string shortcut: 'addr=asm;addr2=asm2'",
    ],
) -> list[dict]:
    """Patch assembly instructions at addresses"""
    items = normalize_dict_list(items, parse_asm_patch_op)

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        instructions = item.get("asm", "")

        try:
            ea = parse_address(addr_str)
            assembles = instructions.split(";")
            for assemble in assembles:
                assemble = assemble.strip()
                try:
                    (check_assemble, bytes_to_patch) = idautils.Assemble(ea, assemble)
                    if not check_assemble:
                        results.append(
                            {
                                "addr": addr_str,
                                "error": f"Failed to assemble: {assemble}",
                            }
                        )
                        break
                    ida_bytes.patch_bytes(ea, bytes_to_patch)
                    ea += len(bytes_to_patch)
                except Exception as e:
                    results.append(
                        {"addr": addr_str, "error": f"Failed at {hex(ea)}: {e}"}
                    )
                    break
            else:
                results.append({"addr": addr_str, "ok": True})
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


def _parse_func_rename(s: str) -> FunctionRename:
    """Parse 'addr=name' format for function renames"""
    if "=" in s:
        addr, name = s.split("=", 1)
        return {"addr": addr.strip(), "name": name.strip()}
    raise ValueError(f"Invalid function rename format: {s} (expected 'addr=name')")


def _parse_global_rename(s: str) -> GlobalRename:
    """Parse 'old=new' format for global renames"""
    if "=" in s:
        old, new = s.split("=", 1)
        return {"old": old.strip(), "new": new.strip()}
    raise ValueError(f"Invalid global rename format: {s} (expected 'old=new')")


def _parse_local_rename(s: str) -> LocalRename:
    """Parse 'func_addr:old=new' format for local variable renames"""
    if ":" in s and "=" in s:
        func_addr, rest = s.split(":", 1)
        old, new = rest.split("=", 1)
        return {
            "func_addr": func_addr.strip(),
            "old": old.strip(),
            "new": new.strip(),
        }
    raise ValueError(f"Invalid local rename format: {s} (expected 'func_addr:old=new')")


def _parse_stack_rename(s: str) -> StackRename:
    """Parse 'func_addr:old=new' format for stack variable renames"""
    if ":" in s and "=" in s:
        func_addr, rest = s.split(":", 1)
        old, new = rest.split("=", 1)
        return {
            "func_addr": func_addr.strip(),
            "old": old.strip(),
            "new": new.strip(),
        }
    raise ValueError(
        f"Invalid stack rename format: {s} (expected 'func_addr:old=new')"
    )


@tool
@idawrite
def rename(batch: RenameBatch) -> dict:
    """Unified rename operation for functions, globals, locals, and stack variables"""

    def _rename_funcs(items: list[FunctionRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                ea = parse_address(item["addr"])
                success = idaapi.set_name(ea, item["name"], idaapi.SN_CHECK)
                if success:
                    func = idaapi.get_func(ea)
                    if func:
                        refresh_decompiler_ctext(func.start_ea)
                results.append(
                    {
                        "addr": item["addr"],
                        "name": item["name"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"addr": item.get("addr"), "error": str(e)})
        return results

    def _rename_globals(items: list[GlobalRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                ea = idaapi.get_name_ea(idaapi.BADADDR, item["old"])
                if ea == idaapi.BADADDR:
                    results.append(
                        {
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": f"Global '{item['old']}' not found",
                        }
                    )
                    continue
                success = idaapi.set_name(ea, item["new"], idaapi.SN_CHECK)
                results.append(
                    {
                        "old": item["old"],
                        "new": item["new"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"old": item.get("old"), "error": str(e)})
        return results

    def _rename_locals(items: list[LocalRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                func = idaapi.get_func(parse_address(item["func_addr"]))
                if not func:
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": f"No function at specified address. Use list_funcs to find valid function addresses.",
                        }
                    )
                    continue
                success = ida_hexrays.rename_lvar(
                    func.start_ea, item["old"], item["new"]
                )
                if success:
                    refresh_decompiler_ctext(func.start_ea)
                results.append(
                    {
                        "func_addr": item["func_addr"],
                        "old": item["old"],
                        "new": item["new"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), "error": str(e)})
        return results

    def _rename_stack(items: list[StackRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                func = idaapi.get_func(parse_address(item["func_addr"]))
                if not func:
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": f"No function at specified address. Use list_funcs to find valid function addresses.",
                        }
                    )
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "Function has no stack frame (may be a thunk or leaf function)",
                        }
                    )
                    continue

                idx, udm = frame_tif.get_udm(item["old"])
                if not udm:
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": f"'{item['old']}' not found",
                        }
                    )
                    continue

                tid = frame_tif.get_udm_tid(idx)
                if ida_frame.is_special_frame_member(tid):
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "Special frame member",
                        }
                    )
                    continue

                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "Argument member",
                        }
                    )
                    continue

                sval = ida_frame.soff_to_fpoff(func, offset)
                success = ida_frame.define_stkvar(func, item["new"], sval, udm.type)
                results.append(
                    {
                        "func_addr": item["func_addr"],
                        "old": item["old"],
                        "new": item["new"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), "error": str(e)})
        return results

    # Process each category (keys match RenameBatch TypedDict)
    result = {}
    if "func" in batch:
        result["func"] = _rename_funcs(
            normalize_dict_list(batch["func"], _parse_func_rename)
        )
    if "data" in batch:
        result["data"] = _rename_globals(
            normalize_dict_list(batch["data"], _parse_global_rename)
        )
    if "local" in batch:
        result["local"] = _rename_locals(
            normalize_dict_list(batch["local"], _parse_local_rename)
        )
    if "stack" in batch:
        result["stack"] = _rename_stack(
            normalize_dict_list(batch["stack"], _parse_stack_rename)
        )

    return result


# ============================================================================
# Code/Data Definition Operations
# ============================================================================


@tool
@idawrite
def make_code(
    addrs: Annotated[list[str] | str, "Address(es) to convert to code"],
) -> list[dict]:
    """Convert bytes at addresses to code instructions.

    Use this when you need to disassemble raw bytes that IDA hasn't recognized as code.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)

            # Check if already code
            if idaapi.is_code(idaapi.get_flags(ea)):
                insn = idaapi.insn_t()
                length = idaapi.decode_insn(insn, ea)
                results.append({
                    "addr": addr_str,
                    "ok": True,
                    "length": length,
                    "note": "Already code",
                })
                continue

            # Try to create instruction
            length = idc.create_insn(ea)
            if length > 0:
                results.append({
                    "addr": addr_str,
                    "ok": True,
                    "length": length,
                })
            else:
                results.append({
                    "addr": addr_str,
                    "ok": False,
                    "error": f"Failed to create instruction at {hex(ea)}. "
                             "Bytes may not form a valid instruction.",
                })
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    return results


@tool
@idawrite
def make_data(
    addrs: Annotated[list[str] | str, "Address(es) to define as data"],
    size: Annotated[int, "Data size: 1=byte, 2=word, 4=dword, 8=qword"] = 1,
) -> list[dict]:
    """Define data items at addresses.

    Size values: 1=byte, 2=word, 4=dword, 8=qword
    """
    addrs = normalize_list_input(addrs)
    results = []

    size_map = {
        1: (ida_bytes.FF_BYTE, "byte"),
        2: (ida_bytes.FF_WORD, "word"),
        4: (ida_bytes.FF_DWORD, "dword"),
        8: (ida_bytes.FF_QWORD, "qword"),
    }

    if size not in size_map:
        return [{"error": f"Invalid size {size}. Use 1, 2, 4, or 8."}]

    flag, type_name = size_map[size]

    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)

            # Undefine first if needed
            if not idc.del_items(ea, idc.DELIT_SIMPLE, size):
                pass  # Not critical if this fails

            if ida_bytes.create_data(ea, flag, size, idaapi.BADADDR):
                results.append({
                    "addr": addr_str,
                    "ok": True,
                    "type": type_name,
                    "size": size,
                })
            else:
                results.append({
                    "addr": addr_str,
                    "ok": False,
                    "error": f"Failed to create {type_name} at {hex(ea)}",
                })
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    return results


@tool
@idawrite
def make_string(
    addrs: Annotated[list[str] | str, "Address(es) to define as strings"],
    string_type: Annotated[str, "String type: c, pascal, len2, unicode, len4"] = "c",
) -> list[dict]:
    """Define strings at addresses.

    String types:
    - c: C-style null-terminated (default)
    - pascal: Pascal-style with length byte
    - len2: 2-byte length prefix
    - unicode: Wide/Unicode string
    - len4: 4-byte length prefix
    """
    addrs = normalize_list_input(addrs)
    results = []

    type_map = {
        "c": ida_nalt.STRTYPE_C,
        "pascal": ida_nalt.STRTYPE_PASCAL,
        "len2": ida_nalt.STRTYPE_LEN2,
        "unicode": ida_nalt.STRTYPE_C_16,
        "len4": ida_nalt.STRTYPE_LEN4,
    }

    if string_type not in type_map:
        return [{"error": f"Invalid string type '{string_type}'. Use: {', '.join(type_map.keys())}"}]

    strtype = type_map[string_type]

    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)

            # Try to create the string
            length = ida_bytes.create_strlit(ea, 0, strtype)
            if length > 0:
                # Read the created string
                string_val = idc.get_strlit_contents(ea, -1, strtype)
                if string_val:
                    try:
                        string_val = string_val.decode('utf-8', errors='replace')
                    except AttributeError:
                        pass
                results.append({
                    "addr": addr_str,
                    "ok": True,
                    "length": length,
                    "value": string_val[:100] if string_val else None,  # Truncate long strings
                })
            else:
                results.append({
                    "addr": addr_str,
                    "ok": False,
                    "error": f"Failed to create string at {hex(ea)}. "
                             "May not be a valid string.",
                })
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    return results


@tool
@idawrite
def make_array(
    addr: Annotated[str, "Start address of the array"],
    count: Annotated[int, "Number of elements"],
    element_size: Annotated[int, "Size of each element: 1, 2, 4, or 8"] = 1,
) -> dict:
    """Create an array of data items at an address."""
    try:
        ea = parse_address(addr)

        size_map = {
            1: (ida_bytes.FF_BYTE, "byte"),
            2: (ida_bytes.FF_WORD, "word"),
            4: (ida_bytes.FF_DWORD, "dword"),
            8: (ida_bytes.FF_QWORD, "qword"),
        }

        if element_size not in size_map:
            return {"addr": addr, "ok": False, "error": f"Invalid element_size {element_size}. Use 1, 2, 4, or 8."}

        flag, type_name = size_map[element_size]
        total_size = count * element_size

        # Undefine the range first
        idc.del_items(ea, idc.DELIT_SIMPLE, total_size)

        # Create the array
        if ida_bytes.create_data(ea, flag, element_size, idaapi.BADADDR):
            if idc.make_array(ea, count):
                return {
                    "addr": addr,
                    "ok": True,
                    "element_type": type_name,
                    "count": count,
                    "total_size": total_size,
                }

        return {
            "addr": addr,
            "ok": False,
            "error": f"Failed to create array at {hex(ea)}",
        }
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


@tool
@idawrite
def undefine(
    addrs: Annotated[list[str] | str, "Address(es) to undefine"],
    size: Annotated[int, "Number of bytes to undefine (default: auto-detect item size)"] = 0,
) -> list[dict]:
    """Undefine items at addresses, converting them back to raw bytes.

    If size is 0, undefines the entire item at that address.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)

            # Get item size if not specified
            if size == 0:
                item_size = idc.get_item_size(ea)
            else:
                item_size = size

            if idc.del_items(ea, idc.DELIT_SIMPLE, item_size):
                results.append({
                    "addr": addr_str,
                    "ok": True,
                    "size": item_size,
                })
            else:
                results.append({
                    "addr": addr_str,
                    "ok": False,
                    "error": f"Failed to undefine at {hex(ea)}",
                })
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    return results


# ============================================================================
# Function Management Operations
# ============================================================================


@tool
@idawrite
def set_function_bounds(
    addr: Annotated[str, "Address inside the function"],
    start: Annotated[str, "New start address (optional)"] = "",
    end: Annotated[str, "New end address (optional)"] = "",
) -> dict:
    """Set function boundaries manually.

    Provide either start, end, or both to adjust function bounds.
    """
    try:
        ea = parse_address(addr)
        func = idaapi.get_func(ea)

        if not func:
            return {
                "addr": addr,
                "ok": False,
                "error": f"No function at {hex(ea)}. Use make_function first.",
            }

        old_start = func.start_ea
        old_end = func.end_ea
        func_name = ida_funcs.get_func_name(old_start)

        new_start = parse_address(start) if start else old_start
        new_end = parse_address(end) if end else old_end

        if new_start >= new_end:
            return {
                "addr": addr,
                "ok": False,
                "error": f"Invalid bounds: start ({hex(new_start)}) must be less than end ({hex(new_end)})",
            }

        # Set the new bounds
        if ida_funcs.set_func_start(old_start, new_start) or new_start == old_start:
            if ida_funcs.set_func_end(new_start, new_end) or new_end == old_end:
                return {
                    "addr": addr,
                    "ok": True,
                    "name": func_name,
                    "old_bounds": {"start": hex(old_start), "end": hex(old_end)},
                    "new_bounds": {"start": hex(new_start), "end": hex(new_end)},
                }

        return {
            "addr": addr,
            "ok": False,
            "error": "Failed to set function bounds. The new range may conflict with existing items.",
        }
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


@tool
@idawrite
def append_func_chunk(
    func_addr: Annotated[str, "Address of the function to extend"],
    chunk_start: Annotated[str, "Start address of the chunk to append"],
    chunk_end: Annotated[str, "End address of the chunk to append"],
) -> dict:
    """Append a non-contiguous chunk to a function.

    Use this for functions with separated code blocks (e.g., exception handlers,
    cold code moved by optimizer).
    """
    try:
        func_ea = parse_address(func_addr)
        start = parse_address(chunk_start)
        end = parse_address(chunk_end)

        func = idaapi.get_func(func_ea)
        if not func:
            return {
                "func_addr": func_addr,
                "ok": False,
                "error": f"No function at {hex(func_ea)}",
            }

        func_name = ida_funcs.get_func_name(func.start_ea)

        if ida_funcs.append_func_tail(func, start, end):
            return {
                "func_addr": func_addr,
                "ok": True,
                "name": func_name,
                "chunk": {"start": hex(start), "end": hex(end)},
            }
        else:
            return {
                "func_addr": func_addr,
                "ok": False,
                "error": f"Failed to append chunk. Range may overlap with existing items.",
            }
    except Exception as e:
        return {"func_addr": func_addr, "ok": False, "error": str(e)}


@tool
@idawrite
def reanalyze(
    start: Annotated[str, "Start address of range to reanalyze"],
    end: Annotated[str, "End address of range to reanalyze (optional, default: single item)"] = "",
) -> dict:
    """Force IDA to reanalyze an address range.

    Useful after making manual changes or when IDA's initial analysis was incomplete.
    """
    try:
        start_ea = parse_address(start)
        end_ea = parse_address(end) if end else start_ea + idc.get_item_size(start_ea)

        # Mark for reanalysis
        ida_auto.plan_range(start_ea, end_ea)

        # Wait for analysis to complete (with timeout)
        ida_auto.auto_wait()

        return {
            "ok": True,
            "range": {"start": hex(start_ea), "end": hex(end_ea)},
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ============================================================================
# Navigation & Bookmarks
# ============================================================================


@tool
@idawrite
def jump_to(
    addr: Annotated[str, "Address to jump to in IDA GUI"],
) -> dict:
    """Jump to an address in the IDA GUI.

    Moves the cursor to the specified address in the disassembly view.
    """
    try:
        ea = parse_address(addr)

        if idaapi.jumpto(ea):
            return {"addr": addr, "ok": True}
        else:
            return {
                "addr": addr,
                "ok": False,
                "error": f"Failed to jump to {hex(ea)}. Address may be invalid.",
            }
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


@tool
@idawrite
def add_bookmark(
    addr: Annotated[str, "Address to bookmark"],
    description: Annotated[str, "Bookmark description"] = "",
) -> dict:
    """Add a bookmark at an address.

    Bookmarks can be viewed in IDA's Jump > Jump to marked position menu.
    """
    try:
        ea = parse_address(addr)

        # Find first free slot
        slot = 1
        while slot <= 1024:
            if idc.get_bookmark(slot) == idaapi.BADADDR:
                break
            slot += 1

        if slot > 1024:
            return {
                "addr": addr,
                "ok": False,
                "error": "No free bookmark slots available",
            }

        idc.put_bookmark(ea, 0, 0, 0, slot, description)
        return {
            "addr": addr,
            "ok": True,
            "slot": slot,
            "description": description,
        }
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


@tool
@idawrite
def delete_bookmark(
    slot: Annotated[int, "Bookmark slot number to delete"],
) -> dict:
    """Delete a bookmark by slot number."""
    try:
        current = idc.get_bookmark(slot)
        if current == idaapi.BADADDR:
            return {
                "slot": slot,
                "ok": False,
                "error": f"No bookmark in slot {slot}",
            }

        idc.put_bookmark(idaapi.BADADDR, 0, 0, 0, slot, "")
        return {
            "slot": slot,
            "ok": True,
            "deleted_addr": hex(current),
        }
    except Exception as e:
        return {"slot": slot, "ok": False, "error": str(e)}


@tool
@idawrite
def list_bookmarks() -> list[dict]:
    """List all bookmarks in the database."""
    results = []
    for slot in range(1, 1025):
        addr = idc.get_bookmark(slot)
        if addr != idaapi.BADADDR:
            desc = idc.get_bookmark_desc(slot)
            results.append({
                "slot": slot,
                "addr": hex(addr),
                "description": desc or "",
            })
    return results


# ============================================================================
# Enum Operations
# ============================================================================


@tool
@idawrite
def create_enum(
    name: Annotated[str, "Name of the enum"],
    members: Annotated[list[dict] | str, "List of {name, value} dicts or 'name=value;name2=value2' string"] = "",
    bitfield: Annotated[bool, "Create as bitfield enum (for flags)"] = False,
) -> dict:
    """Create an enumeration type.

    Members can be provided as:
    - List of dicts: [{"name": "VALUE1", "value": 0}, {"name": "VALUE2", "value": 1}]
    - String: "VALUE1=0;VALUE2=1"
    """
    try:
        # Check if enum already exists (IDA 9.0 uses ida_typeinf)
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, name, ida_typeinf.BTF_ENUM):
            return {
                "name": name,
                "ok": False,
                "error": f"Enum '{name}' already exists",
            }

        # Parse members
        parsed_members = []
        if members:
            if isinstance(members, str):
                for part in members.split(";"):
                    if "=" in part:
                        n, v = part.split("=", 1)
                        parsed_members.append({"name": n.strip(), "value": int(v.strip(), 0)})
            else:
                parsed_members = members

        # Create enum using ida_typeinf (IDA 9.0 API)
        edt = ida_typeinf.enum_type_data_t()
        edm = ida_typeinf.edm_t()

        for member in parsed_members:
            edm.name = member["name"]
            edm.value = member["value"]
            edt.push_back(edm)

        tif = ida_typeinf.tinfo_t()
        if not tif.create_enum(edt):
            return {
                "name": name,
                "ok": False,
                "error": "Failed to create enum type",
            }

        if bitfield:
            tif.set_enum_is_bitmask(ida_typeinf.tinfo_t.ENUMBM_ON)

        # Save the enum with the given name (None = local type library)
        if tif.set_named_type(None, name) != ida_typeinf.TERR_OK:
            return {
                "name": name,
                "ok": False,
                "error": "Failed to save enum to type library",
            }

        return {
            "name": name,
            "ok": True,
            "bitfield": bitfield,
            "members_added": len(parsed_members),
        }
    except Exception as e:
        return {"name": name, "ok": False, "error": str(e)}


@tool
@idawrite
def add_enum_member(
    enum_name: Annotated[str, "Name of the enum"],
    member_name: Annotated[str, "Name of the new member"],
    value: Annotated[int, "Value of the member"],
) -> dict:
    """Add a member to an existing enum."""
    try:
        # IDA 9.0: Use ida_typeinf
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, enum_name, ida_typeinf.BTF_ENUM):
            return {
                "enum_name": enum_name,
                "ok": False,
                "error": f"Enum '{enum_name}' not found",
            }

        # Get existing enum details
        edt = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(edt):
            return {
                "enum_name": enum_name,
                "ok": False,
                "error": "Failed to get enum details",
            }

        # Add new member
        edm = ida_typeinf.edm_t()
        edm.name = member_name
        edm.value = value
        edt.push_back(edm)

        # Recreate the enum with the new member
        new_tif = ida_typeinf.tinfo_t()
        if not new_tif.create_enum(edt):
            return {
                "enum_name": enum_name,
                "ok": False,
                "error": "Failed to update enum",
            }

        # Preserve bitmask setting
        if edt.is_bf():
            new_tif.set_enum_is_bitmask(ida_typeinf.tinfo_t.ENUMBM_ON)

        # Save the updated enum (None = local type library)
        if new_tif.set_named_type(None, enum_name) != ida_typeinf.TERR_OK:
            return {
                "enum_name": enum_name,
                "ok": False,
                "error": "Failed to save updated enum",
            }

        return {
            "enum_name": enum_name,
            "member_name": member_name,
            "value": value,
            "ok": True,
        }
    except Exception as e:
        return {"enum_name": enum_name, "ok": False, "error": str(e)}


@tool
@idawrite
def apply_enum(
    addr: Annotated[str, "Address of the instruction"],
    enum_name: Annotated[str, "Name of the enum to apply"],
    operand: Annotated[int, "Operand number (0 for first operand, 1 for second, etc.)"] = 0,
) -> dict:
    """Apply an enum type to an instruction operand.

    This converts numeric constants to meaningful enum names in the disassembly.
    """
    try:
        ea = parse_address(addr)

        # IDA 9.0: Check if enum exists using ida_typeinf
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, enum_name, ida_typeinf.BTF_ENUM):
            return {
                "addr": addr,
                "ok": False,
                "error": f"Enum '{enum_name}' not found",
            }

        # Get the enum's tid for op_enum
        enum_tid = tif.get_tid()
        if enum_tid == idaapi.BADADDR:
            return {
                "addr": addr,
                "ok": False,
                "error": f"Could not get type ID for enum '{enum_name}'",
            }

        # Apply the enum to the operand using ida_bytes.op_enum
        if ida_bytes.op_enum(ea, operand, enum_tid, 0):
            return {
                "addr": addr,
                "ok": True,
                "enum": enum_name,
                "operand": operand,
            }
        else:
            return {
                "addr": addr,
                "ok": False,
                "error": f"Failed to apply enum to operand {operand}. "
                         "Ensure the operand contains a numeric value.",
            }
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


@tool
@idawrite
def list_enums() -> list[dict]:
    """List all enums in the database."""
    results = []

    # IDA 9.0: Use ida_typeinf to iterate through all types
    limit = ida_typeinf.get_ordinal_limit()

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        # Get only enum types (no til argument in IDA 9.0)
        if not tif.get_numbered_type(ordinal, ida_typeinf.BTF_ENUM):
            continue

        name = tif.get_type_name()
        if not name:
            continue

        # Get enum details
        edt = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(edt):
            continue

        is_bitfield = edt.is_bf()

        # Get members
        members = []
        for i in range(min(edt.size(), 20)):  # Limit to first 20
            edm = edt[i]
            members.append({
                "name": edm.name,
                "value": edm.value,
            })

        results.append({
            "name": name,
            "ordinal": ordinal,
            "bitfield": is_bitfield,
            "member_count": edt.size(),
            "members": members,
        })

    return results


# ============================================================================
# Signature Operations
# ============================================================================


@tool
@idawrite
def apply_flirt(
    sig_name: Annotated[str, "Name of the FLIRT signature file (without .sig extension)"],
) -> dict:
    """Apply a FLIRT signature file to identify library functions.

    Signature files should be in IDA's sig directory.
    """
    try:
        # Try to load the signature
        result = idc.plan_to_apply_idasgn(sig_name)

        if result == 1:
            return {
                "sig_name": sig_name,
                "ok": True,
                "note": "Signature application scheduled. Run reanalyze() if needed.",
            }
        elif result == 0:
            return {
                "sig_name": sig_name,
                "ok": False,
                "error": f"Signature file '{sig_name}' not found in IDA's sig directory",
            }
        else:
            return {
                "sig_name": sig_name,
                "ok": False,
                "error": "Signature already applied or error occurred",
            }
    except Exception as e:
        return {"sig_name": sig_name, "ok": False, "error": str(e)}


@tool
@idawrite
def apply_til(
    til_name: Annotated[str, "Name of the type library (e.g., 'mssdk64_win10', 'gnulnx_x64')"],
) -> dict:
    """Load a type library (.til) to import type definitions.

    Common type libraries:
    - mssdk64_win10, mssdk_win10: Windows SDK
    - ntddk64_win10, ntddk_win10: Windows Driver Kit
    - gnulnx_x64, gnulnx_x86: GNU/Linux
    - macosx64, macosx: macOS
    """
    try:
        # Add the type library
        til = ida_typeinf.add_til(til_name, ida_typeinf.ADDTIL_DEFAULT)

        if til:
            return {
                "til_name": til_name,
                "ok": True,
            }
        else:
            return {
                "til_name": til_name,
                "ok": False,
                "error": f"Failed to load type library '{til_name}'. Check if it exists in IDA's til directory.",
            }
    except Exception as e:
        return {"til_name": til_name, "ok": False, "error": str(e)}


# ============================================================================
# Segment Operations
# ============================================================================


@tool
@idawrite
def create_segment(
    start: Annotated[str, "Start address of the segment"],
    end: Annotated[str, "End address of the segment"],
    name: Annotated[str, "Name of the segment"],
    seg_class: Annotated[str, "Segment class (CODE, DATA, BSS, STACK, etc.)"] = "DATA",
    align: Annotated[int, "Alignment (0=byte, 1=word, 2=dword, 3=para, 4=page)"] = 0,
) -> dict:
    """Create a new memory segment.

    Use this to define memory regions for analysis.
    """
    try:
        start_ea = parse_address(start)
        end_ea = parse_address(end)

        # Create segment
        seg = idaapi.segment_t()
        seg.start_ea = start_ea
        seg.end_ea = end_ea
        seg.align = align
        seg.comb = idaapi.scPub  # Public

        # Set segment type based on class
        class_map = {
            "CODE": idaapi.SEG_CODE,
            "DATA": idaapi.SEG_DATA,
            "BSS": idaapi.SEG_BSS,
            "STACK": idaapi.SEG_DATA,
            "XTRN": idaapi.SEG_XTRN,
            "NULL": idaapi.SEG_NULL,
        }
        seg.type = class_map.get(seg_class.upper(), idaapi.SEG_DATA)

        if idaapi.add_segm_ex(seg, name, seg_class, idaapi.ADDSEG_OR_DIE):
            return {
                "name": name,
                "ok": True,
                "start": hex(start_ea),
                "end": hex(end_ea),
                "class": seg_class,
                "size": hex(end_ea - start_ea),
            }
        else:
            return {
                "name": name,
                "ok": False,
                "error": "Failed to create segment. Range may overlap with existing segment.",
            }
    except Exception as e:
        return {"name": name, "ok": False, "error": str(e)}


@tool
@idawrite
def delete_segment(
    addr: Annotated[str, "Address within the segment to delete"],
    keep_bytes: Annotated[bool, "Keep the bytes (True) or zero them (False)"] = True,
) -> dict:
    """Delete a segment.

    If keep_bytes is True, the bytes are preserved. Otherwise they are zeroed.
    """
    try:
        ea = parse_address(addr)

        seg = idaapi.getseg(ea)
        if not seg:
            return {
                "addr": addr,
                "ok": False,
                "error": f"No segment at {hex(ea)}",
            }

        name = idaapi.get_segm_name(seg)
        start = seg.start_ea
        end = seg.end_ea

        flags = idaapi.SEGMOD_KEEP if keep_bytes else idaapi.SEGMOD_KILL
        if idaapi.del_segm(start, flags):
            return {
                "addr": addr,
                "ok": True,
                "deleted": {
                    "name": name,
                    "start": hex(start),
                    "end": hex(end),
                },
            }
        else:
            return {
                "addr": addr,
                "ok": False,
                "error": f"Failed to delete segment '{name}'",
            }
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}
