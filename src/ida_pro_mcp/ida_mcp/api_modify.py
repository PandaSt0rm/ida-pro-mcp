from typing import Annotated, Literal

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
import ida_lines
import ida_offset
import ida_kernwin

from .rpc import tool
from .sync import idasync, IDAError
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
from .tests import (
    test,
    assert_has_keys,
    assert_is_list,
    get_any_function,
)


# ============================================================================
# Modification Operations
# ============================================================================


@tool
@idasync
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
@idasync
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
@idasync
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


@test()
def test_set_comment_roundtrip():
    """set_comments can set and clear comments"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Get original comment (may be None/empty)
    original_comment = idc.get_cmt(int(fn_addr, 16), False) or ""

    try:
        # Set a test comment
        result = set_comments({"addr": fn_addr, "comment": "__test_comment__"})
        assert_is_list(result, min_length=1)
        assert_has_keys(result[0], "addr")
        # Either "ok" or "error" should be present
        assert "ok" in result[0] or "error" in result[0]

        # Verify comment was set
        new_comment = idc.get_cmt(int(fn_addr, 16), False)
        assert new_comment == "__test_comment__", (
            f"Expected '__test_comment__', got {new_comment!r}"
        )
    finally:
        # Restore original comment
        set_comments({"addr": fn_addr, "comment": original_comment})


@tool
@idasync
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


@test()
def test_patch_asm():
    """patch_asm returns proper result structure"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Get original bytes at function start for potential restore
    ea = int(fn_addr, 16)
    original_bytes = ida_bytes.get_bytes(ea, 16)
    if not original_bytes:
        return  # Skip if can't read bytes

    # Try to assemble a NOP (this may fail depending on architecture)
    # We're just testing the API returns proper structure, not necessarily succeeding
    result = patch_asm({"addr": fn_addr, "asm": "nop"})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr")
    # Result should have either "ok" or "error"
    assert "ok" in result[0] or "error" in result[0]

    # Restore original bytes if patch succeeded
    if result[0].get("ok"):
        ida_bytes.patch_bytes(ea, original_bytes)


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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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
@idasync
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


# ============================================================================
# Item Colors
# ============================================================================


@tool
@idasync
def set_color(
    addrs: Annotated[list[str] | str, "Addresses to set color for"],
    color: Annotated[int, "RGB color value (e.g., 0xFFFF00 for yellow). Use 0xFFFFFFFF to reset to default."],
) -> list[dict]:
    """Set background color for items (instructions/data).

    Color is in RGB format (0xBBGGRR in IDA's internal format).
    Use 0xFFFFFFFF to reset to default color.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            ida_nalt.set_item_color(ea, color)
            results.append({"addr": addr, "color": hex(color), "ok": True, "error": None})
        except Exception as e:
            results.append({"addr": addr, "ok": False, "error": str(e)})

    return results


@tool
@idasync
def get_color(
    addrs: Annotated[list[str] | str, "Addresses to get color for"],
) -> list[dict]:
    """Get background color of items (instructions/data)."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            color = ida_nalt.get_item_color(ea)
            results.append({
                "addr": addr,
                "color": hex(color) if color != 0xFFFFFFFF else None,
                "has_color": color != 0xFFFFFFFF,
                "error": None,
            })
        except Exception as e:
            results.append({"addr": addr, "color": None, "has_color": False, "error": str(e)})

    return results


# ============================================================================
# Operand Type Changes
# ============================================================================


@tool
@idasync
def op_offset(
    addrs: Annotated[list[str] | str, "Addresses to change operand to offset"],
    operand: Annotated[int, "Operand number (0=first, 1=second, -1=all)"] = 0,
    base: Annotated[str | None, "Base address for offset (default: auto-detect)"] = None,
) -> list[dict]:
    """Make an operand an offset (pointer).

    Converts numeric operand to display as an offset/reference to another address.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            base_ea = parse_address(base) if base else 0

            if idc.op_plain_offset(ea, operand, base_ea):
                results.append({"addr": addr, "operand": operand, "ok": True, "error": None})
            else:
                results.append({"addr": addr, "operand": operand, "ok": False, "error": "Failed to set offset"})
        except Exception as e:
            results.append({"addr": addr, "operand": operand, "ok": False, "error": str(e)})

    return results


@tool
@idasync
def op_number(
    addrs: Annotated[list[str] | str, "Addresses to change operand representation"],
    operand: Annotated[int, "Operand number (0=first, 1=second, -1=all)"] = 0,
    radix: Annotated[Literal["hex", "dec", "oct", "bin", "char"], "Number representation"] = "hex",
) -> list[dict]:
    """Change operand number representation.

    Changes how a numeric operand is displayed (hex, decimal, octal, binary, or char).
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)

            success = False
            if radix == "hex":
                success = idc.op_hex(ea, operand)
            elif radix == "dec":
                success = idc.op_dec(ea, operand)
            elif radix == "oct":
                success = idc.op_oct(ea, operand)
            elif radix == "bin":
                success = idc.op_bin(ea, operand)
            elif radix == "char":
                success = idc.op_chr(ea, operand)

            if success:
                results.append({"addr": addr, "operand": operand, "radix": radix, "ok": True, "error": None})
            else:
                results.append({"addr": addr, "operand": operand, "radix": radix, "ok": False, "error": "Failed to change representation"})
        except Exception as e:
            results.append({"addr": addr, "operand": operand, "radix": radix, "ok": False, "error": str(e)})

    return results


@tool
@idasync
def clr_op_type(
    addrs: Annotated[list[str] | str, "Addresses to clear operand type"],
    operand: Annotated[int, "Operand number (0=first, 1=second, -1=all)"] = 0,
) -> list[dict]:
    """Clear operand type/representation, reverting to default."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if ida_bytes.clr_op_type(ea, operand):
                results.append({"addr": addr, "operand": operand, "ok": True, "error": None})
            else:
                results.append({"addr": addr, "operand": operand, "ok": False, "error": "Failed to clear operand type"})
        except Exception as e:
            results.append({"addr": addr, "operand": operand, "ok": False, "error": str(e)})

    return results


# ============================================================================
# Function Comments
# ============================================================================


@tool
@idasync
def set_func_cmt(
    addrs: Annotated[list[str] | str, "Function addresses to set comment for"],
    comment: Annotated[str, "Comment text"],
    repeatable: Annotated[bool, "Repeatable comment (shown at call sites)"] = False,
) -> list[dict]:
    """Set a function-level comment.

    Function comments appear at the function header, not at specific addresses.
    Repeatable function comments are also shown at call sites.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)

            # Get function containing address
            func = idaapi.get_func(ea)
            if not func:
                results.append({
                    "addr": addr,
                    "ok": False,
                    "error": f"No function at {hex(ea)}",
                })
                continue

            # Set the function comment
            if idc.set_func_cmt(func.start_ea, comment, repeatable):
                results.append({
                    "addr": addr,
                    "function": ida_funcs.get_func_name(func.start_ea),
                    "repeatable": repeatable,
                    "ok": True,
                    "error": None,
                })
            else:
                results.append({
                    "addr": addr,
                    "ok": False,
                    "error": "Failed to set function comment",
                })
        except Exception as e:
            results.append({"addr": addr, "ok": False, "error": str(e)})

    return results


@tool
@idasync
def get_func_cmt(
    addrs: Annotated[list[str] | str, "Function addresses to get comment for"],
    repeatable: Annotated[bool, "Get repeatable comment (vs regular)"] = False,
) -> list[dict]:
    """Get function-level comments."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)

            # Get function containing address
            func = idaapi.get_func(ea)
            if not func:
                results.append({
                    "addr": addr,
                    "comment": None,
                    "error": f"No function at {hex(ea)}",
                })
                continue

            comment = idc.get_func_cmt(func.start_ea, repeatable)
            results.append({
                "addr": addr,
                "function": ida_funcs.get_func_name(func.start_ea),
                "comment": comment if comment else None,
                "repeatable": repeatable,
                "error": None,
            })
        except Exception as e:
            results.append({"addr": addr, "comment": None, "error": str(e)})

    return results


# ============================================================================
# Anterior / Posterior Comments (Extra Lines)
# ============================================================================


@tool
@idasync
def set_extra_cmt(
    addrs: Annotated[list[str] | str, "Addresses to set extra comment for"],
    comment: Annotated[str, "Comment text (can be multiline with \\n)"],
    position: Annotated[Literal["anterior", "posterior"], "Before (anterior) or after (posterior) the address"] = "anterior",
) -> list[dict]:
    """Set anterior or posterior extra comments.

    Anterior comments appear before the address as separate lines.
    Posterior comments appear after the address.
    These are useful for extended documentation, ASCII art, or section headers.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)

            # Split into lines and add each
            lines = comment.split("\n")

            if position == "anterior":
                base_line = ida_lines.E_PREV
            else:
                base_line = ida_lines.E_NEXT

            # First, delete any existing extra comments
            for i in range(1000):
                if ida_lines.get_extra_cmt(ea, base_line + i) is None:
                    break
                ida_lines.del_extra_cmt(ea, base_line + i)

            # Add new comment lines
            for i, line in enumerate(lines):
                ida_lines.add_extra_cmt(ea, base_line + i, line)

            results.append({
                "addr": addr,
                "position": position,
                "lines": len(lines),
                "ok": True,
                "error": None,
            })
        except Exception as e:
            results.append({"addr": addr, "ok": False, "error": str(e)})

    return results


@tool
@idasync
def get_extra_cmt(
    addrs: Annotated[list[str] | str, "Addresses to get extra comments from"],
    position: Annotated[Literal["anterior", "posterior", "both"], "Which comments to get"] = "both",
) -> list[dict]:
    """Get anterior and/or posterior extra comments."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)

            result = {"addr": addr, "error": None}

            # Get anterior comments
            if position in ("anterior", "both"):
                anterior = []
                for i in range(1000):
                    cmt = ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + i)
                    if cmt is None:
                        break
                    anterior.append(cmt)
                result["anterior"] = anterior if anterior else None

            # Get posterior comments
            if position in ("posterior", "both"):
                posterior = []
                for i in range(1000):
                    cmt = ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT + i)
                    if cmt is None:
                        break
                    posterior.append(cmt)
                result["posterior"] = posterior if posterior else None

            results.append(result)
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@tool
@idasync
def del_extra_cmt(
    addrs: Annotated[list[str] | str, "Addresses to delete extra comments from"],
    position: Annotated[Literal["anterior", "posterior", "both"], "Which comments to delete"] = "both",
) -> list[dict]:
    """Delete anterior and/or posterior extra comments."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            deleted = {"anterior": 0, "posterior": 0}

            # Delete anterior comments
            if position in ("anterior", "both"):
                for i in range(1000):
                    if ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + i) is None:
                        break
                    ida_lines.del_extra_cmt(ea, ida_lines.E_PREV + i)
                    deleted["anterior"] += 1

            # Delete posterior comments
            if position in ("posterior", "both"):
                for i in range(1000):
                    if ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT + i) is None:
                        break
                    ida_lines.del_extra_cmt(ea, ida_lines.E_NEXT + i)
                    deleted["posterior"] += 1

            results.append({
                "addr": addr,
                "deleted": deleted,
                "ok": True,
                "error": None,
            })
        except Exception as e:
            results.append({"addr": addr, "ok": False, "error": str(e)})

    return results


@test()
def test_rename_function_roundtrip():
    """rename can rename and restore function names"""
    from .api_core import lookup_funcs

    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Get original name
    lookup_result = lookup_funcs(fn_addr)
    if not lookup_result or not lookup_result[0].get("fn"):
        return  # Skip if lookup failed
    original_name = lookup_result[0]["fn"]["name"]

    try:
        # Rename the function
        result = rename({"func": [{"addr": fn_addr, "name": "__test_func_name__"}]})
        assert_has_keys(result, "func")
        assert_is_list(result["func"], min_length=1)
        assert_has_keys(result["func"][0], "addr", "name", "ok")
        assert result["func"][0]["ok"], (
            f"Rename failed: {result['func'][0].get('error')}"
        )

        # Verify the change
        new_lookup = lookup_funcs(fn_addr)
        new_name = new_lookup[0]["fn"]["name"]
        assert new_name == "__test_func_name__", (
            f"Expected '__test_func_name__', got {new_name!r}"
        )
    finally:
        # Restore original name
        rename({"func": [{"addr": fn_addr, "name": original_name}]})


@test()
def test_rename_global_roundtrip():
    """rename can rename and restore global names"""
    from .api_core import list_globals

    # Get a global variable
    globals_result = list_globals({"count": 1})
    if not globals_result or not globals_result[0]["data"]:
        return  # Skip if no globals

    global_info = globals_result[0]["data"][0]
    original_name = global_info["name"]
    global_info["addr"]

    # Skip system globals that can't be renamed
    if original_name.startswith("__") or original_name.startswith("."):
        return

    result = {}
    try:
        # Rename the global
        result = rename(
            {"data": [{"old": original_name, "new": "__test_global_name__"}]}
        )
        assert_has_keys(result, "data")
        assert_is_list(result["data"], min_length=1)
        assert_has_keys(result["data"][0], "old", "new", "ok")

        # Only verify change if rename succeeded (some globals may not be renameable)
        if result["data"][0]["ok"]:
            # Verify we can look it up by new name
            ea = idaapi.get_name_ea(idaapi.BADADDR, "__test_global_name__")
            assert ea != idaapi.BADADDR, "Could not find renamed global"
    finally:
        # Restore original name (only if rename succeeded)
        if result.get("data") and result["data"][0].get("ok"):
            rename({"data": [{"old": "__test_global_name__", "new": original_name}]})


@test()
def test_rename_local_roundtrip():
    """rename can rename and restore local variable names"""
    from .api_analysis import decompile

    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Try to decompile to get local variables
    try:
        dec_result = decompile(fn_addr)
    except IDAError:
        return  # Skip if decompilation fails

    if not dec_result or dec_result[0].get("error"):
        return  # Skip if decompilation failed

    # Get local variables from decompiled code
    lvars = dec_result[0].get("lvars", [])
    if not lvars:
        return  # Skip if no local variables

    # Find a regular local (not argument)
    test_lvar = None
    for lvar in lvars:
        if not lvar.get("is_arg"):
            test_lvar = lvar
            break

    if not test_lvar:
        return  # Skip if no non-argument local found

    original_name = test_lvar["name"]

    result = {}
    try:
        # Rename the local variable
        result = rename(
            {
                "local": [
                    {
                        "func_addr": fn_addr,
                        "old": original_name,
                        "new": "__test_local__",
                    }
                ]
            }
        )
        assert_has_keys(result, "local")
        assert_is_list(result["local"], min_length=1)
        assert_has_keys(result["local"][0], "func_addr", "old", "new", "ok")

        # We don't assert ok=True because some locals may not be renameable
    finally:
        # Restore original name if rename succeeded
        if result.get("local") and result["local"][0].get("ok"):
            rename(
                {
                    "local": [
                        {
                            "func_addr": fn_addr,
                            "old": "__test_local__",
                            "new": original_name,
                        }
                    ]
                }
            )
