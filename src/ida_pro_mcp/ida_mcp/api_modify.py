import idaapi
import idautils
import idc
import ida_hexrays
import ida_bytes
import ida_typeinf
import ida_frame
import ida_dirtree
import ida_funcs
import ida_ua
import ida_auto
import ida_nalt
import ida_segment
import ida_lines

from .rpc import tool
from .sync import idasync, IDAError
from .utils import (
    parse_address,
    decompile_checked,
    refresh_decompiler_ctext,
    normalize_list_input,
    CommentOp,
    AsmPatchOp,
    FunctionRename,
    GlobalRename,
    LocalRename,
    StackRename,
    RenameBatch,
    DefineOp,
    UndefineOp,
)


# ============================================================================
# Modification Operations
# ============================================================================


@tool
@idasync
def set_comments(items: list[CommentOp] | CommentOp):
    """Set comments at addresses (both disassembly and decompiler views)"""
    if isinstance(items, dict):
        items = [items]

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
@idasync
def patch_asm(items: list[AsmPatchOp] | AsmPatchOp) -> list[dict]:
    """Patch assembly instructions at addresses"""
    if isinstance(items, dict):
        items = [items]

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


@tool
@idasync
def rename(batch: RenameBatch) -> dict:
    """Unified rename operation for functions, globals, locals, and stack variables"""

    def _normalize_items(items):
        """Convert single item or None to list"""
        if items is None:
            return []
        return [items] if isinstance(items, dict) else items

    def _has_user_name(ea: int) -> bool:
        flags = idaapi.get_flags(ea)
        checker = getattr(idaapi, "has_user_name", None)
        if checker is not None:
            return checker(flags)
        try:
            import ida_name

            checker = getattr(ida_name, "has_user_name", None)
            if checker is not None:
                return checker(flags)
        except Exception:
            pass
        return False

    def _place_func_in_vibe_dir(ea: int) -> tuple[bool, str | None]:
        tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        if tree is None:
            return False, "Function dirtree not available"

        if not tree.load():
            return False, "Failed to load function dirtree"

        vibe_path = "/vibe/"
        if not tree.isdir(vibe_path):
            err = tree.mkdir(vibe_path)
            if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                return False, f"mkdir failed: {err}"

        old_cwd = tree.getcwd()
        try:
            if tree.chdir(vibe_path) != ida_dirtree.DTE_OK:
                return False, "Failed to chdir to vibe"
            err = tree.link(ea)
            if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                return False, f"link failed: {err}"
            if not tree.save():
                return False, "Failed to save function dirtree"
        finally:
            if old_cwd:
                tree.chdir(old_cwd)

        return True, None

    def _rename_funcs(items: list[FunctionRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                ea = parse_address(item["addr"])
                had_user_name = _has_user_name(ea)
                success = idaapi.set_name(ea, item["name"], idaapi.SN_CHECK)
                if success:
                    func = idaapi.get_func(ea)
                    if func:
                        refresh_decompiler_ctext(func.start_ea)
                    if not had_user_name and func:
                        placed, place_error = _place_func_in_vibe_dir(func.start_ea)
                    else:
                        placed, place_error = None, None
                results.append(
                    {
                        "addr": item["addr"],
                        "name": item["name"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                        "dir": "vibe" if success and placed else None,
                        "dir_error": place_error if success else None,
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
    if "functions" in batch:
        result["functions"] = _rename_funcs(_normalize_items(batch["functions"]))
    if "globals" in batch:
        result["globals"] = _rename_globals(_normalize_items(batch["globals"]))
    if "locals" in batch:
        result["locals"] = _rename_locals(_normalize_items(batch["locals"]))
    if "stack" in batch:
        result["stack"] = _rename_stack(_normalize_items(batch["stack"]))

    return result


@tool
@idasync
def define_func(items: list[DefineOp] | DefineOp) -> list[dict]:
    """Define function(s) at address(es). IDA auto-determines bounds unless end address specified."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        end_str = item.get("end", "")

        try:
            start_ea = parse_address(addr_str)
            end_ea = parse_address(end_str) if end_str else idaapi.BADADDR

            # Check if already a function
            existing = idaapi.get_func(start_ea)
            if existing and existing.start_ea == start_ea:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "Function already exists at this address",
                    }
                )
                continue

            success = ida_funcs.add_func(start_ea, end_ea)
            if success:
                func = idaapi.get_func(start_ea)
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(func.start_ea),
                        "end": hex(func.end_ea),
                        "ok": True,
                    }
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "define_func failed",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@tool
@idasync
def define_code(items: list[DefineOp] | DefineOp) -> list[dict]:
    """Convert bytes to code instruction(s) at address(es)."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")

        try:
            ea = parse_address(addr_str)
            length = ida_ua.create_insn(ea)
            if length > 0:
                results.append(
                    {"addr": addr_str, "ea": hex(ea), "length": length, "ok": True}
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "ea": hex(ea),
                        "error": "Failed to create instruction",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@tool
@idasync
def undefine(items: list[UndefineOp] | UndefineOp) -> list[dict]:
    """Undefine item(s) at address(es), converting back to raw bytes."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        end_str = item.get("end", "")
        size = item.get("size", 0)

        try:
            start_ea = parse_address(addr_str)

            # Determine size from end address or explicit size
            if end_str:
                end_ea = parse_address(end_str)
                nbytes = end_ea - start_ea
            elif size:
                nbytes = size
            else:
                # Default: undefine single item
                nbytes = 1

            success = ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, nbytes)
            if success:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "size": nbytes,
                        "ok": True,
                    }
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "undefine failed",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


# ============================================================================
# Legacy Compatibility Operations
# ============================================================================


@tool
@idasync
def make_function(
    addrs: list[str] | str,
) -> list[dict]:
    """Create functions at specified addresses."""
    if isinstance(addrs, str):
        addrs = [x.strip() for x in addrs.split(",") if x.strip()]

    results = []
    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)
            existing = idaapi.get_func(ea)
            if existing:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": True,
                        "start": hex(existing.start_ea),
                        "end": hex(existing.end_ea),
                        "name": ida_funcs.get_func_name(existing.start_ea),
                    }
                )
                continue

            if not idaapi.is_code(idaapi.get_flags(ea)):
                if not idc.create_insn(ea):
                    results.append(
                        {
                            "addr": addr_str,
                            "ok": False,
                            "error": f"Address {hex(ea)} is not code. Try make_code() first.",
                        }
                    )
                    continue

            if not ida_funcs.add_func(ea, idaapi.BADADDR):
                flags = idaapi.get_flags(ea)
                if idaapi.is_tail(flags):
                    results.append(
                        {
                            "addr": addr_str,
                            "ok": False,
                            "error": f"Address {hex(ea)} is in the middle of another item.",
                        }
                    )
                else:
                    results.append(
                        {
                            "addr": addr_str,
                            "ok": False,
                            "error": f"Failed to create function at {hex(ea)}.",
                        }
                    )
                continue

            new_func = idaapi.get_func(ea)
            if new_func:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": True,
                        "start": hex(new_func.start_ea),
                        "end": hex(new_func.end_ea),
                        "name": ida_funcs.get_func_name(new_func.start_ea),
                    }
                )
            else:
                results.append(
                    {"addr": addr_str, "ok": False, "error": "Failed to retrieve created function"}
                )
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    return results


@tool
@idasync
def delete_function(addrs: list[str] | str) -> list[dict]:
    """Delete functions at specified addresses."""
    if isinstance(addrs, str):
        addrs = [x.strip() for x in addrs.split(",") if x.strip()]

    results = []
    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": False,
                        "error": f"No function at {hex(ea)}",
                    }
                )
                continue

            name = ida_funcs.get_func_name(func.start_ea)
            start_ea = func.start_ea
            end_ea = func.end_ea
            if ida_funcs.del_func(start_ea):
                results.append(
                    {
                        "addr": addr_str,
                        "ok": True,
                        "deleted": {
                            "name": name,
                            "start": hex(start_ea),
                            "end": hex(end_ea),
                        },
                    }
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": False,
                        "error": f"Failed to delete function {name}",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    return results


@tool
@idasync
def make_code(addrs: list[str] | str) -> list[dict]:
    """Convert bytes at addresses to code instructions."""
    if isinstance(addrs, str):
        addrs = [x.strip() for x in addrs.split(",") if x.strip()]
    return define_code([{"addr": a} for a in addrs])


@tool
@idasync
def make_data(
    addrs: list[str] | str,
    size: Annotated[int, "Data size: 1=byte, 2=word, 4=dword, 8=qword"] = 1,
) -> list[dict]:
    """Define data items."""
    if isinstance(addrs, str):
        addrs = [x.strip() for x in addrs.split(",") if x.strip()]

    size_map = {
        1: (ida_bytes.FF_BYTE, "byte"),
        2: (ida_bytes.FF_WORD, "word"),
        4: (ida_bytes.FF_DWORD, "dword"),
        8: (ida_bytes.FF_QWORD, "qword"),
    }

    if size not in size_map:
        return [{"ok": False, "error": f"Invalid size {size}. Use 1, 2, 4, or 8."}]

    flag, type_name = size_map[size]
    results = []
    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)
            if not idc.del_items(ea, idc.DELIT_SIMPLE, size):
                pass
            if ida_bytes.create_data(ea, flag, size, idaapi.BADADDR):
                results.append(
                    {"addr": addr_str, "ok": True, "type": type_name, "size": size}
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": False,
                        "error": f"Failed to define {type_name} at {hex(ea)}",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})
    return results


@tool
@idasync
def make_string(
    addrs: list[str] | str,
    string_type: Annotated[
        str, "String type: c, pascal, len2, unicode, len4"
    ] = "c",
) -> list[dict]:
    """Define strings at addresses."""
    if isinstance(addrs, str):
        addrs = [x.strip() for x in addrs.split(",") if x.strip()]

    type_map = {
        "c": ida_nalt.STRTYPE_C,
        "pascal": ida_nalt.STRTYPE_PASCAL,
        "len2": ida_nalt.STRTYPE_LEN2,
        "unicode": ida_nalt.STRTYPE_C_16,
        "len4": ida_nalt.STRTYPE_LEN4,
    }
    if string_type not in type_map:
        return [
            {"ok": False, "error": f"Invalid string type '{string_type}'. Use: {', '.join(type_map)}"}
        ]

    strtype = type_map[string_type]
    results = []
    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)
            length = ida_bytes.create_strlit(ea, 0, strtype)
            if length <= 0:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": False,
                        "error": f"Failed to create string at {hex(ea)}",
                    }
                )
                continue
            value = idc.get_strlit_contents(ea, -1, strtype)
            if value:
                try:
                    value = value.decode("utf-8", errors="replace")
                except AttributeError:
                    pass
            results.append(
                {
                    "addr": addr_str,
                    "ok": True,
                    "length": length,
                    "value": value[:100] if value else None,
                }
            )
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
    """Create an array definition at an address."""
    try:
        ea = parse_address(addr)
        size_map = {
            1: (ida_bytes.FF_BYTE, "byte"),
            2: (ida_bytes.FF_WORD, "word"),
            4: (ida_bytes.FF_DWORD, "dword"),
            8: (ida_bytes.FF_QWORD, "qword"),
        }
        if element_size not in size_map:
            return {"addr": addr, "ok": False, "error": f"Invalid element_size {element_size}"}
        flag, type_name = size_map[element_size]
        total = count * element_size

        idc.del_items(ea, idc.DELIT_SIMPLE, total)
        if not ida_bytes.create_data(ea, flag, element_size, idaapi.BADADDR):
            return {
                "addr": addr,
                "ok": False,
                "error": f"Failed to create base element at {hex(ea)}",
            }
        if idc.make_array(ea, count):
            return {
                "addr": addr,
                "ok": True,
                "element_type": type_name,
                "count": count,
                "total_size": total,
            }
        return {"addr": addr, "ok": False, "error": f"Failed to create array at {hex(ea)}"}
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


@tool
@idasync
def set_function_bounds(
    addr: Annotated[str, "Address inside a function"],
    start: Annotated[str, "New start address (optional)"] = "",
    end: Annotated[str, "New end address (optional)"] = "",
) -> dict:
    """Set function boundaries manually."""
    try:
        ea = parse_address(addr)
        func = idaapi.get_func(ea)
        if not func:
            return {
                "addr": addr,
                "ok": False,
                "error": f"No function at {hex(ea)}",
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
                "error": f"Invalid bounds: start {hex(new_start)} >= end {hex(new_end)}",
            }

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
            "error": "Failed to set function bounds",
        }
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


@tool
@idasync
def append_func_chunk(
    func_addr: Annotated[str, "Function address"],
    chunk_start: Annotated[str, "Chunk start address"],
    chunk_end: Annotated[str, "Chunk end address"],
) -> dict:
    """Append a non-contiguous chunk to a function."""
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
        name = ida_funcs.get_func_name(func.start_ea)
        if ida_funcs.append_func_tail(func, start, end):
            return {
                "func_addr": func_addr,
                "ok": True,
                "name": name,
                "chunk": {"start": hex(start), "end": hex(end)},
            }
        return {
            "func_addr": func_addr,
            "ok": False,
            "error": "Failed to append function chunk",
        }
    except Exception as e:
        return {"func_addr": func_addr, "ok": False, "error": str(e)}


@tool
@idasync
def reanalyze(
    start: Annotated[str, "Start address"],
    end: Annotated[str, "End address (optional)"] = "",
) -> dict:
    """Force IDA to reanalyze a range."""
    try:
        start_ea = parse_address(start)
        end_ea = parse_address(end) if end else start_ea + idc.get_item_size(start_ea)
        ida_auto.plan_range(start_ea, end_ea)
        ida_auto.auto_wait()
        return {
            "ok": True,
            "range": {"start": hex(start_ea), "end": hex(end_ea)},
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@tool
@idasync
def jump_to(addr: Annotated[str, "Address to jump to"]) -> dict:
    """Jump to address in IDA GUI."""
    try:
        ea = parse_address(addr)
        return {"addr": addr, "ok": bool(idaapi.jumpto(ea))}
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


@tool
@idasync
def add_bookmark(
    addr: Annotated[str, "Address"],
    description: Annotated[str, "Description"] = "",
) -> dict:
    """Add a bookmark at address."""
    try:
        ea = parse_address(addr)
        slot = 1
        while slot <= 1024:
            if idc.get_bookmark(slot) == idaapi.BADADDR:
                break
            slot += 1
        if slot > 1024:
            return {"ok": False, "error": "No free bookmark slots available"}
        idc.put_bookmark(ea, 0, 0, 0, slot, description)
        return {"addr": addr, "ok": True, "slot": slot, "description": description}
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


@tool
@idasync
def delete_bookmark(slot: Annotated[int, "Bookmark slot"]) -> dict:
    """Delete a bookmark."""
    try:
        current = idc.get_bookmark(slot)
        if current == idaapi.BADADDR:
            return {"slot": slot, "ok": False, "error": f"No bookmark in slot {slot}"}
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
    """List all bookmarks."""
    results = []
    for slot in range(1, 1025):
        addr = idc.get_bookmark(slot)
        if addr == idaapi.BADADDR:
            continue
        desc = idc.get_bookmark_desc(slot)
        results.append({"slot": slot, "addr": hex(addr), "description": desc or ""})
    return results


@tool
@idasync
def create_segment(
    start: Annotated[str, "Start address"],
    end: Annotated[str, "End address"],
    name: Annotated[str, "Name"],
    seg_class: Annotated[str, "Class"] = "DATA",
    align: Annotated[int, "Alignment"] = 0,
) -> dict:
    """Create a new segment."""
    try:
        start_ea = parse_address(start)
        end_ea = parse_address(end)
        seg = idaapi.segment_t()
        seg.start_ea = start_ea
        seg.end_ea = end_ea
        seg.align = align
        seg.comb = idaapi.scPub
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
                "ok": True,
                "name": name,
                "start": hex(start_ea),
                "end": hex(end_ea),
                "size": hex(end_ea - start_ea),
            }
        return {"ok": False, "error": "Failed to create segment"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@tool
@idasync
def delete_segment(
    addr: Annotated[str, "Address inside segment to delete"],
    keep_bytes: Annotated[bool, "Keep bytes"] = True,
) -> dict:
    """Delete a segment."""
    try:
        ea = parse_address(addr)
        seg = idaapi.getseg(ea)
        if not seg:
            return {"addr": addr, "ok": False, "error": f"No segment at {hex(ea)}"}
        name = idaapi.get_segm_name(seg)
        start = seg.start_ea
        end = seg.end_ea
        flags = idaapi.SEGMOD_KEEP if keep_bytes else idaapi.SEGMOD_KILL
        if idaapi.del_segm(start, flags):
            return {
                "addr": addr,
                "ok": True,
                "deleted": {"name": name, "start": hex(start), "end": hex(end)},
            }
        return {"addr": addr, "ok": False, "error": f"Failed to delete segment '{name}'"}
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


def _coerce_int(value) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _build_enum_members(members: list[dict] | str) -> list[tuple[str, int]]:
    parsed: list[tuple[str, int]] = []
    if not members:
        return parsed

    if isinstance(members, str):
        for part in members.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                raise ValueError(
                    f"Invalid member format '{part}', expected 'name=value'"
                )
            name, value = part.split("=", 1)
            parsed.append((name.strip(), int(value.strip(), 0)))
        return parsed

    for member in members:
        if not isinstance(member, dict):
            raise ValueError(f"Invalid member payload: {member!r}")
        member_name = member.get("name")
        if not member_name:
            raise ValueError(f"Enum member missing 'name': {member!r}")
        if "value" not in member:
            raise ValueError(f"Enum member '{member_name}' missing 'value'")
        parsed.append((str(member_name), _coerce_int(member["value"])))

    return parsed


def _bitmask_enum_enabled() -> tuple[bool, bool]:
    has_enum_api = all(
        hasattr(ida_typeinf, attr)
        for attr in [
            "tinfo_t",
            "enum_type_data_t",
            "edm_t",
            "BTF_ENUM",
        ]
    )
    has_save_api = hasattr(ida_typeinf.tinfo_t, "set_named_type")
    return has_enum_api, has_save_api


def _normalize_typeinf_enum_result(result):
    if result is True:
        return True
    if result is False:
        return False
    if hasattr(ida_typeinf, "TERR_OK"):
        return result == ida_typeinf.TERR_OK
    return bool(result)


@tool
@idasync
def create_enum(
    name: Annotated[str, "Name of the enum"],
    members: Annotated[list[dict] | str, "Members as list of {name, value} or 'a=1;b=2'"] = "",
    bitfield: Annotated[bool, "Create as bitfield enum"] = False,
) -> dict:
    """Create an enumeration type."""
    if not name:
        return {"name": name, "ok": False, "error": "Missing enum name"}

    has_enum_api, has_save_api = _bitmask_enum_enabled()
    if not has_enum_api or not has_save_api:
        return {
            "name": name,
            "ok": False,
            "error": "Enum API (ida_typeinf) is unavailable in this IDA build",
        }

    try:
        try:
            parsed_members = _build_enum_members(members)
        except ValueError as e:
            return {"name": name, "ok": False, "error": str(e)}

        tif = ida_typeinf.tinfo_t()
        existing = tif.get_named_type(None, name, ida_typeinf.BTF_ENUM)
        if existing:
            return {
                "name": name,
                "ok": False,
                "error": f"Enum '{name}' already exists",
            }

        edt = ida_typeinf.enum_type_data_t()
        edm = ida_typeinf.edm_t()
        for member_name, member_value in parsed_members:
            edm.name = member_name
            edm.value = member_value
            edt.push_back(edm)

        if not tif.create_enum(edt):
            return {
                "name": name,
                "ok": False,
                "error": "Failed to create enum structure",
            }

        if bitfield and hasattr(ida_typeinf.tinfo_t, "set_enum_is_bitmask"):
            enum_bitmask_flag = getattr(ida_typeinf, "ENUMBM_ON", 1)
            tif.set_enum_is_bitmask(enum_bitmask_flag)

        saved = tif.set_named_type(None, name)
        if not _normalize_typeinf_enum_result(saved):
            return {
                "name": name,
                "ok": False,
                "error": "Failed to register enum in local type library",
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
    member_name: Annotated[str, "Name of the member"],
    value: Annotated[int, "Member value"],
) -> dict:
    """Add a member to an existing enum."""
    if not enum_name or not member_name:
        return {
            "enum_name": enum_name,
            "member_name": member_name,
            "ok": False,
            "error": "Missing enum_name or member_name",
        }

    has_enum_api, _ = _bitmask_enum_enabled()
    if not has_enum_api:
        return {
            "enum_name": enum_name,
            "ok": False,
            "error": "Enum API (ida_typeinf) is unavailable in this IDA build",
        }

    try:
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, enum_name, ida_typeinf.BTF_ENUM):
            return {
                "enum_name": enum_name,
                "ok": False,
                "error": f"Enum '{enum_name}' not found",
            }

        edt = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(edt):
            return {
                "enum_name": enum_name,
                "ok": False,
                "error": "Failed to read enum details",
            }

        for existing in edt:
            if existing.name == member_name:
                return {
                    "enum_name": enum_name,
                    "ok": False,
                    "error": f"Member '{member_name}' already exists",
                }

        edm = ida_typeinf.edm_t()
        edm.name = member_name
        edm.value = value
        edt.push_back(edm)

        updated = ida_typeinf.tinfo_t()
        if not updated.create_enum(edt):
            return {
                "enum_name": enum_name,
                "ok": False,
                "error": "Failed to apply updated enum",
            }

        if hasattr(edt, "is_bf") and edt.is_bf() and hasattr(
            ida_typeinf.tinfo_t, "set_enum_is_bitmask"
        ):
            enum_bitmask_flag = getattr(ida_typeinf, "ENUMBM_ON", 1)
            updated.set_enum_is_bitmask(enum_bitmask_flag)

        saved = updated.set_named_type(None, enum_name)
        if not _normalize_typeinf_enum_result(saved):
            return {
                "enum_name": enum_name,
                "ok": False,
                "error": "Failed to register updated enum",
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
    addr: Annotated[str, "Address of the operand"],
    enum_name: Annotated[str, "Enum name"],
    operand: Annotated[int, "Operand index (default 0)"] = 0,
) -> dict:
    """Apply an enum type to an operand."""
    has_enum_api, _ = _bitmask_enum_enabled()
    if not has_enum_api:
        return {
            "addr": addr,
            "ok": False,
            "error": "Enum API (ida_typeinf) is unavailable in this IDA build",
        }

    if not hasattr(ida_bytes, "op_enum"):
        return {
            "addr": addr,
            "ok": False,
            "error": "Operand enum API (ida_bytes.op_enum) unavailable",
        }

    try:
        ea = parse_address(addr)
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, enum_name, ida_typeinf.BTF_ENUM):
            return {
                "addr": addr,
                "ok": False,
                "error": f"Enum '{enum_name}' not found",
            }

        enum_tid = tif.get_tid()
        if enum_tid == idaapi.BADADDR:
            return {
                "addr": addr,
                "ok": False,
                "error": f"Could not resolve enum tid for '{enum_name}'",
            }

        if ida_bytes.op_enum(ea, operand, enum_tid, 0):
            return {
                "addr": addr,
                "ok": True,
                "enum": enum_name,
                "operand": operand,
            }
        return {
            "addr": addr,
            "ok": False,
            "error": "Failed to apply enum to operand",
        }
    except Exception as e:
        return {"addr": addr, "ok": False, "error": str(e)}


@tool
@idasync
def list_enums() -> list[dict]:
    """List all enums in the database."""
    has_enum_api, _ = _bitmask_enum_enabled()
    if not has_enum_api:
        return [
            {
                "error": "Enum API (ida_typeinf) is unavailable in this IDA build",
            }
        ]

    results = []
    limit = getattr(ida_typeinf, "get_ordinal_limit", lambda: 0)()
    if limit <= 0:
        return results

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        try:
            if hasattr(ida_typeinf, "BTF_ENUM"):
                has_type = tif.get_numbered_type(ordinal, ida_typeinf.BTF_ENUM)
            else:
                has_type = tif.get_numbered_type(ordinal)
            if not has_type:
                continue
        except TypeError:
            if not tif.get_numbered_type(ordinal):
                continue

        name = tif.get_type_name()
        if not name:
            continue

        edt = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(edt):
            continue

        members = []
        for i in range(edt.size()):
            member = edt[i]
            members.append(
                {
                    "name": member.name,
                    "value": member.value,
                }
            )

        result = {
            "name": name,
            "ordinal": ordinal,
            "bitfield": edt.is_bf() if hasattr(edt, "is_bf") else False,
            "member_count": edt.size(),
            "members": members,
        }
        results.append(result)

    return results


@tool
@idasync
def apply_flirt(
    sig_name: Annotated[
        str, "FLIRT signature name (without .sig extension)"
    ] = "",
) -> dict:
    """Apply a FLIRT signature file."""
    if not sig_name:
        return {
            "sig_name": sig_name,
            "ok": False,
            "error": "sig_name is required",
        }

    if not hasattr(idc, "plan_to_apply_idasgn"):
        return {
            "sig_name": sig_name,
            "ok": False,
            "error": "FLIRT application API unavailable in this IDA build",
        }

    try:
        result = idc.plan_to_apply_idasgn(sig_name)
        if result == 1:
            return {
                "sig_name": sig_name,
                "ok": True,
                "note": "Signature application scheduled",
            }
        if result == 0:
            return {
                "sig_name": sig_name,
                "ok": False,
                "error": f"Signature '{sig_name}' not found",
            }
        return {
            "sig_name": sig_name,
            "ok": False,
            "error": "Signature already applied or rejected by IDA",
        }
    except Exception as e:
        return {"sig_name": sig_name, "ok": False, "error": str(e)}


@tool
@idasync
def apply_til(
    til_name: Annotated[
        str, "Type library name (for example: gnulnx_x64, mssdk64_win10)"
    ] = "",
) -> dict:
    """Load a type library (.til)."""
    if not til_name:
        return {"til_name": til_name, "ok": False, "error": "til_name is required"}

    if not hasattr(ida_typeinf, "add_til"):
        return {
            "til_name": til_name,
            "ok": False,
            "error": "TIL API unavailable in this IDA build",
        }

    try:
        flags = getattr(ida_typeinf, "ADDTIL_DEFAULT", 0)
        ok = ida_typeinf.add_til(til_name, flags)
        return {"til_name": til_name, "ok": bool(ok)}
    except Exception as e:
        return {"til_name": til_name, "ok": False, "error": str(e)}


@tool
@idasync
def set_color(
    addrs: list[str] | str,
    color: Annotated[int, "RGB color (or 0xFFFFFFFF to clear)"],
) -> list[dict]:
    """Set item color."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            ida_nalt.set_item_color(ea, color)
            results.append({"addr": addr, "color": hex(color), "ok": True})
        except Exception as e:
            results.append({"addr": addr, "ok": False, "error": str(e)})
    return results


@tool
@idasync
def get_color(
    addrs: list[str] | str,
) -> list[dict]:
    """Get item color."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            color = ida_nalt.get_item_color(ea)
            results.append(
                {
                    "addr": addr,
                    "color": hex(color) if color != 0xFFFFFFFF else None,
                    "has_color": color != 0xFFFFFFFF,
                }
            )
        except Exception as e:
            results.append({"addr": addr, "color": None, "has_color": False, "error": str(e)})
    return results


@tool
@idasync
def op_offset(
    addrs: list[str] | str,
    operand: Annotated[int, "Operand index"] = 0,
    base: Annotated[str | None, "Base address"] = None,
) -> list[dict]:
    """Set operand as offset."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            base_ea = parse_address(base) if base else 0
            if ida_bytes.op_plain_offset(ea, operand, base_ea):
                results.append({"addr": addr, "operand": operand, "ok": True})
            else:
                results.append(
                    {"addr": addr, "operand": operand, "ok": False, "error": "Failed"}
                )
        except Exception as e:
            results.append({"addr": addr, "operand": operand, "ok": False, "error": str(e)})
    return results


@tool
@idasync
def op_number(
    addrs: list[str] | str,
    operand: Annotated[int, "Operand index"] = 0,
    radix: Annotated[str, "hex|dec|oct|bin|char"] = "hex",
) -> list[dict]:
    """Change operand number representation."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            if radix == "hex":
                ok = idc.op_hex(ea, operand)
            elif radix == "dec":
                ok = idc.op_dec(ea, operand)
            elif radix == "oct":
                ok = idc.op_oct(ea, operand)
            elif radix == "bin":
                ok = idc.op_bin(ea, operand)
            elif radix == "char":
                ok = idc.op_chr(ea, operand)
            else:
                results.append(
                    {"addr": addr, "operand": operand, "ok": False, "error": f"Unsupported radix {radix}"}
                )
                continue
            results.append(
                {"addr": addr, "operand": operand, "radix": radix, "ok": bool(ok)}
            )
        except Exception as e:
            results.append({"addr": addr, "operand": operand, "ok": False, "error": str(e)})
    return results


@tool
@idasync
def clr_op_type(
    addrs: list[str] | str,
    operand: Annotated[int, "Operand index"] = 0,
) -> list[dict]:
    """Clear operand override."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            ok = ida_bytes.clr_op_type(ea, operand)
            results.append({"addr": addr, "operand": operand, "ok": bool(ok)})
        except Exception as e:
            results.append({"addr": addr, "operand": operand, "ok": False, "error": str(e)})
    return results


@tool
@idasync
def set_func_cmt(
    addrs: list[str] | str,
    comment: Annotated[str, "Comment text"],
    repeatable: Annotated[bool, "Repeatable comment"] = False,
) -> list[dict]:
    """Set function-level comment."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {"addr": addr, "ok": False, "error": f"No function at {hex(ea)}"}
                )
                continue
            ok = idc.set_func_cmt(func.start_ea, comment, repeatable)
            results.append({"addr": addr, "ok": bool(ok)})
        except Exception as e:
            results.append({"addr": addr, "ok": False, "error": str(e)})
    return results


@tool
@idasync
def get_func_cmt(
    addrs: list[str] | str,
    repeatable: Annotated[bool, "Repeatable comment"] = False,
) -> list[dict]:
    """Get function-level comment."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {"addr": addr, "comment": None, "error": f"No function at {hex(ea)}"}
                )
                continue
            results.append(
                {
                    "addr": addr,
                    "comment": idc.get_func_cmt(func.start_ea, repeatable) or None,
                    "repeatable": repeatable,
                }
            )
        except Exception as e:
            results.append({"addr": addr, "comment": None, "error": str(e)})
    return results


@tool
@idasync
def set_extra_cmt(
    addrs: list[str] | str,
    comment: Annotated[str, "Comment text"],
    position: Annotated[str, "anterior|posterior"] = "anterior",
) -> list[dict]:
    """Set anterior/posterior extra comments."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            base = ida_lines.E_PREV if position == "anterior" else ida_lines.E_NEXT
            for i in range(1000):
                if ida_lines.get_extra_cmt(ea, base + i) is None:
                    break
                ida_lines.del_extra_cmt(ea, base + i)
            for i, line in enumerate(comment.split("\n")):
                ida_lines.add_extra_cmt(ea, base + i, line)
            results.append(
                {"addr": addr, "position": position, "lines": len(comment.splitlines()) or 1, "ok": True}
            )
        except Exception as e:
            results.append({"addr": addr, "ok": False, "error": str(e)})
    return results


@tool
@idasync
def get_extra_cmt(
    addrs: list[str] | str,
    position: Annotated[str, "anterior|posterior|both"] = "both",
) -> list[dict]:
    """Read anterior/posterior extra comments."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            entry: dict = {"addr": addr, "ok": True}
            if position in ("anterior", "both"):
                anterior = []
                for i in range(1000):
                    cmt = ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + i)
                    if cmt is None:
                        break
                    anterior.append(cmt)
                if anterior:
                    entry["anterior"] = anterior
            if position in ("posterior", "both"):
                posterior = []
                for i in range(1000):
                    cmt = ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT + i)
                    if cmt is None:
                        break
                    posterior.append(cmt)
                if posterior:
                    entry["posterior"] = posterior
            results.append(entry)
        except Exception as e:
            results.append({"addr": addr, "ok": False, "error": str(e)})
    return results


@tool
@idasync
def del_extra_cmt(
    addrs: list[str] | str,
    position: Annotated[str, "anterior|posterior|both"] = "both",
) -> list[dict]:
    """Delete anterior/posterior extra comments."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            deleted = {"anterior": 0, "posterior": 0}
            if position in ("anterior", "both"):
                for i in range(1000):
                    if ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + i) is None:
                        break
                    ida_lines.del_extra_cmt(ea, ida_lines.E_PREV + i)
                    deleted["anterior"] += 1
            if position in ("posterior", "both"):
                for i in range(1000):
                    if ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT + i) is None:
                        break
                    ida_lines.del_extra_cmt(ea, ida_lines.E_NEXT + i)
                    deleted["posterior"] += 1
            results.append({"addr": addr, "deleted": deleted, "ok": True})
        except Exception as e:
            results.append({"addr": addr, "ok": False, "error": str(e)})
    return results
