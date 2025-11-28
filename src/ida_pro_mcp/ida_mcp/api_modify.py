from typing import Annotated

import idaapi
import idautils
import idc
import ida_hexrays
import ida_bytes
import ida_typeinf
import ida_frame

from .rpc import tool
from .sync import idawrite, IDAError
from .utils import (
    parse_address,
    decompile_checked,
    refresh_decompiler_ctext,
    normalize_dict_list,
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
