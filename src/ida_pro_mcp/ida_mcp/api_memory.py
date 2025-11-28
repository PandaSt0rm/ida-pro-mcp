"""Memory reading and writing operations for IDA Pro MCP.

This module provides batch operations for reading and writing memory at various
granularities (bytes, u8, u16, u32, u64, strings) and patching binary data.
"""

from typing import Annotated
import ida_bytes
import ida_ida
import idaapi

from .rpc import tool
from .sync import idaread, idawrite
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    parse_addr_size,
    parse_addr_data,
    MemoryRead,
    MemoryPatch,
)


# ============================================================================
# Memory Reading Operations
# ============================================================================


@tool
@idaread
def get_bytes(
    regions: Annotated[
        list[MemoryRead] | MemoryRead | str,
        "Memory regions to read. Accepts list of {addr, size} dicts or string shortcut: 'addr:size;addr2:size2'",
    ],
) -> list[dict]:
    """Read bytes from memory addresses"""
    regions = normalize_dict_list(regions, parse_addr_size)

    results = []
    for item in regions:
        addr = item.get("addr", "")
        size = item.get("size", 0)

        try:
            ea = parse_address(addr)
            data = " ".join(f"{x:#02x}" for x in ida_bytes.get_bytes(ea, size))
            results.append({"addr": addr, "data": data})
        except Exception as e:
            results.append({"addr": addr, "data": None, "error": str(e)})

    return results


@tool
@idaread
def get_u8(
    addrs: Annotated[list[str] | str, "Addresses to read 8-bit unsigned integers from"],
) -> list[dict]:
    """Read 8-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_byte(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def get_u16(
    addrs: Annotated[
        list[str] | str, "Addresses to read 16-bit unsigned integers from"
    ],
) -> list[dict]:
    """Read 16-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_word(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def get_u32(
    addrs: Annotated[
        list[str] | str, "Addresses to read 32-bit unsigned integers from"
    ],
) -> list[dict]:
    """Read 32-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_dword(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def get_u64(
    addrs: Annotated[
        list[str] | str, "Addresses to read 64-bit unsigned integers from"
    ],
) -> list[dict]:
    """Read 64-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_qword(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def get_string(
    addrs: Annotated[list[str] | str, "Addresses to read strings from"],
) -> list[dict]:
    """Read strings from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8")
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


def get_global_variable_value_internal(ea: int) -> str:
    import ida_typeinf
    import ida_nalt
    import ida_bytes
    from .sync import IDAError

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")

        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
    else:
        size = tif.get_size()

    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        return_string = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8").strip()
        return f'"{return_string}"'
    elif size == 1:
        return hex(ida_bytes.get_byte(ea))
    elif size == 2:
        return hex(ida_bytes.get_word(ea))
    elif size == 4:
        return hex(ida_bytes.get_dword(ea))
    elif size == 8:
        return hex(ida_bytes.get_qword(ea))
    else:
        return " ".join(hex(x) for x in ida_bytes.get_bytes(ea, size))


@tool
@idaread
def get_global_value(
    queries: Annotated[
        list[str] | str, "Global variable addresses or names to read values from"
    ],
) -> list[dict]:
    """Read global variable values by address or name
    (auto-detects hex addresses vs names)"""
    from .utils import looks_like_address

    queries = normalize_list_input(queries)
    results = []

    for query in queries:
        try:
            ea = idaapi.BADADDR

            # Try as address first if it looks like one
            if looks_like_address(query):
                try:
                    ea = parse_address(query)
                except Exception:
                    ea = idaapi.BADADDR

            # Fall back to name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea == idaapi.BADADDR:
                results.append({"query": query, "value": None, "error": f"Global '{query}' not found. Use list_globals to search for valid names."})
                continue

            value = get_global_variable_value_internal(ea)
            results.append({"query": query, "value": value, "error": None})
        except Exception as e:
            results.append({"query": query, "value": None, "error": str(e)})

    return results


# ============================================================================
# Batch Data Operations
# ============================================================================


@tool
@idawrite
def patch(
    patches: Annotated[
        list[MemoryPatch] | MemoryPatch | str,
        "Memory patches. Accepts list of {addr, data} dicts or string shortcut: 'addr=hexdata;addr2=hexdata2'",
    ],
) -> list[dict]:
    """Patch bytes at memory addresses with hex data"""
    patches = normalize_dict_list(patches, parse_addr_data)

    results = []

    for patch in patches:
        try:
            ea = parse_address(patch["addr"])
            data = bytes.fromhex(patch["data"])

            ida_bytes.patch_bytes(ea, data)
            results.append(
                {"addr": patch["addr"], "size": len(data), "ok": True, "error": None}
            )

        except Exception as e:
            results.append({"addr": patch.get("addr"), "size": 0, "error": str(e)})

    return results


# ============================================================================
# Original Bytes (Pre-Patch Values)
# ============================================================================


@tool
@idaread
def get_original_bytes(
    regions: Annotated[
        list[MemoryRead] | MemoryRead | str,
        "Memory regions to read original bytes from. Accepts list of {addr, size} dicts or string shortcut: 'addr:size;addr2:size2'",
    ],
) -> list[dict]:
    """Read original bytes from memory addresses (before any patches were applied).

    Use this to compare patched bytes with original values or to revert patches.
    """
    regions = normalize_dict_list(regions, parse_addr_size)

    results = []
    for item in regions:
        addr = item.get("addr", "")
        size = item.get("size", 0)

        try:
            ea = parse_address(addr)
            # Get original bytes one by one
            original = []
            for i in range(size):
                original.append(ida_bytes.get_original_byte(ea + i))
            data = " ".join(f"{x:#02x}" for x in original)
            results.append({"addr": addr, "data": data, "error": None})
        except Exception as e:
            results.append({"addr": addr, "data": None, "error": str(e)})

    return results


@tool
@idaread
def get_original_byte(
    addrs: Annotated[list[str] | str, "Addresses to read original bytes from"],
) -> list[dict]:
    """Read original byte values from memory addresses (before patches)."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_original_byte(ea)
            results.append({"addr": addr, "value": value, "error": None})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def get_original_word(
    addrs: Annotated[list[str] | str, "Addresses to read original 16-bit values from"],
) -> list[dict]:
    """Read original 16-bit word values from memory addresses (before patches)."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_original_word(ea)
            results.append({"addr": addr, "value": value, "error": None})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def get_original_dword(
    addrs: Annotated[list[str] | str, "Addresses to read original 32-bit values from"],
) -> list[dict]:
    """Read original 32-bit dword values from memory addresses (before patches)."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_original_dword(ea)
            results.append({"addr": addr, "value": value, "error": None})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def get_original_qword(
    addrs: Annotated[list[str] | str, "Addresses to read original 64-bit values from"],
) -> list[dict]:
    """Read original 64-bit qword values from memory addresses (before patches)."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_original_qword(ea)
            results.append({"addr": addr, "value": value, "error": None})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def list_patched_bytes(
    start: Annotated[str | None, "Start address (default: image base)"] = None,
    end: Annotated[str | None, "End address (default: image end)"] = None,
    limit: Annotated[int, "Maximum number of patches to return (default: 1000)"] = 1000,
) -> dict:
    """List all patched bytes in the specified address range.

    Returns addresses where bytes have been modified from their original values.
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

    patches = []
    count = 0
    ea = start_ea

    while ea < end_ea and count < limit:
        original = ida_bytes.get_original_byte(ea)
        current = ida_bytes.get_byte(ea)

        if original != current:
            patches.append({
                "addr": hex(ea),
                "original": hex(original),
                "current": hex(current),
            })
            count += 1

        ea += 1

    return {
        "patches": patches,
        "count": len(patches),
        "range": {"start": hex(start_ea), "end": hex(end_ea)},
    }
