"""Memory reading and writing operations for IDA Pro MCP.

This module provides batch operations for reading and writing memory at various
granularities (bytes, integers, strings) and patching binary data.
"""

import re
from typing import Annotated

import ida_bytes
import idaapi
import ida_ida

from .rpc import tool
from .sync import idasync
from .utils import (
    IntRead,
    IntWrite,
    MemoryPatch,
    MemoryRead,
    normalize_list_input,
    parse_address,
)


# ============================================================================
# Memory Reading Operations
# ============================================================================


@tool
@idasync
def get_bytes(regions: list[MemoryRead] | MemoryRead) -> list[dict]:
    """Read bytes from memory addresses"""
    if isinstance(regions, dict):
        regions = [regions]

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


_INT_CLASS_RE = re.compile(r"^(?P<sign>[iu])(?P<bits>8|16|32|64)(?P<endian>le|be)?$")


def _parse_int_class(text: str) -> tuple[int, bool, str, str]:
    if not text:
        raise ValueError("Missing integer class")

    cleaned = text.strip().lower()
    match = _INT_CLASS_RE.match(cleaned)
    if not match:
        raise ValueError(f"Invalid integer class: {text}")

    bits = int(match.group("bits"))
    signed = match.group("sign") == "i"
    endian = match.group("endian") or "le"
    byte_order = "little" if endian == "le" else "big"
    normalized = f"{'i' if signed else 'u'}{bits}{endian}"
    return bits, signed, byte_order, normalized


def _parse_int_value(text: str, signed: bool, bits: int) -> int:
    if text is None:
        raise ValueError("Missing integer value")

    value_text = str(text).strip()
    try:
        value = int(value_text, 0)
    except ValueError:
        raise ValueError(f"Invalid integer value: {text}")

    if not signed and value < 0:
        raise ValueError(f"Negative value not allowed for u{bits}")

    return value


@tool
@idasync
def get_int(
    queries: Annotated[
        list[IntRead] | IntRead,
        "Integer read requests (ty, addr). ty: i8/u64/i16le/i16be/etc",
    ],
) -> list[dict]:
    """Read integer values from memory addresses"""
    if isinstance(queries, dict):
        queries = [queries]

    results = []
    for item in queries:
        addr = item.get("addr", "")
        ty = item.get("ty", "")

        try:
            bits, signed, byte_order, normalized = _parse_int_class(ty)
            ea = parse_address(addr)
            size = bits // 8
            data = ida_bytes.get_bytes(ea, size)
            if not data or len(data) != size:
                raise ValueError(f"Failed to read {size} bytes at {addr}")

            value = int.from_bytes(data, byte_order, signed=signed)
            results.append(
                {"addr": addr, "ty": normalized, "value": value, "error": None}
            )
        except Exception as e:
            results.append({"addr": addr, "ty": ty, "value": None, "error": str(e)})

    return results


@tool
@idasync
def get_string(
    addrs: Annotated[list[str] | str, "Addresses to read strings from"],
) -> list[dict]:
    """Read strings from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            raw = idaapi.get_strlit_contents(ea, -1, 0)
            if not raw:
                results.append(
                    {"addr": addr, "value": None, "error": "No string at address"}
                )
                continue
            value = raw.decode("utf-8", errors="replace")
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
        raw = idaapi.get_strlit_contents(ea, -1, 0)
        if not raw:
            return '""'
        return_string = raw.decode("utf-8", errors="replace").strip()
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
@idasync
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
# Fixed-width Integer Reads
# ============================================================================


@tool
@idasync
def get_u8(
    addrs: Annotated[list[str] | str, "Addresses to read 8-bit unsigned integers from"],
) -> list[dict]:
    """Read 8-bit unsigned integers."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            results.append({"addr": addr, "value": ida_bytes.get_wide_byte(ea)})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})
    return results


@tool
@idasync
def get_u16(
    addrs: Annotated[list[str] | str, "Addresses to read 16-bit unsigned integers from"],
) -> list[dict]:
    """Read 16-bit unsigned integers."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            results.append({"addr": addr, "value": ida_bytes.get_wide_word(ea)})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})
    return results


@tool
@idasync
def get_u32(
    addrs: Annotated[list[str] | str, "Addresses to read 32-bit unsigned integers from"],
) -> list[dict]:
    """Read 32-bit unsigned integers."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            results.append({"addr": addr, "value": ida_bytes.get_wide_dword(ea)})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})
    return results


@tool
@idasync
def get_u64(
    addrs: Annotated[list[str] | str, "Addresses to read 64-bit unsigned integers from"],
) -> list[dict]:
    """Read 64-bit unsigned integers."""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            results.append({"addr": addr, "value": ida_bytes.get_qword(ea)})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})
    return results


# ============================================================================
# Batch Data Operations
# ============================================================================


@tool
@idasync
def patch(patches: list[MemoryPatch] | MemoryPatch) -> list[dict]:
    """Patch bytes at memory addresses with hex data"""
    if isinstance(patches, dict):
        patches = [patches]

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


@tool
@idasync
def put_int(
    items: Annotated[
        list[IntWrite] | IntWrite,
        "Integer write requests (ty, addr, value). value is a string; supports 0x.. and negatives",
    ],
) -> list[dict]:
    """Write integer values to memory addresses"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr = item.get("addr", "")
        ty = item.get("ty", "")
        value_text = item.get("value")

        try:
            bits, signed, byte_order, normalized = _parse_int_class(ty)
            value = _parse_int_value(value_text, signed, bits)
            size = bits // 8
            try:
                data = value.to_bytes(size, byte_order, signed=signed)
            except OverflowError:
                raise ValueError(f"Value {value_text} does not fit in {normalized}")

            ea = parse_address(addr)
            ida_bytes.patch_bytes(ea, data)
            results.append(
                {
                    "addr": addr,
                    "ty": normalized,
                    "value": str(value_text),
                    "ok": True,
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "ty": ty,
                    "value": str(value_text) if value_text is not None else None,
                    "ok": False,
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Original Bytes Utilities
# ============================================================================


@tool
@idasync
def get_original_bytes(
    regions: Annotated[
        list[MemoryRead] | MemoryRead,
        "Memory regions to read original bytes from",
    ],
) -> list[dict]:
    """Read original bytes before patches for addresses."""
    if isinstance(regions, dict):
        regions = [regions]
    if not hasattr(ida_bytes, "get_original_byte"):
        return [
            {
                "addr": item.get("addr", ""),
                "data": None,
                "error": "Original-byte API unavailable in this IDA version",
            }
            for item in regions
        ]

    results = []
    for item in regions:
        addr = item.get("addr", "")
        size = item.get("size", 0)
        try:
            ea = parse_address(addr)
            if size < 0:
                raise ValueError("size must be >= 0")

            original = []
            for i in range(size):
                original.append(ida_bytes.get_original_byte(ea + i))
            data = " ".join(f"{x:#02x}" for x in original)
            results.append({"addr": addr, "data": data})
        except Exception as e:
            results.append({"addr": addr, "data": None, "error": str(e)})

    return results


@tool
@idasync
def get_original_byte(
    addrs: Annotated[list[str] | str, "Addresses to read original bytes from"],
) -> list[dict]:
    """Read single original bytes."""
    addrs = normalize_list_input(addrs)
    if not hasattr(ida_bytes, "get_original_byte"):
        return [
            {"addr": addr, "value": None, "error": "Original-byte API unavailable in this IDA version"}
            for addr in addrs
        ]
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_original_byte(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})
    return results


@tool
@idasync
def get_original_word(
    addrs: Annotated[list[str] | str, "Addresses to read original 16-bit words from"],
) -> list[dict]:
    """Read original 16-bit values."""
    addrs = normalize_list_input(addrs)
    if not hasattr(ida_bytes, "get_original_word"):
        return [
            {"addr": addr, "value": None, "error": "Original-word API unavailable in this IDA version"}
            for addr in addrs
        ]
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            results.append({"addr": addr, "value": ida_bytes.get_original_word(ea)})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})
    return results


@tool
@idasync
def get_original_dword(
    addrs: Annotated[list[str] | str, "Addresses to read original 32-bit words from"],
) -> list[dict]:
    """Read original 32-bit values."""
    addrs = normalize_list_input(addrs)
    if not hasattr(ida_bytes, "get_original_dword"):
        return [
            {"addr": addr, "value": None, "error": "Original-dword API unavailable in this IDA version"}
            for addr in addrs
        ]
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            results.append({"addr": addr, "value": ida_bytes.get_original_dword(ea)})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})
    return results


@tool
@idasync
def get_original_qword(
    addrs: Annotated[list[str] | str, "Addresses to read original 64-bit words from"],
) -> list[dict]:
    """Read original 64-bit values."""
    addrs = normalize_list_input(addrs)
    if not hasattr(ida_bytes, "get_original_qword"):
        return [
            {"addr": addr, "value": None, "error": "Original-qword API unavailable in this IDA version"}
            for addr in addrs
        ]
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            results.append({"addr": addr, "value": ida_bytes.get_original_qword(ea)})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})
    return results


@tool
@idasync
def list_patched_bytes(
    start: Annotated[str | None, "Start address (default: image base)"] = None,
    end: Annotated[str | None, "End address (default: image end)"] = None,
    limit: Annotated[int, "Maximum number of patched bytes to return (default: 1000)"] = 1000,
) -> dict:
    """List patched bytes between start/end addresses."""
    if not hasattr(ida_bytes, "get_original_byte"):
        return {
            "patched": [],
            "count": 0,
            "range": None,
            "error": "Original-byte API unavailable in this IDA version",
        }

    if start:
        start_ea = parse_address(start)
    else:
        start_ea = ida_ida.inf_get_min_ea()
    if end:
        end_ea = parse_address(end)
    else:
        end_ea = ida_ida.inf_get_max_ea()

    patches = []
    count_hits = 0
    scan_errors: list[dict] = []
    ea = start_ea

    while ea < end_ea and count_hits < limit:
        try:
            original = ida_bytes.get_original_byte(ea)
            current = ida_bytes.get_byte(ea)
            if original != current:
                patches.append(
                    {
                        "addr": hex(ea),
                        "original": hex(original),
                        "current": hex(current),
                    }
                )
                count_hits += 1
        except Exception as e:  # pragma: no cover - depends on IDA runtime state
            scan_errors.append({"addr": hex(ea), "error": str(e)})
            if len(scan_errors) >= 20:
                break
        ea += 1

    if scan_errors:
        return {
            "patched": patches,
            "count": len(patches),
            "range": {"start": hex(start_ea), "end": hex(end_ea)},
            "scan_errors": scan_errors,
            "error_count": len(scan_errors),
        }

    return {
        "patched": patches,
        "count": len(patches),
        "range": {"start": hex(start_ea), "end": hex(end_ea)},
    }

