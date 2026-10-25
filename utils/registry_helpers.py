"""RegAudit Registry Access Helpers.

Provides defensive, strictly read-only primitives for enumerating Windows Registry
hives, keys, and values, computing SHA-256 integrity hashes, and mapping Windows
registry types. Wrapped to gracefully handle permission failures and non-Windows runtimes.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

LOGGER = logging.getLogger("RegAudit.RegistryHelpers")

try:
    import winreg

    WINREG_AVAILABLE = True
except ImportError:
    winreg = None  # type: ignore
    WINREG_AVAILABLE = False


HIVE_NAME_MAP: Dict[int, str] = {}
HIVE_SHORT_MAP: Dict[int, str] = {}
NAME_TO_HIVE_MAP: Dict[str, int] = {}

if WINREG_AVAILABLE:
    HIVE_NAME_MAP = {
        winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
        winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
        winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
        winreg.HKEY_USERS: "HKEY_USERS",
        winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG",
    }
    HIVE_SHORT_MAP = {
        winreg.HKEY_LOCAL_MACHINE: "HKLM",
        winreg.HKEY_CURRENT_USER: "HKCU",
        winreg.HKEY_CLASSES_ROOT: "HKCR",
        winreg.HKEY_USERS: "HKU",
        winreg.HKEY_CURRENT_CONFIG: "HKCC",
    }
    NAME_TO_HIVE_MAP = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
        "HKEY_USERS": winreg.HKEY_USERS,
        "HKCC": winreg.HKEY_CURRENT_CONFIG,
        "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
    }
else:
    # Dummy IDs for Linux stubs
    HIVE_NAME_MAP = {
        0x80000001: "HKEY_CURRENT_USER",
        0x80000002: "HKEY_LOCAL_MACHINE",
    }
    HIVE_SHORT_MAP = {
        0x80000001: "HKCU",
        0x80000002: "HKLM",
    }
    NAME_TO_HIVE_MAP = {
        "HKLM": 0x80000002,
        "HKEY_LOCAL_MACHINE": 0x80000002,
        "HKCU": 0x80000001,
        "HKEY_CURRENT_USER": 0x80000001,
    }

REG_TYPE_MAP: Dict[int, str] = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}


CANONICAL_HIVE_NAME_MAP: Dict[int, str] = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0x80000001: "HKEY_CURRENT_USER",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0x80000003: "HKEY_USERS",
    0x80000005: "HKEY_CURRENT_CONFIG",
}

CANONICAL_HIVE_SHORT_MAP: Dict[int, str] = {
    0x80000000: "HKCR",
    0x80000001: "HKCU",
    0x80000002: "HKLM",
    0x80000003: "HKU",
    0x80000005: "HKCC",
}


def get_hive_name(hive: int, short: bool = True) -> str:
    """Translate integer hive handle to string representation (e.g. HKLM or HKEY_LOCAL_MACHINE)."""
    masked = (hive & 0xFFFFFFFF) if isinstance(hive, int) else 0
    if short:
        return CANONICAL_HIVE_SHORT_MAP.get(masked, HIVE_SHORT_MAP.get(hive, f"0x{masked:08X}"))
    return CANONICAL_HIVE_NAME_MAP.get(masked, HIVE_NAME_MAP.get(hive, f"0x{masked:08X}"))


def get_hive_from_name(hive_str: str) -> int:
    """Resolve hive string back to integer constant."""
    return NAME_TO_HIVE_MAP.get(hive_str.upper(), 0x80000002)


def get_reg_type_str(reg_type: int) -> str:
    """Translate integer registry type to descriptive string."""
    return REG_TYPE_MAP.get(reg_type, f"REG_TYPE_{reg_type}")


def compute_value_sha256(value_data: Any, reg_type: Optional[int] = None) -> str:
    """Calculate deterministic SHA-256 hash for arbitrary registry data.

    Args:
        value_data: Value data returned by winreg (str, bytes, int, list, etc.).
        reg_type: Optional integer type code.

    Returns:
        Hexadecimal SHA-256 digest string.
    """
    hasher = hashlib.sha256()
    try:
        if isinstance(value_data, bytes):
            hasher.update(value_data)
        elif isinstance(value_data, str):
            hasher.update(value_data.encode("utf-8", errors="replace"))
        elif isinstance(value_data, int):
            hasher.update(str(value_data).encode("utf-8"))
        elif isinstance(value_data, (list, tuple)):
            for item in value_data:
                hasher.update(str(item).encode("utf-8", errors="replace"))
        elif value_data is None:
            hasher.update(b"")
        else:
            hasher.update(str(value_data).encode("utf-8", errors="replace"))
    except Exception as exc:
        LOGGER.debug("Error computing hash for value %s: %s", value_data, exc)
        hasher.update(str(value_data).encode("utf-8", errors="ignore"))

    return hasher.hexdigest()


def normalize_value_data(raw_data: Any) -> str:
    """Convert arbitrary registry value data to human-readable string representation."""
    if isinstance(raw_data, bytes):
        return raw_data.hex()
    if isinstance(raw_data, (list, tuple)):
        return "; ".join(str(item) for item in raw_data)
    if raw_data is None:
        return ""
    return str(raw_data)


def read_key_values(hive: int, subkey: str) -> Dict[str, Dict[str, Any]]:
    """Defensively read all values under a given registry hive and subkey.

    STRICTLY READ-ONLY. Opens registry key with KEY_READ. If key does not exist or
    permission is denied, returns an empty dictionary without raising exceptions.

    Args:
        hive: Integer hive constant (e.g. winreg.HKEY_LOCAL_MACHINE).
        subkey: Registry path relative to the hive.

    Returns:
        Dict mapping value name (or "(Default)") to value payload dict:
            {
                "data": str,
                "data_raw": Any,
                "type": str,
                "type_code": int,
                "sha256": str
            }
    """
    if not WINREG_AVAILABLE:
        LOGGER.debug("winreg is not available on this platform; skipping key read for %s", subkey)
        return {}

    values: Dict[str, Dict[str, Any]] = {}
    flags = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)

    try:
        with winreg.OpenKeyEx(hive, subkey, 0, flags) as reg_key:
            num_subkeys, num_values, _ = winreg.QueryInfoKey(reg_key)
            for idx in range(num_values):
                try:
                    val_name, val_data, val_type = winreg.EnumValue(reg_key, idx)
                    display_name = val_name if val_name else "(Default)"
                    sha256_hash = compute_value_sha256(val_data, val_type)
                    str_data = normalize_value_data(val_data)

                    values[display_name] = {
                        "data": str_data,
                        "data_raw": val_data,
                        "type": get_reg_type_str(val_type),
                        "type_code": val_type,
                        "sha256": sha256_hash,
                    }
                except OSError as val_err:
                    LOGGER.debug("Could not read value at index %d of %s: %s", idx, subkey, val_err)
                    continue

    except FileNotFoundError:
        LOGGER.debug("Registry key not found: %s\\%s", get_hive_name(hive), subkey)
    except PermissionError:
        LOGGER.warning("Permission denied reading registry key: %s\\%s", get_hive_name(hive), subkey)
    except OSError as err:
        LOGGER.debug("OS error opening key %s\\%s: %s", get_hive_name(hive), subkey, err)

    return values


def list_subkeys(hive: int, subkey: str) -> List[str]:
    """Defensively enumerate names of immediate child subkeys.

    Args:
        hive: Integer hive handle.
        subkey: Relative registry key path.

    Returns:
        List of subkey names.
    """
    if not WINREG_AVAILABLE:
        return []

    subkeys: List[str] = []
    flags = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)

    try:
        with winreg.OpenKeyEx(hive, subkey, 0, flags) as reg_key:
            num_subkeys, _, _ = winreg.QueryInfoKey(reg_key)
            for idx in range(num_subkeys):
                try:
                    subkeys.append(winreg.EnumKey(reg_key, idx))
                except OSError:
                    continue
    except (FileNotFoundError, PermissionError, OSError):
        pass

    return subkeys
