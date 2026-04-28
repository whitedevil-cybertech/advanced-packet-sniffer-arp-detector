from __future__ import annotations

from scapy.all import get_if_list


def list_interfaces() -> list[str]:
    """Return raw interface identifiers (Windows: \\Device\\NPF_{GUID})."""
    return list(get_if_list())


def interface_exists(iface: str) -> bool:
    return iface in set(get_if_list())