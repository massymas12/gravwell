"""Built-in asset discovery — ping sweep, ARP, SNMP, TCP connect, CDP/LLDP."""
from gravwell.discovery.runner import discover, DiscoveryResult

__all__ = ["discover", "DiscoveryResult"]
