"""Descubrimiento de red local basado en ARP para LAN-Guardian.

Requisitos:
    - Linux/macOS/Windows con Scapy instalado.
    - El envío de tramas ARP de Capa 2 generalmente requiere privilegios elevados
      (root/Administrador) y una tarjeta de red (NIC) que permita el acceso a paquetes sin procesar (raw packets).
    - En Linux, se pueden utilizar CAP_NET_RAW/CAP_NET_ADMIN en lugar de root completo,
      dependiendo del entorno y de la configuración de Scapy/sockets.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Iterable

from scapy.all import ARP, Ether, conf, srp

LOGGER = logging.getLogger(__name__)


class ScanError(RuntimeError):
    """Raised when an ARP scan cannot be completed."""


@dataclass(frozen=True)
class DeviceObservation:
    """One IP/MAC pair observed during an ARP sweep."""

    ip: str
    mac: str


class ARPScanner:
    """Perform ARP discovery against a single IPv4 subnet."""

    def __init__(
        self,
        interface: str | None = None,
        timeout: float = 2.0,
        retry: int = 1,
        packet_batch_size: int = 1024,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        if retry < 0:
            raise ValueError("retry must be >= 0")
        if packet_batch_size <= 0:
            raise ValueError("packet_batch_size must be > 0")

        self.interface = interface
        self.timeout = timeout
        self.retry = retry
        self.packet_batch_size = packet_batch_size

    @staticmethod
    def _validate_subnet(subnet: str) -> ipaddress.IPv4Network:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid subnet: {subnet}") from exc

        if network.version != 4:
            raise ValueError("LAN-Guardian currently supports IPv4 ARP scanning only.")
        return network

    @staticmethod
    def _normalize_mac(mac: str) -> str:
        return mac.strip().lower()

    def _chunks(self, network: ipaddress.IPv4Network) -> Iterable[list[str]]:
        hosts = [str(host) for host in network.hosts()]
        for index in range(0, len(hosts), self.packet_batch_size):
            yield hosts[index : index + self.packet_batch_size]

    def scan(self, subnet: str) -> list[DeviceObservation]:
        """Return unique IP/MAC observations for *subnet*.

        ARP is link-local. Do not expect this method to discover hosts beyond
        the Layer-2 broadcast domain or across routed boundaries.
        """
        network = self._validate_subnet(subnet)

        if self.interface:
            conf.iface = self.interface
        active_iface = self.interface or str(conf.iface)

        observations: dict[str, DeviceObservation] = {}

        try:
            for destination_ips in self._chunks(network):
                if not destination_ips:
                    continue

                packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    pdst=destination_ips,
                )

                answered, _ = srp(
                    packet,
                    iface=active_iface,
                    timeout=self.timeout,
                    retry=self.retry,
                    verbose=False,
                )

                for _sent, received in answered:
                    ip = getattr(received, "psrc", None)
                    mac = getattr(received, "hwsrc", None)
                    if not ip or not mac:
                        continue
                    normalized_mac = self._normalize_mac(mac)
                    observations[ip] = DeviceObservation(
                        ip=ip,
                        mac=normalized_mac,
                    )

        except PermissionError as exc:
            raise ScanError(
                "Insufficient privileges to send ARP frames. "
                "Run with appropriate raw-socket/network capabilities."
            ) from exc
        except OSError as exc:
            raise ScanError(
                f"Network interface/raw-socket error on {active_iface!r}: {exc}"
            ) from exc
        except Exception as exc:  # Scapy can surface platform-specific exceptions.
            LOGGER.exception("Unexpected ARP scan failure")
            raise ScanError(f"ARP scan failed: {exc}") from exc

        return sorted(
            observations.values(),
            key=lambda item: tuple(int(part) for part in item.ip.split(".")),
        )

