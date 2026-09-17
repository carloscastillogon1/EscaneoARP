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
    """Se lanza cuando no se puede completar un escaneo ARP."""


@dataclass(frozen=True)
class DeviceObservation:
    """Un par IP/MAC observado durante un barrido ARP."""

    ip: str
    mac: str


class ARPScanner:
    """Realiza el descubrimiento ARP en una única subred IPv4."""

    def __init__(
        self,
        interface: str | None = None,
        timeout: float = 2.0,
        retry: int = 1,
        packet_batch_size: int = 1024,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout debe ser > 0")
        if retry < 0:
            raise ValueError("retry debe ser >= 0")
        if packet_batch_size <= 0:
            raise ValueError("packet_batch_size debe ser > 0")

        self.interface = interface
        self.timeout = timeout
        self.retry = retry
        self.packet_batch_size = packet_batch_size

    @staticmethod
    def _validate_subnet(subnet: str) -> ipaddress.IPv4Network:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            raise ValueError(f"Subred inválida: {subnet}") from exc

        if network.version != 4:
            raise ValueError("LAN-Guardian actualmente solo admite escaneo ARP IPv4.")
        return network

    @staticmethod
    def _normalize_mac(mac: str) -> str:
        return mac.strip().lower()

    def _chunks(self, network: ipaddress.IPv4Network) -> Iterable[list[str]]:
        hosts = [str(host) for host in network.hosts()]
        for index in range(0, len(hosts), self.packet_batch_size):
            yield hosts[index : index + self.packet_batch_size]

    def scan(self, subnet: str) -> list[DeviceObservation]:
        """Devuelve observaciones únicas de IP/MAC para la *subnet* especificada.

        El protocolo ARP es de enlace local (link-local). No espere que este método
        descubra hosts más allá del dominio de difusión de Capa 2 o a través de
        límites enrutados.
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
                "Privilegios insuficientes para enviar tramas ARP. "
                "Ejecute con las capacidades de red o socket de bajo nivel apropiadas."
            ) from exc
        except OSError as exc:
            raise ScanError(
                f"Error en la interfaz de red o socket de bajo nivel en {active_iface!r}: {exc}"
            ) from exc
        except Exception as exc:  # Scapy puede arrojar excepciones específicas de la plataforma.
            LOGGER.exception("Falla inesperada en el escaneo ARP")
            raise ScanError(f"El escaneo ARP falló: {exc}") from exc

        return sorted(
            observations.values(),
            key=lambda item: tuple(int(part) for part in item.ip.split(".")),
        )

