"""Análisis de MAC/OUI e identificación ligera de fabricantes.

El mapa OUI local que figura a continuación contiene intencionadamente solo un pequeño
conjunto de prefijos comunes. Para una mayor cobertura, el módulo puede consultar
opcionalmente la API pública macvendors.com cuando se habilita explícitamente.

La detección de privacidad/aleatorización es heurística:
    - El bit 1 del primer octeto (bit U/L) indica una MAC administrada localmente.
      Las MACs móviles o de Wi-Fi privado suelen utilizar este espacio.
    - Este indicador no es una prueba absoluta de que una MAC sea aleatoria, ya que
      las direcciones administradas localmente también pueden asignarse manualmente
      o virtualizarse.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import requests

MAC_RE = re.compile(
    r"^(?P<a>[0-9a-f]{2})[:\-]"
    r"(?P<b>[0-9a-f]{2})[:\-]"
    r"(?P<c>[0-9a-f]{2})[:\-]"
    r"(?P<d>[0-9a-f]{2})[:\-]"
    r"(?P<e>[0-9a-f]{2})[:\-]"
    r"(?P<f>[0-9a-f]{2})$",
    re.IGNORECASE,
)

COMMON_OUIS = {
    "00:17:f2": "Apple",
    "00:1a:79": "Samsung Electronics",
    "28:cf:e9": "Samsung Electronics",
    "3c:5a:b4": "Google",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "3c:52:82": "Cisco",
    "00:1b:21": "Intel",
    "3c:22:fb": "Intel",
}


@dataclass(frozen=True)
class VendorInfo:
    vendor: str
    is_locally_administered: bool
    is_broadcast_or_multicast: bool


def normalize_mac(mac: str) -> str:
    match = MAC_RE.match(mac.strip())
    if not match:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    octets = [match.group(name).lower() for name in "abcdef"]
    return ":".join(octets)


def _is_local_administered(first_octet: int) -> bool:
    return bool(first_octet & 0b00000010)


def _is_multicast(first_octet: int) -> bool:
    return bool(first_octet & 0b00000001)


def lookup_vendor(
    mac: str,
    *,
    use_remote_api: bool | None = None,
    timeout: float = 3.0,
) -> VendorInfo:
    normalized = normalize_mac(mac)
    first_octet = int(normalized.split(":")[0], 16)

    locally_administered = _is_local_administered(first_octet)
    multicast = _is_multicast(first_octet)

    if multicast:
        return VendorInfo(
            vendor="Multicast/Group address",
            is_locally_administered=locally_administered,
            is_broadcast_or_multicast=True,
        )

    if locally_administered:
        # Revisa primero el mapa configurable, luego etiquétalo como privacidad/local.
        vendor = COMMON_OUIS.get(normalized[:8], "Locally administered / possible privacy MAC")
        if vendor == "Locally administered / possible privacy MAC":
            return VendorInfo(
                vendor=vendor,
                is_locally_administered=True,
                is_broadcast_or_multicast=False,
            )

    vendor = COMMON_OUIS.get(normalized[:8])
    if vendor:
        return VendorInfo(
            vendor=vendor,
            is_locally_administered=locally_administered,
            is_broadcast_or_multicast=False,
        )

    remote_enabled = (
        os.getenv("LAN_GUARDIAN_VENDOR_API", "0").lower()
        in {"1", "true", "yes", "on"}
        if use_remote_api is None
        else use_remote_api
    )

    if remote_enabled:
        try:
            response = requests.get(
                f"https://api.macvendors.com/{normalized}",
                timeout=timeout,
                headers={"User-Agent": "LAN-Guardian/1.0"},
            )
            if response.ok:
                vendor_text = response.text.strip()
                if vendor_text:
                    return VendorInfo(
                        vendor=vendor_text,
                        is_locally_administered=locally_administered,
                        is_broadcast_or_multicast=False,
                    )
        except requests.RequestException:
           # La búsqueda de proveedor nunca debería hacer que la exploración de la red falle.
            pass

    return VendorInfo(
        vendor="Unknown OUI",
        is_locally_administered=locally_administered,
        is_broadcast_or_multicast=False,
    )

