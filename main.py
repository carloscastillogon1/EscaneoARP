#!/usr/bin/env python3
"""LAN-Guardian CLI."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from dataclasses import asdict

from src.database import NetworkDatabase
from src.notifier import Alert, build_notifier_chain
from src.scanner import ARPScanner, ScanError
from src.vendor import lookup_vendor

LOGGER = logging.getLogger("lan-guardian")


class GracefulStop:
    def __init__(self) -> None:
        self.stop = False

    def __call__(self, _signum, _frame) -> None:
        self.stop = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "LAN-Guardian: Monitor de red local basado en ARP para "
            "descubrir dispositivos nuevos en la red."
        )
    )
    parser.add_argument(
        "--interface",
        default=os.getenv("LAN_GUARDIAN_INTERFACE"),
        help="Interfaz de red (por ejemplo, eth0, enp3s0, adaptador Wi-Fi).",
    )
    parser.add_argument(
        "--subnet",
        default=os.getenv("LAN_GUARDIAN_SUBNET"),
        required=os.getenv("LAN_GUARDIAN_SUBNET") is None,
        help="IPv4 CIDR to scan, e.g. 192.168.1.0/24.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.getenv("LAN_GUARDIAN_INTERVAL", "60")),
        help="Segundos entre escaneos en modo loop (por defecto: 60).",
    )
    parser.add_argument(
        "--mode",
        choices=("once", "loop"),
        default=os.getenv("LAN_GUARDIAN_MODE", "loop"),
        help="Ejecutar una vez o continuamente (por defecto: loop).",
    )
    parser.add_argument(
        "--db",
        default=os.getenv("LAN_GUARDIAN_DB", "network.db"),
        help="Ruta de la base de datos SQLite (por defecto: network.db).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.getenv("LAN_GUARDIAN_SCAN_TIMEOUT", "2")),
        help="Tiempo de espera por lote de respuestas ARP en segundos.",
    )
    parser.add_argument(
        "--retry",
        type=int,
        default=int(os.getenv("LAN_GUARDIAN_RETRY", "1")),
        help="Número de reintentos de Scapy por lote.",
    )
    parser.add_argument(
        "--vendor-api",
        action="store_true",
        help="Permitir consultas remotas a macvendors.com para OUIs desconocidos.",
    )
    parser.add_argument(
        "--discord-webhook",
        default=os.getenv("LAN_GUARDIAN_DISCORD_WEBHOOK"),
        help="URL del webhook de entrada de Discord.",
    )
    parser.add_argument(
        "--telegram-bot-token",
        default=os.getenv("LAN_GUARDIAN_TELEGRAM_BOT_TOKEN"),
        help="Telegram Bot API token.",
    )
    parser.add_argument(
        "--telegram-chat-id",
        default=os.getenv("LAN_GUARDIAN_TELEGRAM_CHAT_ID"),
        help="Telegram chat ID.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Activar registro de depuración (debug logging).",
    )
    return parser.parse_args()


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def run_scan(
    *,
    scanner: ARPScanner,
    db: NetworkDatabase,
    notifier,
    subnet: str,
    vendor_api: bool,
) -> int:
    observations = scanner.scan(subnet)
    LOGGER.info("ARP scan completed: %d device(s) observed", len(observations))

    new_count = 0

    for observation in observations:
        vendor_info = lookup_vendor(
            observation.mac,
            use_remote_api=vendor_api,
        )

        record, is_new = db.upsert_observation(
            mac=observation.mac,
            ip=observation.ip,
            vendor=vendor_info.vendor,
        )

        if is_new:
            new_count += 1
            notifier.send(
                Alert(
                    ip=record.last_ip,
                    mac=record.mac,
                    vendor=(
                        f"{record.vendor or 'Unknown'}"
                        + (
                            " [posible MAC aleatoria/privacidad]"
                            if vendor_info.is_locally_administered
                            else ""
                        )
                    ),
                    first_seen=record.first_seen,
                )
            )

        LOGGER.debug(
            "Observed %s -> %s (vendor=%s, status=%s, new=%s)",
            observation.ip,
            observation.mac,
            vendor_info.vendor,
            record.status,
            is_new,
        )

    return new_count


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)

    if args.interval <= 0:
        LOGGER.error("--interval debe ser > 0")
        return 2

    if args.timeout <= 0:
        LOGGER.error("--timeout debe ser > 0")
        return 2

    try:
        scanner = ARPScanner(
            interface=args.interface,
            timeout=args.timeout,
            retry=args.retry,
        )
    except ValueError as exc:
        LOGGER.error("Configuracion invalida del escaner: %s", exc)
        return 2

    notifier = build_notifier_chain(
        discord_webhook=args.discord_webhook,
        telegram_bot_token=args.telegram_bot_token,
        telegram_chat_id=args.telegram_chat_id,
    )

    stopper = GracefulStop()
    signal.signal(signal.SIGINT, stopper)
    signal.signal(signal.SIGTERM, stopper)

    with NetworkDatabase(args.db) as db:
        while not stopper.stop:
            started = time.monotonic()

            try:
                new_count = run_scan(
                    scanner=scanner,
                    db=db,
                    notifier=notifier,
                    subnet=args.subnet,
                    vendor_api=args.vendor_api,
                )
                LOGGER.info("Resumen del escaneo: %d dispositivo(s) nuevo(s)", new_count)
            except ScanError as exc:
                LOGGER.error("%s", exc)
                if args.mode == "once":
                    return 1
            except KeyboardInterrupt:
                break
            except Exception:
                LOGGER.exception("Error inesperado en el monitor")
                if args.mode == "once":
                    return 1

            if args.mode == "once":
                break

            elapsed = time.monotonic() - started
            sleep_for = max(0.0, args.interval - elapsed)

            LOGGER.info(
                "Próximo escaneo en %.1f segundo(s). Presione Ctrl+C para detener.",
                sleep_for,
            )

            # Pausar en cortos intervalos para que SIGINT/SIGTERM sea ágil.
            deadline = time.monotonic() + sleep_for
            while not stopper.stop and time.monotonic() < deadline:
                time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))

    LOGGER.info("LAN-Guardian stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

