"""Sistema de alertas modular para LAN-Guardian."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Protocol

import requests

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class Alert:
    ip: str
    mac: str
    vendor: str
    first_seen: str


class Notifier(Protocol):
    def send(self, alert: Alert) -> bool:
        """Envía una alerta y devuelve True si es exitosa."""
        ...


class ConsoleNotifier:
    """Sistema de notificación amigable para humanos."""

    def send(self, alert: Alert) -> bool:
        print(
            "\n"
            "╭─ LAN-GUARDIAN ALERT ─────────────────────╮\n"
            f"│ Nuevo dispositivo : {alert.ip:<26}│\n"
            f"│ MAC        : {alert.mac:<26}│\n"
            f"│ Fabricante     : {alert.vendor:<26}│\n"
            f"│ Primera aparición : {alert.first_seen:<26}│\n"
            "╰──────────────────────────────────────────╯"
        )
        return True


class DiscordWebhookNotifier:
    """Sistema de notificación a través de Discord webhooks."""

    def __init__(self, webhook_url: str, timeout: float = 5.0) -> None:
        self.webhook_url = webhook_url
        self.timeout = timeout

    def send(self, alert: Alert) -> bool:
        payload = {
            "embeds": [
                {
                    "title": "LAN-Guardian: Nuevo dispositivo descubierto",
                    "description": "Se ha observado una nueva dirección MAC nunca antes vista.",
                    "fields": [
                        {"name": "IP", "value": alert.ip, "inline": True},
                        {"name": "MAC", "value": alert.mac, "inline": True},
                        {"name": "Fabricante", "value": alert.vendor, "inline": True},
                        {"name": "Primera aparición", "value": alert.first_seen, "inline": False},
                    ],
                }
            ]
        }
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return True
        except requests.RequestException:
            LOGGER.exception("Fallo en la notificación a través de Discord webhook")
            return False


class TelegramNotifier:
    """Telegram Bot API notifier."""

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        timeout: float = 5.0,
    ) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.timeout = timeout

    def send(self, alert: Alert) -> bool:
        text = (
            "🚨 LAN-Guardian: nuevo dispositivo\n"
            f"IP: {alert.ip}\n"
            f"MAC: {alert.mac}\n"
            f"Fabricante: {alert.vendor}\n"
            f"Primera aparición: {alert.first_seen}"
        )

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        try:
            response = requests.post(
                url,
                json={"chat_id": self.chat_id, "text": text},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return True
        except requests.RequestException:
            LOGGER.exception("Fallo en la notificación a través de Telegram")
            return False


class NotifierChain:
    """Notificador con distribución múltiple (fan-out); los fallos se aíslan por destino."""

    def __init__(self, notifiers: list[Notifier]) -> None:
        self.notifiers = notifiers

    def send(self, alert: Alert) -> bool:
        if not self.notifiers:
            return True

        overall_ok = True
        for notifier in self.notifiers:
            try:
                ok = notifier.send(alert)
                overall_ok = overall_ok and ok
            except Exception:
                LOGGER.exception("El notificador %r lanzó una excepción inesperada", notifier)
                overall_ok = False
        return overall_ok


def build_notifier_chain(
    *,
    discord_webhook: str | None = None,
    telegram_bot_token: str | None = None,
    telegram_chat_id: str | None = None,
) -> NotifierChain:
    """Crea la consola configurada + notificadores remotos opcionales."""
    notifiers: list[Notifier] = [ConsoleNotifier()]

    if discord_webhook:
        notifiers.append(DiscordWebhookNotifier(discord_webhook))

    if telegram_bot_token and telegram_chat_id:
        notifiers.append(TelegramNotifier(telegram_bot_token, telegram_chat_id))

    return NotifierChain(notifiers)

