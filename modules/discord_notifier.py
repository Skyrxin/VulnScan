"""
Discord notifier for VulnScan

Provides a simple DiscordNotifier class that sends an embed summary to a
Discord webhook URL when a vulnerability scan completes.

Usage:
    from modules.discord_notifier import DiscordNotifier
    notifier = DiscordNotifier(webhook_url)
    notifier.send_notification(results, target_url)

This module uses the requests library. Ensure it's listed in requirements.txt
"""
import json
from datetime import datetime
from typing import Dict, Any

import requests
from colorama import Fore, Style


class DiscordNotifier:
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url

    def set_webhook_url(self, url: str):
        self.webhook_url = url

    def _build_embed(self, results: Dict[str, Any], target: str | None = None) -> Dict[str, Any]:
        total = sum(len(v) for v in results.values()) if results else 0
        title = "✅ Scan Completed - No Vulnerabilities" if total == 0 else f"⚠️ Scan Completed - {total} Vulnerabilities"
        color = 3066993 if total == 0 else 15158332

        fields = []
        if results:
            for k, v in results.items():
                if v:
                    fields.append({
                        "name": k.upper(),
                        "value": str(len(v)),
                        "inline": True
                    })

        embed = {
            "title": title,
            "description": f"Target: {target or 'Unknown'}\nCompleted: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "color": color,
            "fields": fields[:10],
        }

        return embed

    def send_notification(self, results: Dict[str, Any], target: str | None = None) -> bool:
        if not self.webhook_url:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Discord webhook not configured. Skipping notification.")
            return False

        embed = self._build_embed(results, target)

        payload = {"embeds": [embed]}

        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            if resp.status_code in (200, 204):
                print(f"{Fore.GREEN}[+] Discord notification sent successfully!{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to send Discord notification. Status: {resp.status_code} Response: {resp.text}")
                return False
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Exception while sending Discord notification: {e}")
            return False
