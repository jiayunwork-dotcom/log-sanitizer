import os
import json
import time
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional
from .models import AlertEvent, AlertSeverity
from .config import WebhookConfig


class AlertOutput:
    def __init__(self, alert_file: Optional[str], webhook_config: Optional[WebhookConfig] = None):
        self.alert_file = alert_file
        self.webhook_config = webhook_config or WebhookConfig()
        self._lock = threading.Lock()
        self._file_handle = None

        if self.alert_file:
            self._ensure_alert_file()

    def _ensure_alert_file(self) -> None:
        if not self.alert_file:
            return

        alert_dir = os.path.dirname(os.path.abspath(self.alert_file))
        if alert_dir:
            os.makedirs(alert_dir, exist_ok=True)

    def _get_file_handle(self):
        if self._file_handle is None and self.alert_file:
            self._file_handle = open(self.alert_file, 'a', encoding='utf-8', buffering=1)
        return self._file_handle

    def write_alert(self, alert: AlertEvent) -> None:
        self._write_to_file(alert)

        if alert.severity == AlertSeverity.CRITICAL and self.webhook_config.url:
            self._send_webhook(alert)

    def _write_to_file(self, alert: AlertEvent) -> None:
        if not self.alert_file:
            return

        with self._lock:
            try:
                handle = self._get_file_handle()
                if handle:
                    alert_json = json.dumps(alert.to_dict(), ensure_ascii=False)
                    handle.write(alert_json + '\n')
                    handle.flush()
            except Exception as e:
                print(f"Error writing alert to file: {e}", flush=True)

    def _send_webhook(self, alert: AlertEvent) -> None:
        if not self.webhook_config.url:
            return

        alert_json = json.dumps(alert.to_dict(), ensure_ascii=False).encode('utf-8')

        max_retries = self.webhook_config.max_retries
        retry_interval = self.webhook_config.retry_interval_seconds
        timeout = self.webhook_config.timeout_seconds

        last_error = None
        for attempt in range(max_retries + 1):
            try:
                headers = {
                    'Content-Type': 'application/json',
                    **self.webhook_config.headers,
                }

                req = urllib.request.Request(
                    self.webhook_config.url,
                    data=alert_json,
                    headers=headers,
                    method='POST'
                )

                with urllib.request.urlopen(req, timeout=timeout) as response:
                    if 200 <= response.status < 300:
                        return
                    else:
                        last_error = f"HTTP {response.status}: {response.read().decode('utf-8', errors='replace')}"

            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
                last_error = str(e)

            if attempt < max_retries:
                time.sleep(retry_interval)

        if last_error:
            print(f"Failed to send webhook after {max_retries + 1} attempts: {last_error}", flush=True)
            self._write_to_dead_letter(alert, last_error)

    def _write_to_dead_letter(self, alert: AlertEvent, error: str) -> None:
        dead_letter_file = self.webhook_config.dead_letter_file
        if not dead_letter_file:
            return

        try:
            dead_letter_dir = os.path.dirname(os.path.abspath(dead_letter_file))
            if dead_letter_dir:
                os.makedirs(dead_letter_dir, exist_ok=True)

            dead_letter_entry = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'error': error,
                'alert': alert.to_dict(),
                'webhook_url': self.webhook_config.url,
            }

            with open(dead_letter_file, 'a', encoding='utf-8', buffering=1) as f:
                f.write(json.dumps(dead_letter_entry, ensure_ascii=False) + '\n')
        except Exception as e:
            print(f"Error writing to dead letter file: {e}", flush=True)

    def close(self) -> None:
        with self._lock:
            if self._file_handle:
                try:
                    self._file_handle.close()
                except Exception:
                    pass
                self._file_handle = None
