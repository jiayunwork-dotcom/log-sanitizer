import re
import threading
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Callable, Tuple
from collections import defaultdict
from .models import (
    AlertEvent,
    AlertSeverity,
    AlertType,
    SuppressionRule,
    SuppressionAction,
    PendingAlert,
)
from .config import AnomalyDetectionConfig


class SuppressionEngine:
    def __init__(self, config: AnomalyDetectionConfig):
        self.config = config
        self.rules = config.suppression_rules
        self._lock = threading.Lock()
        self._pending_alerts: List[PendingAlert] = []
        self._recent_alerts: Dict[Tuple[str, AlertType], List[datetime]] = defaultdict(list)
        self._output_callback: Optional[Callable[[AlertEvent], None]] = None

    def set_output_callback(self, callback: Callable[[AlertEvent], None]) -> None:
        self._output_callback = callback

    def _matches_rule(self, alert: AlertEvent, rule: SuppressionRule) -> bool:
        if not rule.enabled:
            return False

        match = rule.match

        if match.source_pattern:
            if not re.search(match.source_pattern, alert.source):
                return False

        if match.alert_types:
            if alert.alert_type not in match.alert_types:
                return False

        if match.severities:
            if alert.severity not in match.severities:
                return False

        if match.cron_expression:
            if not self._check_cron(match.cron_expression, alert.timestamp):
                return False

        return True

    def _check_cron(self, cron_expr: str, timestamp: datetime) -> bool:
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return True

        minute, hour, day, month, weekday = parts

        now = timestamp

        def _matches(value: int, expr: str) -> bool:
            if expr == '*':
                return True
            if ',' in expr:
                return any(_matches(value, p) for p in expr.split(','))
            if '-' in expr:
                start, end = map(int, expr.split('-'))
                return start <= value <= end
            if expr.startswith('*/'):
                step = int(expr[2:])
                return value % step == 0
            return value == int(expr)

        return (
            _matches(now.minute, minute) and
            _matches(now.hour, hour) and
            _matches(now.day, day) and
            _matches(now.month, month) and
            _matches(now.weekday(), weekday)
        )

    def _downgrade_severity(self, severity: AlertSeverity) -> AlertSeverity:
        if severity == AlertSeverity.CRITICAL:
            return AlertSeverity.WARNING
        elif severity == AlertSeverity.WARNING:
            return AlertSeverity.INFO
        return severity

    def process_alert(self, alert: AlertEvent) -> Optional[AlertEvent]:
        with self._lock:
            for rule in self.rules:
                if self._matches_rule(alert, rule):
                    rule.hit_count += 1
                    rule.last_hit_time = datetime.now(timezone.utc)

                    if rule.action == SuppressionAction.SUPPRESS:
                        return None

                    elif rule.action == SuppressionAction.DOWNGRADE:
                        alert.severity = self._downgrade_severity(alert.severity)
                        alert.extra['suppression_rule'] = rule.name
                        alert.extra['suppression_action'] = 'downgraded'
                        return alert

                    elif rule.action == SuppressionAction.DELAY:
                        delay_until = datetime.now(timezone.utc) + timedelta(seconds=rule.delay_seconds)
                        pending = PendingAlert(
                            alert=alert,
                            rule_name=rule.name,
                            delay_until=delay_until,
                            check_alert_type=alert.alert_type,
                            check_source=alert.source,
                        )
                        self._pending_alerts.append(pending)
                        return None

            return alert

    def check_pending_alerts(self) -> None:
        with self._lock:
            now = datetime.now(timezone.utc)
            expired = []
            remaining = []

            for pending in self._pending_alerts:
                if now >= pending.delay_until:
                    expired.append(pending)
                else:
                    remaining.append(pending)

            self._pending_alerts = remaining

        for pending in expired:
            self._process_expired_pending(pending)

    def _process_expired_pending(self, pending: PendingAlert) -> None:
        source = pending.check_source
        alert_type = pending.check_alert_type
        delay_seconds = pending.rule.delay_seconds if hasattr(pending.rule, 'delay_seconds') else 0

        recent = self._recent_alerts.get((source, alert_type), [])
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=delay_seconds)
        has_recent = any(ts > cutoff for ts in recent)

        if has_recent:
            alert = pending.alert
            alert.extra['suppression_rule'] = pending.rule_name
            alert.extra['suppression_action'] = 'delayed_kept'
            if self._output_callback:
                self._output_callback(alert)

    def record_alert(self, alert: AlertEvent) -> None:
        with self._lock:
            key = (alert.source, alert.alert_type)
            self._recent_alerts[key].append(alert.timestamp)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
            self._recent_alerts[key] = [
                ts for ts in self._recent_alerts[key] if ts > cutoff
            ]

    def get_rule_stats(self) -> List[Dict[str, Any]]:
        with self._lock:
            stats = []
            for rule in self.rules:
                stats.append({
                    'name': rule.name,
                    'enabled': rule.enabled,
                    'action': rule.action.value,
                    'match': {
                        'source_pattern': rule.match.source_pattern,
                        'alert_types': [t.value for t in rule.match.alert_types] if rule.match.alert_types else None,
                        'severities': [s.value for s in rule.match.severities] if rule.match.severities else None,
                        'cron_expression': rule.match.cron_expression,
                    },
                    'delay_seconds': rule.delay_seconds,
                    'hit_count': rule.hit_count,
                    'last_hit_time': rule.last_hit_time.isoformat() if rule.last_hit_time else None,
                })
            return stats

    def get_pending_count(self) -> int:
        with self._lock:
            return len(self._pending_alerts)

    def flush_pending(self) -> None:
        with self._lock:
            for pending in self._pending_alerts:
                alert = pending.alert
                alert.extra['suppression_rule'] = pending.rule_name
                alert.extra['suppression_action'] = 'flushed'
                if self._output_callback:
                    self._output_callback(alert)
            self._pending_alerts = []

    def load_rule_stats(self, stats_data: Dict[str, Dict[str, Any]]) -> None:
        with self._lock:
            for rule in self.rules:
                if rule.name in stats_data:
                    data = stats_data[rule.name]
                    rule.hit_count = data.get('hit_count', 0)
                    if data.get('last_hit_time'):
                        rule.last_hit_time = datetime.fromisoformat(data['last_hit_time'].replace('Z', '+00:00'))

    def to_dict(self) -> Dict[str, Any]:
        return {
            rule.name: {
                'hit_count': rule.hit_count,
                'last_hit_time': rule.last_hit_time.isoformat() if rule.last_hit_time else None,
            }
            for rule in self.rules
        }
