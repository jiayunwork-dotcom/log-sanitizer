import threading
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Callable, Dict, Tuple
from collections import defaultdict
from .models import (
    AlertEvent,
    AlertSeverity,
    AlertType,
    DetectorName,
    AlertStats,
)
from .config import AnomalyDetectionConfig


class AlertAggregator:
    def __init__(self, config: AnomalyDetectionConfig):
        self.config = config
        self._lock = threading.Lock()
        self._last_alert_time: Dict[Tuple[str, AlertType], datetime] = {}
        self._pending_alerts: Dict[str, Dict[AlertType, AlertEvent]] = defaultdict(dict)
        self._output_callback: Optional[Callable[[AlertEvent], None]] = None
        self.stats = AlertStats()

    def set_output_callback(self, callback: Callable[[AlertEvent], None]) -> None:
        self._output_callback = callback

    def process_alert(self, alert: AlertEvent) -> None:
        if self._is_suppressed(alert):
            return

        with self._lock:
            self._record_alert_time(alert)

            if self._should_correlate(alert):
                pending = self._pending_alerts[alert.source]
                if alert.alert_type in pending:
                    self._emit_alert(pending[alert.alert_type])
                pending[alert.alert_type] = alert
                self._check_and_emit_composite(alert.source)
            else:
                self._emit_alert(alert)

    def _is_suppressed(self, alert: AlertEvent) -> bool:
        key = (alert.source, alert.alert_type)
        suppression_window = timedelta(seconds=self.config.suppression_window_seconds)

        with self._lock:
            last_time = self._last_alert_time.get(key)
            if last_time and (alert.timestamp - last_time) < suppression_window:
                return True
            return False

    def _record_alert_time(self, alert: AlertEvent) -> None:
        key = (alert.source, alert.alert_type)
        self._last_alert_time[key] = alert.timestamp

    def _should_correlate(self, alert: AlertEvent) -> bool:
        return alert.alert_type in (AlertType.FREQUENCY_SPIKE, AlertType.ERROR_RATE_SURGE)

    def _check_and_emit_composite(self, source: str) -> None:
        pending = self._pending_alerts.get(source, {})
        correlation_window = timedelta(seconds=self.config.correlation_window_seconds)

        freq_alert = pending.get(AlertType.FREQUENCY_SPIKE)
        err_alert = pending.get(AlertType.ERROR_RATE_SURGE)

        if freq_alert and err_alert:
            time_diff = abs((freq_alert.timestamp - err_alert.timestamp).total_seconds())
            if time_diff <= self.config.correlation_window_seconds:
                composite_alert = self._create_composite_alert(freq_alert, err_alert)
                del pending[AlertType.FREQUENCY_SPIKE]
                del pending[AlertType.ERROR_RATE_SURGE]
                self._emit_alert(composite_alert)
                return

        if freq_alert:
            time_since = (datetime.now(timezone.utc) - freq_alert.timestamp).total_seconds()
            if time_since > self.config.correlation_window_seconds:
                del pending[AlertType.FREQUENCY_SPIKE]
                self._emit_alert(freq_alert)

        if err_alert:
            time_since = (datetime.now(timezone.utc) - err_alert.timestamp).total_seconds()
            if time_since > self.config.correlation_window_seconds:
                del pending[AlertType.ERROR_RATE_SURGE]
                self._emit_alert(err_alert)

    def _create_composite_alert(self, freq_alert: AlertEvent, err_alert: AlertEvent) -> AlertEvent:
        line_range = None
        if freq_alert.line_range and err_alert.line_range:
            line_range = (
                min(freq_alert.line_range[0], err_alert.line_range[0]),
                max(freq_alert.line_range[1], err_alert.line_range[1]),
            )
        elif freq_alert.line_range:
            line_range = freq_alert.line_range
        elif err_alert.line_range:
            line_range = err_alert.line_range

        description = (
            f"Composite anomaly detected: Frequency spike ({freq_alert.trigger_value:.4f} entries/sec) "
            f"and Error rate surge ({err_alert.trigger_value:.4f}) occurred within "
            f"{self.config.correlation_window_seconds} seconds"
        )

        return AlertEvent(
            id=str(uuid.uuid4()),
            timestamp=max(freq_alert.timestamp, err_alert.timestamp),
            severity=AlertSeverity.CRITICAL,
            alert_type=AlertType.COMPOSITE_ANOMALY,
            source=freq_alert.source,
            detector=DetectorName.FREQUENCY,
            trigger_value=max(freq_alert.trigger_value, err_alert.trigger_value),
            threshold=min(freq_alert.threshold, err_alert.threshold),
            baseline_value=freq_alert.baseline_value,
            line_range=line_range,
            description=description,
            extra={
                "frequency_alert": freq_alert.to_dict(),
                "error_rate_alert": err_alert.to_dict(),
                "correlation_window_seconds": self.config.correlation_window_seconds,
            }
        )

    def _emit_alert(self, alert: AlertEvent) -> None:
        self._update_stats(alert)
        if self._output_callback:
            try:
                self._output_callback(alert)
            except Exception as e:
                print(f"Error in alert output callback: {e}", flush=True)

    def _update_stats(self, alert: AlertEvent) -> None:
        self.stats.total_alerts += 1
        self.stats.by_severity[alert.severity] = self.stats.by_severity.get(alert.severity, 0) + 1
        self.stats.by_type[alert.alert_type] = self.stats.by_type.get(alert.alert_type, 0) + 1
        self.stats.by_source[alert.source] = self.stats.by_source.get(alert.source, 0) + 1
        self.stats.by_detector[alert.detector] = self.stats.by_detector.get(alert.detector, 0) + 1

    def flush_pending(self) -> None:
        with self._lock:
            for source, pending in list(self._pending_alerts.items()):
                for alert_type, alert in list(pending.items()):
                    del pending[alert_type]
                    self._emit_alert(alert)
            self._pending_alerts.clear()

    def get_stats(self) -> AlertStats:
        with self._lock:
            return AlertStats(
                total_alerts=self.stats.total_alerts,
                by_severity=dict(self.stats.by_severity),
                by_type=dict(self.stats.by_type),
                by_source=dict(self.stats.by_source),
                by_detector=dict(self.stats.by_detector),
            )

    def reset_stats(self) -> None:
        with self._lock:
            self.stats = AlertStats()
