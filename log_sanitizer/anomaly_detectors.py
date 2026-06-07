import re
import math
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, List
from .models import (
    LogEntry,
    LogLevel,
    AlertEvent,
    AlertSeverity,
    AlertType,
    DetectorName,
    FrequencyState,
    ErrorRateState,
    PatternState,
)
from .config import (
    FrequencyAlgorithmConfig,
    ErrorRateAlgorithmConfig,
    PatternAlgorithmConfig,
)
from .event_bus import EventBus


IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
UUID_PATTERN = r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
NUM_PATTERN = r'\b\d+\b'
PATH_VAR_PATTERN = r'/\d+(?:/|$)'


class BaseDetector:
    def __init__(self, config, event_bus: EventBus, min_samples: int = 100):
        self.config = config
        self.event_bus = event_bus
        self.min_samples = min_samples
        self.current_line_start: int = 0
        self.current_line_end: int = 0

    def set_line_range(self, start: int, end: int) -> None:
        self.current_line_start = start
        self.current_line_end = end

    def _publish_alert(self, alert: AlertEvent) -> None:
        alert.line_range = (self.current_line_start, self.current_line_end)
        self.event_bus.publish(alert.alert_type.value, alert)


class FrequencyDetector(BaseDetector):
    def __init__(self, config: FrequencyAlgorithmConfig, event_bus: EventBus, min_samples: int = 100):
        super().__init__(config, event_bus, min_samples)
        self.states: dict[str, FrequencyState] = {}

    def process_entry(self, entry: LogEntry) -> None:
        source = entry.source
        now = entry.timestamp or datetime.now(timezone.utc)

        if source not in self.states:
            self.states[source] = FrequencyState()

        state = self.states[source]

        if state.window_start is None:
            state.window_start = now
            state.window_count = 1
            state.last_update = now
            return

        window_size = timedelta(seconds=self.config.window_size_seconds)
        time_diff = now - state.window_start

        if time_diff >= window_size:
            current_freq = state.window_count / self.config.window_size_seconds

            if state.ewma is None:
                state.ewma = current_freq
            else:
                new_ewma = self.config.alpha * current_freq + (1 - self.config.alpha) * state.ewma
                threshold = state.ewma * self.config.threshold_multiplier

                if current_freq > threshold:
                    alert = AlertEvent(
                        severity=AlertSeverity.WARNING,
                        alert_type=AlertType.FREQUENCY_SPIKE,
                        source=source,
                        detector=DetectorName.FREQUENCY,
                        trigger_value=current_freq,
                        threshold=threshold,
                        baseline_value=state.ewma,
                        description=f"Frequency spike detected: {current_freq:.4f} entries/sec exceeds baseline {state.ewma:.4f} entries/sec by {self.config.threshold_multiplier}x",
                        extra={
                            "window_size_seconds": self.config.window_size_seconds,
                            "alpha": self.config.alpha,
                            "window_count": state.window_count,
                        }
                    )
                    self._publish_alert(alert)

                state.ewma = new_ewma

            state.window_start = now
            state.window_count = 1
            state.last_update = now
        else:
            state.window_count += 1
            state.last_update = now

    def force_check_window(self, source: str) -> None:
        if source not in self.states:
            return

        state = self.states[source]
        if state.window_start is None or state.window_count == 0:
            return

        current_freq = state.window_count / self.config.window_size_seconds

        if state.ewma is not None:
            threshold = state.ewma * self.config.threshold_multiplier
            if current_freq > threshold:
                alert = AlertEvent(
                    severity=AlertSeverity.WARNING,
                    alert_type=AlertType.FREQUENCY_SPIKE,
                    source=source,
                    detector=DetectorName.FREQUENCY,
                    trigger_value=current_freq,
                    threshold=threshold,
                    baseline_value=state.ewma,
                    description=f"Frequency spike detected: {current_freq:.4f} entries/sec exceeds baseline {state.ewma:.4f} entries/sec by {self.config.threshold_multiplier}x",
                    extra={
                        "window_size_seconds": self.config.window_size_seconds,
                        "alpha": self.config.alpha,
                        "window_count": state.window_count,
                    }
                )
                self._publish_alert(alert)

            new_ewma = self.config.alpha * current_freq + (1 - self.config.alpha) * state.ewma
            state.ewma = new_ewma
        else:
            state.ewma = current_freq

        state.window_start = None
        state.window_count = 0

    def reset_source(self, source: str) -> None:
        if source in self.states:
            del self.states[source]

    def load_state(self, source: str, state_dict: dict) -> None:
        state = FrequencyState(
            ewma=state_dict.get('ewma'),
            window_start=datetime.fromisoformat(state_dict['window_start']) if state_dict.get('window_start') else None,
            window_count=state_dict.get('window_count', 0),
            last_update=datetime.fromisoformat(state_dict['last_update']) if state_dict.get('last_update') else None,
        )
        self.states[source] = state


def calculate_modified_z_score(values: List[float], current_value: float) -> float:
    if not values:
        return 0.0

    sorted_vals = sorted(values)
    n = len(sorted_vals)
    median = sorted_vals[n // 2] if n % 2 == 1 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2

    abs_deviations = [abs(v - median) for v in values]
    sorted_abs = sorted(abs_deviations)
    mad = sorted_abs[n // 2] if n % 2 == 1 else (sorted_abs[n // 2 - 1] + sorted_abs[n // 2]) / 2

    if mad == 0:
        return float('inf') if current_value != median else 0.0

    return (current_value - median) / (1.4826 * mad)


class ErrorRateDetector(BaseDetector):
    def __init__(self, config: ErrorRateAlgorithmConfig, event_bus: EventBus, min_samples: int = 100):
        super().__init__(config, event_bus, min_samples)
        self.states: dict[str, ErrorRateState] = {}

    def process_entry(self, entry: LogEntry) -> None:
        source = entry.source
        now = entry.timestamp or datetime.now(timezone.utc)

        if source not in self.states:
            self.states[source] = ErrorRateState()

        state = self.states[source]

        if state.window_start is None:
            state.window_start = now
            state.window_total = 1
            state.window_errors = 1 if entry.level in (LogLevel.ERROR, LogLevel.WARN) else 0
            return

        window_size = timedelta(seconds=self.config.window_size_seconds)
        time_diff = now - state.window_start

        if time_diff >= window_size:
            error_rate = state.window_errors / state.window_total if state.window_total > 0 else 0.0

            if len(state.history) >= 1:
                z_score = calculate_modified_z_score(state.history, error_rate)

                if z_score > self.config.z_score_threshold:
                    alert = AlertEvent(
                        severity=AlertSeverity.WARNING,
                        alert_type=AlertType.ERROR_RATE_SURGE,
                        source=source,
                        detector=DetectorName.ERROR_RATE,
                        trigger_value=error_rate,
                        threshold=self.config.z_score_threshold,
                        baseline_value=float('inf') if z_score == float('inf') else None,
                        description=f"Error rate surge detected: {error_rate:.4f} has Z-score {z_score:.4f} > threshold {self.config.z_score_threshold}",
                        extra={
                            "window_size_seconds": self.config.window_size_seconds,
                            "k_windows": self.config.k_windows,
                            "z_score": z_score,
                            "window_total": state.window_total,
                            "window_errors": state.window_errors,
                            "history_length": len(state.history),
                        }
                    )
                    self._publish_alert(alert)

            state.history.append(error_rate)
            if len(state.history) > self.config.k_windows:
                state.history = state.history[-self.config.k_windows:]

            state.window_start = now
            state.window_total = 1
            state.window_errors = 1 if entry.level in (LogLevel.ERROR, LogLevel.WARN) else 0
        else:
            state.window_total += 1
            if entry.level in (LogLevel.ERROR, LogLevel.WARN):
                state.window_errors += 1

    def force_check_window(self, source: str) -> None:
        if source not in self.states:
            return

        state = self.states[source]
        if state.window_start is None or state.window_total == 0:
            return

        error_rate = state.window_errors / state.window_total if state.window_total > 0 else 0.0

        if len(state.history) >= 1:
            z_score = calculate_modified_z_score(state.history, error_rate)

            if z_score > self.config.z_score_threshold:
                alert = AlertEvent(
                    severity=AlertSeverity.WARNING,
                    alert_type=AlertType.ERROR_RATE_SURGE,
                    source=source,
                    detector=DetectorName.ERROR_RATE,
                    trigger_value=error_rate,
                    threshold=self.config.z_score_threshold,
                    baseline_value=float('inf') if z_score == float('inf') else None,
                    description=f"Error rate surge detected: {error_rate:.4f} has Z-score {z_score:.4f} > threshold {self.config.z_score_threshold}",
                    extra={
                        "window_size_seconds": self.config.window_size_seconds,
                        "k_windows": self.config.k_windows,
                        "z_score": z_score,
                        "window_total": state.window_total,
                        "window_errors": state.window_errors,
                        "history_length": len(state.history),
                    }
                )
                self._publish_alert(alert)

        state.history.append(error_rate)
        if len(state.history) > self.config.k_windows:
            state.history = state.history[-self.config.k_windows:]

        state.window_start = None
        state.window_total = 0
        state.window_errors = 0

    def reset_source(self, source: str) -> None:
        if source in self.states:
            del self.states[source]

    def load_state(self, source: str, state_dict: dict) -> None:
        state = ErrorRateState(
            history=state_dict.get('history', []),
            window_start=datetime.fromisoformat(state_dict['window_start']) if state_dict.get('window_start') else None,
            window_total=state_dict.get('window_total', 0),
            window_errors=state_dict.get('window_errors', 0),
        )
        self.states[source] = state


def templatize_message(message: str) -> str:
    template = message

    template = re.sub(EMAIL_PATTERN, '<EMAIL>', template)
    template = re.sub(UUID_PATTERN, '<UUID>', template)
    template = re.sub(IPV6_PATTERN, '<IP>', template)
    template = re.sub(IPV4_PATTERN, '<IP>', template)
    template = re.sub(PATH_VAR_PATTERN, '/<VAR>/', template)
    template = re.sub(NUM_PATTERN, '<NUM>', template)
    template = re.sub(r'/(<VAR>)/+', r'/\1/', template)

    return template


class PatternDetector(BaseDetector):
    def __init__(self, config: PatternAlgorithmConfig, event_bus: EventBus, min_samples: int = 100):
        super().__init__(config, event_bus, min_samples)
        self.states: dict[str, PatternState] = {}
        self._window_templates: dict[str, set[str]] = {}

    def process_entry(self, entry: LogEntry) -> None:
        source = entry.source
        now = entry.timestamp or datetime.now(timezone.utc)

        if source not in self.states:
            self.states[source] = PatternState()
            self._window_templates[source] = set()

        state = self.states[source]
        state.total_count += 1

        template = templatize_message(entry.message)

        if source not in self._window_templates:
            self._window_templates[source] = set()

        self._window_templates[source].add(template)

        if template not in state.known_templates:
            if state.total_count > self.min_samples:
                alert = AlertEvent(
                    severity=AlertSeverity.WARNING,
                    alert_type=AlertType.NEW_PATTERN,
                    source=source,
                    detector=DetectorName.PATTERN,
                    trigger_value=1.0,
                    threshold=0.0,
                    baseline_value=0.0,
                    description=f"New log pattern detected: {template}",
                    extra={
                        "template": template,
                        "total_count": state.total_count,
                        "min_samples": self.min_samples,
                    }
                )
                self._publish_alert(alert)

            state.known_templates[template] = 1
            state.windows_without[template] = 0
        else:
            state.known_templates[template] += 1
            state.windows_without[template] = 0

        state.template_last_seen[template] = now

        if state.window_start is None:
            state.window_start = now
            return

        window_size = timedelta(seconds=self.config.window_size_seconds)
        time_diff = now - state.window_start

        if time_diff >= window_size:
            self._check_disappeared_patterns(source)
            state.window_start = now
            self._window_templates[source] = set()

    def _check_disappeared_patterns(self, source: str) -> None:
        if source not in self.states or source not in self._window_templates:
            return

        state = self.states[source]
        current_window_templates = self._window_templates[source]

        for template in list(state.known_templates.keys()):
            if template not in current_window_templates:
                state.windows_without[template] = state.windows_without.get(template, 0) + 1

                if state.windows_without[template] >= self.config.disappear_windows:
                    alert = AlertEvent(
                        severity=AlertSeverity.INFO,
                        alert_type=AlertType.PATTERN_DISAPPEARED,
                        source=source,
                        detector=DetectorName.PATTERN,
                        trigger_value=float(state.windows_without[template]),
                        threshold=float(self.config.disappear_windows),
                        baseline_value=0.0,
                        description=f"Pattern disappeared for {state.windows_without[template]} windows: {template}",
                        extra={
                            "template": template,
                            "disappear_windows": state.windows_without[template],
                            "threshold_windows": self.config.disappear_windows,
                        }
                    )
                    self._publish_alert(alert)
                    del state.windows_without[template]
            else:
                state.windows_without[template] = 0

    def force_check_window(self, source: str) -> None:
        self._check_disappeared_patterns(source)
        if source in self.states:
            self.states[source].window_start = None
        if source in self._window_templates:
            self._window_templates[source] = set()

    def reset_source(self, source: str) -> None:
        if source in self.states:
            del self.states[source]
        if source in self._window_templates:
            del self._window_templates[source]

    def load_state(self, source: str, state_dict: dict) -> None:
        template_last_seen = {}
        for t, dt_str in state_dict.get('template_last_seen', {}).items():
            try:
                template_last_seen[t] = datetime.fromisoformat(dt_str)
            except (ValueError, TypeError):
                template_last_seen[t] = datetime.now(timezone.utc)

        state = PatternState(
            known_templates=state_dict.get('known_templates', {}),
            template_last_seen=template_last_seen,
            windows_without=state_dict.get('windows_without', {}),
            total_count=state_dict.get('total_count', 0),
        )
        self.states[source] = state
        if source not in self._window_templates:
            self._window_templates[source] = set()
