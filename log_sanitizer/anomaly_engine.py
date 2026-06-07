import queue
import threading
import time
import json
from typing import Optional, Set, Dict, Any, Tuple, List
from datetime import datetime, timezone
from .models import LogEntry, AlertEvent, AlertStats, AlertStatus
from .config import AnomalyDetectionConfig
from .event_bus import EventBus
from .anomaly_detectors import (
    FrequencyDetector,
    ErrorRateDetector,
    PatternDetector,
)
from .alert_aggregator import AlertAggregator
from .alert_output import AlertOutput
from .state_persistence import StatePersistence
from .suppression_engine import SuppressionEngine
from .feedback_processor import FeedbackProcessor


class AnomalyDetectionEngine:
    def __init__(self, config: AnomalyDetectionConfig):
        self.config = config
        self.enabled = config.enabled
        self.event_bus: Optional[EventBus] = None
        self.queue: Optional[queue.Queue[Optional[Tuple[LogEntry, int, int]]]] = None
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._pending_check_thread: Optional[threading.Thread] = None
        self._active_sources: Set[str] = set()
        self._current_file_line_start: int = 0
        self._current_file_line_end: int = 0
        self.frequency_detector: Optional[FrequencyDetector] = None
        self.error_rate_detector: Optional[ErrorRateDetector] = None
        self.pattern_detector: Optional[PatternDetector] = None
        self.alert_aggregator: Optional[AlertAggregator] = None
        self.alert_output: Optional[AlertOutput] = None
        self.state_persistence: Optional[StatePersistence] = None
        self.suppression_engine: Optional[SuppressionEngine] = None
        self.feedback_processor: Optional[FeedbackProcessor] = None

        if not self.enabled:
            return

        self.event_bus = EventBus()
        self.queue = queue.Queue()

        self.frequency_detector = FrequencyDetector(
            config.algorithms.frequency,
            self.event_bus,
            config.min_samples,
        )
        self.error_rate_detector = ErrorRateDetector(
            config.algorithms.error_rate,
            self.event_bus,
            config.min_samples,
        )
        self.pattern_detector = PatternDetector(
            config.algorithms.pattern,
            self.event_bus,
            config.min_samples,
        )

        self.suppression_engine = SuppressionEngine(config)
        self.feedback_processor = FeedbackProcessor(config)

        self.alert_aggregator = AlertAggregator(
            config,
            suppression_engine=self.suppression_engine,
            feedback_processor=self.feedback_processor,
        )
        self.alert_output = AlertOutput(
            config.alert_file,
            config.webhook,
        )
        self.state_persistence = StatePersistence(config.state_file)

        self.feedback_processor.set_detectors(
            self.frequency_detector,
            self.error_rate_detector,
        )
        self.feedback_processor.set_status_change_callback(
            self._on_alert_status_change
        )
        self.suppression_engine.set_output_callback(
            self._on_delayed_alert_ready
        )

        self._setup_event_subscriptions()
        self.state_persistence.load_state(
            self.frequency_detector,
            self.error_rate_detector,
            self.pattern_detector,
            self.suppression_engine,
            self.feedback_processor,
        )

        if config.feedback_file:
            self._load_initial_feedback(config.feedback_file)

    def _setup_event_subscriptions(self) -> None:
        self.event_bus.subscribe('*', self.alert_aggregator.process_alert)
        self.alert_aggregator.set_output_callback(self.alert_output.write_alert)

    def _on_alert_status_change(self, alert: AlertEvent, old_status, new_status) -> None:
        if self.alert_output:
            self.alert_output.send_status_change(alert, old_status, new_status)

    def _on_delayed_alert_ready(self, alert: AlertEvent) -> None:
        if self.alert_output:
            self.alert_output.write_alert(alert)

    def _load_initial_feedback(self, file_path: str) -> None:
        try:
            result = self.feedback_processor.process_feedback_file(file_path)
            print(f"Loaded initial feedback: {result['total_processed']} entries, "
                  f"{result['threshold_adjustments']} threshold adjustments, "
                  f"{result['status_changes']} status changes", flush=True)
        except Exception as e:
            print(f"Warning: Failed to load initial feedback file: {e}", flush=True)

    def _pending_check_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                if self.suppression_engine:
                    self.suppression_engine.check_pending_alerts()
                time.sleep(1.0)
            except Exception as e:
                print(f"Error in pending check loop: {e}", flush=True)

    def process_feedback(self, file_path: str) -> Dict[str, Any]:
        if not self.enabled or not self.feedback_processor:
            return {"error": "Anomaly detection not enabled"}
        return self.feedback_processor.process_feedback_file(file_path)

    def get_suppression_rules(self) -> List[Dict[str, Any]]:
        if not self.enabled or not self.suppression_engine:
            return []
        return self.suppression_engine.get_rule_stats()

    def get_alerts(self, status: Optional[AlertStatus] = None,
                   source_pattern: Optional[str] = None,
                   sort_by: str = 'timestamp') -> List[AlertEvent]:
        if not self.enabled or not self.feedback_processor:
            return []

        if status:
            alerts = self.feedback_processor.get_alerts_by_status(status)
        else:
            alerts = self.feedback_processor.get_all_alerts()

        if source_pattern:
            import re
            alerts = [a for a in alerts if re.search(source_pattern, a.source)]

        if sort_by == 'severity':
            severity_order = {'CRITICAL': 3, 'WARNING': 2, 'INFO': 1}
            alerts.sort(key=lambda a: severity_order.get(a.severity.value, 0), reverse=True)
        elif sort_by == 'source':
            alerts.sort(key=lambda a: a.source)
        else:
            alerts.sort(key=lambda a: a.timestamp, reverse=True)

        return alerts

    def start(self) -> None:
        if not self.enabled:
            return

        if self._worker_thread and self._worker_thread.is_alive():
            return

        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

        self._pending_check_thread = threading.Thread(target=self._pending_check_loop, daemon=True)
        self._pending_check_thread.start()

    def stop(self) -> None:
        if not self.enabled:
            return

        self._stop_event.set()
        self.queue.put(None)

        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)
            self._worker_thread = None

        if self._pending_check_thread:
            self._pending_check_thread.join(timeout=2.0)
            self._pending_check_thread = None

        self._flush_all_detectors()
        self.alert_aggregator.flush_pending()
        self.alert_output.close()

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                item = self.queue.get(timeout=0.1)
                if item is None:
                    break

                entry, line_start, line_end = item
                self._process_entry_sync(entry, line_start, line_end)
                self.queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in anomaly detection worker: {e}", flush=True)

    def _process_entry_sync(
        self,
        entry: LogEntry,
        line_start: int,
        line_end: int,
    ) -> None:
        self.frequency_detector.set_line_range(line_start, line_end)
        self.error_rate_detector.set_line_range(line_start, line_end)
        self.pattern_detector.set_line_range(line_start, line_end)

        source = entry.source
        self._active_sources.add(source)

        self.frequency_detector.process_entry(entry)
        self.error_rate_detector.process_entry(entry)
        self.pattern_detector.process_entry(entry)

    def process_entry(self, entry: LogEntry, line_start: int, line_end: int) -> None:
        if not self.enabled:
            return

        self.queue.put((entry, line_start, line_end))

    def _flush_all_detectors(self) -> None:
        for source in self._active_sources:
            self.frequency_detector.force_check_window(source)
            self.error_rate_detector.force_check_window(source)
            self.pattern_detector.force_check_window(source)

    def on_file_completed(self) -> None:
        if not self.enabled:
            return

        self.queue.join()
        self._flush_all_detectors()
        self.alert_aggregator.flush_pending()
        self.state_persistence.mark_dirty()
        self.state_persistence.save_state(
            self.frequency_detector,
            self.error_rate_detector,
            self.pattern_detector,
            self.suppression_engine,
            self.feedback_processor,
            force=True,
        )

    def reset_source(self, source: str) -> None:
        if not self.enabled:
            return

        self.state_persistence.reset_source_state(
            source,
            self.frequency_detector,
            self.error_rate_detector,
            self.pattern_detector,
            self.suppression_engine,
            self.feedback_processor,
        )

    def get_status(self) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}

        sources = {}
        all_sources = set()
        all_sources.update(self.frequency_detector.states.keys())
        all_sources.update(self.error_rate_detector.states.keys())
        all_sources.update(self.pattern_detector.states.keys())

        for source in all_sources:
            source_info: Dict[str, Any] = {}

            freq_state = self.frequency_detector.states.get(source)
            if freq_state:
                source_info["frequency_ewma"] = freq_state.ewma
                source_info["frequency_window_count"] = freq_state.window_count
                source_info["frequency_threshold_override"] = self.frequency_detector.threshold_overrides.get(source)

            err_state = self.error_rate_detector.states.get(source)
            if err_state:
                source_info["error_rate_history"] = err_state.history
                source_info["error_rate_history_length"] = len(err_state.history)
                source_info["error_rate_threshold_override"] = self.error_rate_detector.threshold_overrides.get(source)

            pat_state = self.pattern_detector.states.get(source)
            if pat_state:
                source_info["known_templates_count"] = len(pat_state.known_templates)
                source_info["total_log_count"] = pat_state.total_count

            sources[source] = source_info

        stats = self.alert_aggregator.get_stats()

        suppression_rules_stats = []
        if self.suppression_engine:
            suppression_rules_stats = self.suppression_engine.get_rule_stats()

        alert_status_counts = {}
        if self.feedback_processor:
            alert_status_counts = self.feedback_processor.get_status_counts()

        pending_count = 0
        if self.suppression_engine:
            pending_count = self.suppression_engine.get_pending_count()

        return {
            "enabled": True,
            "queue_size": self.queue.qsize(),
            "pending_delayed_alerts": pending_count,
            "active_sources": list(self._active_sources),
            "sources": sources,
            "alert_stats": {
                "total_alerts": stats.total_alerts,
                "suppressed_count": stats.suppressed_count,
                "delayed_count": stats.delayed_count,
                "downgraded_count": stats.downgraded_count,
                "by_severity": {k.value: v for k, v in stats.by_severity.items()},
                "by_type": {k.value: v for k, v in stats.by_type.items()},
                "by_source": stats.by_source,
                "by_detector": {k.value: v for k, v in stats.by_detector.items()},
                "by_status": {k.value: v for k, v in stats.by_status.items()},
            },
            "alert_status_counts": alert_status_counts,
            "suppression_rules": suppression_rules_stats,
            "threshold_overrides": self.feedback_processor.get_threshold_overrides() if self.feedback_processor else {},
            "state_file": self.config.state_file,
            "alert_file": self.config.alert_file,
            "feedback_file": self.config.feedback_file,
        }

    def get_alert_stats(self) -> AlertStats:
        return self.alert_aggregator.get_stats()

    @staticmethod
    def replay_alerts(alert_file: str) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        try:
            with open(alert_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            alert = json.loads(line)
                            alerts.append(alert)
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            print(f"Alert file not found: {alert_file}", flush=True)
        except Exception as e:
            print(f"Error reading alert file: {e}", flush=True)

        return alerts

    def __enter__(self) -> 'AnomalyDetectionEngine':
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
