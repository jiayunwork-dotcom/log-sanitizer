import queue
import threading
import time
import json
from typing import Optional, Set, Dict, Any, Tuple, List
from datetime import datetime, timezone
from .models import LogEntry, AlertEvent, AlertStats
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


class AnomalyDetectionEngine:
    def __init__(self, config: AnomalyDetectionConfig):
        self.config = config
        self.enabled = config.enabled
        self.event_bus: Optional[EventBus] = None
        self.queue: Optional[queue.Queue[Optional[Tuple[LogEntry, int, int]]]] = None
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._active_sources: Set[str] = set()
        self._current_file_line_start: int = 0
        self._current_file_line_end: int = 0
        self.frequency_detector: Optional[FrequencyDetector] = None
        self.error_rate_detector: Optional[ErrorRateDetector] = None
        self.pattern_detector: Optional[PatternDetector] = None
        self.alert_aggregator: Optional[AlertAggregator] = None
        self.alert_output: Optional[AlertOutput] = None
        self.state_persistence: Optional[StatePersistence] = None

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

        self.alert_aggregator = AlertAggregator(config)
        self.alert_output = AlertOutput(
            config.alert_file,
            config.webhook,
        )
        self.state_persistence = StatePersistence(config.state_file)

        self._setup_event_subscriptions()
        self.state_persistence.load_state(
            self.frequency_detector,
            self.error_rate_detector,
            self.pattern_detector,
        )

    def _setup_event_subscriptions(self) -> None:
        self.event_bus.subscribe('*', self.alert_aggregator.process_alert)
        self.alert_aggregator.set_output_callback(self.alert_output.write_alert)

    def start(self) -> None:
        if not self.enabled:
            return

        if self._worker_thread and self._worker_thread.is_alive():
            return

        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def stop(self) -> None:
        if not self.enabled:
            return

        self._stop_event.set()
        self.queue.put(None)

        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)
            self._worker_thread = None

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

            err_state = self.error_rate_detector.states.get(source)
            if err_state:
                source_info["error_rate_history"] = err_state.history
                source_info["error_rate_history_length"] = len(err_state.history)

            pat_state = self.pattern_detector.states.get(source)
            if pat_state:
                source_info["known_templates_count"] = len(pat_state.known_templates)
                source_info["total_log_count"] = pat_state.total_count

            sources[source] = source_info

        stats = self.alert_aggregator.get_stats()

        return {
            "enabled": True,
            "queue_size": self.queue.qsize(),
            "active_sources": list(self._active_sources),
            "sources": sources,
            "alert_stats": {
                "total_alerts": stats.total_alerts,
                "by_severity": {k.value: v for k, v in stats.by_severity.items()},
                "by_type": {k.value: v for k, v in stats.by_type.items()},
                "by_source": stats.by_source,
                "by_detector": {k.value: v for k, v in stats.by_detector.items()},
            },
            "state_file": self.config.state_file,
            "alert_file": self.config.alert_file,
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
