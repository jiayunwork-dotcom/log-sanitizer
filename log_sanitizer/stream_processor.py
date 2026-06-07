import os
import sys
import json
import queue
import signal
import threading
import time
from typing import Optional, List, Dict, Any, Tuple, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, field

from .config import PipelineConfig
from .models import LogEntry, LogFormat
from .parser import LogParser
from .detector import SensitiveDataDetector
from .sanitizer import SanitizationEngine
from .mapping_manager import MappingManager
from .anomaly_engine import AnomalyDetectionEngine
from .state_persistence import StatePersistence
from .audit_logger import AuditLogger
from .stream_sources import StreamInputSource, PipeInputSource, TailInputSource


@dataclass
class StreamStatus:
    processed_lines: int = 0
    source_processed_lines: Dict[str, int] = field(default_factory=dict)
    source_sanitization_hits: Dict[str, Dict[str, int]] = field(default_factory=dict)
    queue_depth: int = 0
    queue_depth_history: List[Tuple[float, int]] = field(default_factory=list)
    backpressure_paused: bool = False
    backpressure_trigger_count: int = 0
    backpressure_total_pause_seconds: float = 0.0
    backpressure_last_trigger_time: Optional[float] = None
    last_alert_time: Optional[datetime] = None
    detector_summaries: Dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class StreamProcessor:
    def __init__(self, config: PipelineConfig, output_target: str = "stdout", watch_list_path: Optional[str] = None):
        self.config = config
        self.output_target = output_target
        self._stream_config = config.stream
        self._watch_list_path = watch_list_path
        self._watch_list_mtime: Optional[float] = None
        
        self._processing_queue: queue.Queue[Optional[Tuple[str, str]]] = queue.Queue(
            maxsize=config.stream.high_watermark * 2
        )
        self._stop_event = threading.Event()
        self._drain_event = threading.Event()
        self._graceful_shutdown = threading.Event()
        
        self._input_source: Optional[StreamInputSource] = None
        self._parser_cache: Dict[str, LogParser] = {}
        
        self._status_lock = threading.Lock()
        self.status = StreamStatus()
        
        self._backpressure_lock = threading.Lock()
        self._backpressure_paused = False
        self._backpressure_event = threading.Event()
        self._backpressure_event.set()
        
        self._output_lock = threading.Lock()
        self._output_handles: Dict[str, Any] = {}
        self._output_locks: Dict[str, threading.Lock] = {}
        self._default_output_target = output_target
        self._route_rules = config.stream.route_rules
        self._open_output_handle(output_target)
        
        self._threads: List[threading.Thread] = []
        self._worker_thread: Optional[threading.Thread] = None
        self._window_timer_thread: Optional[threading.Thread] = None
        self._checkpoint_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._watch_list_thread: Optional[threading.Thread] = None
        self._queue_sampler_thread: Optional[threading.Thread] = None
        
        self.detector = self._create_detector()
        self.mapping_manager = self._create_mapping_manager()
        self.sanitizer = SanitizationEngine(self.detector, self.mapping_manager)
        
        self.audit_logger: Optional[AuditLogger] = None
        if config.audit_log.enabled and config.audit_log.file:
            self.audit_logger = AuditLogger(
                config.audit_log.file,
                config.audit_log.enabled,
            )
        
        self.anomaly_engine: Optional[AnomalyDetectionEngine] = None
        if config.anomaly_detection.enabled:
            self.anomaly_engine = AnomalyDetectionEngine(config.anomaly_detection)
            self._enable_wall_clock_mode()
            self.anomaly_engine.start()
        
        self.state_persistence: Optional[StatePersistence] = None
        if config.anomaly_detection.state_file:
            self.state_persistence = StatePersistence(config.anomaly_detection.state_file)
        
        self._setup_signal_handlers()
        self._alert_callback: Optional[Callable[[Any], None]] = None
        
        if self.anomaly_engine and self.anomaly_engine.alert_output:
            original_write = self.anomaly_engine.alert_output.write_alert
            def wrapped_write(alert):
                self._update_last_alert_time()
                original_write(alert)
            self.anomaly_engine.alert_output.write_alert = wrapped_write
    
    def _open_output_handle(self, target: str) -> None:
        if target in self._output_handles:
            return
        
        self._output_locks[target] = threading.Lock()
        
        if target == "stdout":
            self._output_handles[target] = sys.stdout
        else:
            output_dir = os.path.dirname(os.path.abspath(target))
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            self._output_handles[target] = open(target, 'a', encoding=self.config.output.encoding, buffering=1)

    def _enable_wall_clock_mode(self) -> None:
        if not self.anomaly_engine:
            return
        for detector in [
            self.anomaly_engine.frequency_detector,
            self.anomaly_engine.error_rate_detector,
            self.anomaly_engine.pattern_detector,
        ]:
            if detector:
                detector.enable_wall_clock_mode()

    def _setup_signal_handlers(self) -> None:
        def handle_signal(signum, frame):
            sig_name = signal.Signals(signum).name
            print(f"\n[INFO] Received {sig_name}, initiating graceful shutdown...", file=sys.stderr, flush=True)
            self._graceful_shutdown.set()
            if self._input_source:
                self._input_source.stop()
        
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

    def _create_detector(self) -> SensitiveDataDetector:
        sanitizers = self.config.sanitizers
        
        custom_rules_data = []
        for rule in sanitizers.custom_rules:
            rule_dict: Dict[str, Any] = {
                "name": rule.name,
                "pattern": rule.pattern or "",
                "type": rule.type.value if rule.type else "custom",
                "strategy": rule.strategy.value if rule.strategy else "mask",
                "params": rule.params,
            }
            custom_rules_data.append(rule_dict)
        
        return SensitiveDataDetector(
            builtin_rules=sanitizers.builtin_rules,
            custom_rules=custom_rules_data,
            override_strategies=sanitizers.strategies,
            override_params=sanitizers.params,
        )

    def _create_mapping_manager(self) -> MappingManager:
        sanitizers = self.config.sanitizers
        hmac_key = sanitizers.hmac_key.encode('utf-8') if sanitizers.hmac_key else None
        
        return MappingManager(
            db_path=sanitizers.mapping_db_path,
            hmac_key=hmac_key,
            in_memory=sanitizers.mapping_in_memory or sanitizers.mapping_db_path is None,
        )

    def _get_route_target(self, entry: LogEntry) -> str:
        entry_level = entry.level.value.upper() if entry.level else "UNKNOWN"
        
        for rule in self._route_rules:
            levels = [l.strip().upper() for l in rule.level_match.split(',')]
            if entry_level in levels:
                self._open_output_handle(rule.output_target)
                return rule.output_target
        
        return self._default_output_target

    def _get_parser(self, source: str) -> LogParser:
        if source not in self._parser_cache:
            self._parser_cache[source] = LogParser(
                format=self.config.parser.format,
                custom_pattern=self.config.parser.custom_pattern,
                custom_field_names=self.config.parser.custom_field_names,
                source=source,
            )
        return self._parser_cache[source]

    def _check_backpressure(self) -> None:
        current_depth = self._processing_queue.qsize()
        self.status.queue_depth = current_depth
        
        with self._backpressure_lock:
            if not self._backpressure_paused and current_depth >= self._stream_config.high_watermark:
                self._backpressure_paused = True
                self._backpressure_event.clear()
                self.status.backpressure_paused = True
                self.status.backpressure_trigger_count += 1
                self.status.backpressure_last_trigger_time = time.monotonic()
                print(
                    f"[WARNING] Backpressure activated: queue depth {current_depth} >= high_watermark {self._stream_config.high_watermark}, pausing input reading",
                    file=sys.stderr,
                    flush=True
                )
            elif self._backpressure_paused and current_depth <= self._stream_config.low_watermark:
                self._backpressure_paused = False
                self._backpressure_event.set()
                self.status.backpressure_paused = False
                if self.status.backpressure_last_trigger_time is not None:
                    pause_duration = time.monotonic() - self.status.backpressure_last_trigger_time
                    self.status.backpressure_total_pause_seconds += pause_duration
                    self.status.backpressure_last_trigger_time = None
                print(
                    f"[INFO] Backpressure released: queue depth {current_depth} <= low_watermark {self._stream_config.low_watermark}, resuming input reading",
                    file=sys.stderr,
                    flush=True
                )

    def _sample_queue_depth(self) -> None:
        current_depth = self._processing_queue.qsize()
        now = time.time()
        with self._status_lock:
            self.status.queue_depth_history.append((now, current_depth))
            cutoff_time = now - 60.0
            self.status.queue_depth_history = [
                (t, d) for t, d in self.status.queue_depth_history
                if t >= cutoff_time
            ][-60:]

    def _queue_put(self, source: str, line: str) -> None:
        while not self._stop_event.is_set() and not self._graceful_shutdown.is_set():
            self._backpressure_event.wait(timeout=0.5)
            if self._stop_event.is_set() or self._graceful_shutdown.is_set():
                return
            
            try:
                self._processing_queue.put((source, line), timeout=0.1)
                self._check_backpressure()
                return
            except queue.Full:
                continue

    def _update_last_alert_time(self) -> None:
        with self._status_lock:
            self.status.last_alert_time = datetime.now(timezone.utc)

    def _should_keep(self, entry: LogEntry) -> bool:
        if not self.config.filters:
            return True
        
        filters = self.config.filters
        
        if filters.levels and entry.level not in filters.levels:
            return False
        
        if filters.start_time and entry.timestamp and entry.timestamp < filters.start_time:
            return False
        
        if filters.end_time and entry.timestamp and entry.timestamp > filters.end_time:
            return False
        
        if filters.include_keywords:
            content = entry.raw
            if not any(kw in content for kw in filters.include_keywords):
                return False
        
        if filters.exclude_keywords:
            content = entry.raw
            if any(kw in content for kw in filters.exclude_keywords):
                return False
        
        return True

    def _process_line(self, source: str, line: str) -> None:
        parser = self._get_parser(source)
        entry = parser.parse_line(line)
        
        if not entry.is_parseable:
            self._write_output(entry)
            return
        
        if not self._should_keep(entry):
            return
        
        entry, detections, sanitized, total_fields, audit_entries, field_path_counts = self.sanitizer.sanitize_entry(entry)
        
        with self._status_lock:
            self.status.source_processed_lines[source] = self.status.source_processed_lines.get(source, 0) + 1
            if detections:
                if source not in self.status.source_sanitization_hits:
                    self.status.source_sanitization_hits[source] = {}
                for stype, count in detections.items():
                    type_key = stype.value if hasattr(stype, 'value') else str(stype)
                    self.status.source_sanitization_hits[source][type_key] = \
                        self.status.source_sanitization_hits[source].get(type_key, 0) + count
        
        if self.audit_logger and audit_entries:
            with self._status_lock:
                current_line = self.status.processed_lines
            for f_path, orig_val, sanitized_val, rule_name in audit_entries:
                self.audit_logger.log(
                    line_number=current_line,
                    field_path=f_path,
                    original_value=orig_val,
                    sanitized_value=sanitized_val,
                    rule_name=rule_name,
                    timestamp=entry.timestamp,
                )
        
        self._write_output(entry)
        
        if self.anomaly_engine and entry.is_parseable:
            with self._status_lock:
                current_line = self.status.processed_lines
            self.anomaly_engine.process_entry(entry, current_line, current_line)

    def _write_output(self, entry: LogEntry) -> None:
        json_str = json.dumps(entry.to_standard_dict(), ensure_ascii=False)
        if self.config.output.pretty:
            json_str = json.dumps(entry.to_standard_dict(), ensure_ascii=False, indent=2)
        
        target = self._get_route_target(entry)
        handle = self._output_handles.get(target)
        lock = self._output_locks.get(target)
        
        if handle and lock:
            with lock:
                handle.write(json_str + '\n')
                handle.flush()
        else:
            with self._output_lock:
                default_handle = self._output_handles.get(self._default_output_target, sys.stdout)
                default_handle.write(json_str + '\n')
                default_handle.flush()

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                item = self._processing_queue.get(timeout=0.1)
                if item is None:
                    break
                
                source, line = item
                try:
                    self._process_line(source, line)
                except Exception as e:
                    print(f"[ERROR] Error processing line from {source}: {e}", file=sys.stderr, flush=True)
                finally:
                    with self._status_lock:
                        self.status.processed_lines += 1
                    self._processing_queue.task_done()
                    self._check_backpressure()
                
            except queue.Empty:
                if self._graceful_shutdown.is_set() and self._processing_queue.empty():
                    self._drain_event.set()
                    break
                continue

    def _window_timer_loop(self) -> None:
        if not self.anomaly_engine:
            return
        
        min_window_size = min(
            self.config.anomaly_detection.algorithms.frequency.window_size_seconds,
            self.config.anomaly_detection.algorithms.error_rate.window_size_seconds,
            self.config.anomaly_detection.algorithms.pattern.window_size_seconds,
        )
        check_interval = max(0.5, min(min_window_size / 10, 1.0))
        
        while not self._stop_event.is_set():
            try:
                start_time = time.monotonic()
                
                if self.anomaly_engine.frequency_detector:
                    self.anomaly_engine.frequency_detector.check_windows_by_wallclock()
                if self.anomaly_engine.error_rate_detector:
                    self.anomaly_engine.error_rate_detector.check_windows_by_wallclock()
                if self.anomaly_engine.pattern_detector:
                    self.anomaly_engine.pattern_detector.check_windows_by_wallclock()
                
                elapsed = time.monotonic() - start_time
                sleep_time = max(0, check_interval - elapsed)
                
                actual_trigger_time = time.monotonic()
                theoretical_time = start_time + check_interval
                error = abs(actual_trigger_time - theoretical_time)
                if error > 1.0:
                    print(
                        f"[WARNING] Window timer drift: {error:.3f}s error (expected < 1s)",
                        file=sys.stderr,
                        flush=True
                    )
                
                if self._stop_event.wait(sleep_time):
                    break
                    
            except Exception as e:
                print(f"[ERROR] Error in window timer loop: {e}", file=sys.stderr, flush=True)
                if self._stop_event.wait(check_interval):
                    break

    def _checkpoint_loop(self) -> None:
        interval = self._stream_config.checkpoint_interval
        while not self._stop_event.is_set():
            if self._stop_event.wait(interval):
                break
            self._save_checkpoint()

    def _save_checkpoint(self) -> None:
        if self.state_persistence and self.anomaly_engine:
            try:
                self.state_persistence.mark_dirty()
                self.state_persistence.save_state(
                    self.anomaly_engine.frequency_detector,
                    self.anomaly_engine.error_rate_detector,
                    self.anomaly_engine.pattern_detector,
                    self.anomaly_engine.suppression_engine,
                    self.anomaly_engine.feedback_processor,
                    force=True,
                )
            except Exception as e:
                print(f"[ERROR] Error saving checkpoint: {e}", file=sys.stderr, flush=True)
        
        self._export_metrics()
    
    def _export_metrics(self) -> None:
        metrics_file = self._stream_config.metrics_file
        if not metrics_file:
            return
        
        try:
            with self._status_lock:
                total_processed = self.status.processed_lines
                source_lines = dict(self.status.source_processed_lines)
                source_hits = dict(self.status.source_sanitization_hits)
                queue_depth_series = [
                    {"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(), "depth": d}
                    for t, d in self.status.queue_depth_history
                ]
                backpressure_triggers = self.status.backpressure_trigger_count
                backpressure_total_pause = self.status.backpressure_total_pause_seconds
                
                if self.status.backpressure_paused and self.status.backpressure_last_trigger_time is not None:
                    backpressure_total_pause += time.monotonic() - self.status.backpressure_last_trigger_time
                
                detector_stats = {}
                if self.anomaly_engine:
                    sources = getattr(self.anomaly_engine, '_active_sources', set())
                    for source in sources:
                        source_detector_stats = {}
                        if self.anomaly_engine.frequency_detector:
                            freq_stats = self.anomaly_engine.frequency_detector.get_window_stats(source)
                            if freq_stats:
                                source_detector_stats['frequency'] = freq_stats
                        if self.anomaly_engine.error_rate_detector:
                            err_stats = self.anomaly_engine.error_rate_detector.get_window_stats(source)
                            if err_stats:
                                source_detector_stats['error_rate'] = err_stats
                        if self.anomaly_engine.pattern_detector:
                            pat_stats = self.anomaly_engine.pattern_detector.get_window_stats(source)
                            if pat_stats:
                                source_detector_stats['pattern'] = pat_stats
                        if source_detector_stats:
                            detector_stats[source] = source_detector_stats
            
            metrics = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_processed_lines": total_processed,
                "source_processed_lines": source_lines,
                "source_sanitization_hits": source_hits,
                "queue_depth_time_series": queue_depth_series,
                "backpressure": {
                    "trigger_count": backpressure_triggers,
                    "total_pause_seconds": round(backpressure_total_pause, 2),
                    "currently_paused": self.status.backpressure_paused,
                },
                "detector_window_stats": detector_stats,
            }
            
            metrics_dir = os.path.dirname(os.path.abspath(metrics_file))
            if metrics_dir:
                os.makedirs(metrics_dir, exist_ok=True)
            
            with open(metrics_file, 'w', encoding='utf-8') as f:
                json.dump(metrics, f, ensure_ascii=False, indent=2)
            
        except Exception as e:
            print(f"[ERROR] Error exporting metrics: {e}", file=sys.stderr, flush=True)
    
    def _queue_sampler_loop(self) -> None:
        while not self._stop_event.is_set():
            self._sample_queue_depth()
            if self._stop_event.wait(1.0):
                break
    
    def _watch_list_loop(self) -> None:
        if not self._watch_list_path:
            return
        
        check_interval = 5.0
        while not self._stop_event.is_set():
            try:
                self._check_watch_list()
            except Exception as e:
                print(f"[ERROR] Error checking watch list: {e}", file=sys.stderr, flush=True)
            
            if self._stop_event.wait(check_interval):
                break
    
    def _check_watch_list(self) -> None:
        if not self._watch_list_path or not isinstance(self._input_source, TailInputSource):
            return
        
        try:
            current_mtime = os.path.getmtime(self._watch_list_path)
        except OSError:
            if self._watch_list_mtime is not None:
                print(f"[WARNING] Watch list file not found: {self._watch_list_path}, keeping current list", file=sys.stderr, flush=True)
            self._watch_list_mtime = None
            return
        
        if self._watch_list_mtime is not None and current_mtime <= self._watch_list_mtime:
            return
        
        self._watch_list_mtime = current_mtime
        
        try:
            with open(self._watch_list_path, 'r', encoding='utf-8') as f:
                watch_list_data = json.load(f)
            
            if not isinstance(watch_list_data, list):
                raise ValueError("Watch list must be a JSON array")
            
            desired_files: Dict[str, str] = {}
            for item in watch_list_data:
                if not isinstance(item, dict):
                    raise ValueError(f"Invalid watch list entry: {item}")
                path = item.get('path')
                encoding = item.get('encoding', 'utf-8')
                if not path:
                    raise ValueError(f"Watch list entry missing 'path': {item}")
                desired_files[path] = encoding
            
        except (json.JSONDecodeError, ValueError) as e:
            print(f"[WARNING] Failed to parse watch list: {e}, keeping current list", file=sys.stderr, flush=True)
            return
        
        current_files = set(self._input_source.get_active_files())
        desired_paths = set(desired_files.keys())
        
        files_to_add = desired_paths - current_files
        files_to_remove = current_files - desired_paths
        
        for file_path in files_to_remove:
            self._input_source.remove_file(file_path)
        
        for file_path in files_to_add:
            encoding = desired_files[file_path]
            self._input_source.add_file(file_path, encoding=encoding, from_end=True)

    def _heartbeat_loop(self) -> None:
        interval = self._stream_config.heartbeat_interval
        while not self._stop_event.is_set():
            if self._stop_event.wait(interval):
                break
            self._emit_heartbeat()

    def _emit_heartbeat(self) -> None:
        now = datetime.now(timezone.utc)
        
        with self._status_lock:
            processed = self.status.processed_lines
            queue_depth = self._processing_queue.qsize()
            backpressure = self.status.backpressure_paused
            last_alert = self.status.last_alert_time
            
            detector_summaries = {}
            if self.anomaly_engine:
                sources = getattr(self.anomaly_engine, '_active_sources', set())
                for source in list(sources)[:5]:
                    source_stats = {}
                    if self.anomaly_engine.frequency_detector:
                        freq_stats = self.anomaly_engine.frequency_detector.get_window_stats(source)
                        if freq_stats:
                            source_stats['frequency'] = {
                                'ewma': f"{freq_stats.get('ewma', 0):.4f}" if freq_stats.get('ewma') is not None else 'N/A',
                                'window_count': freq_stats.get('window_count', 0),
                            }
                    if self.anomaly_engine.error_rate_detector:
                        err_stats = self.anomaly_engine.error_rate_detector.get_window_stats(source)
                        if err_stats:
                            history = err_stats.get('error_rate_history', [])
                            avg_err = sum(history) / len(history) if history else 0
                            source_stats['error_rate'] = {
                                'avg_error_rate': f"{avg_err:.4f}",
                                'window_total': err_stats.get('window_total', 0),
                            }
                    if self.anomaly_engine.pattern_detector:
                        pat_stats = self.anomaly_engine.pattern_detector.get_window_stats(source)
                        if pat_stats:
                            source_stats['pattern'] = {
                                'known_templates': pat_stats.get('known_templates_count', 0),
                                'window_templates': pat_stats.get('window_templates_count', 0),
                            }
                    if source_stats:
                        detector_summaries[source] = source_stats
        
        last_alert_str = last_alert.strftime("%Y-%m-%d %H:%M:%S UTC") if last_alert else "None"
        
        parts = [
            f"[HEARTBEAT] {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"processed={processed}",
            f"queue_depth={queue_depth}",
            f"backpressure={'ON' if backpressure else 'OFF'}",
            f"last_alert={last_alert_str}",
        ]
        
        if detector_summaries:
            for source, stats in detector_summaries.items():
                stat_parts = []
                if 'frequency' in stats:
                    stat_parts.append(f"freq={stats['frequency']['ewma']}")
                if 'error_rate' in stats:
                    stat_parts.append(f"err={stats['error_rate']['avg_error_rate']}")
                if 'pattern' in stats:
                    stat_parts.append(f"templates={stats['pattern']['known_templates']}")
                if stat_parts:
                    parts.append(f"{os.path.basename(source)}=[{', '.join(stat_parts)}]")
        
        print(" | ".join(parts), file=sys.stderr, flush=True)

    def start(self, input_source: StreamInputSource) -> None:
        self._input_source = input_source
        
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="stream-worker")
        self._worker_thread.start()
        self._threads.append(self._worker_thread)
        
        self._queue_sampler_thread = threading.Thread(target=self._queue_sampler_loop, daemon=True, name="queue-sampler")
        self._queue_sampler_thread.start()
        self._threads.append(self._queue_sampler_thread)
        
        if self._watch_list_path and isinstance(input_source, TailInputSource):
            self._watch_list_thread = threading.Thread(target=self._watch_list_loop, daemon=True, name="watch-list")
            self._watch_list_thread.start()
            self._threads.append(self._watch_list_thread)
        
        if self.anomaly_engine:
            self._window_timer_thread = threading.Thread(
                target=self._window_timer_loop,
                daemon=True,
                name="window-timer"
            )
            self._window_timer_thread.start()
            self._threads.append(self._window_timer_thread)
        
        if self._stream_config.checkpoint_interval > 0:
            self._checkpoint_thread = threading.Thread(
                target=self._checkpoint_loop,
                daemon=True,
                name="checkpoint"
            )
            self._checkpoint_thread.start()
            self._threads.append(self._checkpoint_thread)
        
        if self._stream_config.heartbeat_interval > 0:
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                daemon=True,
                name="heartbeat"
            )
            self._heartbeat_thread.start()
            self._threads.append(self._heartbeat_thread)
        
        input_source.start()

    def wait_for_completion(self) -> None:
        if isinstance(self._input_source, PipeInputSource):
            self._input_source.join()
            self._graceful_shutdown.set()
        
        drain_timeout = self._stream_config.drain_timeout
        if not self._drain_event.wait(timeout=drain_timeout):
            remaining = self._processing_queue.qsize()
            print(
                f"[WARNING] Drain timeout after {drain_timeout}s, {remaining} unprocessed entries will be lost",
                file=sys.stderr,
                flush=True
            )
        
        self._stop_event.set()
        self._backpressure_event.set()

    def stop(self) -> None:
        self._stop_event.set()
        self._backpressure_event.set()
        self._processing_queue.put(None)
        
        for thread in self._threads:
            thread.join(timeout=2.0)
        
        if self.anomaly_engine:
            self.anomaly_engine.stop()
        
        self._save_checkpoint()
        
        for target, handle in list(self._output_handles.items()):
            if handle != sys.stdout:
                try:
                    handle.flush()
                    handle.close()
                except Exception:
                    pass
        
        self.mapping_manager.close()
        if self.audit_logger:
            self.audit_logger.close()

    def run_pipe(self, buffer_size: int = 1000) -> None:
        pipe_source = PipeInputSource(
            queue_put_callback=self._queue_put,
            stop_event=self._stop_event,
            encoding=self.config.inputs.encoding,
            buffer_size=buffer_size,
        )
        
        print(
            f"[INFO] Starting stream processing in PIPE mode (buffer_size={buffer_size})",
            file=sys.stderr,
            flush=True
        )
        
        self.start(pipe_source)
        self.wait_for_completion()
        self.stop()
        
        with self._status_lock:
            print(
                f"[INFO] Stream processing completed. Total lines processed: {self.status.processed_lines}",
                file=sys.stderr,
                flush=True
            )

    def run_tail(self, file_paths: List[str]) -> None:
        tail_source = TailInputSource(
            queue_put_callback=self._queue_put,
            stop_event=self._stop_event,
            file_paths=file_paths,
            encoding=self.config.inputs.encoding,
            poll_interval=self._stream_config.tail.poll_interval,
            max_line_length=self._stream_config.tail.max_line_length,
        )
        
        print(
            f"[INFO] Starting stream processing in TAIL mode for {len(file_paths)} file(s): {', '.join(file_paths)}",
            file=sys.stderr,
            flush=True
        )
        
        self.start(tail_source)
        
        try:
            while not self._graceful_shutdown.is_set():
                if self._stop_event.wait(0.5):
                    break
        finally:
            self.wait_for_completion()
            self.stop()
        
        with self._status_lock:
            print(
                f"[INFO] Stream processing completed. Total lines processed: {self.status.processed_lines}",
                file=sys.stderr,
                flush=True
            )
