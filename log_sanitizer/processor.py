import os
import re
import glob
import json
import sys
import io
import codecs
from typing import List, Optional, Dict, Any, Generator, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from datetime import datetime
from .models import LogEntry, FileStats, AuditReport, LogLevel, SensitiveType, AuditLogEntry
from .config import PipelineConfig, SanitizersConfig, ConfigLoader
from .parser import LogParser
from .detector import SensitiveDataDetector
from .sanitizer import SanitizationEngine
from .mapping_manager import MappingManager
from .report import ReportAccumulator, ReportGenerator
from .state_manager import StateManager
from .audit_logger import AuditLogger
from .anomaly_engine import AnomalyDetectionEngine


class LogProcessor:
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.detector = self._create_detector()
        self.mapping_manager = self._create_mapping_manager()
        self.sanitizer = SanitizationEngine(self.detector, self.mapping_manager)
        self._output_handles: Dict[str, io.TextIOWrapper] = {}
        self.state_manager: Optional[StateManager] = None
        self.audit_logger: Optional[AuditLogger] = None
        self.anomaly_engine: Optional[AnomalyDetectionEngine] = None
        self._config_mtime: Optional[float] = None
        self._hot_reload_enabled = False
        self._current_line_number: int = 0
        
        if self.config.incremental and self.config.state_file:
            self.state_manager = StateManager(self.config.state_file)
        
        if self.config.audit_log.enabled and self.config.audit_log.file:
            self.audit_logger = AuditLogger(
                self.config.audit_log.file,
                self.config.audit_log.enabled,
            )
        
        if self.config.anomaly_detection.enabled:
            self.anomaly_engine = AnomalyDetectionEngine(self.config.anomaly_detection)
            self.anomaly_engine.start()
        
        if self.config.config_path and os.path.exists(self.config.config_path):
            try:
                self._config_mtime = os.path.getmtime(self.config.config_path)
                self._hot_reload_enabled = True
            except OSError:
                self._hot_reload_enabled = False

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

    def discover_files(self) -> List[str]:
        files = []
        for path_pattern in self.config.inputs.paths:
            if os.path.isfile(path_pattern):
                files.append(os.path.abspath(path_pattern))
            elif os.path.isdir(path_pattern):
                pattern = "**/*" if self.config.inputs.recursive else "*"
                full_pattern = os.path.join(path_pattern, pattern)
                for f in glob.glob(full_pattern, recursive=self.config.inputs.recursive):
                    if os.path.isfile(f):
                        files.append(os.path.abspath(f))
            else:
                for f in glob.glob(path_pattern, recursive=self.config.inputs.recursive):
                    if os.path.isfile(f):
                        files.append(os.path.abspath(f))
        
        return sorted(list(set(files)))

    @staticmethod
    def count_lines(file_path: str, encoding: str = "utf-8") -> int:
        count = 0
        with open(file_path, 'rb') as f:
            for _ in f:
                count += 1
        return count

    def should_keep(self, entry: LogEntry) -> bool:
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

    def _check_config_hot_reload(self) -> bool:
        if not self._hot_reload_enabled or not self.config.config_path:
            return False
        
        try:
            current_mtime = os.path.getmtime(self.config.config_path)
            if current_mtime != self._config_mtime:
                self._reload_sanitizers()
                self._config_mtime = current_mtime
                return True
        except OSError:
            pass
        return False
    
    def _reload_sanitizers(self) -> None:
        if not self.config.config_path:
            return
        
        try:
            new_sanitizers_config = ConfigLoader.load_sanitizers_only(self.config.config_path)
            
            custom_rules_data = []
            for rule in new_sanitizers_config.custom_rules:
                rule_dict: Dict[str, Any] = {
                    "name": rule.name,
                    "pattern": rule.pattern or "",
                    "type": rule.type.value if rule.type else "custom",
                    "strategy": rule.strategy.value if rule.strategy else "mask",
                    "params": rule.params,
                }
                custom_rules_data.append(rule_dict)
            
            self.detector.reload_rules(
                builtin_rules=new_sanitizers_config.builtin_rules,
                custom_rules=custom_rules_data,
                override_strategies=new_sanitizers_config.strategies,
                override_params=new_sanitizers_config.params,
            )
            
            self.sanitizer._rebuild_rule_cache()
            
            self.config.sanitizers = new_sanitizers_config
            
            print(f"[INFO] Sanitization rules reloaded successfully from {self.config.config_path}", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[WARNING] Failed to reload sanitization rules, keeping old rules: {e}", file=sys.stderr, flush=True)
    
    def _process_line(
        self,
        text_line: str,
        line_bytes: int,
        stats: FileStats,
        parser: LogParser,
        file_path: str,
        preview_records: List[Tuple[str, str]],
    ) -> None:
        entry = parser.parse_line(text_line)
        
        if entry.is_parseable:
            stats.parsed_lines += 1
        else:
            stats.unparsed_lines += 1
            if not self.config.dry_run:
                self._write_output(entry, file_path)
            return
        
        if not self.should_keep(entry):
            return
        
        original_message = entry.message
        entry, detections, sanitized, total_fields, audit_entries, field_path_counts = self.sanitizer.sanitize_entry(entry)
        
        stats.sanitized_fields += sanitized
        stats.total_fields += total_fields
        
        for stype, count in detections.items():
            stats.detections[stype] = stats.detections.get(stype, 0) + count
        
        for f_path, count in field_path_counts.items():
            stats.field_path_counts[f_path] = stats.field_path_counts.get(f_path, 0) + count
        
        if self.audit_logger and audit_entries:
            for f_path, orig_val, sanitized_val, rule_name in audit_entries:
                self.audit_logger.log(
                    line_number=stats.total_lines,
                    field_path=f_path,
                    original_value=orig_val,
                    sanitized_value=sanitized_val,
                    rule_name=rule_name,
                    timestamp=entry.timestamp,
                )
        
        if self.config.dry_run and len(preview_records) < 20:
            preview_records.append((original_message, entry.message))
        
        if not self.config.dry_run:
            self._write_output(entry, file_path)
    
    def _read_lines_with_offset(
        self,
        file_path: str,
        start_offset: int,
        encoding: str,
    ) -> Generator[Tuple[str, int], None, None]:
        with open(file_path, 'rb') as f_bin:
            if start_offset > 0:
                f_bin.seek(start_offset)
            
            decoder = codecs.getincrementaldecoder(encoding)(errors='replace')
            buffer = ''
            
            while True:
                chunk = f_bin.read(65536)
                if not chunk:
                    remaining = decoder.decode(b'', final=True)
                    if remaining:
                        lines = remaining.splitlines(keepends=True)
                        for line in lines:
                            has_newline = line.endswith('\n') or line.endswith('\r\n') or line.endswith('\r')
                            if has_newline or remaining.rstrip('\r\n'):
                                if has_newline:
                                    line_bytes = len(line.encode(encoding))
                                else:
                                    line_bytes = len(line.encode(encoding))
                                text_line = line.rstrip('\r\n')
                                yield text_line, line_bytes
                    break
                
                buffer += decoder.decode(chunk, final=False)
                
                while True:
                    newline_pos = -1
                    newline_len = 0
                    
                    if '\r\n' in buffer:
                        newline_pos = buffer.index('\r\n')
                        newline_len = 2
                    elif '\n' in buffer:
                        newline_pos = buffer.index('\n')
                        newline_len = 1
                    elif '\r' in buffer:
                        newline_pos = buffer.index('\r')
                        newline_len = 1
                    
                    if newline_pos < 0:
                        break
                    
                    line = buffer[:newline_pos + newline_len]
                    buffer = buffer[newline_pos + newline_len:]
                    
                    line_bytes = len(line.encode(encoding))
                    text_line = line.rstrip('\r\n')
                    yield text_line, line_bytes
    
    def process_file(self, file_path: str, show_progress: bool = True, progress_callback=None) -> Tuple[FileStats, List[Tuple[str, str]]]:
        stats = FileStats(file_path=file_path)
        parser = LogParser(
            format=self.config.parser.format,
            custom_pattern=self.config.parser.custom_pattern,
            custom_field_names=self.config.parser.custom_field_names,
            source=file_path,
        )
        
        preview_records: List[Tuple[str, str]] = []
        
        start_offset = 0
        if self.state_manager:
            start_offset = self.state_manager.should_start_from_breakpoint(file_path)
        
        current_offset = start_offset
        total_lines = self.count_lines(file_path, self.config.inputs.encoding)
        
        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            file_size = 0
        
        stats.start_offset = start_offset
        stats.end_offset = start_offset
        
        if self.state_manager and start_offset >= file_size and file_size > 0:
            stats.skipped_no_new_data = True
            stats.end_offset = start_offset
            return stats, preview_records
        
        initial_lines = 0
        if start_offset > 0:
            with open(file_path, 'rb') as f:
                f.seek(0)
                while f.tell() < start_offset:
                    line = f.readline()
                    if not line:
                        break
                    initial_lines += 1
        
        pbar = tqdm(
            total=total_lines,
            initial=initial_lines,
            desc=f"Processing {os.path.basename(file_path)}",
            unit="lines",
            disable=not show_progress,
            leave=False,
        )
        
        try:
            lines_processed = 0
            for text_line, line_bytes in self._read_lines_with_offset(
                file_path, start_offset, self.config.inputs.encoding
            ):
                current_offset += line_bytes
                stats.total_lines += 1
                stats.bytes_processed += line_bytes
                lines_processed += 1
                self._current_line_number = initial_lines + lines_processed
                pbar.update(1)
                
                if lines_processed % 1000 == 0:
                    self._check_config_hot_reload()
                    if self.state_manager:
                        self.state_manager.update_file_state(file_path, current_offset)
                        self.state_manager.save()
                    if progress_callback:
                        progress_callback(stats.detections)
                
                self._process_line(
                    text_line, line_bytes, stats, parser, file_path, preview_records
                )
        
        finally:
            stats.end_offset = current_offset
            if 'pbar' in locals():
                pbar.close()
            if self.state_manager:
                self.state_manager.update_file_state(file_path, current_offset)
                self.state_manager.save()
            
            if self.anomaly_engine:
                self.anomaly_engine.on_file_completed()
        
        return stats, preview_records

    def _get_output_path(self, entry: LogEntry) -> Optional[str]:
        output = self.config.output
        
        if not output.file:
            return None
        
        output_path = output.file
        
        split_by = output.split_by_time
        if not split_by and output.split_by_day:
            split_by = 'day'
        
        if split_by and entry.timestamp:
            date_str = entry.timestamp.strftime('%Y-%m-%d')
            hour_str = entry.timestamp.strftime('%H')
            
            template = output.filename_template
            if '{date}' in template or '{hour}' in template:
                output_path = template.format(date=date_str, hour=hour_str)
            else:
                base, ext = os.path.splitext(output.file)
                if split_by == 'hour':
                    output_path = f"{base}_{date_str}_{hour_str}{ext}"
                else:
                    output_path = f"{base}_{date_str}{ext}"
            
            if not os.path.isabs(output_path) and output.file:
                base_dir = os.path.dirname(output.file)
                if base_dir:
                    output_path = os.path.join(base_dir, os.path.basename(output_path))
        
        return output_path
    
    def _write_output(self, entry: LogEntry, source_file: str) -> None:
        output = self.config.output
        
        if self.anomaly_engine and entry.is_parseable:
            self.anomaly_engine.process_entry(entry, self._current_line_number, self._current_line_number)
        
        if output.stdout or output.target == 'stdout':
            json_str = json.dumps(entry.to_standard_dict(), ensure_ascii=False)
            if output.pretty:
                json_str = json.dumps(entry.to_standard_dict(), ensure_ascii=False, indent=2)
            print(json_str)
            return
        
        output_path = self._get_output_path(entry)
        if output_path:
            handle = self._get_output_handle(output_path)
            json_str = json.dumps(entry.to_standard_dict(), ensure_ascii=False)
            if output.pretty:
                json_str = json.dumps(entry.to_standard_dict(), ensure_ascii=False, indent=2)
            handle.write(json_str + '\n')

    def _get_output_handle(self, output_path: str) -> io.TextIOWrapper:
        if output_path not in self._output_handles:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            mode = 'w' if self.config.output.overwrite else 'a'
            self._output_handles[output_path] = open(
                output_path,
                mode,
                encoding=self.config.output.encoding,
                buffering=1,
            )
        return self._output_handles[output_path]

    def close(self) -> None:
        for handle in self._output_handles.values():
            try:
                handle.close()
            except Exception:
                pass
        self._output_handles.clear()
        self.mapping_manager.close()
        if self.state_manager:
            self.state_manager.close()
        if self.audit_logger:
            self.audit_logger.close()
        if self.anomaly_engine:
            self.anomaly_engine.stop()

    def run(self, show_progress: bool = True) -> AuditReport:
        files = self.discover_files()
        
        if not files:
            raise ValueError("No input files found")
        
        accumulator = ReportAccumulator()
        accumulator.report.incremental_mode = self.config.incremental
        all_preview: List[Tuple[str, str, str]] = []
        
        try:
            if self.config.parallelism > 1 and len(files) > 1 and not self.config.dry_run:
                results = self._run_parallel(files, show_progress)
            else:
                results = self._run_sequential(files, show_progress)
            
            for file_path, stats, preview in results:
                accumulator.add_file_stats(file_path, stats)
                if self.config.dry_run:
                    for orig, sanitized in preview:
                        all_preview.append((file_path, orig, sanitized))
            
            if self.config.dry_run:
                self._print_dry_run_preview(all_preview)
            
            report = accumulator.finalize()
            self._save_reports(report)
            
            return report
        
        finally:
            self.close()

    def _run_sequential(
        self,
        files: List[str],
        show_progress: bool
    ) -> List[Tuple[str, FileStats, List[Tuple[str, str]]]]:
        results = []
        for file_path in tqdm(files, desc="Overall progress", unit="files", disable=not show_progress):
            stats, preview = self.process_file(file_path, show_progress=show_progress)
            results.append((file_path, stats, preview))
        return results

    def _run_parallel(
        self,
        files: List[str],
        show_progress: bool
    ) -> List[Tuple[str, FileStats, List[Tuple[str, str]]]]:
        results: List[Tuple[str, FileStats, List[Tuple[str, str]]]] = []
        
        config_dict = self._config_to_dict()
        
        with ProcessPoolExecutor(max_workers=self.config.parallelism) as executor:
            futures = {
                executor.submit(self._process_file_worker, file_path, config_dict): file_path
                for file_path in files
            }
            
            for future in tqdm(
                as_completed(futures),
                total=len(files),
                desc="Overall progress",
                unit="files",
                disable=not show_progress,
            ):
                file_path = futures[future]
                try:
                    stats, preview = future.result()
                    results.append((file_path, stats, preview))
                except Exception as e:
                    print(f"Error processing {file_path}: {e}", file=sys.stderr)
        
        return results

    @staticmethod
    def _process_file_worker(
        file_path: str,
        config_dict: Dict[str, Any]
    ) -> Tuple[FileStats, List[Tuple[str, str]]]:
        from .config import ConfigLoader
        import tempfile
        
        config_str = json.dumps(config_dict)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(config_str)
            temp_path = f.name
        
        try:
            config = ConfigLoader.load_from_string(config_str)
            processor = LogProcessor(config)
            stats, preview = processor.process_file(file_path, show_progress=False)
            processor.close()
            return stats, preview
        finally:
            os.unlink(temp_path)

    def _config_to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.config.name,
            "inputs": {
                "paths": self.config.inputs.paths,
                "recursive": self.config.inputs.recursive,
                "encoding": self.config.inputs.encoding,
            },
            "parser": {
                "format": self.config.parser.format.value,
                "custom_pattern": self.config.parser.custom_pattern,
                "custom_field_names": self.config.parser.custom_field_names,
                "buffer_size": self.config.parser.buffer_size,
            },
            "filters": {
                "levels": [l.value for l in self.config.filters.levels] if self.config.filters and self.config.filters.levels else None,
                "start_time": self.config.filters.start_time.isoformat() if self.config.filters and self.config.filters.start_time else None,
                "end_time": self.config.filters.end_time.isoformat() if self.config.filters and self.config.filters.end_time else None,
                "include_keywords": self.config.filters.include_keywords if self.config.filters else None,
                "exclude_keywords": self.config.filters.exclude_keywords if self.config.filters else None,
            } if self.config.filters else None,
            "sanitizers": {
                "builtin_rules": [{"name": k, "enabled": v} for k, v in self.config.sanitizers.builtin_rules.items()],
                "custom_rules": [
                    {
                        "name": r.name,
                        "enabled": r.enabled,
                        "strategy": r.strategy.value if r.strategy else None,
                        "params": r.params,
                        "pattern": r.pattern,
                        "type": r.type.value if r.type else None,
                    }
                    for r in self.config.sanitizers.custom_rules
                ],
                "strategies": {k: v.value for k, v in self.config.sanitizers.strategies.items()},
                "params": self.config.sanitizers.params,
                "mapping_db_path": self.config.sanitizers.mapping_db_path,
                "hmac_key": self.config.sanitizers.hmac_key,
                "mapping_in_memory": self.config.sanitizers.mapping_in_memory,
            },
            "output": {
                "file": self.config.output.file,
                "stdout": self.config.output.stdout,
                "target": self.config.output.target,
                "split_by_day": self.config.output.split_by_day,
                "split_by_time": self.config.output.split_by_time,
                "filename_template": self.config.output.filename_template,
                "overwrite": self.config.output.overwrite,
                "encoding": self.config.output.encoding,
                "pretty": self.config.output.pretty,
            },
            "parallelism": self.config.parallelism,
            "dry_run": self.config.dry_run,
            "report_file": self.config.report_file,
            "report_json": self.config.report_json,
            "state_file": self.config.state_file,
            "incremental": self.config.incremental,
            "audit_log": {
                "enabled": self.config.audit_log.enabled,
                "file": self.config.audit_log.file,
            },
            "anomaly_detection": {
                "enabled": self.config.anomaly_detection.enabled,
                "alert_file": self.config.anomaly_detection.alert_file,
                "min_samples": self.config.anomaly_detection.min_samples,
                "state_file": self.config.anomaly_detection.state_file,
                "suppression_window_seconds": self.config.anomaly_detection.suppression_window_seconds,
                "correlation_window_seconds": self.config.anomaly_detection.correlation_window_seconds,
                "algorithms": {
                    "frequency": {
                        "window_size_seconds": self.config.anomaly_detection.algorithms.frequency.window_size_seconds,
                        "alpha": self.config.anomaly_detection.algorithms.frequency.alpha,
                        "threshold_multiplier": self.config.anomaly_detection.algorithms.frequency.threshold_multiplier,
                    },
                    "error_rate": {
                        "window_size_seconds": self.config.anomaly_detection.algorithms.error_rate.window_size_seconds,
                        "k_windows": self.config.anomaly_detection.algorithms.error_rate.k_windows,
                        "z_score_threshold": self.config.anomaly_detection.algorithms.error_rate.z_score_threshold,
                    },
                    "pattern": {
                        "window_size_seconds": self.config.anomaly_detection.algorithms.pattern.window_size_seconds,
                        "min_samples": self.config.anomaly_detection.algorithms.pattern.min_samples,
                        "disappear_windows": self.config.anomaly_detection.algorithms.pattern.disappear_windows,
                    },
                },
                "webhook": {
                    "url": self.config.anomaly_detection.webhook.url,
                    "headers": self.config.anomaly_detection.webhook.headers,
                    "timeout_seconds": self.config.anomaly_detection.webhook.timeout_seconds,
                    "max_retries": self.config.anomaly_detection.webhook.max_retries,
                    "retry_interval_seconds": self.config.anomaly_detection.webhook.retry_interval_seconds,
                    "dead_letter_file": self.config.anomaly_detection.webhook.dead_letter_file,
                },
            },
        }

    def _print_dry_run_preview(self, preview: List[Tuple[str, str, str]]) -> None:
        if not preview:
            print("\n[DRY RUN] No sensitive information detected in first 20 lines of each file.")
            return
        
        print("\n" + "=" * 100)
        print("[DRY RUN] SANITIZATION PREVIEW (first 20 entries)")
        print("=" * 100)
        
        for i, (file_path, original, sanitized) in enumerate(preview, 1):
            print(f"\n--- Entry {i} (from: {os.path.basename(file_path)}) ---")
            print(f"ORIGINAL: {original}")
            print(f"SANITIZED: {sanitized}")
            if original == sanitized:
                print("  (No changes)")
        
        print("\n" + "=" * 100)
        print(f"Total entries previewed: {len(preview)}")
        print("=" * 100 + "\n")

    def _save_reports(self, report: AuditReport) -> None:
        if self.config.report_file:
            ReportGenerator.save_report(report, self.config.report_file, "text")
        
        if self.config.report_json:
            ReportGenerator.save_report(report, self.config.report_json, "json")
