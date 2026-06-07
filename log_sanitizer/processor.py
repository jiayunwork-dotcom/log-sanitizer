import os
import re
import glob
import json
import sys
import io
from typing import List, Optional, Dict, Any, Generator, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from datetime import datetime
from .models import LogEntry, FileStats, AuditReport, LogLevel, SensitiveType
from .config import PipelineConfig
from .parser import LogParser
from .detector import SensitiveDataDetector
from .sanitizer import SanitizationEngine
from .mapping_manager import MappingManager
from .report import ReportAccumulator, ReportGenerator


class LogProcessor:
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.detector = self._create_detector()
        self.mapping_manager = self._create_mapping_manager()
        self.sanitizer = SanitizationEngine(self.detector, self.mapping_manager)
        self._output_handles: Dict[str, io.TextIOWrapper] = {}

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

    def process_file(self, file_path: str, show_progress: bool = True) -> Tuple[FileStats, List[Tuple[str, str]]]:
        stats = FileStats(file_path=file_path)
        parser = LogParser(
            format=self.config.parser.format,
            custom_pattern=self.config.parser.custom_pattern,
            custom_field_names=self.config.parser.custom_field_names,
            source=file_path,
        )
        
        preview_records: List[Tuple[str, str]] = []
        total_lines = self.count_lines(file_path, self.config.inputs.encoding)
        
        pbar = tqdm(
            total=total_lines,
            desc=f"Processing {os.path.basename(file_path)}",
            unit="lines",
            disable=not show_progress,
            leave=False,
        )
        
        try:
            with open(file_path, 'r', encoding=self.config.inputs.encoding, errors='replace') as f:
                for line in f:
                    stats.total_lines += 1
                    pbar.update(1)
                    
                    entry = parser.parse_line(line)
                    
                    if entry.is_parseable:
                        stats.parsed_lines += 1
                    else:
                        stats.unparsed_lines += 1
                        if not self.config.dry_run:
                            self._write_output(entry, file_path)
                        continue
                    
                    if not self.should_keep(entry):
                        continue
                    
                    original_message = entry.message
                    entry, detections, sanitized, total_fields = self.sanitizer.sanitize_entry(entry)
                    
                    stats.sanitized_fields += sanitized
                    stats.total_fields += total_fields
                    
                    for stype, count in detections.items():
                        stats.detections[stype] = stats.detections.get(stype, 0) + count
                    
                    if self.config.dry_run and len(preview_records) < 20:
                        preview_records.append((original_message, entry.message))
                    
                    if not self.config.dry_run:
                        self._write_output(entry, file_path)
        
        finally:
            pbar.close()
        
        return stats, preview_records

    def _write_output(self, entry: LogEntry, source_file: str) -> None:
        output = self.config.output
        
        if output.stdout:
            json_str = json.dumps(entry.to_standard_dict(), ensure_ascii=False)
            if output.pretty:
                json_str = json.dumps(entry.to_standard_dict(), ensure_ascii=False, indent=2)
            print(json_str)
            return
        
        if output.file:
            output_path = output.file
            if output.split_by_day and entry.timestamp:
                day_str = entry.timestamp.strftime('%Y-%m-%d')
                base, ext = os.path.splitext(output.file)
                output_path = f"{base}_{day_str}{ext}"
            
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

    def run(self, show_progress: bool = True) -> AuditReport:
        files = self.discover_files()
        
        if not files:
            raise ValueError("No input files found")
        
        accumulator = ReportAccumulator()
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
                "split_by_day": self.config.output.split_by_day,
                "overwrite": self.config.output.overwrite,
                "encoding": self.config.output.encoding,
                "pretty": self.config.output.pretty,
            },
            "parallelism": self.config.parallelism,
            "dry_run": self.config.dry_run,
            "report_file": self.config.report_file,
            "report_json": self.config.report_json,
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
