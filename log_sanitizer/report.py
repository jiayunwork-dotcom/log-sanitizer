import json
import os
from typing import Dict, Any
from datetime import datetime, timezone
from .models import AuditReport, FileStats, SensitiveType


class ReportGenerator:
    @staticmethod
    def generate_json(report: AuditReport) -> str:
        data = ReportGenerator._report_to_dict(report)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @staticmethod
    def generate_text(report: AuditReport) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("LOG SANITIZER AUDIT REPORT")
        lines.append("=" * 70)
        lines.append("")
        
        if report.start_time:
            lines.append(f"Start Time:     {report.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if report.end_time:
            lines.append(f"End Time:       {report.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Processing Time: {report.processing_time:.2f} seconds")
        lines.append(f"Throughput:      {report.throughput:.0f} lines/second")
        lines.append("")
        
        lines.append("-" * 70)
        lines.append("PARSING STATISTICS")
        lines.append("-" * 70)
        lines.append(f"Total Lines:     {report.total_lines:,}")
        lines.append(f"Parsed Lines:    {report.parsed_lines:,}")
        lines.append(f"Unparsed Lines:  {report.unparsed_lines:,}")
        lines.append(f"Failure Rate:    {report.parse_failure_rate:.2%}")
        lines.append("")
        
        lines.append("-" * 70)
        lines.append("SANITIZATION STATISTICS")
        lines.append("-" * 70)
        lines.append(f"Total Fields:    {report.total_fields:,}")
        lines.append(f"Sanitized Fields: {report.sanitized_fields:,}")
        lines.append(f"Coverage:        {report.sanitize_coverage:.2%}")
        lines.append("")
        
        lines.append("-" * 70)
        lines.append("SENSITIVE INFORMATION DETECTED")
        lines.append("-" * 70)
        if report.detections:
            max_type_len = max(len(t.value) for t in report.detections.keys())
            for stype, count in sorted(report.detections.items(), key=lambda x: -x[1]):
                padding = " " * (max_type_len - len(stype.value))
                lines.append(f"  {stype.value.upper():<{max_type_len}}: {count:,}")
        else:
            lines.append("  No sensitive information detected.")
        lines.append("")
        
        lines.append("-" * 70)
        lines.append("PER-FILE STATISTICS")
        lines.append("-" * 70)
        if report.file_stats:
            for file_path, stats in sorted(report.file_stats.items()):
                lines.append(f"\nFile: {file_path}")
                lines.append(f"  Total Lines:    {stats.total_lines:,}")
                lines.append(f"  Parsed:         {stats.parsed_lines:,}")
                lines.append(f"  Unparsed:       {stats.unparsed_lines:,}")
                if stats.total_fields > 0:
                    coverage = stats.sanitized_fields / stats.total_fields
                    lines.append(f"  Sanitized Fields: {stats.sanitized_fields:,}/{stats.total_fields:,} ({coverage:.2%})")
                if stats.detections:
                    det_str = ", ".join(f"{k.value}={v:,}" for k, v in sorted(stats.detections.items()))
                    lines.append(f"  Detections:     {det_str}")
        else:
            lines.append("  No files processed.")
        lines.append("")
        
        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)
        
        return "\n".join(lines)

    @staticmethod
    def _report_to_dict(report: AuditReport) -> Dict[str, Any]:
        return {
            "start_time": report.start_time.isoformat() if report.start_time else None,
            "end_time": report.end_time.isoformat() if report.end_time else None,
            "processing_time_seconds": round(report.processing_time, 2),
            "throughput_lines_per_second": round(report.throughput, 2),
            "parsing": {
                "total_lines": report.total_lines,
                "parsed_lines": report.parsed_lines,
                "unparsed_lines": report.unparsed_lines,
                "failure_rate": round(report.parse_failure_rate, 4),
            },
            "sanitization": {
                "total_fields": report.total_fields,
                "sanitized_fields": report.sanitized_fields,
                "coverage": round(report.sanitize_coverage, 4),
            },
            "detections": {k.value: v for k, v in report.detections.items()},
            "files": {
                file_path: ReportGenerator._file_stats_to_dict(stats)
                for file_path, stats in report.file_stats.items()
            },
        }

    @staticmethod
    def _file_stats_to_dict(stats: FileStats) -> Dict[str, Any]:
        return {
            "total_lines": stats.total_lines,
            "parsed_lines": stats.parsed_lines,
            "unparsed_lines": stats.unparsed_lines,
            "total_fields": stats.total_fields,
            "sanitized_fields": stats.sanitized_fields,
            "detections": {k.value: v for k, v in stats.detections.items()},
        }

    @staticmethod
    def save_report(report: AuditReport, output_path: str, format: str = "text") -> None:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        if format == "json":
            content = ReportGenerator.generate_json(report)
        else:
            content = ReportGenerator.generate_text(report)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)


class ReportAccumulator:
    def __init__(self):
        self.report = AuditReport()
        self.report.start_time = datetime.now(timezone.utc)

    def add_file_stats(self, file_path: str, stats: FileStats) -> None:
        self.report.total_lines += stats.total_lines
        self.report.parsed_lines += stats.parsed_lines
        self.report.unparsed_lines += stats.unparsed_lines
        self.report.total_fields += stats.total_fields
        self.report.sanitized_fields += stats.sanitized_fields
        
        for stype, count in stats.detections.items():
            self.report.detections[stype] = self.report.detections.get(stype, 0) + count
        
        self.report.file_stats[file_path] = stats

    def finalize(self) -> AuditReport:
        self.report.end_time = datetime.now(timezone.utc)
        if self.report.start_time:
            self.report.processing_time = (self.report.end_time - self.report.start_time).total_seconds()
        
        if self.report.total_lines > 0:
            self.report.parse_failure_rate = self.report.unparsed_lines / self.report.total_lines
        
        if self.report.total_fields > 0:
            self.report.sanitize_coverage = self.report.sanitized_fields / self.report.total_fields
        
        if self.report.processing_time > 0:
            self.report.throughput = self.report.total_lines / self.report.processing_time
        
        return self.report
