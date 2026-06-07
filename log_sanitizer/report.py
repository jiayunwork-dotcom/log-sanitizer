import json
import os
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from .models import AuditReport, FileStats, SensitiveType


class ReportGenerator:
    @staticmethod
    def generate_console_summary(report: AuditReport) -> Panel:
        console = Console()
        
        duration = report.processing_time
        throughput = report.throughput
        
        main_table = Table.grid(padding=(0, 2))
        main_table.add_column(style="cyan")
        main_table.add_column()
        
        main_table.add_row(
            "[bold]处理时长:",
            f"[green]{duration:.2f}[/green] 秒"
        )
        main_table.add_row(
            "[bold]吞吐量:",
            f"[green]{throughput:.0f}[/green] 行/秒"
        )
        main_table.add_row(
            "[bold]总行数:",
            f"[white]{report.total_lines:,}[/white]"
        )
        main_table.add_row(
            "[bold]解析成功:",
            f"[green]{report.parsed_lines:,}[/green]"
        )
        main_table.add_row(
            "[bold]解析失败:",
            f"[red]{report.unparsed_lines:,}[/red] ([yellow]{report.parse_failure_rate:.2%}[/yellow])"
        )
        main_table.add_row(
            "[bold]脱敏字段:",
            f"[magenta]{report.sanitized_fields:,}[/magenta] / {report.total_fields:,} ([cyan]{report.sanitize_coverage:.2%}[/cyan])"
        )
        
        detection_items = list(report.detections.items())
        if detection_items:
            max_count = max(count for _, count in detection_items)
            max_bar_width = 30
            
            detection_table = Table(
                show_header=True,
                header_style="bold magenta",
                border_style="dim",
                box=None,
            )
            detection_table.add_column("类型", style="cyan", no_wrap=True)
            detection_table.add_column("计数", justify="right", style="green")
            detection_table.add_column("分布", justify="left")
            
            for stype, count in sorted(detection_items, key=lambda x: -x[1]):
                bar_width = int(count / max_count * max_bar_width) if max_count > 0 else 0
                bar = "█" * bar_width
                color = "green"
                if stype.value in ["ipv4", "ipv6"]:
                    color = "blue"
                elif stype.value in ["email", "phone"]:
                    color = "yellow"
                elif stype.value in ["id_card", "bank_card"]:
                    color = "red"
                detection_table.add_row(
                    stype.value.upper(),
                    f"{count:,}",
                    f"[{color}]{bar}[/{color}] [dim]({count/max_count*100:.0f}%)[/dim]"
                )
            
            main_table.add_row("", "")
            main_table.add_row("[bold]敏感信息分布:", "")
            main_table.add_row(Panel(detection_table, border_style="magenta"), "")
        
        if report.field_path_counts:
            top_fields = sorted(
                report.field_path_counts.items(),
                key=lambda x: -x[1]
            )[:5]
            
            top_table = Table(
                show_header=True,
                header_style="bold cyan",
                border_style="dim",
                box=None,
            )
            top_table.add_column("排名", justify="right", style="yellow")
            top_table.add_column("字段路径", style="white")
            top_table.add_column("脱敏次数", justify="right", style="magenta")
            
            for i, (field_path, count) in enumerate(top_fields, 1):
                top_table.add_row(str(i), field_path, f"{count:,}")
            
            main_table.add_row("", "")
            main_table.add_row("[bold]Top 5 脱敏字段:", "")
            main_table.add_row(Panel(top_table, border_style="cyan"), "")
        
        return Panel(
            main_table,
            title="[bold green]✓ 处理完成[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    
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
        
        for field_path, count in stats.field_path_counts.items():
            self.report.field_path_counts[field_path] = self.report.field_path_counts.get(field_path, 0) + count
        
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
