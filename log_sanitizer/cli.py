import os
import sys
import typer
from typing import Optional, List
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from . import __version__
from .config import ConfigLoader, PipelineConfig
from .processor import LogProcessor
from .report import ReportGenerator
from .models import LogFormat, SanitizeStrategy

app = typer.Typer(
    help="批量日志文件脱敏与格式标准化命令行工具",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"log-sanitizer v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="显示版本信息",
        callback=_version_callback,
        is_eager=True,
    ),
):
    """
    批量日志文件脱敏与格式标准化命令行工具
    
    支持识别日志中的敏感信息并按规则替换，同时将各种格式的日志统一转成标准JSON输出。
    """
    pass


@app.command("run")
def run_pipeline(
    config: Path = typer.Option(
        ...,
        "--config",
        "-c",
        help="Pipeline配置文件路径(YAML格式)",
        exists=True,
        readable=True,
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="只预览脱敏效果，不实际写入输出文件",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="覆盖已存在的输出文件，默认是追加模式",
    ),
    parallelism: Optional[int] = typer.Option(
        None,
        "--parallelism",
        "-p",
        help="并行处理的文件数，默认使用CPU核心数",
    ),
    input_: Optional[List[Path]] = typer.Option(
        None,
        "--input",
        "-i",
        help="输入文件路径，可多次指定，覆盖配置文件中的inputs",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="输出文件路径，覆盖配置文件中的output",
    ),
    no_progress: bool = typer.Option(
        False,
        "--no-progress",
        help="不显示进度条",
    ),
    incremental: bool = typer.Option(
        False,
        "--incremental",
        help="启用增量处理模式，从上次处理的断点继续",
    ),
):
    """
    执行日志处理Pipeline
    """
    try:
        pipeline_config = ConfigLoader.load(str(config))
        
        if dry_run:
            pipeline_config.dry_run = True
        
        if overwrite:
            pipeline_config.output.overwrite = True
        
        if parallelism is not None:
            pipeline_config.parallelism = max(1, parallelism)
        
        if input_:
            pipeline_config.inputs.paths = [str(p) for p in input_]
        
        if output:
            pipeline_config.output.file = str(output)
            pipeline_config.output.stdout = False
        
        if incremental:
            pipeline_config.incremental = True
        
        processor = LogProcessor(pipeline_config)
        files = processor.discover_files()
        
        if not files:
            console.print("[yellow]警告: 没有找到匹配的输入文件[/yellow]")
            return
        
        info_lines = [f"[bold]发现 {len(files)} 个文件待处理[/bold]"]
        if pipeline_config.incremental:
            info_lines.append("[cyan]增量处理模式已启用[/cyan]")
        if pipeline_config.audit_log.enabled:
            info_lines.append("[magenta]审计日志已启用[/magenta]")
        
        console.print(Panel.fit(
            "\n".join(info_lines),
            border_style="blue",
        ))
        
        report = processor.run(show_progress=not no_progress)
        
        console.print()
        console.print(ReportGenerator.generate_console_summary(report))
        
        if pipeline_config.report_file:
            console.print(f"\n[dim]文本报告已保存到: {pipeline_config.report_file}[/dim]")
        if pipeline_config.report_json:
            console.print(f"[dim]JSON报告已保存到: {pipeline_config.report_json}[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]错误:[/bold red] {str(e)}")
        raise typer.Exit(code=1)


@app.command("init")
def init_config(
    output: Path = typer.Option(
        "sanitizer-config.yaml",
        "--output",
        "-o",
        help="配置文件输出路径",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="如果文件已存在，强制覆盖",
    ),
):
    """
    生成示例配置文件
    """
    if output.exists() and not force:
        console.print(f"[yellow]文件已存在: {output}，使用 --force 覆盖[/yellow]")
        raise typer.Exit(code=1)
    
    example_config = """# log-sanitizer Pipeline 配置文件
name: "log-processing-pipeline"

# 输入源配置
inputs:
  paths:
    - "./logs/*.log"
    - "./data/access_log"
  recursive: true
  encoding: "utf-8"

# 解析器配置
parser:
  # 日志格式: auto, json, apache, nginx, syslog, plaintext, custom
  format: "auto"
  # 自定义格式时使用，正则表达式中使用命名捕获组
  # custom_pattern: '^(?P<timestamp>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) \\[(?P<level>[A-Z]+)\\] (?P<message>.*)$'
  # custom_field_names:
  #   timestamp: "timestamp"
  #   level: "level"
  #   message: "message"

# 过滤条件(可选)
filters:
  # 只处理指定级别
  # levels: ["INFO", "WARN", "ERROR"]
  # 时间范围过滤
  # start_time: "2024-01-01T00:00:00+00:00"
  # end_time: "2024-12-31T23:59:59+00:00"
  # 包含关键词
  # include_keywords: ["error", "warning"]
  # 排除关键词
  # exclude_keywords: ["healthcheck", "debug"]

# 脱敏规则配置
sanitizers:
  # 内置规则开关
  builtin_rules:
    - name: "ipv4"
      enabled: true
      strategy: "generalize"  # mask, hash, replace, delete, generalize
    - name: "ipv6"
      enabled: true
      strategy: "generalize"
    - name: "email"
      enabled: true
      strategy: "generalize"
    - name: "phone"
      enabled: true
      strategy: "mask"
      params:
        keep_start: 3
        keep_end: 4
    - name: "id_card"
      enabled: true
      strategy: "mask"
      params:
        keep_start: 4
        keep_end: 4
    - name: "bank_card"
      enabled: true
      strategy: "mask"
      params:
        keep_start: 6
        keep_end: 4
    - name: "token"
      enabled: true
      strategy: "replace"
      params:
        replacement: "[REDACTED_TOKEN]"
    - name: "session"
      enabled: true
      strategy: "replace"
      params:
        replacement: "[REDACTED_SESSION]"
    - name: "cookie"
      enabled: true
      strategy: "replace"
      params:
        replacement: "[REDACTED_COOKIE]"

  # 自定义检测规则
  custom_rules:
    - name: "custom_ssn"
      enabled: true
      pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
      type: "custom"
      strategy: "mask"
      params:
        keep_start: 0
        keep_end: 4
        mask_char: "*"

  # 脱敏映射持久化配置
  # mapping_db_path: "./sanitizer_mappings.db"
  # hmac_key: "your-secret-key-here"  # 用于HMAC签名，保护原始值
  mapping_in_memory: true  # 仅内存中保持一致性，不持久化

# 输出配置
output:
  # 输出目标: file 或 stdout
  target: "file"
  file: "./output/sanitized_logs.jsonl"
  stdout: false
  # 按时间分割: day 或 hour
  # split_by_time: "day"
  # 文件名模板, 支持 {date} 和 {hour} 占位符
  # filename_template: "output_{date}_{hour}.jsonl"
  split_by_day: false  # 按天分割输出文件(已废弃, 使用 split_by_time)
  overwrite: false
  encoding: "utf-8"
  pretty: false  # 格式化JSON输出

# 处理配置
parallelism: 4  # 并行处理的文件数，默认CPU核心数
dry_run: false  # 只预览不实际写入
incremental: false  # 增量处理模式
# 增量处理状态文件路径(JSON格式)
# state_file: "./output/.processing_state.json"

# 脱敏前后对照审计日志
audit_log:
  enabled: false
  file: "./output/audit_log.jsonl"

# 审计报告配置
report_file: "./output/audit_report.txt"
report_json: "./output/audit_report.json"
"""
    
    with open(output, 'w', encoding='utf-8') as f:
        f.write(example_config)
    
    console.print(f"[green]示例配置文件已生成: {output}[/green]")
    console.print("[dim]请根据实际需求修改配置文件后执行: log-sanitizer run -c sanitizer-config.yaml[/dim]")


@app.command("validate")
def validate_config(
    config: Path = typer.Option(
        ...,
        "--config",
        "-c",
        help="配置文件路径",
        exists=True,
        readable=True,
    ),
):
    """
    验证配置文件是否正确
    """
    try:
        pipeline_config = ConfigLoader.load(str(config))
        
        table = Table(title="配置验证结果", show_header=True, header_style="bold blue")
        table.add_column("项目", style="cyan")
        table.add_column("值", style="green")
        
        table.add_row("Pipeline名称", pipeline_config.name)
        table.add_row("输入路径", ", ".join(pipeline_config.inputs.paths))
        table.add_row("日志格式", pipeline_config.parser.format.value)
        table.add_row("并行度", str(pipeline_config.parallelism))
        table.add_row("Dry Run", "是" if pipeline_config.dry_run else "否")
        
        if pipeline_config.output.file:
            table.add_row("输出文件", pipeline_config.output.file)
        if pipeline_config.output.stdout or pipeline_config.output.target == "stdout":
            table.add_row("输出到标准输出", "是")
        if pipeline_config.output.split_by_time:
            table.add_row("按时间分割", pipeline_config.output.split_by_time)
        if pipeline_config.output.filename_template != "output_{date}.jsonl":
            table.add_row("文件名模板", pipeline_config.output.filename_template)
        
        if pipeline_config.incremental:
            table.add_row("增量模式", "已启用")
            if pipeline_config.state_file:
                table.add_row("状态文件", pipeline_config.state_file)
        
        if pipeline_config.audit_log.enabled:
            table.add_row("审计日志", "已启用")
            if pipeline_config.audit_log.file:
                table.add_row("审计日志文件", pipeline_config.audit_log.file)
        
        table.add_row(
            "内置脱敏规则",
            str(len([r for r in pipeline_config.sanitizers.builtin_rules.values() if r]))
        )
        table.add_row(
            "自定义规则",
            str(len(pipeline_config.sanitizers.custom_rules))
        )
        
        if pipeline_config.filters:
            if pipeline_config.filters.levels:
                table.add_row("过滤级别", ", ".join(l.value for l in pipeline_config.filters.levels))
        
        console.print(table)
        console.print("\n[bold green]配置文件验证通过![/bold green]")
        
        processor = LogProcessor(pipeline_config)
        files = processor.discover_files()
        console.print(f"[dim]发现 {len(files)} 个匹配的输入文件[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]配置验证失败:[/bold red] {str(e)}")
        raise typer.Exit(code=1)


@app.command("list-rules")
def list_rules():
    """
    列出所有内置的敏感信息检测规则
    """
    table = Table(title="内置脱敏规则", show_header=True, header_style="bold blue")
    table.add_column("规则名称", style="cyan")
    table.add_column("类型", style="magenta")
    table.add_column("默认策略", style="green")
    table.add_column("说明", style="dim")
    
    rules_info = [
        ("ipv4", "IP地址(IPv4)", "generalize", "匹配IPv4地址，默认泛化处理(保留前两段)"),
        ("ipv6", "IP地址(IPv6)", "generalize", "匹配IPv6地址，默认泛化处理"),
        ("email", "邮箱地址", "generalize", "匹配标准邮箱格式，默认泛化处理(仅保留域名)"),
        ("phone", "手机号码", "mask", "匹配中国大陆11位手机号，支持+86前缀，默认掩码(前3后4)"),
        ("id_card", "身份证号", "mask", "匹配18位身份证号，验证校验位，默认掩码(前4后4)"),
        ("bank_card", "银行卡号", "mask", "匹配16-19位数字，验证Luhn算法，默认掩码(前6后4)"),
        ("token", "URL Token", "replace", "匹配URL参数中的token=xxx等，默认替换为[REDACTED_TOKEN]"),
        ("session", "Session ID", "replace", "匹配session_id等，默认替换为[REDACTED_SESSION]"),
        ("cookie", "Cookie值", "replace", "匹配Set-Cookie头，默认替换为[REDACTED_COOKIE]"),
    ]
    
    for name, type_, strategy, desc in rules_info:
        table.add_row(name, type_, strategy, desc)
    
    console.print(table)
    console.print("\n[dim]脱敏策略说明:[/dim]")
    strategies = [
        ("mask", "掩码 - 保留前后N位，中间用*替换"),
        ("hash", "哈希 - SHA256取前16位hex替换"),
        ("replace", "替换 - 用固定占位符替换"),
        ("delete", "删除 - 移除字段值"),
        ("generalize", "泛化 - 部分信息隐藏，如IP保留前两段"),
    ]
    for strat, desc in strategies:
        console.print(f"  [cyan]{strat:<12}[/cyan] {desc}")


@app.command("detect")
def detect_sensitive(
    input_: Path = typer.Option(
        ...,
        "--input",
        "-i",
        help="输入文件路径",
        exists=True,
        readable=True,
    ),
    limit: int = typer.Option(
        100,
        "--limit",
        "-n",
        help="扫描的行数",
    ),
):
    """
    检测文件中的敏感信息(不执行脱敏)
    """
    try:
        from .detector import SensitiveDataDetector
        
        detector = SensitiveDataDetector()
        detections_total = {}
        lines_with_detections = 0
        
        console.print(f"正在扫描 {input_} 的前 {limit} 行...\n")
        
        with open(input_, 'r', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, 1):
                if line_num > limit:
                    break
                
                matches = detector.detect_in_value(line)
                if matches:
                    lines_with_detections += 1
                    for match in matches:
                        key = match.type.value
                        detections_total[key] = detections_total.get(key, 0) + 1
                        if lines_with_detections <= 10:
                            context_start = max(0, match.start - 20)
                            context_end = min(len(line), match.end + 20)
                            context = line[context_start:context_end].strip()
                            console.print(
                                f"[dim]行 {line_num}:[/dim] "
                                f"[yellow]{match.type.value}[/yellow] "
                                f"[red]{match.value}[/red] "
                                f"[dim]'{context}'[/dim]"
                            )
        
        console.print("\n" + "=" * 60)
        console.print(f"扫描行数: {min(limit, line_num)}")
        console.print(f"发现敏感信息的行数: {lines_with_detections}")
        
        if detections_total:
            table = Table(title="检测到的敏感信息类型", show_header=True)
            table.add_column("类型", style="cyan")
            table.add_column("数量", style="magenta", justify="right")
            
            for stype, count in sorted(detections_total.items(), key=lambda x: -x[1]):
                table.add_row(stype, str(count))
            
            console.print(table)
        else:
            console.print("[green]未检测到敏感信息[/green]")
        
    except Exception as e:
        console.print(f"[bold red]错误:[/bold red] {str(e)}")
        raise typer.Exit(code=1)


def entry_point():
    app()


if __name__ == "__main__":
    entry_point()
