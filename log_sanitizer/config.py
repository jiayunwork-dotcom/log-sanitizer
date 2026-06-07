import os
import re
import yaml
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Pattern
from datetime import datetime
from .models import (
    LogFormat,
    LogLevel,
    SanitizeStrategy,
    SensitiveType,
    AlertType,
    AlertSeverity,
    SuppressionAction,
    SuppressionRule,
    SuppressionRuleMatch,
)


@dataclass
class InputConfig:
    paths: List[str] = field(default_factory=list)
    recursive: bool = True
    encoding: str = "utf-8"


@dataclass
class ParserConfig:
    format: LogFormat = LogFormat.AUTO
    custom_pattern: Optional[str] = None
    custom_field_names: Dict[str, str] = field(default_factory=dict)
    buffer_size: int = 8192

    def __post_init__(self):
        if isinstance(self.format, str):
            self.format = LogFormat(self.format.lower())


@dataclass
class FilterConfig:
    levels: Optional[List[LogLevel]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    include_keywords: Optional[List[str]] = None
    exclude_keywords: Optional[List[str]] = None

    def __post_init__(self):
        if self.levels:
            self.levels = [
                LogLevel(level.upper()) if isinstance(level, str) else level
                for level in self.levels
            ]
        if self.start_time and isinstance(self.start_time, str):
            self.start_time = datetime.fromisoformat(self.start_time.replace('Z', '+00:00'))
        if self.end_time and isinstance(self.end_time, str):
            self.end_time = datetime.fromisoformat(self.end_time.replace('Z', '+00:00'))


@dataclass
class SanitizerRuleConfig:
    name: str
    enabled: bool = True
    strategy: Optional[SanitizeStrategy] = None
    params: Dict[str, Any] = field(default_factory=dict)
    pattern: Optional[str] = None
    type: Optional[SensitiveType] = None

    def __post_init__(self):
        if self.strategy and isinstance(self.strategy, str):
            self.strategy = SanitizeStrategy(self.strategy.lower())
        if self.type and isinstance(self.type, str):
            try:
                self.type = SensitiveType(self.type.lower())
            except ValueError:
                self.type = SensitiveType.CUSTOM


@dataclass
class SanitizersConfig:
    builtin_rules: Dict[str, bool] = field(default_factory=dict)
    custom_rules: List[SanitizerRuleConfig] = field(default_factory=list)
    strategies: Dict[str, SanitizeStrategy] = field(default_factory=dict)
    params: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    mapping_db_path: Optional[str] = None
    hmac_key: Optional[str] = None
    mapping_in_memory: bool = False

    def __post_init__(self):
        for key, value in list(self.strategies.items()):
            if isinstance(value, str):
                self.strategies[key] = SanitizeStrategy(value.lower())


@dataclass
class OutputConfig:
    file: Optional[str] = None
    stdout: bool = False
    target: str = "file"
    split_by_day: bool = False
    split_by_time: Optional[str] = None
    filename_template: str = "output_{date}.jsonl"
    overwrite: bool = False
    encoding: str = "utf-8"
    pretty: bool = False


@dataclass
class AuditLogConfig:
    enabled: bool = False
    file: Optional[str] = None


@dataclass
class FrequencyAlgorithmConfig:
    window_size_seconds: int = 300
    alpha: float = 0.3
    threshold_multiplier: Any = 3.0
    weight: float = 1.0
    initial_threshold_multiplier: float = 3.0

    def __post_init__(self):
        if isinstance(self.threshold_multiplier, str) and self.threshold_multiplier.lower() == 'auto':
            self.threshold_multiplier = 'auto'
        else:
            self.threshold_multiplier = float(self.threshold_multiplier)
            self.initial_threshold_multiplier = self.threshold_multiplier


@dataclass
class ErrorRateAlgorithmConfig:
    window_size_seconds: int = 300
    k_windows: int = 20
    z_score_threshold: Any = 2.5
    weight: float = 1.0
    initial_z_score_threshold: float = 2.5

    def __post_init__(self):
        if isinstance(self.z_score_threshold, str) and self.z_score_threshold.lower() == 'auto':
            self.z_score_threshold = 'auto'
        else:
            self.z_score_threshold = float(self.z_score_threshold)
            self.initial_z_score_threshold = self.z_score_threshold


@dataclass
class PatternAlgorithmConfig:
    window_size_seconds: int = 300
    min_samples: int = 100
    disappear_windows: int = 3
    weight: float = 1.0


@dataclass
class AnomalyDetectionAlgorithmsConfig:
    frequency: FrequencyAlgorithmConfig = field(default_factory=FrequencyAlgorithmConfig)
    error_rate: ErrorRateAlgorithmConfig = field(default_factory=ErrorRateAlgorithmConfig)
    pattern: PatternAlgorithmConfig = field(default_factory=PatternAlgorithmConfig)


@dataclass
class WebhookConfig:
    url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 5
    max_retries: int = 2
    retry_interval_seconds: int = 1
    dead_letter_file: Optional[str] = None


@dataclass
class AnomalyDetectionConfig:
    enabled: bool = False
    algorithms: AnomalyDetectionAlgorithmsConfig = field(default_factory=AnomalyDetectionAlgorithmsConfig)
    alert_file: Optional[str] = None
    webhook: WebhookConfig = field(default_factory=WebhookConfig)
    min_samples: int = 100
    state_file: Optional[str] = None
    suppression_window_seconds: int = 600
    correlation_window_seconds: int = 30
    suppression_rules: List[SuppressionRule] = field(default_factory=list)
    feedback_file: Optional[str] = None
    max_resolved_alerts: int = 100


@dataclass
class StreamTailConfig:
    poll_interval: float = 0.5
    max_line_length: int = 65536


@dataclass
class StreamConfig:
    enabled: bool = False
    high_watermark: int = 10000
    low_watermark: int = 5000
    drain_timeout: int = 30
    checkpoint_interval: int = 60
    heartbeat_interval: int = 30
    tail: StreamTailConfig = field(default_factory=StreamTailConfig)

    def __post_init__(self):
        if self.low_watermark >= self.high_watermark:
            raise ValueError(
                f"low_watermark ({self.low_watermark}) must be less than "
                f"high_watermark ({self.high_watermark})"
            )


@dataclass
class PipelineConfig:
    name: str = "default"
    inputs: InputConfig = field(default_factory=InputConfig)
    parser: ParserConfig = field(default_factory=ParserConfig)
    filters: Optional[FilterConfig] = None
    sanitizers: SanitizersConfig = field(default_factory=SanitizersConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    parallelism: int = os.cpu_count() or 1
    dry_run: bool = False
    report_file: Optional[str] = None
    report_json: Optional[str] = None
    state_file: Optional[str] = None
    incremental: bool = False
    audit_log: AuditLogConfig = field(default_factory=AuditLogConfig)
    anomaly_detection: AnomalyDetectionConfig = field(default_factory=AnomalyDetectionConfig)
    stream: StreamConfig = field(default_factory=StreamConfig)
    config_path: Optional[str] = None


class ConfigLoader:
    @staticmethod
    def load(config_path: str) -> PipelineConfig:
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        pipeline = ConfigLoader._parse_config(config_data)
        pipeline.config_path = os.path.abspath(config_path)
        return pipeline
    
    @staticmethod
    def load_sanitizers_only(config_path: str) -> SanitizersConfig:
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        sanitizers_data = config_data.get('sanitizers', {})
        if not sanitizers_data:
            raise ValueError("No sanitizers configuration found")
        
        return ConfigLoader._parse_sanitizers_config(sanitizers_data)
    
    @staticmethod
    def _parse_sanitizers_config(sanitizers_data: Dict[str, Any]) -> SanitizersConfig:
        builtin_rules = {}
        strategies: Dict[str, SanitizeStrategy] = {}
        params: Dict[str, Dict[str, Any]] = {}
        
        if 'builtin_rules' in sanitizers_data:
            for rule in sanitizers_data['builtin_rules']:
                if isinstance(rule, dict):
                    name = rule.get('name', '')
                    enabled = rule.get('enabled', True)
                    builtin_rules[name] = enabled
                    if 'strategy' in rule:
                        strategies[name] = SanitizeStrategy(rule['strategy'].lower())
                    if 'params' in rule:
                        params[name] = rule['params']
                elif isinstance(rule, str):
                    builtin_rules[rule] = True
        
        custom_rules = []
        if 'custom_rules' in sanitizers_data:
            for rule_data in sanitizers_data['custom_rules']:
                rule = SanitizerRuleConfig(
                    name=rule_data.get('name', f"custom_{len(custom_rules)}"),
                    enabled=rule_data.get('enabled', True),
                    strategy=rule_data.get('strategy'),
                    params=rule_data.get('params', {}),
                    pattern=rule_data.get('pattern'),
                    type=rule_data.get('type', 'custom'),
                )
                ConfigLoader._validate_custom_rule(rule)
                custom_rules.append(rule)
        
        return SanitizersConfig(
            builtin_rules=builtin_rules,
            custom_rules=custom_rules,
            strategies=strategies,
            params=params,
            mapping_db_path=sanitizers_data.get('mapping_db_path'),
            hmac_key=sanitizers_data.get('hmac_key'),
            mapping_in_memory=sanitizers_data.get('mapping_in_memory', False),
        )

    @staticmethod
    def load_from_string(config_str: str) -> PipelineConfig:
        config_data = yaml.safe_load(config_str)
        return ConfigLoader._parse_config(config_data)

    @staticmethod
    def _parse_config(config_data: Dict[str, Any]) -> PipelineConfig:
        if not isinstance(config_data, dict):
            raise ValueError("Invalid config format: expected a dictionary")
        
        audit_log_data = config_data.get('audit_log', {})
        audit_log_config = AuditLogConfig(
            enabled=audit_log_data.get('enabled', False),
            file=audit_log_data.get('file'),
        )
        
        pipeline = PipelineConfig(
            name=config_data.get('name', 'default'),
            parallelism=config_data.get('parallelism', os.cpu_count() or 1),
            dry_run=config_data.get('dry_run', False),
            report_file=config_data.get('report_file'),
            report_json=config_data.get('report_json'),
            state_file=config_data.get('state_file'),
            incremental=config_data.get('incremental', False),
            audit_log=audit_log_config,
        )
        
        inputs_data = config_data.get('inputs', {})
        if isinstance(inputs_data, list):
            pipeline.inputs = InputConfig(paths=inputs_data)
        else:
            pipeline.inputs = InputConfig(
                paths=inputs_data.get('paths', []),
                recursive=inputs_data.get('recursive', True),
                encoding=inputs_data.get('encoding', 'utf-8'),
            )
        
        if not pipeline.inputs.paths:
            raise ValueError("No input paths specified in config")
        
        parser_data = config_data.get('parser', {})
        if parser_data:
            pipeline.parser = ParserConfig(
                format=parser_data.get('format', 'auto'),
                custom_pattern=parser_data.get('custom_pattern'),
                custom_field_names=parser_data.get('custom_field_names', {}),
                buffer_size=parser_data.get('buffer_size', 8192),
            )
        
        filters_data = config_data.get('filters')
        if filters_data:
            pipeline.filters = FilterConfig(
                levels=filters_data.get('levels'),
                start_time=filters_data.get('start_time'),
                end_time=filters_data.get('end_time'),
                include_keywords=filters_data.get('include_keywords'),
                exclude_keywords=filters_data.get('exclude_keywords'),
            )
        
        sanitizers_data = config_data.get('sanitizers', {})
        if sanitizers_data:
            builtin_rules = {}
            if 'builtin_rules' in sanitizers_data:
                for rule in sanitizers_data['builtin_rules']:
                    if isinstance(rule, dict):
                        name = rule.get('name', '')
                        enabled = rule.get('enabled', True)
                        builtin_rules[name] = enabled
                        if 'strategy' in rule:
                            pipeline.sanitizers.strategies[name] = SanitizeStrategy(rule['strategy'].lower())
                        if 'params' in rule:
                            pipeline.sanitizers.params[name] = rule['params']
                    elif isinstance(rule, str):
                        builtin_rules[rule] = True
            
            custom_rules = []
            if 'custom_rules' in sanitizers_data:
                for rule_data in sanitizers_data['custom_rules']:
                    rule = SanitizerRuleConfig(
                        name=rule_data.get('name', f"custom_{len(custom_rules)}"),
                        enabled=rule_data.get('enabled', True),
                        strategy=rule_data.get('strategy'),
                        params=rule_data.get('params', {}),
                        pattern=rule_data.get('pattern'),
                        type=rule_data.get('type', 'custom'),
                    )
                    ConfigLoader._validate_custom_rule(rule)
                    custom_rules.append(rule)
            
            pipeline.sanitizers = SanitizersConfig(
                builtin_rules=builtin_rules,
                custom_rules=custom_rules,
                strategies=pipeline.sanitizers.strategies,
                params=pipeline.sanitizers.params,
                mapping_db_path=sanitizers_data.get('mapping_db_path'),
                hmac_key=sanitizers_data.get('hmac_key'),
                mapping_in_memory=sanitizers_data.get('mapping_in_memory', False),
            )
        
        output_data = config_data.get('output', {})
        if output_data:
            target = output_data.get('target', 'file')
            stdout = output_data.get('stdout', False)
            if target == 'stdout':
                stdout = True
            
            pipeline.output = OutputConfig(
                file=output_data.get('file'),
                stdout=stdout,
                target=target,
                split_by_day=output_data.get('split_by_day', False),
                split_by_time=output_data.get('split_by_time'),
                filename_template=output_data.get('filename_template', 'output_{date}.jsonl'),
                overwrite=output_data.get('overwrite', False),
                encoding=output_data.get('encoding', 'utf-8'),
                pretty=output_data.get('pretty', False),
            )
        
        if not pipeline.output.file and not pipeline.output.stdout:
            raise ValueError("No output destination specified (file or stdout)")
        
        anomaly_data = config_data.get('anomaly_detection', {})
        if anomaly_data:
            ad_config = AnomalyDetectionConfig(
                enabled=anomaly_data.get('enabled', False),
                alert_file=anomaly_data.get('alert_file'),
                min_samples=anomaly_data.get('min_samples', 100),
                state_file=anomaly_data.get('state_file'),
                suppression_window_seconds=anomaly_data.get('suppression_window_seconds', 600),
                correlation_window_seconds=anomaly_data.get('correlation_window_seconds', 30),
                feedback_file=anomaly_data.get('feedback_file'),
                max_resolved_alerts=anomaly_data.get('max_resolved_alerts', 100),
            )

            suppression_rules_data = anomaly_data.get('suppression_rules', [])
            if suppression_rules_data:
                ad_config.suppression_rules = ConfigLoader._parse_suppression_rules(suppression_rules_data)

            algos_data = anomaly_data.get('algorithms', {})
            if algos_data:
                freq_data = algos_data.get('frequency', {})
                ad_config.algorithms.frequency = FrequencyAlgorithmConfig(
                    window_size_seconds=freq_data.get('window_size_seconds', 300),
                    alpha=freq_data.get('alpha', 0.3),
                    threshold_multiplier=freq_data.get('threshold_multiplier', 3.0),
                    weight=float(freq_data.get('weight', 1.0)),
                )

                err_data = algos_data.get('error_rate', {})
                ad_config.algorithms.error_rate = ErrorRateAlgorithmConfig(
                    window_size_seconds=err_data.get('window_size_seconds', 300),
                    k_windows=err_data.get('k_windows', 20),
                    z_score_threshold=err_data.get('z_score_threshold', 2.5),
                    weight=float(err_data.get('weight', 1.0)),
                )

                pat_data = algos_data.get('pattern', {})
                ad_config.algorithms.pattern = PatternAlgorithmConfig(
                    window_size_seconds=pat_data.get('window_size_seconds', 300),
                    min_samples=pat_data.get('min_samples', 100),
                    disappear_windows=pat_data.get('disappear_windows', 3),
                    weight=float(pat_data.get('weight', 1.0)),
                )

            webhook_data = anomaly_data.get('webhook', {})
            if webhook_data:
                ad_config.webhook = WebhookConfig(
                    url=webhook_data.get('url'),
                    headers=webhook_data.get('headers', {}),
                    timeout_seconds=webhook_data.get('timeout_seconds', 5),
                    max_retries=webhook_data.get('max_retries', 2),
                    retry_interval_seconds=webhook_data.get('retry_interval_seconds', 1),
                    dead_letter_file=webhook_data.get('dead_letter_file'),
                )

            pipeline.anomaly_detection = ad_config

        stream_data = config_data.get('stream', {})
        if stream_data:
            tail_data = stream_data.get('tail', {})
            stream_tail_config = StreamTailConfig(
                poll_interval=float(tail_data.get('poll_interval', 0.5)),
                max_line_length=int(tail_data.get('max_line_length', 65536)),
            )
            pipeline.stream = StreamConfig(
                enabled=bool(stream_data.get('enabled', False)),
                high_watermark=int(stream_data.get('high_watermark', 10000)),
                low_watermark=int(stream_data.get('low_watermark', 5000)),
                drain_timeout=int(stream_data.get('drain_timeout', 30)),
                checkpoint_interval=int(stream_data.get('checkpoint_interval', 60)),
                heartbeat_interval=int(stream_data.get('heartbeat_interval', 30)),
                tail=stream_tail_config,
            )

        return pipeline

    @staticmethod
    def _parse_suppression_rules(rules_data: List[Dict[str, Any]]) -> List[SuppressionRule]:
        rules = []
        for idx, rule_data in enumerate(rules_data):
            match_data = rule_data.get('match', {})
            action_str = rule_data.get('action', 'suppress')

            try:
                action = SuppressionAction(action_str.lower())
            except ValueError:
                raise ValueError(f"Invalid suppression action '{action_str}' at index {idx}")

            alert_types = None
            if 'alert_types' in match_data:
                try:
                    alert_types = [AlertType(t.lower()) for t in match_data['alert_types']]
                except ValueError as e:
                    raise ValueError(f"Invalid alert_type in suppression rule {idx}: {e}")

            severities = None
            if 'severities' in match_data:
                try:
                    severities = [AlertSeverity(s.upper()) for s in match_data['severities']]
                except ValueError as e:
                    raise ValueError(f"Invalid severity in suppression rule {idx}: {e}")

            match = SuppressionRuleMatch(
                source_pattern=match_data.get('source_pattern'),
                alert_types=alert_types,
                severities=severities,
                cron_expression=match_data.get('cron_expression'),
            )

            rule = SuppressionRule(
                name=rule_data.get('name', f"rule_{idx}"),
                match=match,
                action=action,
                enabled=rule_data.get('enabled', True),
                delay_seconds=int(rule_data.get('delay_seconds', 0)),
            )
            rules.append(rule)
        return rules

    @staticmethod
    def _validate_custom_rule(rule: SanitizerRuleConfig) -> None:
        if not rule.pattern:
            raise ValueError(f"Custom rule '{rule.name}' is missing 'pattern'")
        
        try:
            re.compile(rule.pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern for custom rule '{rule.name}': {e}") from e
        
        if rule.strategy and not isinstance(rule.strategy, SanitizeStrategy):
            try:
                rule.strategy = SanitizeStrategy(str(rule.strategy).lower())
            except ValueError:
                raise ValueError(f"Invalid strategy '{rule.strategy}' for custom rule '{rule.name}'")
