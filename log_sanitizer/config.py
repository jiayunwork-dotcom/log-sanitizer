import os
import re
import yaml
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Pattern
from datetime import datetime
from .models import LogFormat, LogLevel, SanitizeStrategy, SensitiveType


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
    split_by_day: bool = False
    overwrite: bool = False
    encoding: str = "utf-8"
    pretty: bool = False


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


class ConfigLoader:
    @staticmethod
    def load(config_path: str) -> PipelineConfig:
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        return ConfigLoader._parse_config(config_data)

    @staticmethod
    def load_from_string(config_str: str) -> PipelineConfig:
        config_data = yaml.safe_load(config_str)
        return ConfigLoader._parse_config(config_data)

    @staticmethod
    def _parse_config(config_data: Dict[str, Any]) -> PipelineConfig:
        if not isinstance(config_data, dict):
            raise ValueError("Invalid config format: expected a dictionary")
        
        pipeline = PipelineConfig(
            name=config_data.get('name', 'default'),
            parallelism=config_data.get('parallelism', os.cpu_count() or 1),
            dry_run=config_data.get('dry_run', False),
            report_file=config_data.get('report_file'),
            report_json=config_data.get('report_json'),
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
            pipeline.output = OutputConfig(
                file=output_data.get('file'),
                stdout=output_data.get('stdout', False),
                split_by_day=output_data.get('split_by_day', False),
                overwrite=output_data.get('overwrite', False),
                encoding=output_data.get('encoding', 'utf-8'),
                pretty=output_data.get('pretty', False),
            )
        
        if not pipeline.output.file and not pipeline.output.stdout:
            raise ValueError("No output destination specified (file or stdout)")
        
        return pipeline

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
