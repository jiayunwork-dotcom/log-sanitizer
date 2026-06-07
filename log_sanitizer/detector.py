import re
from typing import List, Dict, Any, Optional, Tuple
from .models import DetectionMatch, SensitiveType, SanitizeRule, SanitizeStrategy
from .utils import (
    IPV4_PATTERN,
    IPV6_PATTERN,
    EMAIL_PATTERN,
    PHONE_PATTERN,
    ID_CARD_PATTERN,
    BANK_CARD_PATTERN,
    TOKEN_PATTERN,
    SESSION_PATTERN,
    COOKIE_PATTERN,
    id_card_check,
    luhn_check,
    is_id_field,
    find_overlaps
)


DEFAULT_RULES_CONFIG = [
    {
        "name": "ipv4",
        "type": SensitiveType.IPV4,
        "pattern": IPV4_PATTERN,
        "strategy": SanitizeStrategy.GENERALIZE,
        "enabled": True,
    },
    {
        "name": "ipv6",
        "type": SensitiveType.IPV6,
        "pattern": IPV6_PATTERN,
        "strategy": SanitizeStrategy.GENERALIZE,
        "enabled": True,
    },
    {
        "name": "email",
        "type": SensitiveType.EMAIL,
        "pattern": EMAIL_PATTERN,
        "strategy": SanitizeStrategy.GENERALIZE,
        "enabled": True,
    },
    {
        "name": "phone",
        "type": SensitiveType.PHONE,
        "pattern": PHONE_PATTERN,
        "strategy": SanitizeStrategy.MASK,
        "enabled": True,
        "params": {"keep_start": 3, "keep_end": 4},
    },
    {
        "name": "id_card",
        "type": SensitiveType.ID_CARD,
        "pattern": ID_CARD_PATTERN,
        "strategy": SanitizeStrategy.MASK,
        "enabled": True,
        "params": {"keep_start": 4, "keep_end": 4},
    },
    {
        "name": "bank_card",
        "type": SensitiveType.BANK_CARD,
        "pattern": BANK_CARD_PATTERN,
        "strategy": SanitizeStrategy.MASK,
        "enabled": True,
        "params": {"keep_start": 6, "keep_end": 4},
    },
    {
        "name": "token",
        "type": SensitiveType.TOKEN,
        "pattern": TOKEN_PATTERN,
        "strategy": SanitizeStrategy.REPLACE,
        "enabled": True,
        "params": {"replacement": "[REDACTED_TOKEN]"},
    },
    {
        "name": "session",
        "type": SensitiveType.TOKEN,
        "pattern": SESSION_PATTERN,
        "strategy": SanitizeStrategy.REPLACE,
        "enabled": True,
        "params": {"replacement": "[REDACTED_SESSION]"},
    },
    {
        "name": "cookie",
        "type": SensitiveType.COOKIE,
        "pattern": COOKIE_PATTERN,
        "strategy": SanitizeStrategy.REPLACE,
        "enabled": True,
        "params": {"replacement": "[REDACTED_COOKIE]"},
    },
]


class SensitiveDataDetector:
    def __init__(
        self,
        builtin_rules: Optional[Dict[str, bool]] = None,
        custom_rules: Optional[List[Dict[str, Any]]] = None,
        override_strategies: Optional[Dict[str, SanitizeStrategy]] = None,
        override_params: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.rules: List[SanitizeRule] = []
        self._builtin_rules_config = builtin_rules
        self._custom_rules_config = custom_rules
        self._override_strategies = override_strategies
        self._override_params = override_params
        self._compile_rules(builtin_rules, custom_rules, override_strategies, override_params)

    def reload_rules(
        self,
        builtin_rules: Optional[Dict[str, bool]] = None,
        custom_rules: Optional[List[Dict[str, Any]]] = None,
        override_strategies: Optional[Dict[str, SanitizeStrategy]] = None,
        override_params: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        if builtin_rules is not None:
            self._builtin_rules_config = builtin_rules
        if custom_rules is not None:
            self._custom_rules_config = custom_rules
        if override_strategies is not None:
            self._override_strategies = override_strategies
        if override_params is not None:
            self._override_params = override_params
        
        self.rules.clear()
        self._compile_rules(
            self._builtin_rules_config,
            self._custom_rules_config,
            self._override_strategies,
            self._override_params,
        )

    def _compile_rules(
        self,
        builtin_rules: Optional[Dict[str, bool]],
        custom_rules: Optional[List[Dict[str, Any]]],
        override_strategies: Optional[Dict[str, SanitizeStrategy]],
        override_params: Optional[Dict[str, Dict[str, Any]]],
    ) -> None:
        for rule_config in DEFAULT_RULES_CONFIG:
            rule_name = rule_config["name"]
            enabled = rule_config["enabled"]
            if builtin_rules and rule_name in builtin_rules:
                enabled = builtin_rules[rule_name]
            
            if not enabled:
                continue
            
            strategy = rule_config["strategy"]
            if override_strategies and rule_name in override_strategies:
                strategy = override_strategies[rule_name]
            
            params = rule_config.get("params", {}).copy()
            if override_params and rule_name in override_params:
                params.update(override_params[rule_name])
            
            try:
                compiled_pattern = re.compile(rule_config["pattern"], re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"Invalid pattern for builtin rule '{rule_name}': {e}")
            
            self.rules.append(SanitizeRule(
                name=rule_name,
                type=rule_config["type"],
                pattern=compiled_pattern,
                strategy=strategy,
                enabled=True,
                params=params,
            ))
        
        if custom_rules:
            for idx, rule_config in enumerate(custom_rules):
                rule_name = rule_config.get("name", f"custom_{idx}")
                pattern_str = rule_config.get("pattern", "")
                type_str = rule_config.get("type", "custom")
                strategy_str = rule_config.get("strategy", "mask")
                params = rule_config.get("params", {})
                
                if not pattern_str:
                    raise ValueError(f"Custom rule '{rule_name}' is missing 'pattern'")
                
                try:
                    compiled_pattern = re.compile(pattern_str, re.IGNORECASE)
                except re.error as e:
                    raise ValueError(f"Invalid pattern for custom rule '{rule_name}': {e}") from e
                
                try:
                    strategy = SanitizeStrategy(strategy_str.lower())
                except ValueError:
                    raise ValueError(f"Invalid strategy '{strategy_str}' for custom rule '{rule_name}'")
                
                try:
                    sensitive_type = SensitiveType(type_str.lower())
                except ValueError:
                    sensitive_type = SensitiveType.CUSTOM
                
                self.rules.append(SanitizeRule(
                    name=rule_name,
                    type=sensitive_type,
                    pattern=compiled_pattern,
                    strategy=strategy,
                    enabled=True,
                    params=params,
                ))

    def detect_in_value(
        self,
        value: str,
        field_name: Optional[str] = None,
    ) -> List[DetectionMatch]:
        if not value or not isinstance(value, str):
            return []
        
        all_matches: List[Tuple[int, int, DetectionMatch]] = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            if rule.type == SensitiveType.PHONE and is_id_field(field_name):
                continue
            
            for match in rule.pattern.finditer(value):
                matched_value = match.group(1) if match.lastindex else match.group(0)
                matched_value = matched_value.strip()
                
                if not matched_value:
                    continue
                
                if rule.type == SensitiveType.ID_CARD and not id_card_check(matched_value):
                    continue
                
                if rule.type == SensitiveType.BANK_CARD and not luhn_check(matched_value):
                    continue
                
                start = match.start()
                end = match.end()
                if match.lastindex:
                    full_match = match.group(0)
                    value_start = full_match.find(matched_value)
                    start = match.start() + value_start
                    end = start + len(matched_value)
                
                all_matches.append((start, end, DetectionMatch(
                    type=rule.type,
                    value=matched_value,
                    start=start,
                    end=end,
                    field_name=field_name,
                    rule_name=rule.name,
                )))
        
        if not all_matches:
            return []
        
        all_matches.sort(key=lambda x: (x[0], -x[1]))
        result: List[DetectionMatch] = []
        last_end = -1
        
        for start, end, match in all_matches:
            if start >= last_end:
                result.append(match)
                last_end = end
        
        return result

    def detect_in_dict(self, data: Dict[str, Any]) -> Dict[str, List[DetectionMatch]]:
        results: Dict[str, List[DetectionMatch]] = {}
        
        for field_name, value in data.items():
            if isinstance(value, str):
                matches = self.detect_in_value(value, field_name)
                if matches:
                    results[field_name] = matches
            elif isinstance(value, dict):
                nested_results = self.detect_in_dict(value)
                for nested_field, nested_matches in nested_results.items():
                    results[f"{field_name}.{nested_field}"] = nested_matches
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        matches = self.detect_in_value(item, f"{field_name}[{i}]")
                        if matches:
                            results[f"{field_name}[{i}]"] = matches
                    elif isinstance(item, dict):
                        nested_results = self.detect_in_dict(item)
                        for nested_field, nested_matches in nested_results.items():
                            results[f"{field_name}[{i}].{nested_field}"] = nested_matches
        
        return results

    def get_rule(self, rule_name: str) -> Optional[SanitizeRule]:
        for rule in self.rules:
            if rule.name == rule_name:
                return rule
        return None
