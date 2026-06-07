from typing import Dict, Any, List, Optional, Tuple
from .models import (
    LogEntry,
    DetectionMatch,
    SanitizeStrategy,
    SanitizeRule,
    SensitiveType,
)
from .mapping_manager import MappingManager
from .detector import SensitiveDataDetector
from .utils import (
    mask_value,
    generalize_ip,
    generalize_email,
    sha256_hash,
)


class SanitizationEngine:
    def __init__(
        self,
        detector: SensitiveDataDetector,
        mapping_manager: Optional[MappingManager] = None,
    ):
        self.detector = detector
        self.mapping_manager = mapping_manager or MappingManager(in_memory=True)
        self._rule_cache: Dict[str, SanitizeRule] = {rule.name: rule for rule in self.detector.rules}
    
    @staticmethod
    def _parse_field_path(path: str) -> List[str]:
        parts: List[str] = []
        current = ""
        i = 0
        while i < len(path):
            if path[i] == '.':
                if current:
                    parts.append(current)
                    current = ""
                i += 1
            elif path[i] == '[':
                if current:
                    parts.append(current)
                    current = ""
                end = path.find(']', i)
                if end == -1:
                    current += path[i]
                    i += 1
                else:
                    parts.append(path[i:end+1])
                    i = end + 1
            else:
                current += path[i]
                i += 1
        if current:
            parts.append(current)
        return parts

    def sanitize_entry(self, entry: LogEntry) -> Tuple[LogEntry, Dict[SensitiveType, int], int, int]:
        if not entry.is_parseable:
            return entry, {}, 0, 0
        
        detections: Dict[SensitiveType, int] = {}
        sanitized_fields_count = 0
        total_fields_count = 0
        
        fields_to_process = [
            ("message", entry.message),
        ]
        
        def collect_fields(prefix: str, data: Any) -> None:
            if isinstance(data, str):
                fields_to_process.append((prefix, data))
            elif isinstance(data, dict):
                for k, v in data.items():
                    collect_fields(f"{prefix}.{k}", v)
            elif isinstance(data, list):
                for i, v in enumerate(data):
                    collect_fields(f"{prefix}[{i}]", v)
        
        for key, value in entry.extra.items():
            collect_fields(f"extra.{key}", value)
        
        total_fields_count = len(fields_to_process)
        
        field_detections: Dict[str, List[DetectionMatch]] = {}
        for field_name, value in fields_to_process:
            matches = self.detector.detect_in_value(value, field_name)
            if matches:
                field_detections[field_name] = matches
                for match in matches:
                    detections[match.type] = detections.get(match.type, 0) + 1
        
        if not field_detections:
            return entry, detections, sanitized_fields_count, total_fields_count
        
        if "message" in field_detections:
            entry.message = self._sanitize_value(
                entry.message,
                field_detections["message"],
            )
            sanitized_fields_count += 1
        
        def update_nested_field(data: Any, path_parts: List[str], value: str) -> Any:
            if not path_parts:
                return value
            part = path_parts[0]
            if '[' in part and part.endswith(']'):
                key, idx_str = part[:-1].split('[', 1)
                idx = int(idx_str)
                if isinstance(data, dict) and key in data and isinstance(data[key], list) and idx < len(data[key]):
                    data[key][idx] = update_nested_field(data[key][idx], path_parts[1:], value)
            elif isinstance(data, dict) and part in data:
                data[part] = update_nested_field(data[part], path_parts[1:], value)
            return data
        
        def get_nested_field(data: Any, path_parts: List[str]) -> Optional[str]:
            if not path_parts:
                return data if isinstance(data, str) else None
            part = path_parts[0]
            if '[' in part and part.endswith(']'):
                key, idx_str = part[:-1].split('[', 1)
                idx = int(idx_str)
                if isinstance(data, dict) and key in data and isinstance(data[key], list) and idx < len(data[key]):
                    return get_nested_field(data[key][idx], path_parts[1:])
            elif isinstance(data, dict) and part in data:
                return get_nested_field(data[part], path_parts[1:])
            return None
        
        for field_path, matches in field_detections.items():
            if field_path == "message":
                continue
            if field_path.startswith("extra."):
                path_str = field_path[6:]
                path_parts = self._parse_field_path(path_str)
                current_value = get_nested_field(entry.extra, path_parts)
                if current_value is not None and isinstance(current_value, str):
                    rule_name = matches[0].rule_name if matches else None
                    rule = self._rule_cache.get(rule_name) if rule_name else None
                    
                    if rule and rule.strategy == SanitizeStrategy.DELETE:
                        new_value = ""
                    else:
                        new_value = self._sanitize_value(current_value, matches)
                    
                    entry.extra = update_nested_field(entry.extra, path_parts, new_value)
                    sanitized_fields_count += 1
        
        return entry, detections, sanitized_fields_count, total_fields_count

    def _sanitize_value(
        self,
        value: str,
        matches: List[DetectionMatch],
    ) -> str:
        if not matches:
            return value
        
        sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
        
        for match in sorted_matches:
            rule = self._rule_cache.get(match.rule_name) if match.rule_name else None
            if not rule:
                continue
            
            sanitized = self._apply_strategy(match.value, rule)
            
            value = value[:match.start] + sanitized + value[match.end:]
        
        return value

    def _apply_strategy(self, original_value: str, rule: SanitizeRule) -> str:
        strategy = rule.strategy
        params = rule.params

        def generate_value() -> str:
            if strategy == SanitizeStrategy.MASK:
                keep_start = params.get("keep_start", 3)
                keep_end = params.get("keep_end", 4)
                mask_char = params.get("mask_char", "*")
                return mask_value(original_value, keep_start, keep_end, mask_char)
            
            elif strategy == SanitizeStrategy.HASH:
                length = params.get("hash_length", 16)
                return sha256_hash(original_value, length)
            
            elif strategy == SanitizeStrategy.REPLACE:
                replacement = params.get("replacement", f"[REDACTED_{rule.type.value.upper()}]")
                return replacement
            
            elif strategy == SanitizeStrategy.DELETE:
                return ""
            
            elif strategy == SanitizeStrategy.GENERALIZE:
                if rule.type in (SensitiveType.IPV4, SensitiveType.IPV6):
                    return generalize_ip(original_value)
                elif rule.type == SensitiveType.EMAIL:
                    return generalize_email(original_value)
                else:
                    keep_start = params.get("keep_start", 1)
                    keep_end = params.get("keep_end", 0)
                    return mask_value(original_value, keep_start, keep_end, "*")
            
            return original_value

        if strategy == SanitizeStrategy.HASH:
            return generate_value()
        
        if strategy == SanitizeStrategy.REPLACE:
            return params.get("replacement", f"[REDACTED_{rule.type.value.upper()}]")
        
        if strategy == SanitizeStrategy.DELETE:
            return ""
        
        return self.mapping_manager.get(original_value, generate_value)

    def sanitize_dict(self, data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[SensitiveType, int], int, int]:
        detections: Dict[SensitiveType, int] = {}
        sanitized_fields = 0
        total_fields = 0
        
        all_detections = self.detector.detect_in_dict(data)
        
        for field_path, matches in all_detections.items():
            for match in matches:
                detections[match.type] = detections.get(match.type, 0) + 1
        
        for field_path, matches in all_detections.items():
            parts = field_path.split('.')
            current = data
            for part in parts[:-1]:
                if '[' in part and part.endswith(']'):
                    key, idx = part[:-1].split('[')
                    idx = int(idx)
                    if key in current and isinstance(current[key], list) and idx < len(current[key]):
                        current = current[key][idx]
                    else:
                        break
                else:
                    if part in current and isinstance(current[part], dict):
                        current = current[part]
                    else:
                        break
            else:
                last_part = parts[-1]
                if '[' in last_part and last_part.endswith(']'):
                    key, idx = last_part[:-1].split('[')
                    idx = int(idx)
                    if key in current and isinstance(current[key], list) and idx < len(current[key]):
                        if isinstance(current[key][idx], str):
                            rule_name = matches[0].rule_name if matches else None
                            rule = self._rule_cache.get(rule_name) if rule_name else None
                            if rule and rule.strategy == SanitizeStrategy.DELETE:
                                current[key][idx] = ""
                            else:
                                current[key][idx] = self._sanitize_value(current[key][idx], matches)
                            sanitized_fields += 1
                else:
                    if last_part in current and isinstance(current[last_part], str):
                        rule_name = matches[0].rule_name if matches else None
                        rule = self._rule_cache.get(rule_name) if rule_name else None
                        if rule and rule.strategy == SanitizeStrategy.DELETE:
                            current[last_part] = ""
                        else:
                            current[last_part] = self._sanitize_value(current[last_part], matches)
                        sanitized_fields += 1
        
        total_fields = len(all_detections)
        
        return data, detections, sanitized_fields, total_fields
