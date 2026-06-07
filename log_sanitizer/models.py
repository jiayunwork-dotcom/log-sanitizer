from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List, Pattern, Tuple
from datetime import datetime, timezone
import uuid


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    WARNING = "WARN"
    ERROR = "ERROR"
    TRACE = "TRACE"
    CRITICAL = "ERROR"
    FATAL = "ERROR"
    UNKNOWN = "UNKNOWN"


class LogFormat(str, Enum):
    AUTO = "auto"
    JSON = "json"
    APACHE = "apache"
    NGINX = "nginx"
    SYSLOG = "syslog"
    PLAINTEXT = "plaintext"
    CUSTOM = "custom"
    UNPARSEABLE = "unparseable"


class SanitizeStrategy(str, Enum):
    MASK = "mask"
    HASH = "hash"
    REPLACE = "replace"
    DELETE = "delete"
    GENERALIZE = "generalize"


class SensitiveType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    PHONE = "phone"
    ID_CARD = "id_card"
    BANK_CARD = "bank_card"
    TOKEN = "token"
    COOKIE = "cookie"
    CUSTOM = "custom"


@dataclass
class LogEntry:
    raw: str
    source: str
    format: LogFormat = LogFormat.UNPARSEABLE
    timestamp: Optional[datetime] = None
    level: LogLevel = LogLevel.UNKNOWN
    message: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    is_parseable: bool = True
    parse_error: Optional[str] = None

    def to_standard_dict(self) -> Dict[str, Any]:
        result = {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level": self.level.value.upper() if self.level else "UNKNOWN",
            "source": self.source,
            "message": self.message if self.is_parseable else self.raw,
            "extra": self.extra if self.is_parseable else {},
        }
        if not self.is_parseable:
            result["_unparseable"] = True
            result["_parse_error"] = self.parse_error
        return result


@dataclass
class DetectionMatch:
    type: SensitiveType
    value: str
    start: int
    end: int
    field_name: Optional[str] = None
    rule_name: Optional[str] = None


@dataclass
class SanitizeRule:
    name: str
    type: SensitiveType
    pattern: Pattern
    strategy: SanitizeStrategy
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileStats:
    file_path: str
    total_lines: int = 0
    parsed_lines: int = 0
    unparsed_lines: int = 0
    sanitized_fields: int = 0
    total_fields: int = 0
    detections: Dict[SensitiveType, int] = field(default_factory=dict)
    field_path_counts: Dict[str, int] = field(default_factory=dict)
    bytes_processed: int = 0
    skipped_no_new_data: bool = False
    start_offset: int = 0
    end_offset: int = 0


@dataclass
class AuditLogEntry:
    line_number: int
    field_path: str
    original_value: str
    sanitized_value: str
    rule_name: str
    timestamp: Optional[datetime] = None


@dataclass
class FileState:
    file_path: str
    inode: int
    last_offset: int
    last_processed_time: Optional[datetime] = None
    file_size: int = 0


@dataclass
class StateFile:
    version: str = "1.0"
    files: Dict[str, FileState] = field(default_factory=dict)
    last_updated: Optional[datetime] = None


@dataclass
class AuditReport:
    total_lines: int = 0
    parsed_lines: int = 0
    unparsed_lines: int = 0
    parse_failure_rate: float = 0.0
    total_fields: int = 0
    sanitized_fields: int = 0
    sanitize_coverage: float = 0.0
    detections: Dict[SensitiveType, int] = field(default_factory=dict)
    file_stats: Dict[str, FileStats] = field(default_factory=dict)
    processing_time: float = 0.0
    throughput: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    field_path_counts: Dict[str, int] = field(default_factory=dict)
    skipped_files: List[str] = field(default_factory=list)
    incremental_mode: bool = False


class AlertSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertType(str, Enum):
    FREQUENCY_SPIKE = "frequency_spike"
    ERROR_RATE_SURGE = "error_rate_surge"
    NEW_PATTERN = "new_pattern"
    PATTERN_DISAPPEARED = "pattern_disappeared"
    COMPOSITE_ANOMALY = "composite_anomaly"


class DetectorName(str, Enum):
    FREQUENCY = "frequency_detector"
    ERROR_RATE = "error_rate_detector"
    PATTERN = "pattern_detector"


@dataclass
class AlertEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: AlertSeverity = AlertSeverity.WARNING
    alert_type: AlertType = AlertType.FREQUENCY_SPIKE
    source: str = ""
    detector: DetectorName = DetectorName.FREQUENCY
    trigger_value: float = 0.0
    threshold: float = 0.0
    baseline_value: Optional[float] = None
    line_range: Optional[Tuple[int, int]] = None
    description: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "alert_type": self.alert_type.value,
            "source": self.source,
            "detector": self.detector.value,
            "trigger_value": self.trigger_value,
            "threshold": self.threshold,
            "baseline_value": self.baseline_value,
            "line_range": list(self.line_range) if self.line_range else None,
            "description": self.description,
            "extra": self.extra,
        }


@dataclass
class FrequencyState:
    ewma: Optional[float] = None
    window_start: Optional[datetime] = None
    window_count: int = 0
    last_update: Optional[datetime] = None


@dataclass
class ErrorRateState:
    history: List[float] = field(default_factory=list)
    window_start: Optional[datetime] = None
    window_total: int = 0
    window_errors: int = 0


@dataclass
class PatternState:
    known_templates: Dict[str, int] = field(default_factory=dict)
    template_last_seen: Dict[str, datetime] = field(default_factory=dict)
    window_start: Optional[datetime] = None
    windows_without: Dict[str, int] = field(default_factory=dict)
    total_count: int = 0


@dataclass
class AnomalyDetectionState:
    version: str = "1.0"
    frequency_states: Dict[str, FrequencyState] = field(default_factory=dict)
    error_rate_states: Dict[str, ErrorRateState] = field(default_factory=dict)
    pattern_states: Dict[str, PatternState] = field(default_factory=dict)
    last_updated: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "frequency_states": {
                source: {
                    "ewma": fs.ewma,
                    "window_start": fs.window_start.isoformat() if fs.window_start else None,
                    "window_count": fs.window_count,
                    "last_update": fs.last_update.isoformat() if fs.last_update else None,
                }
                for source, fs in self.frequency_states.items()
            },
            "error_rate_states": {
                source: {
                    "history": ers.history,
                    "window_start": ers.window_start.isoformat() if ers.window_start else None,
                    "window_total": ers.window_total,
                    "window_errors": ers.window_errors,
                }
                for source, ers in self.error_rate_states.items()
            },
            "pattern_states": {
                source: {
                    "known_templates": ps.known_templates,
                    "template_last_seen": {
                        t: dt.isoformat() for t, dt in ps.template_last_seen.items()
                    },
                    "windows_without": ps.windows_without,
                    "total_count": ps.total_count,
                }
                for source, ps in self.pattern_states.items()
            },
        }


@dataclass
class AlertStats:
    total_alerts: int = 0
    by_severity: Dict[AlertSeverity, int] = field(default_factory=dict)
    by_type: Dict[AlertType, int] = field(default_factory=dict)
    by_source: Dict[str, int] = field(default_factory=dict)
    by_detector: Dict[DetectorName, int] = field(default_factory=dict)
