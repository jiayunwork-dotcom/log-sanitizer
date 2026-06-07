from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List, Pattern
from datetime import datetime


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
