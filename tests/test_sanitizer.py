import pytest
from log_sanitizer.detector import SensitiveDataDetector
from log_sanitizer.sanitizer import SanitizationEngine
from log_sanitizer.mapping_manager import MappingManager
from log_sanitizer.models import LogEntry, LogFormat, LogLevel, SanitizeStrategy, SensitiveType
from log_sanitizer.parser import LogParser


def test_mask_sanitization():
    detector = SensitiveDataDetector(
        builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": True, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False},
        override_strategies={"phone": SanitizeStrategy.MASK},
        override_params={"phone": {"keep_start": 3, "keep_end": 4}}
    )
    mapping = MappingManager(in_memory=True)
    sanitizer = SanitizationEngine(detector, mapping)
    
    parser = LogParser(format=LogFormat.PLAINTEXT, source="test.log")
    entry = parser.parse_line("2024-01-15 08:30:45 [INFO] user 13812345678 logged in")
    
    sanitized, detections, s_count, t_count = sanitizer.sanitize_entry(entry)
    
    assert "138****5678" in sanitized.message
    assert SensitiveType.PHONE in detections
    assert detections[SensitiveType.PHONE] == 1


def test_hash_sanitization():
    detector = SensitiveDataDetector(
        builtin_rules={"ipv4": False, "ipv6": False, "email": True, "phone": False, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False},
        override_strategies={"email": SanitizeStrategy.HASH}
    )
    mapping = MappingManager(in_memory=True)
    sanitizer = SanitizationEngine(detector, mapping)
    
    parser = LogParser(format=LogFormat.PLAINTEXT, source="test.log")
    entry = parser.parse_line("2024-01-15 08:30:45 [INFO] email test@example.com")
    
    sanitized, detections, _, _ = sanitizer.sanitize_entry(entry)
    
    assert "test@example.com" not in sanitized.message
    assert "***@example.com" not in sanitized.message


def test_replace_sanitization():
    detector = SensitiveDataDetector(
        builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": False, "id_card": False, "bank_card": False, "token": True, "session": False, "cookie": False}
    )
    mapping = MappingManager(in_memory=True)
    sanitizer = SanitizationEngine(detector, mapping)
    
    parser = LogParser(format=LogFormat.PLAINTEXT, source="test.log")
    entry = parser.parse_line("2024-01-15 08:30:45 [INFO] request with token=abc123")
    
    sanitized, detections, _, _ = sanitizer.sanitize_entry(entry)
    
    assert "[REDACTED_TOKEN]" in sanitized.message or "[REDACTED_TOKEN]" in sanitized.message
    assert "abc123" not in sanitized.message


def test_generalize_sanitization():
    detector = SensitiveDataDetector(
        builtin_rules={"ipv4": True, "ipv6": False, "email": True, "phone": False, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False}
    )
    mapping = MappingManager(in_memory=True)
    sanitizer = SanitizationEngine(detector, mapping)
    
    parser = LogParser(format=LogFormat.PLAINTEXT, source="test.log")
    entry = parser.parse_line("2024-01-15 08:30:45 [INFO] connection from 192.168.1.100, email user@example.com")
    
    sanitized, detections, _, _ = sanitizer.sanitize_entry(entry)
    
    assert "192.168.*.*" in sanitized.message
    assert "***@example.com" in sanitized.message
    assert "192.168.1.100" not in sanitized.message
    assert "user@example.com" not in sanitized.message


def test_delete_sanitization():
    detector = SensitiveDataDetector(
        builtin_rules={"ipv4": False, "ipv6": False, "email": True, "phone": False, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False},
        override_strategies={"email": SanitizeStrategy.DELETE}
    )
    mapping = MappingManager(in_memory=True)
    sanitizer = SanitizationEngine(detector, mapping)
    
    parser = LogParser(format=LogFormat.PLAINTEXT, source="test.log")
    entry = parser.parse_line("2024-01-15 08:30:45 [INFO] send email to test@example.com")
    
    sanitized, detections, _, _ = sanitizer.sanitize_entry(entry)
    
    assert "test@example.com" not in sanitized.message


def test_consistency_within_batch():
    detector = SensitiveDataDetector(
        builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": True, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False}
    )
    mapping = MappingManager(in_memory=True)
    sanitizer = SanitizationEngine(detector, mapping)
    
    parser = LogParser(format=LogFormat.PLAINTEXT, source="test.log")
    
    entry1 = parser.parse_line("2024-01-15 08:30:45 [INFO] user 13812345678 called")
    entry2 = parser.parse_line("2024-01-15 09:00:00 [INFO] user 13812345678 logged in")
    
    sanitized1, _, _, _ = sanitizer.sanitize_entry(entry1)
    sanitized2, _, _, _ = sanitizer.sanitize_entry(entry2)
    
    assert "138****5678" in sanitized1.message
    assert "138****5678" in sanitized2.message


def test_extra_fields_sanitization():
    detector = SensitiveDataDetector()
    mapping = MappingManager(in_memory=True)
    sanitizer = SanitizationEngine(detector, mapping)
    
    parser = LogParser(format=LogFormat.JSON, source="test.log")
    entry = parser.parse_line('{"timestamp": "2024-01-15T08:30:45Z", "level": "INFO", "message": "test", "email": "user@example.com", "ip": "192.168.1.100"}')
    
    sanitized, detections, s_count, t_count = sanitizer.sanitize_entry(entry)
    
    assert sanitized.extra.get("email") == "***@example.com"
    assert sanitized.extra.get("ip") == "192.168.*.*"


def test_bank_card_mask():
    detector = SensitiveDataDetector(
        builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": False, "id_card": False, "bank_card": True, "token": False, "session": False, "cookie": False}
    )
    mapping = MappingManager(in_memory=True)
    sanitizer = SanitizationEngine(detector, mapping)
    
    parser = LogParser(format=LogFormat.PLAINTEXT, source="test.log")
    entry = parser.parse_line("2024-01-15 08:30:45 [INFO] card 4111111111111111 used")
    
    sanitized, detections, _, _ = sanitizer.sanitize_entry(entry)
    
    assert "411111" in sanitized.message
    assert "1111" in sanitized.message
    assert "411111********1111" in sanitized.message or "411111******1111" in sanitized.message
    assert "4111111111111111" not in sanitized.message


def test_id_card_mask():
    detector = SensitiveDataDetector(
        builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": False, "id_card": True, "bank_card": False, "token": False, "session": False, "cookie": False}
    )
    mapping = MappingManager(in_memory=True)
    sanitizer = SanitizationEngine(detector, mapping)
    
    parser = LogParser(format=LogFormat.PLAINTEXT, source="test.log")
    entry = parser.parse_line("2024-01-15 08:30:45 [INFO] ID 110101199001011237")
    
    sanitized, detections, _, _ = sanitizer.sanitize_entry(entry)
    
    assert "1101" in sanitized.message
    assert "1237" in sanitized.message
    assert "1101**********1237" in sanitized.message or "1101********1237" in sanitized.message
