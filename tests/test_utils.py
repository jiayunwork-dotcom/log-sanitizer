import pytest
from datetime import datetime, timezone
from log_sanitizer.utils import (
    sha256_hash,
    hmac_sha256,
    luhn_check,
    id_card_check,
    is_id_field,
    parse_timestamp,
    parse_log_level,
    mask_value,
    generalize_ip,
    generalize_email,
    find_overlaps,
)
from log_sanitizer.models import LogLevel


def test_sha256_hash():
    result = sha256_hash("test", 16)
    assert len(result) == 16
    assert isinstance(result, str)
    assert result == sha256_hash("test", 16)
    assert result != sha256_hash("other", 16)


def test_hmac_sha256():
    key = b"test-key"
    result = hmac_sha256("test", key)
    assert isinstance(result, str)
    assert len(result) == 64
    assert result == hmac_sha256("test", key)


def test_luhn_check():
    assert luhn_check("79927398713")
    assert luhn_check("4111111111111111")
    assert not luhn_check("1234567890123456")
    assert not luhn_check("0000000000000000")


def test_id_card_check():
    valid_id = "110101199001011237"
    assert id_card_check(valid_id)
    
    invalid_check = "110101199001011234"
    assert not id_card_check(invalid_check)
    
    assert not id_card_check("12345678901234567X")
    assert not id_card_check("12345")


def test_is_id_field():
    assert is_id_field("user_id")
    assert is_id_field("seq_no")
    assert is_id_field("orderNumber")
    assert is_id_field("UUID")
    assert not is_id_field("username")
    assert not is_id_field("email")
    assert not is_id_field(None)


def test_parse_timestamp():
    dt = parse_timestamp("2024-01-15 08:30:45")
    assert dt is not None
    assert dt.year == 2024
    assert dt.month == 1
    assert dt.day == 15
    assert dt.hour == 8
    assert dt.tzinfo == timezone.utc
    
    dt2 = parse_timestamp("2024-01-15T08:30:45Z")
    assert dt2 is not None
    
    dt3 = parse_timestamp("15/Jan/2024:08:30:45 +0000")
    assert dt3 is not None
    
    assert parse_timestamp("invalid") is None


def test_parse_log_level():
    assert parse_log_level("[INFO] message") == LogLevel.INFO
    assert parse_log_level("ERROR something happened") == LogLevel.ERROR
    assert parse_log_level("warn: test") == LogLevel.WARN
    assert parse_log_level("Debug mode") == LogLevel.DEBUG
    assert parse_log_level("no level here") == LogLevel.UNKNOWN


def test_mask_value():
    assert mask_value("13800138000", 3, 4) == "138****8000"
    assert mask_value("1234567890", 3, 4) == "123***7890"
    assert mask_value("short", 3, 4) == "*****"
    assert mask_value("test", 0, 0) == "****"


def test_generalize_ip():
    assert generalize_ip("192.168.1.100") == "192.168.*.*"
    assert generalize_ip("2001:db8:85a3::8a2e:370:7334") == "2001:db8::*"
    assert generalize_ip("invalid") == "invalid"


def test_generalize_email():
    assert generalize_email("user@example.com") == "***@example.com"
    assert generalize_email("no_at_sign") == "no_at_sign"


def test_find_overlaps():
    matches = [(0, 5, "a"), (3, 7, "b"), (10, 15, "c")]
    result = find_overlaps(matches)
    assert len(result) == 2
    assert result[0][2] == "a"
    assert result[1][2] == "c"
