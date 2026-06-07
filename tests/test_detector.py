import pytest
from log_sanitizer.detector import SensitiveDataDetector
from log_sanitizer.models import SensitiveType


def test_detect_ipv4():
    detector = SensitiveDataDetector(builtin_rules={"ipv4": True, "ipv6": False, "email": False, "phone": False, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False})
    
    matches = detector.detect_in_value("User IP: 192.168.1.100 connected")
    assert len(matches) == 1
    assert matches[0].type == SensitiveType.IPV4
    assert matches[0].value == "192.168.1.100"


def test_detect_ipv6():
    detector = SensitiveDataDetector(builtin_rules={"ipv4": False, "ipv6": True, "email": False, "phone": False, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False})
    
    matches = detector.detect_in_value("Request from 2001:db8:85a3::8a2e:370:7334")
    assert len(matches) >= 1
    assert any(m.type == SensitiveType.IPV6 for m in matches)


def test_detect_email():
    detector = SensitiveDataDetector(builtin_rules={"ipv4": False, "ipv6": False, "email": True, "phone": False, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False})
    
    matches = detector.detect_in_value("Contact: test.user@example.com for support")
    assert len(matches) == 1
    assert matches[0].type == SensitiveType.EMAIL
    assert matches[0].value == "test.user@example.com"


def test_detect_phone():
    detector = SensitiveDataDetector(builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": True, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False})
    
    matches = detector.detect_in_value("Call me at 13812345678")
    assert len(matches) == 1
    assert matches[0].type == SensitiveType.PHONE
    assert matches[0].value == "13812345678"
    
    matches2 = detector.detect_in_value("Call me at +86 138-1234-5678")
    assert len(matches2) == 1


def test_detect_phone_id_field_skipped():
    detector = SensitiveDataDetector(builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": True, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False})
    
    matches = detector.detect_in_value("13812345678", field_name="user_id")
    assert len(matches) == 0
    
    matches2 = detector.detect_in_value("13812345678", field_name="phone")
    assert len(matches2) == 1


def test_detect_id_card():
    detector = SensitiveDataDetector(builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": False, "id_card": True, "bank_card": False, "token": False, "session": False, "cookie": False})
    
    valid_id = "110101199001011237"
    matches = detector.detect_in_value(f"ID Card: {valid_id}")
    assert len(matches) == 1
    assert matches[0].type == SensitiveType.ID_CARD
    
    invalid_id = "110101199001011234"
    matches2 = detector.detect_in_value(f"ID Card: {invalid_id}")
    assert len(matches2) == 0


def test_detect_bank_card():
    detector = SensitiveDataDetector(builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": False, "id_card": False, "bank_card": True, "token": False, "session": False, "cookie": False})
    
    valid_card = "4111111111111111"
    matches = detector.detect_in_value(f"Card: {valid_card}")
    assert len(matches) == 1
    assert matches[0].type == SensitiveType.BANK_CARD
    
    invalid_card = "1234567890123456"
    matches2 = detector.detect_in_value(f"Card: {invalid_card}")
    assert len(matches2) == 0


def test_detect_token():
    detector = SensitiveDataDetector(builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": False, "id_card": False, "bank_card": False, "token": True, "session": False, "cookie": False})
    
    matches = detector.detect_in_value("url?token=abc123&other=value")
    assert len(matches) == 1
    assert matches[0].type == SensitiveType.TOKEN
    assert matches[0].value == "abc123"
    
    matches2 = detector.detect_in_value("api_key=secret-key-123")
    assert len(matches2) == 1


def test_detect_cookie():
    detector = SensitiveDataDetector(builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": False, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": True})
    
    matches = detector.detect_in_value("Set-Cookie: sessionId=abc123; path=/")
    assert len(matches) == 1
    assert matches[0].type == SensitiveType.COOKIE


def test_multiple_detections():
    detector = SensitiveDataDetector()
    
    text = "User 13812345678 with email test@example.com logged in from 192.168.1.100"
    matches = detector.detect_in_value(text)
    
    types = [m.type for m in matches]
    assert SensitiveType.PHONE in types
    assert SensitiveType.EMAIL in types
    assert SensitiveType.IPV4 in types


def test_detect_in_dict():
    detector = SensitiveDataDetector()
    
    data = {
        "user": {
            "email": "test@example.com",
            "phone": "13812345678"
        },
        "ip": "192.168.1.100"
    }
    
    results = detector.detect_in_dict(data)
    assert "user.email" in results
    assert "user.phone" in results
    assert "ip" in results


def test_custom_rule():
    custom_rules = [
        {
            "name": "us_ssn",
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "type": "custom",
            "strategy": "mask",
            "params": {"keep_start": 0, "keep_end": 4}
        }
    ]
    detector = SensitiveDataDetector(
        builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": False, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False},
        custom_rules=custom_rules
    )
    
    matches = detector.detect_in_value("SSN: 123-45-6789")
    assert len(matches) == 1
    assert matches[0].rule_name == "us_ssn"


def test_invalid_custom_rule_pattern():
    custom_rules = [
        {
            "name": "bad_pattern",
            "pattern": "[invalid",
            "type": "custom",
            "strategy": "mask",
        }
    ]
    
    with pytest.raises(ValueError, match="Invalid pattern for custom rule"):
        SensitiveDataDetector(
            builtin_rules={"ipv4": False, "ipv6": False, "email": False, "phone": False, "id_card": False, "bank_card": False, "token": False, "session": False, "cookie": False},
            custom_rules=custom_rules
        )
