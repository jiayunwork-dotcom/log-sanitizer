import pytest
import json
from datetime import datetime, timezone
from log_sanitizer.parser import LogParser
from log_sanitizer.models import LogFormat, LogLevel


def test_parse_json():
    parser = LogParser(format=LogFormat.JSON, source="test.log")
    
    json_line = '{"timestamp": "2024-01-15T08:30:45Z", "level": "INFO", "message": "user login success", "user_id": 123}'
    entry = parser.parse_line(json_line)
    
    assert entry.is_parseable
    assert entry.format == LogFormat.JSON
    assert entry.timestamp is not None
    assert entry.level == LogLevel.INFO
    assert entry.message == "user login success"
    assert entry.extra.get("user_id") == 123
    assert entry.source == "test.log"


def test_parse_invalid_json():
    parser = LogParser(format=LogFormat.JSON, source="test.log")
    
    entry = parser.parse_line("not a json")
    assert not entry.is_parseable
    assert "JSON parse error" in entry.parse_error


def test_parse_apache():
    parser = LogParser(format=LogFormat.APACHE, source="access.log")
    
    apache_line = '192.168.1.100 - - [15/Jan/2024:08:30:45 +0000] "GET /api/users HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"'
    entry = parser.parse_line(apache_line)
    
    assert entry.is_parseable
    assert entry.format == LogFormat.APACHE
    assert entry.timestamp is not None
    assert entry.level == LogLevel.INFO
    assert "GET /api/users HTTP/1.1" in entry.message
    assert entry.extra.get("ip") == "192.168.1.100"
    assert entry.extra.get("status") == "200"


def test_parse_syslog_3164():
    parser = LogParser(format=LogFormat.SYSLOG, source="syslog")
    
    syslog_line = '<134>Jan 15 08:30:45 server1 sshd[1234]: Accepted password for user1 from 192.168.1.100 port 22 ssh2'
    entry = parser.parse_line(syslog_line)
    
    assert entry.is_parseable
    assert entry.format == LogFormat.SYSLOG
    assert entry.timestamp is not None
    assert entry.extra.get("hostname") == "server1"
    assert entry.extra.get("tag") == "sshd"
    assert entry.extra.get("pid") == "1234"


def test_parse_syslog_5424():
    parser = LogParser(format=LogFormat.SYSLOG, source="syslog")
    
    syslog_line = '<165>1 2024-01-15T08:30:45.003Z server1 sshd 1234 ID47 [meta sequenceId="1"] Accepted password for user1'
    entry = parser.parse_line(syslog_line)
    
    assert entry.is_parseable
    assert entry.format == LogFormat.SYSLOG
    assert entry.timestamp is not None
    assert entry.timestamp.tzinfo == timezone.utc
    assert entry.extra.get("hostname") == "server1"


def test_parse_plaintext():
    parser = LogParser(format=LogFormat.PLAINTEXT, source="app.log")
    
    line = "2024-01-15 08:30:45 [INFO] user login success, ip=192.168.1.100"
    entry = parser.parse_line(line)
    
    assert entry.is_parseable
    assert entry.format == LogFormat.PLAINTEXT
    assert entry.timestamp is not None
    assert entry.level == LogLevel.INFO
    assert "user login success" in entry.message


def test_parse_custom_format():
    custom_pattern = r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>[A-Z]+)\] (?P<service>[a-z]+): (?P<message>.*)$'
    parser = LogParser(
        format=LogFormat.CUSTOM,
        custom_pattern=custom_pattern,
        custom_field_names={"timestamp": "timestamp", "level": "level", "message": "message"},
        source="app.log"
    )
    
    line = "2024-01-15 08:30:45 [ERROR] auth: login failed for user admin from 192.168.1.100"
    entry = parser.parse_line(line)
    
    assert entry.is_parseable
    assert entry.format == LogFormat.CUSTOM
    assert entry.timestamp is not None
    assert entry.level == LogLevel.ERROR
    assert entry.extra.get("service") == "auth"


def test_auto_detect_format():
    parser = LogParser(format=LogFormat.AUTO, source="test.log")
    
    json_line = '{"timestamp": "2024-01-15T08:30:45Z", "level": "INFO", "message": "test"}'
    entry = parser.parse_line(json_line)
    assert entry.format == LogFormat.JSON
    
    parser2 = LogParser(format=LogFormat.AUTO, source="test.log")
    plain_line = "2024-01-15 08:30:45 [INFO] test message"
    entry2 = parser2.parse_line(plain_line)
    assert entry2.format == LogFormat.PLAINTEXT


def test_unparseable_line():
    parser = LogParser(format=LogFormat.AUTO, source="test.log")
    
    entry = parser.parse_line("")
    assert not entry.is_parseable
    assert entry.parse_error == "Empty line"
    
    entry2 = parser.parse_line("some random text without format")
    assert not entry2.is_parseable


def test_to_standard_dict():
    parser = LogParser(format=LogFormat.PLAINTEXT, source="test.log")
    line = "2024-01-15 08:30:45 [INFO] test message"
    entry = parser.parse_line(line)
    
    result = entry.to_standard_dict()
    assert "timestamp" in result
    assert "level" in result
    assert result["level"] == "INFO"
    assert "source" in result
    assert result["source"] == "test.log"
    assert "message" in result
    assert "extra" in result


def test_unparseable_standard_dict():
    parser = LogParser(format=LogFormat.AUTO, source="test.log")
    entry = parser.parse_line("random text")
    
    result = entry.to_standard_dict()
    assert result["_unparseable"] is True
    assert "_parse_error" in result
