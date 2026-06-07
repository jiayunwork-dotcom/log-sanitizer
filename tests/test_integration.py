import os
import json
import tempfile
import pytest
from log_sanitizer.config import ConfigLoader
from log_sanitizer.processor import LogProcessor
from log_sanitizer.models import SensitiveType


@pytest.fixture
def temp_output_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


def test_full_pipeline_plaintext(temp_output_dir):
    test_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(test_dir, "data", "sample_plaintext.log")
    
    config_yaml = f"""
name: "test-pipeline"
inputs:
  paths:
    - "{input_file}"
parser:
  format: "auto"
sanitizers:
  mapping_in_memory: true
output:
  file: "{os.path.join(temp_output_dir, 'output.jsonl')}"
  overwrite: true
parallelism: 1
dry_run: false
"""
    
    config = ConfigLoader.load_from_string(config_yaml)
    processor = LogProcessor(config)
    
    report = processor.run(show_progress=False)
    
    assert report.total_lines == 10
    assert report.parsed_lines == 9
    assert report.unparsed_lines == 1
    assert report.parse_failure_rate == 0.1
    
    assert SensitiveType.IPV4 in report.detections
    assert SensitiveType.EMAIL in report.detections
    assert SensitiveType.PHONE in report.detections
    
    output_file = os.path.join(temp_output_dir, "output.jsonl")
    assert os.path.exists(output_file)
    
    with open(output_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    assert len(lines) == 10
    
    for line in lines:
        data = json.loads(line)
        assert "timestamp" in data
        assert "level" in data
        assert "source" in data
        assert "message" in data
        assert "extra" in data
    
    sensitive_values = ["192.168.1.100", "test@example.com", "13812345678", "4111111111111111"]
    full_output = "".join(lines)
    for sensitive in sensitive_values:
        assert sensitive not in full_output, f"Found unredacted sensitive value: {sensitive}"
    
    assert "192.168.*.*" in full_output
    assert "***@example.com" in full_output
    assert "138****5678" in full_output


def test_full_pipeline_json(temp_output_dir):
    test_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(test_dir, "data", "sample_json.log")
    
    config_yaml = f"""
name: "test-pipeline-json"
inputs:
  paths:
    - "{input_file}"
parser:
  format: "json"
sanitizers:
  mapping_in_memory: true
output:
  file: "{os.path.join(temp_output_dir, 'output_json.jsonl')}"
  overwrite: true
parallelism: 1
"""
    
    config = ConfigLoader.load_from_string(config_yaml)
    processor = LogProcessor(config)
    
    report = processor.run(show_progress=False)
    
    assert report.total_lines == 5
    assert report.parsed_lines == 5
    
    output_file = os.path.join(temp_output_dir, "output_json.jsonl")
    with open(output_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    full_output = "".join(lines)
    
    assert "192.168.1.100" not in full_output
    assert "user@example.com" not in full_output
    assert "4111111111111111" not in full_output
    assert "110101199001011237" not in full_output


def test_dry_run_mode(temp_output_dir):
    test_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(test_dir, "data", "sample_plaintext.log")
    
    config_yaml = f"""
name: "test-dry-run"
inputs:
  paths:
    - "{input_file}"
parser:
  format: "plaintext"
sanitizers:
  mapping_in_memory: true
output:
  file: "{os.path.join(temp_output_dir, 'dry_run_output.jsonl')}"
  overwrite: true
parallelism: 1
dry_run: true
"""
    
    config = ConfigLoader.load_from_string(config_yaml)
    processor = LogProcessor(config)
    
    report = processor.run(show_progress=False)
    
    output_file = os.path.join(temp_output_dir, "dry_run_output.jsonl")
    assert not os.path.exists(output_file) or os.path.getsize(output_file) == 0


def test_full_pipeline_apache(temp_output_dir):
    test_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(test_dir, "data", "sample_apache.log")
    
    config_yaml = f"""
name: "test-pipeline-apache"
inputs:
  paths:
    - "{input_file}"
parser:
  format: "apache"
sanitizers:
  mapping_in_memory: true
output:
  file: "{os.path.join(temp_output_dir, 'output_apache.jsonl')}"
  overwrite: true
parallelism: 1
"""
    
    config = ConfigLoader.load_from_string(config_yaml)
    processor = LogProcessor(config)
    
    report = processor.run(show_progress=False)
    
    assert report.total_lines == 5
    assert report.parsed_lines == 5
    
    assert SensitiveType.IPV4 in report.detections
    assert report.detections[SensitiveType.IPV4] >= 5
    
    output_file = os.path.join(temp_output_dir, "output_apache.jsonl")
    with open(output_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    full_output = "".join(lines)
    
    assert "192.168.1.100" not in full_output
    assert "192.168.*.*" in full_output
    assert "abc123" not in full_output
    assert "[REDACTED_TOKEN]" in full_output or "[REDACTED_TOKEN]" in full_output


def test_filter_by_level(temp_output_dir):
    test_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(test_dir, "data", "sample_plaintext.log")
    
    config_yaml = f"""
name: "test-filter"
inputs:
  paths:
    - "{input_file}"
parser:
  format: "plaintext"
filters:
  levels: ["ERROR", "WARN"]
sanitizers:
  mapping_in_memory: true
output:
  file: "{os.path.join(temp_output_dir, 'output_filtered.jsonl')}"
  overwrite: true
parallelism: 1
"""
    
    config = ConfigLoader.load_from_string(config_yaml)
    processor = LogProcessor(config)
    
    report = processor.run(show_progress=False)
    
    assert report.total_lines == 10
    
    output_file = os.path.join(temp_output_dir, "output_filtered.jsonl")
    with open(output_file, 'r', encoding='utf-8') as f:
        lines = [json.loads(line) for line in f if line.strip()]
    
    levels = [line["level"] for line in lines]
    assert all(l in ["ERROR", "WARN", "UNKNOWN"] for l in levels)


def test_custom_rule(temp_output_dir):
    test_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(test_dir, "data", "sample_plaintext.log")
    
    config_yaml = f"""
name: "test-custom-rule"
inputs:
  paths:
    - "{input_file}"
parser:
  format: "plaintext"
sanitizers:
  builtin_rules:
    - name: "ipv4"
      enabled: false
    - name: "ipv6"
      enabled: false
    - name: "email"
      enabled: false
    - name: "phone"
      enabled: false
    - name: "id_card"
      enabled: false
    - name: "bank_card"
      enabled: false
    - name: "token"
      enabled: false
    - name: "session"
      enabled: false
    - name: "cookie"
      enabled: false
  custom_rules:
    - name: "order_number"
      enabled: true
      pattern: "order #\\\\d+"
      type: "custom"
      strategy: "mask"
      params:
        keep_start: 6
        keep_end: 0
        mask_char: "*"
  mapping_in_memory: true
output:
  file: "{os.path.join(temp_output_dir, 'output_custom.jsonl')}"
  overwrite: true
parallelism: 1
"""
    
    config = ConfigLoader.load_from_string(config_yaml)
    processor = LogProcessor(config)
    
    report = processor.run(show_progress=False)
    
    assert SensitiveType.CUSTOM in report.detections
    
    output_file = os.path.join(temp_output_dir, "output_custom.jsonl")
    with open(output_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    full_output = "".join(lines)
    assert "order #12345" not in full_output
    assert "order *****" in full_output or "order #*****" in full_output
