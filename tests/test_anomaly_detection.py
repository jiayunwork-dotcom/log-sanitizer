import os
import json
import tempfile
import time
from datetime import datetime, timezone, timedelta
import pytest
from log_sanitizer.models import (
    LogEntry,
    LogLevel,
    AlertEvent,
    AlertSeverity,
    AlertType,
    DetectorName,
    LogFormat,
)
from log_sanitizer.config import (
    AnomalyDetectionConfig,
    FrequencyAlgorithmConfig,
    ErrorRateAlgorithmConfig,
    PatternAlgorithmConfig,
    WebhookConfig,
)
from log_sanitizer.event_bus import EventBus
from log_sanitizer.anomaly_detectors import (
    FrequencyDetector,
    ErrorRateDetector,
    PatternDetector,
    calculate_modified_z_score,
    templatize_message,
)
from log_sanitizer.alert_aggregator import AlertAggregator
from log_sanitizer.alert_output import AlertOutput
from log_sanitizer.state_persistence import StatePersistence
from log_sanitizer.anomaly_engine import AnomalyDetectionEngine


def create_log_entry(
    source: str,
    message: str,
    level: LogLevel = LogLevel.INFO,
    timestamp: datetime = None,
) -> LogEntry:
    return LogEntry(
        raw=message,
        source=source,
        format=LogFormat.JSON,
        timestamp=timestamp or datetime.now(timezone.utc),
        level=level,
        message=message,
        is_parseable=True,
    )


class TestEventBus:
    def test_publish_subscribe(self):
        bus = EventBus()
        received = []

        def callback(event):
            received.append(event)

        bus.subscribe('test_event', callback)

        alert = AlertEvent(
            source='test',
            alert_type=AlertType.FREQUENCY_SPIKE,
            description='test'
        )

        bus.publish('test_event', alert)
        assert len(received) == 1
        assert received[0].source == 'test'

    def test_wildcard_subscribe(self):
        bus = EventBus()
        received = []

        def callback(event):
            received.append(event)

        bus.subscribe('*', callback)

        alert = AlertEvent(
            source='test',
            alert_type=AlertType.FREQUENCY_SPIKE,
            description='test'
        )

        bus.publish('any_event', alert)
        assert len(received) == 1

    def test_unsubscribe(self):
        bus = EventBus()
        received = []

        def callback(event):
            received.append(event)

        bus.subscribe('test_event', callback)
        bus.unsubscribe('test_event', callback)

        from log_sanitizer.models import AlertEvent
        alert = AlertEvent(
            source='test',
            alert_type=AlertType.FREQUENCY_SPIKE,
            description='test'
        )

        bus.publish('test_event', alert)
        assert len(received) == 0


class TestModifiedZScore:
    def test_normal_calculation(self):
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        z = calculate_modified_z_score(values, 10.0)
        assert z > 2.0

    def test_mad_zero_same_values(self):
        values = [2.0, 2.0, 2.0, 2.0]
        z = calculate_modified_z_score(values, 2.0)
        assert z == 0.0

    def test_mad_zero_different_current(self):
        values = [2.0, 2.0, 2.0, 2.0]
        z = calculate_modified_z_score(values, 5.0)
        assert z == float('inf')

    def test_empty_history(self):
        z = calculate_modified_z_score([], 1.0)
        assert z == 0.0


class TestTemplatizeMessage:
    def test_ip_replacement(self):
        result = templatize_message("Connection from 192.168.1.1")
        assert "<IP>" in result
        assert "192.168.1.1" not in result

    def test_email_replacement(self):
        result = templatize_message("Email sent to user@example.com")
        assert "<EMAIL>" in result
        assert "user@example.com" not in result

    def test_uuid_replacement(self):
        result = templatize_message("Request ID: 550e8400-e29b-41d4-a716-446655440000")
        assert "<UUID>" in result
        assert "550e8400" not in result

    def test_number_replacement(self):
        result = templatize_message("User 12345 logged in")
        assert "<NUM>" in result
        assert "12345" not in result

    def test_path_var_replacement(self):
        result = templatize_message("GET /api/users/123/profile")
        assert "<VAR>" in result

    def test_multiple_patterns(self):
        result = templatize_message("User 123 from 10.0.0.1 emailed admin@test.com")
        assert "<NUM>" in result
        assert "<IP>" in result
        assert "<EMAIL>" in result


class TestFrequencyDetector:
    def test_initial_window(self):
        config = FrequencyAlgorithmConfig(window_size_seconds=1, alpha=0.3, threshold_multiplier=3.0)
        bus = EventBus()
        detector = FrequencyDetector(config, bus)

        alerts = []
        def on_alert(event):
            alerts.append(event)
        bus.subscribe('*', on_alert)

        base_time = datetime.now(timezone.utc)
        entry = create_log_entry('test', 'message', timestamp=base_time)
        detector.process_entry(entry)

        assert len(alerts) == 0
        assert 'test' in detector.states
        assert detector.states['test'].window_count == 1

    def test_frequency_spike_detection(self):
        config = FrequencyAlgorithmConfig(window_size_seconds=1, alpha=0.3, threshold_multiplier=2.0)
        bus = EventBus()
        detector = FrequencyDetector(config, bus)

        alerts = []
        def on_alert(event):
            alerts.append(event)
        bus.subscribe('*', on_alert)

        base_time = datetime.now(timezone.utc)

        for i in range(10):
            entry = create_log_entry('test', 'message', timestamp=base_time + timedelta(seconds=i * 0.2))
            detector.process_entry(entry)

        spike_time = base_time + timedelta(seconds=1.1)
        for i in range(30):
            entry = create_log_entry('test', 'message', timestamp=spike_time + timedelta(milliseconds=i * 10))
            detector.process_entry(entry)

        detector.force_check_window('test')

        assert len(alerts) >= 1
        assert alerts[0].alert_type == AlertType.FREQUENCY_SPIKE
        assert alerts[0].severity == AlertSeverity.WARNING

    def test_ewma_formula(self):
        config = FrequencyAlgorithmConfig(window_size_seconds=1, alpha=0.3, threshold_multiplier=3.0)
        bus = EventBus()
        detector = FrequencyDetector(config, bus)

        base_time = datetime.now(timezone.utc)

        for i in range(10):
            entry = create_log_entry('test', 'message', timestamp=base_time + timedelta(seconds=i))
            detector.process_entry(entry)

        assert detector.states['test'].ewma is not None

    def test_reset_source(self):
        config = FrequencyAlgorithmConfig(window_size_seconds=1, alpha=0.3, threshold_multiplier=3.0)
        bus = EventBus()
        detector = FrequencyDetector(config, bus)

        base_time = datetime.now(timezone.utc)
        entry = create_log_entry('test', 'message', timestamp=base_time)
        detector.process_entry(entry)

        assert 'test' in detector.states
        detector.reset_source('test')
        assert 'test' not in detector.states


class TestErrorRateDetector:
    def test_initial_window(self):
        config = ErrorRateAlgorithmConfig(window_size_seconds=1, k_windows=20, z_score_threshold=2.5)
        bus = EventBus()
        detector = ErrorRateDetector(config, bus)

        alerts = []
        def on_alert(event):
            alerts.append(event)
        bus.subscribe('*', on_alert)

        base_time = datetime.now(timezone.utc)
        entry = create_log_entry('test', 'message', level=LogLevel.INFO, timestamp=base_time)
        detector.process_entry(entry)

        assert len(alerts) == 0
        assert 'test' in detector.states

    def test_error_rate_surge_detection(self):
        config = ErrorRateAlgorithmConfig(window_size_seconds=1, k_windows=5, z_score_threshold=1.0)
        bus = EventBus()
        detector = ErrorRateDetector(config, bus)

        alerts = []
        def on_alert(event):
            alerts.append(event)
        bus.subscribe('*', on_alert)

        base_time = datetime.now(timezone.utc)

        for window in range(6):
            window_time = base_time + timedelta(seconds=window * 1.1)
            for i in range(10):
                level = LogLevel.ERROR if window == 5 and i < 8 else LogLevel.INFO
                entry = create_log_entry('test', 'message', level=level, timestamp=window_time + timedelta(milliseconds=i * 10))
                detector.process_entry(entry)

        detector.force_check_window('test')

        assert len(alerts) >= 1
        assert alerts[0].alert_type == AlertType.ERROR_RATE_SURGE

    def test_reset_source(self):
        config = ErrorRateAlgorithmConfig(window_size_seconds=1, k_windows=20, z_score_threshold=2.5)
        bus = EventBus()
        detector = ErrorRateDetector(config, bus)

        base_time = datetime.now(timezone.utc)
        entry = create_log_entry('test', 'message', timestamp=base_time)
        detector.process_entry(entry)

        assert 'test' in detector.states
        detector.reset_source('test')
        assert 'test' not in detector.states


class TestPatternDetector:
    def test_new_pattern_detection(self):
        config = PatternAlgorithmConfig(window_size_seconds=1, min_samples=5, disappear_windows=3)
        bus = EventBus()
        detector = PatternDetector(config, bus, min_samples=5)

        alerts = []
        def on_alert(event):
            alerts.append(event)
        bus.subscribe('*', on_alert)

        base_time = datetime.now(timezone.utc)

        for i in range(10):
            entry = create_log_entry('test', f'User logged in', timestamp=base_time + timedelta(milliseconds=i * 10))
            detector.process_entry(entry)

        new_pattern_entry = create_log_entry('test', 'New error occurred: DB connection failed', timestamp=base_time + timedelta(milliseconds=200))
        detector.process_entry(new_pattern_entry)

        new_alerts = [a for a in alerts if a.alert_type == AlertType.NEW_PATTERN]
        assert len(new_alerts) >= 1
        assert new_alerts[0].severity == AlertSeverity.WARNING

    def test_no_new_pattern_before_min_samples(self):
        config = PatternAlgorithmConfig(window_size_seconds=1, min_samples=100, disappear_windows=3)
        bus = EventBus()
        detector = PatternDetector(config, bus, min_samples=100)

        alerts = []
        def on_alert(event):
            alerts.append(event)
        bus.subscribe('*', on_alert)

        base_time = datetime.now(timezone.utc)

        for i in range(10):
            entry = create_log_entry('test', f'Message {i}', timestamp=base_time + timedelta(milliseconds=i * 10))
            detector.process_entry(entry)

        new_pattern_alerts = [a for a in alerts if a.alert_type == AlertType.NEW_PATTERN]
        assert len(new_pattern_alerts) == 0

    def test_pattern_disappeared_detection(self):
        config = PatternAlgorithmConfig(window_size_seconds=1, min_samples=2, disappear_windows=2)
        bus = EventBus()
        detector = PatternDetector(config, bus, min_samples=2)

        alerts = []
        def on_alert(event):
            alerts.append(event)
        bus.subscribe('*', on_alert)

        base_time = datetime.now(timezone.utc)

        entry1 = create_log_entry('test', 'Pattern A', timestamp=base_time)
        entry2 = create_log_entry('test', 'Pattern A', timestamp=base_time + timedelta(milliseconds=50))
        entry3 = create_log_entry('test', 'Pattern B', timestamp=base_time + timedelta(milliseconds=100))
        detector.process_entry(entry1)
        detector.process_entry(entry2)
        detector.process_entry(entry3)

        for window in range(3):
            window_time = base_time + timedelta(seconds=(window + 1) * 1.1)
            entry = create_log_entry('test', 'Pattern B', timestamp=window_time)
            detector.process_entry(entry)

        disappeared_alerts = [a for a in alerts if a.alert_type == AlertType.PATTERN_DISAPPEARED]
        assert len(disappeared_alerts) >= 1
        assert disappeared_alerts[0].severity == AlertSeverity.INFO

    def test_reset_source(self):
        config = PatternAlgorithmConfig(window_size_seconds=1, min_samples=5, disappear_windows=3)
        bus = EventBus()
        detector = PatternDetector(config, bus)

        base_time = datetime.now(timezone.utc)
        entry = create_log_entry('test', 'message', timestamp=base_time)
        detector.process_entry(entry)

        assert 'test' in detector.states
        detector.reset_source('test')
        assert 'test' not in detector.states


class TestAlertAggregator:
    def test_suppression(self):
        config = AnomalyDetectionConfig(suppression_window_seconds=600, correlation_window_seconds=30)
        aggregator = AlertAggregator(config)

        received = []
        aggregator.set_output_callback(lambda a: received.append(a))

        alert1 = AlertEvent(
            source='test',
            alert_type=AlertType.FREQUENCY_SPIKE,
            description='test1',
        )
        alert2 = AlertEvent(
            source='test',
            alert_type=AlertType.FREQUENCY_SPIKE,
            description='test2',
            timestamp=alert1.timestamp + timedelta(seconds=100),
        )

        aggregator.process_alert(alert1)
        aggregator.process_alert(alert2)
        aggregator.flush_pending()

        assert len(received) == 1

    def test_no_suppression_after_window(self):
        config = AnomalyDetectionConfig(suppression_window_seconds=10, correlation_window_seconds=30)
        aggregator = AlertAggregator(config)

        received = []
        aggregator.set_output_callback(lambda a: received.append(a))

        alert1 = AlertEvent(
            source='test',
            alert_type=AlertType.FREQUENCY_SPIKE,
            description='test1',
        )
        alert2 = AlertEvent(
            source='test',
            alert_type=AlertType.FREQUENCY_SPIKE,
            description='test2',
            timestamp=alert1.timestamp + timedelta(seconds=20),
        )

        aggregator.process_alert(alert1)
        aggregator.process_alert(alert2)
        aggregator.flush_pending()

        assert len(received) == 2

    def test_correlation(self):
        config = AnomalyDetectionConfig(suppression_window_seconds=600, correlation_window_seconds=30)
        aggregator = AlertAggregator(config)

        received = []
        aggregator.set_output_callback(lambda a: received.append(a))

        freq_alert = AlertEvent(
            source='test',
            alert_type=AlertType.FREQUENCY_SPIKE,
            detector=DetectorName.FREQUENCY,
            description='frequency spike',
        )
        err_alert = AlertEvent(
            source='test',
            alert_type=AlertType.ERROR_RATE_SURGE,
            detector=DetectorName.ERROR_RATE,
            description='error rate surge',
            timestamp=freq_alert.timestamp + timedelta(seconds=10),
        )

        aggregator.process_alert(freq_alert)
        aggregator.process_alert(err_alert)
        aggregator.flush_pending()

        composite_alerts = [a for a in received if a.alert_type == AlertType.COMPOSITE_ANOMALY]
        assert len(composite_alerts) == 1
        assert composite_alerts[0].severity == AlertSeverity.CRITICAL

    def test_severity_levels(self):
        config = AnomalyDetectionConfig(suppression_window_seconds=600, correlation_window_seconds=30)
        aggregator = AlertAggregator(config)

        received = []
        aggregator.set_output_callback(lambda a: received.append(a))

        alert1 = AlertEvent(
            source='test',
            alert_type=AlertType.FREQUENCY_SPIKE,
            description='test',
        )
        alert2 = AlertEvent(
            source='test2',
            alert_type=AlertType.PATTERN_DISAPPEARED,
            severity=AlertSeverity.INFO,
            description='test',
        )

        aggregator.process_alert(alert1)
        aggregator.process_alert(alert2)
        aggregator.flush_pending()

        assert received[0].severity == AlertSeverity.INFO
        assert received[1].severity == AlertSeverity.WARNING

    def test_stats(self):
        config = AnomalyDetectionConfig(suppression_window_seconds=0, correlation_window_seconds=30)
        aggregator = AlertAggregator(config)

        received = []
        aggregator.set_output_callback(lambda a: received.append(a))

        for i in range(5):
            alert = AlertEvent(
                source=f'source{i % 2}',
                alert_type=AlertType.FREQUENCY_SPIKE,
                description='test',
            )
            aggregator.process_alert(alert)

        aggregator.flush_pending()
        stats = aggregator.get_stats()

        assert stats.total_alerts == 5
        assert stats.by_severity[AlertSeverity.WARNING] == 5
        assert stats.by_type[AlertType.FREQUENCY_SPIKE] == 5


class TestAlertOutput:
    def test_write_alert_to_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            alert_file = f.name

        try:
            output = AlertOutput(alert_file)

            alert = AlertEvent(
                source='test',
                alert_type=AlertType.FREQUENCY_SPIKE,
                description='test alert',
            )

            output.write_alert(alert)
            output.close()

            with open(alert_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data['source'] == 'test'
            assert data['alert_type'] == 'frequency_spike'
        finally:
            os.unlink(alert_file)

    def test_no_file_when_no_alert_file(self):
        output = AlertOutput(None)

        alert = AlertEvent(
            source='test',
            alert_type=AlertType.FREQUENCY_SPIKE,
            description='test alert',
        )

        output.write_alert(alert)
        output.close()

    def test_dead_letter_on_webhook_failure(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            dead_letter_file = f.name

        try:
            webhook_config = WebhookConfig(
                url='http://invalid-url-that-will-fail.example.com',
                timeout_seconds=1,
                max_retries=0,
                dead_letter_file=dead_letter_file,
            )

            output = AlertOutput(None, webhook_config)

            alert = AlertEvent(
                source='test',
                alert_type=AlertType.COMPOSITE_ANOMALY,
                severity=AlertSeverity.CRITICAL,
                description='critical alert',
            )

            output.write_alert(alert)
            output.close()

            time.sleep(0.5)

            with open(dead_letter_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            assert len(lines) >= 1
            data = json.loads(lines[0])
            assert 'alert' in data
            assert 'error' in data
        finally:
            if os.path.exists(dead_letter_file):
                os.unlink(dead_letter_file)


class TestStatePersistence:
    def test_save_and_load_state(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        try:
            config = FrequencyAlgorithmConfig(window_size_seconds=1, alpha=0.3, threshold_multiplier=3.0)
            err_config = ErrorRateAlgorithmConfig(window_size_seconds=1, k_windows=20, z_score_threshold=2.5)
            pat_config = PatternAlgorithmConfig(window_size_seconds=1, min_samples=5, disappear_windows=3)

            bus = EventBus()
            freq_detector = FrequencyDetector(config, bus)
            err_detector = ErrorRateDetector(err_config, bus)
            pat_detector = PatternDetector(pat_config, bus)

            base_time = datetime.now(timezone.utc)
            entry = create_log_entry('test_source', 'message', timestamp=base_time)

            freq_detector.process_entry(entry)
            err_detector.process_entry(entry)
            pat_detector.process_entry(entry)

            persistence = StatePersistence(state_file)
            persistence.mark_dirty()
            persistence.save_state(freq_detector, err_detector, pat_detector, force=True)

            assert os.path.exists(state_file)

            new_bus = EventBus()
            new_freq = FrequencyDetector(config, new_bus)
            new_err = ErrorRateDetector(err_config, new_bus)
            new_pat = PatternDetector(pat_config, new_bus)

            persistence.load_state(new_freq, new_err, new_pat)

            assert 'test_source' in new_freq.states
            assert 'test_source' in new_err.states
            assert 'test_source' in new_pat.states
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)

    def test_reset_source_state(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        try:
            config = FrequencyAlgorithmConfig(window_size_seconds=1, alpha=0.3, threshold_multiplier=3.0)
            err_config = ErrorRateAlgorithmConfig(window_size_seconds=1, k_windows=20, z_score_threshold=2.5)
            pat_config = PatternAlgorithmConfig(window_size_seconds=1, min_samples=5, disappear_windows=3)

            bus = EventBus()
            freq_detector = FrequencyDetector(config, bus)
            err_detector = ErrorRateDetector(err_config, bus)
            pat_detector = PatternDetector(pat_config, bus)

            base_time = datetime.now(timezone.utc)
            entry = create_log_entry('test_source', 'message', timestamp=base_time)

            freq_detector.process_entry(entry)
            err_detector.process_entry(entry)
            pat_detector.process_entry(entry)

            persistence = StatePersistence(state_file)
            persistence.mark_dirty()
            persistence.save_state(freq_detector, err_detector, pat_detector, force=True)

            persistence.reset_source_state('test_source', freq_detector, err_detector, pat_detector)

            assert 'test_source' not in freq_detector.states
            assert 'test_source' not in err_detector.states
            assert 'test_source' not in pat_detector.states
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)


class TestAnomalyDetectionEngine:
    def test_engine_disabled(self):
        config = AnomalyDetectionConfig(enabled=False)
        engine = AnomalyDetectionEngine(config)

        assert not engine.enabled
        assert engine.frequency_detector is None

        entry = create_log_entry('test', 'message')
        engine.process_entry(entry, 1, 1)
        engine.stop()

    def test_async_processing(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            alert_file = f.name

        try:
            config = AnomalyDetectionConfig(
                enabled=True,
                alert_file=alert_file,
                algorithms=AnomalyDetectionConfig().algorithms,
            )

            with AnomalyDetectionEngine(config) as engine:
                base_time = datetime.now(timezone.utc)
                for i in range(100):
                    entry = create_log_entry(
                        'test',
                        f'Message {i}',
                        timestamp=base_time + timedelta(milliseconds=i * 10)
                    )
                    engine.process_entry(entry, i + 1, i + 1)

                time.sleep(0.5)

                engine.on_file_completed()

                status = engine.get_status()
                assert status['enabled'] is True
                assert 'test' in status['sources']
        finally:
            if os.path.exists(alert_file):
                os.unlink(alert_file)

    def test_get_status(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            alert_file = f.name

        try:
            config = AnomalyDetectionConfig(
                enabled=True,
                alert_file=alert_file,
            )

            engine = AnomalyDetectionEngine(config)
            engine.start()

            base_time = datetime.now(timezone.utc)
            entry = create_log_entry('test_source', 'message', timestamp=base_time)
            engine.process_entry(entry, 1, 1)

            time.sleep(0.3)

            status = engine.get_status()
            assert status['enabled'] is True
            assert 'queue_size' in status
            assert 'sources' in status
            assert 'alert_stats' in status

            engine.stop()
        finally:
            if os.path.exists(alert_file):
                os.unlink(alert_file)

    def test_replay_alerts(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            alert_file = f.name

        try:
            alert = AlertEvent(
                source='test',
                alert_type=AlertType.FREQUENCY_SPIKE,
                description='test alert',
            )

            with open(alert_file, 'w', encoding='utf-8') as f:
                f.write(json.dumps(alert.to_dict()) + '\n')

            alerts = AnomalyDetectionEngine.replay_alerts(alert_file)
            assert len(alerts) == 1
            assert alerts[0]['source'] == 'test'
        finally:
            if os.path.exists(alert_file):
                os.unlink(alert_file)


class TestConfigIntegration:
    def test_load_anomaly_config(self):
        from log_sanitizer.config import ConfigLoader

        config_yaml = """
name: "test"
inputs:
  paths: ["/tmp/test.log"]
parser:
  format: "json"
output:
  file: "/tmp/output.jsonl"
anomaly_detection:
  enabled: true
  alert_file: "/tmp/alerts.jsonl"
  state_file: "/tmp/state.json"
  min_samples: 50
  algorithms:
    frequency:
      window_size_seconds: 60
      alpha: 0.5
      threshold_multiplier: 2.5
    error_rate:
      window_size_seconds: 60
      k_windows: 10
      z_score_threshold: 3.0
    pattern:
      window_size_seconds: 60
      min_samples: 50
      disappear_windows: 5
  webhook:
    url: "http://example.com/alerts"
    headers:
      Authorization: "Bearer token"
"""

        config = ConfigLoader.load_from_string(config_yaml)

        assert config.anomaly_detection.enabled is True
        assert config.anomaly_detection.alert_file == "/tmp/alerts.jsonl"
        assert config.anomaly_detection.state_file == "/tmp/state.json"
        assert config.anomaly_detection.min_samples == 50
        assert config.anomaly_detection.algorithms.frequency.window_size_seconds == 60
        assert config.anomaly_detection.algorithms.frequency.alpha == 0.5
        assert config.anomaly_detection.algorithms.frequency.threshold_multiplier == 2.5
        assert config.anomaly_detection.algorithms.error_rate.k_windows == 10
        assert config.anomaly_detection.algorithms.error_rate.z_score_threshold == 3.0
        assert config.anomaly_detection.algorithms.pattern.disappear_windows == 5
        assert config.anomaly_detection.webhook.url == "http://example.com/alerts"
        assert config.anomaly_detection.webhook.headers["Authorization"] == "Bearer token"
