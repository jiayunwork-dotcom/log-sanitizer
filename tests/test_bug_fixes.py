#!/usr/bin/env python3
"""测试脚本，用于复现和验证三个bug的修复"""
import os
import sys
import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_sanitizer.models import (
    AlertEvent,
    AlertSeverity,
    AlertType,
    DetectorName,
    AlertStatus,
    SuppressionRule,
    SuppressionAction,
    SuppressionRuleMatch,
)
from log_sanitizer.config import AnomalyDetectionConfig, ConfigLoader
from log_sanitizer.anomaly_engine import AnomalyDetectionEngine
from log_sanitizer.suppression_engine import SuppressionEngine, PendingAlert


def test_pending_alert_delay_seconds():
    """测试问题1: PendingAlert是否有delay_seconds属性"""
    print("=== 测试问题1: PendingAlert.delay_seconds ===")
    
    alert = AlertEvent(
        source="test-service",
        alert_type=AlertType.FREQUENCY_SPIKE,
        severity=AlertSeverity.WARNING,
        detector=DetectorName.FREQUENCY,
    )
    
    pending = PendingAlert(
        alert=alert,
        rule_name="test-delay-rule",
        delay_seconds=60,
        delay_until=datetime.now(timezone.utc) + timedelta(seconds=60),
        check_alert_type=alert.alert_type,
        check_source=alert.source,
    )
    
    assert hasattr(pending, 'delay_seconds'), "PendingAlert缺少delay_seconds属性"
    assert pending.delay_seconds == 60, f"delay_seconds应该是60, 实际是{pending.delay_seconds}"
    
    print("✓ PendingAlert有delay_seconds属性")
    
    # 测试suppression_engine创建pending_alert
    config = AnomalyDetectionConfig(
        enabled=True,
        suppression_rules=[
            SuppressionRule(
                name="test-delay",
                enabled=True,
                action=SuppressionAction.DELAY,
                match=SuppressionRuleMatch(),
                delay_seconds=30,
            )
        ]
    )
    
    engine = SuppressionEngine(config)
    result = engine.process_alert(alert)
    
    assert result is None, "delay规则应该返回None"
    assert len(engine._pending_alerts) == 1, "应该有1个pending alert"
    
    pending = engine._pending_alerts[0]
    assert pending.delay_seconds == 30, f"pending.delay_seconds应该是30, 实际是{pending.delay_seconds}"
    
    print("✓ SuppressionEngine正确创建带delay_seconds的PendingAlert")
    
    # 测试_process_expired_pending不会崩溃
    try:
        engine._process_expired_pending(pending)
        print("✓ _process_expired_pending不会崩溃")
    except AttributeError as e:
        print(f"✗ _process_expired_pending崩溃: {e}")
        raise
    
    print()


def create_test_state_file(state_file: Path, alert_id: str):
    """创建测试用的状态文件"""
    alert = AlertEvent(
        id=alert_id,
        source="test-service",
        alert_type=AlertType.FREQUENCY_SPIKE,
        severity=AlertSeverity.WARNING,
        detector=DetectorName.FREQUENCY,
        status=AlertStatus.ACTIVE,
        trigger_value=10.0,
        threshold=3.0,
        description="Test alert",
    )
    
    state_data = {
        "version": "2.0",
        "frequency_states": {
            "test-service": {
                "ewma": 2.0,
                "window_start": None,
                "window_count": 0,
                "last_update": None,
            }
        },
        "error_rate_states": {},
        "pattern_states": {},
        "active_alerts": {
            alert_id: alert.to_dict()
        },
        "acknowledged_alerts": {},
        "resolved_alerts": [],
        "threshold_overrides": {},
        "suppression_rule_stats": {},
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }
    
    with open(state_file, 'w') as f:
        json.dump(state_data, f, indent=2)


def test_threshold_adjustment():
    """测试问题2: 自适应阈值调整"""
    print("=== 测试问题2: 自适应阈值调整 ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        state_file = tmpdir / "state.json"
        alert_file = tmpdir / "alerts.json"
        feedback_file = tmpdir / "feedback.jsonl"
        
        alert_id = "test-alert-id-12345"
        create_test_state_file(state_file, alert_id)
        
        # 直接创建AnomalyDetectionConfig
        from log_sanitizer.config import (
            AnomalyDetectionAlgorithmsConfig,
            FrequencyAlgorithmConfig,
            ErrorRateAlgorithmConfig,
            PatternAlgorithmConfig,
        )
        
        config = AnomalyDetectionConfig(
            enabled=True,
            state_file=str(state_file),
            alert_file=str(alert_file),
            min_samples=1,
            algorithms=AnomalyDetectionAlgorithmsConfig(
                frequency=FrequencyAlgorithmConfig(
                    threshold_multiplier='auto',
                    initial_threshold_multiplier=3.0,
                    weight=1.0,
                ),
                error_rate=ErrorRateAlgorithmConfig(
                    z_score_threshold=2.5,
                    weight=1.0,
                ),
                pattern=PatternAlgorithmConfig(
                    weight=1.0,
                ),
            ),
        )
        
        # 创建feedback文件
        feedback_data = {
            "alert_id": alert_id,
            "is_false_positive": True
        }
        feedback_file.write_text(json.dumps(feedback_data) + "\n")
        
        # 创建引擎
        engine = AnomalyDetectionEngine(config)
        
        # 检查初始状态
        status = engine.get_status()
        print(f"初始threshold_overrides: {status.get('threshold_overrides', {})}")
        
        # 处理feedback
        result = engine.process_feedback(str(feedback_file))
        print(f"Feedback处理结果: {result}")
        
        # 检查阈值是否调整
        status = engine.get_status()
        threshold_overrides = status.get('threshold_overrides', {})
        print(f"调整后threshold_overrides: {threshold_overrides}")
        
        assert result.get('threshold_adjustments', 0) >= 1, f"应该至少调整1次阈值, 实际调整了{result.get('threshold_adjustments', 0)}次"
        assert 'frequency' in threshold_overrides, "应该有frequency的阈值覆盖"
        assert 'test-service' in threshold_overrides.get('frequency', {}), "test-service应该有阈值覆盖"
        
        # 验证阈值上调了5% (3.0 * 1.05 = 3.15)
        expected_threshold = 3.0 * 1.05
        actual_threshold = threshold_overrides['frequency']['test-service']
        assert abs(actual_threshold - expected_threshold) < 0.001, f"阈值应该是{expected_threshold}, 实际是{actual_threshold}"
        
        print(f"✓ 阈值正确调整为 {actual_threshold}")
        
        print()


def test_alerts_filter_by_state():
    """测试问题3: anomaly alerts按state筛选"""
    print("=== 测试问题3: anomaly alerts按state筛选 ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        state_file = tmpdir / "state.json"
        alert_file = tmpdir / "alerts.json"
        
        alert_id = "test-alert-id-67890"
        create_test_state_file(state_file, alert_id)
        
        # 直接创建AnomalyDetectionConfig
        from log_sanitizer.config import (
            AnomalyDetectionAlgorithmsConfig,
            FrequencyAlgorithmConfig,
            ErrorRateAlgorithmConfig,
            PatternAlgorithmConfig,
        )
        
        config = AnomalyDetectionConfig(
            enabled=True,
            state_file=str(state_file),
            alert_file=str(alert_file),
            min_samples=1,
            algorithms=AnomalyDetectionAlgorithmsConfig(
                frequency=FrequencyAlgorithmConfig(
                    threshold_multiplier=3.0,
                    weight=1.0,
                ),
                error_rate=ErrorRateAlgorithmConfig(
                    z_score_threshold=2.5,
                    weight=1.0,
                ),
                pattern=PatternAlgorithmConfig(
                    weight=1.0,
                ),
            ),
        )
        
        # 创建引擎
        engine = AnomalyDetectionEngine(config)
        
        # 测试获取active告警
        from log_sanitizer.models import AlertStatus
        
        active_alerts = engine.get_alerts(status=AlertStatus.ACTIVE)
        print(f"找到active告警数量: {len(active_alerts)}")
        
        assert len(active_alerts) == 1, f"应该找到1个active告警, 实际找到{len(active_alerts)}个"
        assert active_alerts[0].id == alert_id, f"告警ID应该是{alert_id}, 实际是{active_alerts[0].id}"
        assert active_alerts[0].status == AlertStatus.ACTIVE, f"告警状态应该是ACTIVE, 实际是{active_alerts[0].status}"
        
        print(f"✓ 正确找到active告警: {active_alerts[0].id}")
        
        # 测试获取acknowledged告警（应该为空）
        ack_alerts = engine.get_alerts(status=AlertStatus.ACKNOWLEDGED)
        assert len(ack_alerts) == 0, f"acknowledged告警应该为空, 实际有{len(ack_alerts)}个"
        print("✓ acknowledged告警为空")
        
        # 测试获取所有告警
        all_alerts = engine.get_alerts()
        assert len(all_alerts) == 1, f"应该找到1个告警, 实际找到{len(all_alerts)}个"
        print("✓ 获取所有告警正确")
        
        print()


def test_feedback_status_change():
    """测试feedback中的status change"""
    print("=== 测试Feedback状态变更 ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        state_file = tmpdir / "state.json"
        alert_file = tmpdir / "alerts.json"
        
        alert_id = "test-alert-status"
        create_test_state_file(state_file, alert_id)
        
        # 直接创建AnomalyDetectionConfig
        from log_sanitizer.config import (
            AnomalyDetectionAlgorithmsConfig,
            FrequencyAlgorithmConfig,
            ErrorRateAlgorithmConfig,
            PatternAlgorithmConfig,
        )
        
        config = AnomalyDetectionConfig(
            enabled=True,
            state_file=str(state_file),
            alert_file=str(alert_file),
            min_samples=1,
            algorithms=AnomalyDetectionAlgorithmsConfig(
                frequency=FrequencyAlgorithmConfig(
                    threshold_multiplier=3.0,
                    weight=1.0,
                ),
                error_rate=ErrorRateAlgorithmConfig(
                    z_score_threshold=2.5,
                    weight=1.0,
                ),
                pattern=PatternAlgorithmConfig(
                    weight=1.0,
                ),
            ),
        )
        
        # 创建feedback文件 - acknowledge
        feedback_file = tmpdir / "feedback.jsonl"
        feedback_lines = [
            json.dumps({"alert_id": alert_id, "action": "acknowledge"}) + "\n",
        ]
        feedback_file.write_text("".join(feedback_lines))
        
        engine = AnomalyDetectionEngine(config)
        
        # 处理feedback
        result = engine.process_feedback(str(feedback_file))
        print(f"Feedback处理结果: {result}")
        
        assert result.get('status_changes', 0) == 1, f"应该有1次状态变更, 实际{result.get('status_changes', 0)}次"
        
        # 检查状态是否变更
        from log_sanitizer.models import AlertStatus
        active_alerts = engine.get_alerts(status=AlertStatus.ACTIVE)
        ack_alerts = engine.get_alerts(status=AlertStatus.ACKNOWLEDGED)
        
        assert len(active_alerts) == 0, f"active告警应该为空, 实际{len(active_alerts)}个"
        assert len(ack_alerts) == 1, f"acknowledged告警应该有1个, 实际{len(ack_alerts)}个"
        assert ack_alerts[0].status == AlertStatus.ACKNOWLEDGED
        
        print("✓ 状态变更正确: active → acknowledged")
        
        print()


if __name__ == "__main__":
    print("=" * 60)
    print("异常检测引擎Bug修复验证测试")
    print("=" * 60)
    print()
    
    try:
        test_pending_alert_delay_seconds()
        test_threshold_adjustment()
        test_alerts_filter_by_state()
        test_feedback_status_change()
        
        print("=" * 60)
        print("✓ 所有测试通过!")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n✗ 测试失败: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ 发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
