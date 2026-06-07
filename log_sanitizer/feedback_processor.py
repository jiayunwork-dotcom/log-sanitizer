import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from .models import (
    AlertEvent,
    AlertStatus,
    AlertType,
    DetectorName,
    FeedbackAction,
)
from .config import (
    AnomalyDetectionConfig,
    FrequencyAlgorithmConfig,
    ErrorRateAlgorithmConfig,
)


class FeedbackProcessor:
    def __init__(self, config: AnomalyDetectionConfig):
        self.config = config
        self._lock = threading.Lock()
        self._active_alerts: Dict[str, AlertEvent] = {}
        self._acknowledged_alerts: Dict[str, AlertEvent] = {}
        self._resolved_alerts: List[AlertEvent] = []
        self._threshold_overrides: Dict[str, Dict[str, float]] = {}
        self._frequency_detector = None
        self._error_rate_detector = None
        self._status_change_callback = None

    def set_detectors(self, frequency_detector, error_rate_detector) -> None:
        self._frequency_detector = frequency_detector
        self._error_rate_detector = error_rate_detector

    def set_status_change_callback(self, callback) -> None:
        self._status_change_callback = callback

    def load_alert_states(self, active: Dict[str, AlertEvent],
                         acknowledged: Dict[str, AlertEvent],
                         resolved: List[AlertEvent]) -> None:
        with self._lock:
            self._active_alerts = dict(active)
            self._acknowledged_alerts = dict(acknowledged)
            self._resolved_alerts = list(resolved)

    def load_threshold_overrides(self, overrides: Dict[str, Dict[str, float]]) -> None:
        with self._lock:
            self._threshold_overrides = dict(overrides)

    def get_alert_states(self) -> Tuple[Dict[str, AlertEvent], Dict[str, AlertEvent], List[AlertEvent]]:
        with self._lock:
            return (
                dict(self._active_alerts),
                dict(self._acknowledged_alerts),
                list(self._resolved_alerts),
            )

    def get_threshold_overrides(self) -> Dict[str, Dict[str, float]]:
        with self._lock:
            return dict(self._threshold_overrides)

    def register_alert(self, alert: AlertEvent) -> None:
        with self._lock:
            self._active_alerts[alert.id] = alert
            self._cleanup_resolved_alerts()

    def process_feedback_file(self, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Feedback file not found: {file_path}")

        total_processed = 0
        threshold_adjustments = 0
        status_changes = 0
        errors = 0

        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    feedback = json.loads(line)
                    result = self._process_single_feedback(feedback)
                    total_processed += 1
                    if result.get('threshold_adjusted'):
                        threshold_adjustments += 1
                    if result.get('status_changed'):
                        status_changes += 1
                except Exception as e:
                    errors += 1
                    print(f"Error processing feedback line {line_num}: {e}", flush=True)

        return {
            'total_processed': total_processed,
            'threshold_adjustments': threshold_adjustments,
            'status_changes': status_changes,
            'errors': errors,
        }

    def _process_single_feedback(self, feedback: Dict[str, Any]) -> Dict[str, Any]:
        alert_id = feedback.get('alert_id')
        if not alert_id:
            raise ValueError("Missing alert_id in feedback")

        result = {'threshold_adjusted': False, 'status_changed': False}

        if 'is_false_positive' in feedback:
            is_fp = feedback['is_false_positive']
            if self._adjust_threshold_from_feedback(alert_id, is_fp):
                result['threshold_adjusted'] = True

        if 'action' in feedback:
            action_str = feedback['action']
            try:
                action = FeedbackAction(action_str.lower())
            except ValueError:
                raise ValueError(f"Invalid action: {action_str}")

            if self._process_status_change(alert_id, action):
                result['status_changed'] = True

        return result

    def _get_alert_source_and_detector(self, alert_id: str) -> Optional[Tuple[str, DetectorName]]:
        alert = self._active_alerts.get(alert_id)
        if not alert:
            alert = self._acknowledged_alerts.get(alert_id)
        if not alert:
            for a in self._resolved_alerts:
                if a.id == alert_id:
                    alert = a
                    break

        if alert:
            return (alert.source, alert.detector)
        return None

    def _adjust_threshold_from_feedback(self, alert_id: str, is_false_positive: bool) -> bool:
        info = self._get_alert_source_and_detector(alert_id)
        if not info:
            return False

        source, detector = info
        adjusted = False

        if detector == DetectorName.FREQUENCY and self._frequency_detector:
            config: FrequencyAlgorithmConfig = self._frequency_detector.config
            base_threshold = config.threshold_multiplier
            if base_threshold == 'auto':
                base_threshold = config.initial_threshold_multiplier

            current = self._frequency_detector.threshold_overrides.get(source, base_threshold)

            if is_false_positive:
                new_val = current * 1.05
                upper_bound = config.initial_threshold_multiplier * 3.0
                new_val = min(new_val, upper_bound)
            else:
                new_val = current * 0.98
                lower_bound = config.initial_threshold_multiplier * 0.3
                new_val = max(new_val, lower_bound)

            self._frequency_detector.set_threshold_override(source, new_val)
            self._threshold_overrides.setdefault('frequency', {})[source] = new_val
            adjusted = True

        elif detector == DetectorName.ERROR_RATE and self._error_rate_detector:
            config: ErrorRateAlgorithmConfig = self._error_rate_detector.config
            base_threshold = config.z_score_threshold
            if base_threshold == 'auto':
                base_threshold = config.initial_z_score_threshold

            current = self._error_rate_detector.threshold_overrides.get(source, base_threshold)

            if is_false_positive:
                new_val = current * 1.05
                upper_bound = config.initial_z_score_threshold * 3.0
                new_val = min(new_val, upper_bound)
            else:
                new_val = current * 0.98
                lower_bound = config.initial_z_score_threshold * 0.3
                new_val = max(new_val, lower_bound)

            self._error_rate_detector.set_threshold_override(source, new_val)
            self._threshold_overrides.setdefault('error_rate', {})[source] = new_val
            adjusted = True

        return adjusted

    def _process_status_change(self, alert_id: str, action: FeedbackAction) -> bool:
        with self._lock:
            alert = None
            source_container = None

            if alert_id in self._active_alerts:
                alert = self._active_alerts[alert_id]
                source_container = 'active'
            elif alert_id in self._acknowledged_alerts:
                alert = self._acknowledged_alerts[alert_id]
                source_container = 'acknowledged'

            if not alert:
                return False

            now = datetime.now(timezone.utc)
            old_status = alert.status
            changed = False

            if action == FeedbackAction.ACKNOWLEDGE:
                if alert.status == AlertStatus.ACTIVE:
                    alert.status = AlertStatus.ACKNOWLEDGED
                    alert.acknowledged_at = now
                    del self._active_alerts[alert_id]
                    self._acknowledged_alerts[alert_id] = alert
                    changed = True

            elif action == FeedbackAction.RESOLVE:
                if alert.status in (AlertStatus.ACTIVE, AlertStatus.ACKNOWLEDGED):
                    alert.status = AlertStatus.RESOLVED
                    alert.resolved_at = now

                    if source_container == 'active':
                        del self._active_alerts[alert_id]
                    else:
                        del self._acknowledged_alerts[alert_id]

                    self._resolved_alerts.append(alert)
                    self._cleanup_resolved_alerts()
                    changed = True

                    if changed and self._status_change_callback:
                        try:
                            self._status_change_callback(alert, old_status, AlertStatus.RESOLVED)
                        except Exception as e:
                            print(f"Error in status change callback: {e}", flush=True)

            elif action == FeedbackAction.REOPEN:
                if alert.status == AlertStatus.RESOLVED:
                    alert.status = AlertStatus.ACTIVE
                    alert.resolved_at = None
                    self._resolved_alerts = [a for a in self._resolved_alerts if a.id != alert_id]
                    self._active_alerts[alert_id] = alert
                    changed = True
                elif alert.status == AlertStatus.ACKNOWLEDGED:
                    alert.status = AlertStatus.ACTIVE
                    alert.acknowledged_at = None
                    del self._acknowledged_alerts[alert_id]
                    self._active_alerts[alert_id] = alert
                    changed = True

            return changed

    def _cleanup_resolved_alerts(self) -> None:
        max_resolved = self.config.max_resolved_alerts
        if len(self._resolved_alerts) > max_resolved:
            self._resolved_alerts.sort(key=lambda a: a.resolved_at or a.timestamp)
            self._resolved_alerts = self._resolved_alerts[-max_resolved:]

    def get_status_counts(self) -> Dict[str, int]:
        with self._lock:
            return {
                'active': len(self._active_alerts),
                'acknowledged': len(self._acknowledged_alerts),
                'resolved': len(self._resolved_alerts),
            }

    def get_alerts_by_status(self, status: AlertStatus) -> List[AlertEvent]:
        with self._lock:
            if status == AlertStatus.ACTIVE:
                return list(self._active_alerts.values())
            elif status == AlertStatus.ACKNOWLEDGED:
                return list(self._acknowledged_alerts.values())
            elif status == AlertStatus.RESOLVED:
                return list(self._resolved_alerts)
            return []

    def get_all_alerts(self) -> List[AlertEvent]:
        with self._lock:
            all_alerts = []
            all_alerts.extend(self._active_alerts.values())
            all_alerts.extend(self._acknowledged_alerts.values())
            all_alerts.extend(self._resolved_alerts)
            return all_alerts
