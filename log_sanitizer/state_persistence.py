import os
import json
import stat
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from .models import AnomalyDetectionState
from .anomaly_detectors import FrequencyDetector, ErrorRateDetector, PatternDetector
from .suppression_engine import SuppressionEngine
from .feedback_processor import FeedbackProcessor


class StatePersistence:
    def __init__(self, state_file_path: Optional[str]):
        self.state_file_path = state_file_path
        self._lock = threading.Lock()
        self._dirty = False

    def mark_dirty(self) -> None:
        self._dirty = True

    def save_state(
        self,
        frequency_detector: FrequencyDetector,
        error_rate_detector: ErrorRateDetector,
        pattern_detector: PatternDetector,
        suppression_engine: Optional[SuppressionEngine] = None,
        feedback_processor: Optional[FeedbackProcessor] = None,
        force: bool = False,
    ) -> None:
        if not self.state_file_path:
            return

        if not force and not self._dirty:
            return

        with self._lock:
            try:
                state = AnomalyDetectionState(
                    last_updated=datetime.now(timezone.utc),
                )

                for source, fs in frequency_detector.states.items():
                    state.frequency_states[source] = fs

                for source, ers in error_rate_detector.states.items():
                    state.error_rate_states[source] = ers

                for source, ps in pattern_detector.states.items():
                    state.pattern_states[source] = ps

                if feedback_processor:
                    active, acknowledged, resolved = feedback_processor.get_alert_states()
                    state.active_alerts = active
                    state.acknowledged_alerts = acknowledged
                    state.resolved_alerts = resolved
                    state.threshold_overrides = feedback_processor.get_threshold_overrides()

                if suppression_engine:
                    state.suppression_rule_stats = suppression_engine.to_dict()

                state_dir = os.path.dirname(os.path.abspath(self.state_file_path))
                if state_dir:
                    os.makedirs(state_dir, exist_ok=True)

                data = state.to_dict()

                temp_path = self.state_file_path + '.tmp'
                with open(temp_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                os.replace(temp_path, self.state_file_path)
                os.chmod(self.state_file_path, stat.S_IRUSR | stat.S_IWUSR)
                self._dirty = False

            except Exception as e:
                print(f"Error saving anomaly detection state: {e}", flush=True)
                temp_path = self.state_file_path + '.tmp'
                if os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass

    def load_state(
        self,
        frequency_detector: FrequencyDetector,
        error_rate_detector: ErrorRateDetector,
        pattern_detector: PatternDetector,
        suppression_engine: Optional[SuppressionEngine] = None,
        feedback_processor: Optional[FeedbackProcessor] = None,
    ) -> None:
        if not self.state_file_path or not os.path.exists(self.state_file_path):
            return

        with self._lock:
            try:
                with open(self.state_file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                state = AnomalyDetectionState.from_dict(data)

                freq_states = data.get('frequency_states', {})
                for source, state_dict in freq_states.items():
                    frequency_detector.load_state(source, state_dict)

                err_states = data.get('error_rate_states', {})
                for source, state_dict in err_states.items():
                    error_rate_detector.load_state(source, state_dict)

                pat_states = data.get('pattern_states', {})
                for source, state_dict in pat_states.items():
                    pattern_detector.load_state(source, state_dict)

                if feedback_processor:
                    feedback_processor.load_alert_states(
                        state.active_alerts,
                        state.acknowledged_alerts,
                        state.resolved_alerts,
                    )
                    feedback_processor.load_threshold_overrides(state.threshold_overrides)

                    for source, value in state.threshold_overrides.get('frequency', {}).items():
                        frequency_detector.set_threshold_override(source, value)
                    for source, value in state.threshold_overrides.get('error_rate', {}).items():
                        error_rate_detector.set_threshold_override(source, value)

                if suppression_engine and state.suppression_rule_stats:
                    suppression_engine.load_rule_stats(state.suppression_rule_stats)

                print(f"Anomaly detection state loaded successfully from {self.state_file_path}", flush=True)

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"Warning: Failed to load anomaly detection state, starting fresh: {e}", flush=True)

    def reset_source_state(
        self,
        source: str,
        frequency_detector: FrequencyDetector,
        error_rate_detector: ErrorRateDetector,
        pattern_detector: PatternDetector,
        suppression_engine: Optional[SuppressionEngine] = None,
        feedback_processor: Optional[FeedbackProcessor] = None,
    ) -> None:
        frequency_detector.reset_source(source)
        error_rate_detector.reset_source(source)
        pattern_detector.reset_source(source)
        if source in frequency_detector.threshold_overrides:
            del frequency_detector.threshold_overrides[source]
        if source in error_rate_detector.threshold_overrides:
            del error_rate_detector.threshold_overrides[source]
        self.mark_dirty()
        self.save_state(
            frequency_detector,
            error_rate_detector,
            pattern_detector,
            suppression_engine,
            feedback_processor,
            force=True,
        )

    def get_state(self) -> Optional[Dict[str, Any]]:
        if not self.state_file_path or not os.path.exists(self.state_file_path):
            return None

        try:
            with open(self.state_file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading state file: {e}", flush=True)
            return None
