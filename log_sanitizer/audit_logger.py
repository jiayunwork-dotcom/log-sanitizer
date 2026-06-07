import os
import json
import stat
from datetime import datetime, timezone
from typing import Optional, List
from .models import AuditLogEntry


class AuditLogger:
    def __init__(self, audit_file_path: Optional[str] = None, enabled: bool = False):
        self.audit_file_path = audit_file_path
        self.enabled = enabled and audit_file_path is not None
        self._file_handle = None
        self._init_file()
    
    def _init_file(self) -> None:
        if not self.enabled or not self.audit_file_path:
            return
        
        audit_dir = os.path.dirname(os.path.abspath(self.audit_file_path))
        if audit_dir:
            os.makedirs(audit_dir, exist_ok=True)
        
        self._file_handle = open(
            self.audit_file_path,
            'a',
            encoding='utf-8',
            buffering=1,
        )
        
        try:
            os.chmod(self.audit_file_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    
    def log(
        self,
        line_number: int,
        field_path: str,
        original_value: str,
        sanitized_value: str,
        rule_name: str,
        timestamp: Optional[datetime] = None,
    ) -> None:
        if not self.enabled or not self._file_handle:
            return
        
        if original_value == sanitized_value:
            return
        
        entry = AuditLogEntry(
            line_number=line_number,
            field_path=field_path,
            original_value=original_value,
            sanitized_value=sanitized_value,
            rule_name=rule_name,
            timestamp=timestamp or datetime.now(timezone.utc),
        )
        
        entry_dict = {
            'line_number': entry.line_number,
            'field_path': entry.field_path,
            'original_value': entry.original_value,
            'sanitized_value': entry.sanitized_value,
            'rule_name': entry.rule_name,
            'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
        }
        
        try:
            self._file_handle.write(json.dumps(entry_dict, ensure_ascii=False) + '\n')
        except Exception as e:
            print(f"Warning: Failed to write audit log: {e}", flush=True)
    
    def log_batch(self, entries: List[AuditLogEntry]) -> None:
        if not self.enabled or not self._file_handle:
            return
        
        for entry in entries:
            if entry.original_value == entry.sanitized_value:
                continue
            
            entry_dict = {
                'line_number': entry.line_number,
                'field_path': entry.field_path,
                'original_value': entry.original_value,
                'sanitized_value': entry.sanitized_value,
                'rule_name': entry.rule_name,
                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
            }
            
            try:
                self._file_handle.write(json.dumps(entry_dict, ensure_ascii=False) + '\n')
            except Exception as e:
                print(f"Warning: Failed to write audit log: {e}", flush=True)
    
    def close(self) -> None:
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None
    
    def __enter__(self) -> 'AuditLogger':
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
