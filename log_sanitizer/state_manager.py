import os
import json
import stat
from datetime import datetime, timezone
from typing import Optional, Dict
from .models import StateFile, FileState


class StateManager:
    def __init__(self, state_file_path: Optional[str] = None):
        self.state_file_path = state_file_path
        self._state: StateFile = StateFile()
        self._dirty = False
        if state_file_path:
            self._load_state()
    
    def _load_state(self) -> None:
        if not self.state_file_path or not os.path.exists(self.state_file_path):
            return
        
        try:
            with open(self.state_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self._state.version = data.get('version', '1.0')
            self._state.last_updated = datetime.fromisoformat(
                data['last_updated']
            ) if data.get('last_updated') else None
            
            files_data = data.get('files', {})
            for file_path, file_state_data in files_data.items():
                file_state = FileState(
                    file_path=file_state_data.get('file_path', file_path),
                    inode=file_state_data.get('inode', 0),
                    last_offset=file_state_data.get('last_offset', 0),
                    file_size=file_state_data.get('file_size', 0),
                    last_processed_time=datetime.fromisoformat(
                        file_state_data['last_processed_time']
                    ) if file_state_data.get('last_processed_time') else None,
                )
                self._state.files[file_path] = file_state
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"Warning: Failed to load state file, starting fresh: {e}", flush=True)
            self._state = StateFile()
    
    def get_file_state(self, file_path: str) -> Optional[FileState]:
        abs_path = os.path.abspath(file_path)
        return self._state.files.get(abs_path)
    
    def should_start_from_breakpoint(self, file_path: str) -> int:
        abs_path = os.path.abspath(file_path)
        file_state = self._state.files.get(abs_path)
        
        if not file_state:
            return 0
        
        if not os.path.exists(abs_path):
            return 0
        
        try:
            stat_result = os.stat(abs_path)
            current_inode = stat_result.st_ino
            current_size = stat_result.st_size
            
            if current_inode != file_state.inode:
                return 0
            
            if current_size < file_state.last_offset:
                return 0
            
            return file_state.last_offset
        except OSError:
            return 0
    
    def update_file_state(
        self,
        file_path: str,
        offset: int,
        file_size: Optional[int] = None,
    ) -> None:
        abs_path = os.path.abspath(file_path)
        
        try:
            stat_result = os.stat(abs_path)
            current_inode = stat_result.st_ino
            if file_size is None:
                file_size = stat_result.st_size
        except OSError:
            return
        
        self._state.files[abs_path] = FileState(
            file_path=abs_path,
            inode=current_inode,
            last_offset=offset,
            file_size=file_size,
            last_processed_time=datetime.now(timezone.utc),
        )
        self._dirty = True
    
    def save(self) -> None:
        if not self.state_file_path or not self._dirty:
            return
        
        self._state.last_updated = datetime.now(timezone.utc)
        
        state_dir = os.path.dirname(os.path.abspath(self.state_file_path))
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)
        
        data = {
            'version': self._state.version,
            'last_updated': self._state.last_updated.isoformat() if self._state.last_updated else None,
            'files': {},
        }
        
        for file_path, file_state in self._state.files.items():
            data['files'][file_path] = {
                'file_path': file_state.file_path,
                'inode': file_state.inode,
                'last_offset': file_state.last_offset,
                'file_size': file_state.file_size,
                'last_processed_time': file_state.last_processed_time.isoformat()
                    if file_state.last_processed_time else None,
            }
        
        temp_path = self.state_file_path + '.tmp'
        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            os.replace(temp_path, self.state_file_path)
            os.chmod(self.state_file_path, stat.S_IRUSR | stat.S_IWUSR)
            self._dirty = False
        except Exception as e:
            print(f"Warning: Failed to save state file: {e}", flush=True)
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
    
    def close(self) -> None:
        self.save()
