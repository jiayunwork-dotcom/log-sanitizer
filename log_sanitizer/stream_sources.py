import os
import sys
import threading
import time
import codecs
from typing import Optional, Callable, List, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class TailFileState:
    file_path: str
    inode: int
    offset: int
    file_size: int


class StreamInputSource:
    def __init__(self, queue_put_callback: Callable[[str, str], None],
                 stop_event: threading.Event,
                 encoding: str = "utf-8"):
        self._queue_put = queue_put_callback
        self._stop_event = stop_event
        self.encoding = encoding
        self._lines_read = 0
        self._lock = threading.Lock()

    @property
    def lines_read(self) -> int:
        with self._lock:
            return self._lines_read

    def _increment_lines(self) -> None:
        with self._lock:
            self._lines_read += 1

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        self._stop_event.set()


class PipeInputSource(StreamInputSource):
    def __init__(self, queue_put_callback: Callable[[str, str], None],
                 stop_event: threading.Event,
                 encoding: str = "utf-8",
                 buffer_size: int = 1000):
        super().__init__(queue_put_callback, stop_event, encoding)
        self.buffer_size = buffer_size
        self._thread: Optional[threading.Thread] = None
        self._eof_reached = threading.Event()

    @property
    def eof_reached(self) -> bool:
        return self._eof_reached.is_set()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout=timeout)

    def _read_loop(self) -> None:
        try:
            buffer = ''
            decoder = codecs.getincrementaldecoder(self.encoding)(errors='replace')
            
            while not self._stop_event.is_set():
                chunk = sys.stdin.buffer.read(65536)
                
                if not chunk:
                    remaining = decoder.decode(b'', final=True)
                    if remaining:
                        lines = remaining.splitlines(keepends=True)
                        for line in lines:
                            text_line = line.rstrip('\r\n')
                            if text_line or line.strip():
                                self._queue_put("stdin", text_line)
                                self._increment_lines()
                    self._eof_reached.set()
                    break
                
                buffer += decoder.decode(chunk, final=False)
                
                while True:
                    newline_pos = -1
                    newline_len = 0
                    
                    if '\r\n' in buffer:
                        newline_pos = buffer.index('\r\n')
                        newline_len = 2
                    elif '\n' in buffer:
                        newline_pos = buffer.index('\n')
                        newline_len = 1
                    elif '\r' in buffer:
                        newline_pos = buffer.index('\r')
                        newline_len = 1
                    
                    if newline_pos < 0:
                        break
                    
                    line = buffer[:newline_pos + newline_len]
                    buffer = buffer[newline_pos + newline_len:]
                    
                    text_line = line.rstrip('\r\n')
                    self._queue_put("stdin", text_line)
                    self._increment_lines()
                    
        except Exception as e:
            print(f"[ERROR] Pipe input error: {e}", file=sys.stderr, flush=True)
            self._eof_reached.set()


class TailInputSource(StreamInputSource):
    def __init__(self, queue_put_callback: Callable[[str, str], None],
                 stop_event: threading.Event,
                 file_paths: List[str],
                 encoding: str = "utf-8",
                 poll_interval: float = 0.5,
                 max_line_length: int = 65536,
                 state_file: Optional[str] = None):
        super().__init__(queue_put_callback, stop_event, encoding)
        self.file_paths = list(file_paths)
        self.poll_interval = poll_interval
        self.max_line_length = max_line_length
        self.state_file = state_file
        self._file_states: Dict[str, TailFileState] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._file_locks: Dict[str, threading.Lock] = {}
        self._file_stop_events: Dict[str, threading.Event] = {}
        self._file_handles: Dict[str, object] = {}
        self._encodings: Dict[str, str] = {}
        
        for path in file_paths:
            self._file_locks[path] = threading.Lock()
            self._file_stop_events[path] = threading.Event()
            self._encodings[path] = encoding
            self._init_file_state(path)
    
    def get_active_files(self) -> List[str]:
        with self._lock:
            return list(self.file_paths)
    
    def add_file(self, file_path: str, encoding: str = "utf-8", from_end: bool = True) -> bool:
        with self._lock:
            if file_path in self.file_paths:
                return False
            
            self.file_paths.append(file_path)
            self._file_locks[file_path] = threading.Lock()
            self._file_stop_events[file_path] = threading.Event()
            self._encodings[file_path] = encoding
            
            if from_end:
                self._init_file_state(file_path)
            else:
                self._file_states[file_path] = TailFileState(
                    file_path=file_path,
                    inode=0,
                    offset=0,
                    file_size=0
                )
            
            t = threading.Thread(
                target=self._tail_file,
                args=(file_path,),
                daemon=True,
                name=f"tail-{os.path.basename(file_path)}"
            )
            self._threads[file_path] = t
            t.start()
            
            print(f"[INFO] Added file to tail: {file_path} (encoding={encoding})", file=sys.stderr, flush=True)
            return True
    
    def remove_file(self, file_path: str) -> bool:
        with self._lock:
            if file_path not in self.file_paths:
                return False
            
            self._file_stop_events[file_path].set()
            
            if file_path in self._threads:
                self._threads[file_path].join(timeout=2.0)
                del self._threads[file_path]
            
            if file_path in self._file_handles:
                try:
                    self._file_handles[file_path].close()
                except Exception:
                    pass
                del self._file_handles[file_path]
            
            if file_path in self.file_paths:
                self.file_paths.remove(file_path)
            if file_path in self._file_states:
                del self._file_states[file_path]
            if file_path in self._file_locks:
                del self._file_locks[file_path]
            if file_path in self._file_stop_events:
                del self._file_stop_events[file_path]
            if file_path in self._encodings:
                del self._encodings[file_path]
            
            print(f"[INFO] Removed file from tail: {file_path}", file=sys.stderr, flush=True)
            return True

    def _init_file_state(self, file_path: str) -> None:
        try:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                self._file_states[file_path] = TailFileState(
                    file_path=file_path,
                    inode=stat.st_ino,
                    offset=stat.st_size,
                    file_size=stat.st_size
                )
            else:
                self._file_states[file_path] = TailFileState(
                    file_path=file_path,
                    inode=0,
                    offset=0,
                    file_size=0
                )
        except OSError as e:
            print(f"[WARNING] Cannot access file {file_path}: {e}", file=sys.stderr, flush=True)
            self._file_states[file_path] = TailFileState(
                file_path=file_path,
                inode=0,
                offset=0,
                file_size=0
            )

    def _get_file_inode(self, file_path: str) -> int:
        try:
            return os.stat(file_path).st_ino
        except OSError:
            return 0

    def _get_file_size(self, file_path: str) -> int:
        try:
            return os.path.getsize(file_path)
        except OSError:
            return 0

    def start(self) -> None:
        for file_path in self.file_paths:
            if file_path not in self._threads or not self._threads[file_path].is_alive():
                t = threading.Thread(
                    target=self._tail_file,
                    args=(file_path,),
                    daemon=True,
                    name=f"tail-{os.path.basename(file_path)}"
                )
                self._threads[file_path] = t
                t.start()

    def join(self, timeout: Optional[float] = None) -> None:
        for t in list(self._threads.values()):
            t.join(timeout=timeout)

    def _read_new_lines(self, file_path: str, handle) -> List[Tuple[str, int]]:
        lines = []
        state = self._file_states[file_path]
        encoding = self._encodings.get(file_path, self.encoding)
        
        try:
            handle.seek(state.offset)
            decoder = codecs.getincrementaldecoder(encoding)(errors='replace')
            buffer = ''
            
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    remaining = decoder.decode(b'', final=True)
                    if remaining:
                        remaining = buffer + remaining
                        if len(remaining) > self.max_line_length:
                            print(
                                f"[WARNING] Line exceeds max length {self.max_line_length} in {file_path}, truncating",
                                file=sys.stderr,
                                flush=True
                            )
                            remaining = remaining[:self.max_line_length]
                        if remaining.strip() or remaining:
                            lines.append((remaining.rstrip('\r\n'), len(remaining.encode(encoding))))
                    break
                
                buffer += decoder.decode(chunk, final=False)
                
                while True:
                    newline_pos = -1
                    newline_len = 0
                    
                    if '\r\n' in buffer:
                        newline_pos = buffer.index('\r\n')
                        newline_len = 2
                    elif '\n' in buffer:
                        newline_pos = buffer.index('\n')
                        newline_len = 1
                    elif '\r' in buffer:
                        newline_pos = buffer.index('\r')
                        newline_len = 1
                    
                    if newline_pos < 0:
                        break
                    
                    if newline_pos > self.max_line_length:
                        print(
                            f"[WARNING] Line exceeds max length {self.max_line_length} in {file_path}, truncating",
                            file=sys.stderr,
                            flush=True
                        )
                        line = buffer[:self.max_line_length]
                        buffer = buffer[newline_pos + newline_len:]
                    else:
                        line = buffer[:newline_pos]
                        buffer = buffer[newline_pos + newline_len:]
                    
                    line_bytes = len(line.encode(encoding)) + newline_len
                    lines.append((line, line_bytes))
                    
        except Exception as e:
            print(f"[ERROR] Error reading {file_path}: {e}", file=sys.stderr, flush=True)
        
        return lines

    def _tail_file(self, file_path: str) -> None:
        current_handle: Optional[object] = None
        
        try:
            file_stop = self._file_stop_events[file_path]
            while not self._stop_event.is_set() and not file_stop.is_set():
                if not os.path.exists(file_path):
                    if current_handle:
                        try:
                            current_handle.close()
                        except Exception:
                            pass
                        current_handle = None
                    if file_stop.wait(timeout=self.poll_interval):
                        break
                    continue
                
                try:
                    stat = os.stat(file_path)
                except OSError:
                    if file_stop.wait(timeout=self.poll_interval):
                        break
                    continue
                
                with self._file_locks[file_path]:
                    if file_stop.is_set():
                        break
                    state = self._file_states[file_path]
                    
                    if current_handle is None:
                        try:
                            current_handle = open(file_path, 'rb')
                            self._file_handles[file_path] = current_handle
                        except OSError as e:
                            print(f"[WARNING] Cannot open {file_path}: {e}", file=sys.stderr, flush=True)
                            if file_stop.wait(timeout=self.poll_interval):
                                break
                            continue
                    
                    if state.inode == 0:
                        state.inode = stat.st_ino
                        state.offset = stat.st_size
                        state.file_size = stat.st_size
                        current_handle.seek(state.offset)
                    elif stat.st_ino != state.inode:
                        print(f"[INFO] File {file_path} rotated (inode changed), reopening from beginning", file=sys.stderr, flush=True)
                        try:
                            current_handle.close()
                        except Exception:
                            pass
                        current_handle = open(file_path, 'rb')
                        self._file_handles[file_path] = current_handle
                        state.inode = stat.st_ino
                        state.offset = 0
                        state.file_size = stat.st_size
                    elif stat.st_size < state.file_size:
                        print(f"[INFO] File {file_path} truncated, reopening from beginning", file=sys.stderr, flush=True)
                        try:
                            current_handle.close()
                        except Exception:
                            pass
                        current_handle = open(file_path, 'rb')
                        self._file_handles[file_path] = current_handle
                        state.offset = 0
                        state.file_size = stat.st_size
                    else:
                        state.file_size = stat.st_size
                    
                    if state.offset < stat.st_size:
                        lines = self._read_new_lines(file_path, current_handle)
                        for line_text, line_bytes in lines:
                            if file_stop.is_set() or self._stop_event.is_set():
                                break
                            self._queue_put(file_path, line_text)
                            self._increment_lines()
                            state.offset += line_bytes
                    
                if file_stop.wait(timeout=self.poll_interval):
                    break
                
        except Exception as e:
            print(f"[ERROR] Tail error for {file_path}: {e}", file=sys.stderr, flush=True)
        finally:
            if current_handle:
                try:
                    current_handle.close()
                except Exception:
                    pass
            if file_path in self._file_handles:
                del self._file_handles[file_path]

    def get_states(self) -> Dict[str, TailFileState]:
        with self._lock:
            return dict(self._file_states)
