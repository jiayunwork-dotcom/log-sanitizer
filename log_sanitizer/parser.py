import json
import re
import os
from datetime import datetime
from typing import Optional, List, Pattern, Dict, Any, Tuple
from .models import LogEntry, LogFormat, LogLevel
from .utils import (
    parse_timestamp,
    parse_log_level,
    APACHE_COMBINED_PATTERN,
    SYSLOG_3164_PATTERN,
    SYSLOG_5424_PATTERN,
    PLAINTEXT_PATTERN,
    IPV4_PATTERN
)


class LogParser:
    def __init__(
        self,
        format: LogFormat = LogFormat.AUTO,
        custom_pattern: Optional[str] = None,
        custom_field_names: Optional[Dict[str, str]] = None,
        source: str = ""
    ):
        self.format = format
        self.source = source
        self.custom_pattern: Optional[Pattern] = None
        self.custom_field_names = custom_field_names or {}
        self._detected_format: Optional[LogFormat] = None
        
        if custom_pattern:
            try:
                self.custom_pattern = re.compile(custom_pattern)
            except re.error as e:
                raise ValueError(f"Invalid custom regex pattern: {e}")

    def parse_line(self, line: str) -> LogEntry:
        line = line.rstrip('\n').rstrip('\r')
        entry = LogEntry(raw=line, source=self.source)
        
        if not line.strip():
            entry.is_parseable = False
            entry.parse_error = "Empty line"
            return entry

        try:
            if self.format == LogFormat.AUTO:
                entry = self._auto_detect_parse(line, entry)
            elif self.format == LogFormat.JSON:
                entry = self._parse_json(line, entry)
            elif self.format in (LogFormat.APACHE, LogFormat.NGINX):
                entry = self._parse_apache_nginx(line, entry)
            elif self.format == LogFormat.SYSLOG:
                entry = self._parse_syslog(line, entry)
            elif self.format == LogFormat.PLAINTEXT:
                entry = self._parse_plaintext(line, entry)
            elif self.format == LogFormat.CUSTOM:
                entry = self._parse_custom(line, entry)
        except Exception as e:
            entry.is_parseable = False
            entry.parse_error = str(e)
            entry.format = LogFormat.UNPARSEABLE

        if not entry.is_parseable:
            entry.format = LogFormat.UNPARSEABLE

        return entry

    def _auto_detect_parse(self, line: str, entry: LogEntry) -> LogEntry:
        if self._detected_format:
            return self._parse_by_format(line, entry, self._detected_format)

        parsers = [
            (LogFormat.JSON, self._parse_json),
            (LogFormat.APACHE, self._parse_apache_nginx),
            (LogFormat.SYSLOG, self._parse_syslog),
            (LogFormat.PLAINTEXT, self._parse_plaintext),
        ]

        for fmt, parser in parsers:
            try:
                test_entry = LogEntry(raw=line, source=self.source)
                result = parser(line, test_entry)
                if result.is_parseable:
                    self._detected_format = fmt
                    return result
            except Exception:
                continue

        if self.custom_pattern:
            try:
                result = self._parse_custom(line, entry)
                if result.is_parseable:
                    self._detected_format = LogFormat.CUSTOM
                    return result
            except Exception:
                pass

        entry.is_parseable = False
        entry.parse_error = "Unable to detect log format"
        return entry

    def _parse_by_format(self, line: str, entry: LogEntry, fmt: LogFormat) -> LogEntry:
        parsers = {
            LogFormat.JSON: self._parse_json,
            LogFormat.APACHE: self._parse_apache_nginx,
            LogFormat.NGINX: self._parse_apache_nginx,
            LogFormat.SYSLOG: self._parse_syslog,
            LogFormat.PLAINTEXT: self._parse_plaintext,
            LogFormat.CUSTOM: self._parse_custom,
        }
        return parsers[fmt](line, entry)

    def _parse_json(self, line: str, entry: LogEntry) -> LogEntry:
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                entry.is_parseable = False
                entry.parse_error = "JSON is not an object"
                return entry

            entry.format = LogFormat.JSON
            
            timestamp = self._extract_timestamp(data)
            if timestamp:
                entry.timestamp = timestamp
            
            level = self._extract_level(data)
            if level:
                entry.level = level
            
            message = self._extract_message(data)
            if message:
                entry.message = message
            
            standard_fields = {'timestamp', 'time', 'date', 'level', 'log_level', 'severity', 'message', 'msg', 'content'}
            entry.extra = {k: v for k, v in data.items() if k.lower() not in standard_fields}
            
            entry.is_parseable = True
            return entry
        except json.JSONDecodeError as e:
            entry.is_parseable = False
            entry.parse_error = f"JSON parse error: {e}"
            return entry

    def _extract_timestamp(self, data: Dict[str, Any]) -> Optional[datetime]:
        timestamp_fields = ['timestamp', 'time', 'date', '@timestamp', 'ts', 'datetime']
        for field in timestamp_fields:
            if field in data and data[field]:
                ts = parse_timestamp(str(data[field]))
                if ts:
                    return ts
        return None

    def _extract_level(self, data: Dict[str, Any]) -> Optional[LogLevel]:
        level_fields = ['level', 'log_level', 'severity', 'loglevel', 'priority']
        for field in level_fields:
            if field in data and data[field]:
                level = parse_log_level(str(data[field]))
                if level != LogLevel.UNKNOWN:
                    return level
        return None

    def _extract_message(self, data: Dict[str, Any]) -> str:
        message_fields = ['message', 'msg', 'content', 'text', 'log']
        for field in message_fields:
            if field in data and data[field]:
                return str(data[field])
        return json.dumps(data, ensure_ascii=False)

    def _parse_apache_nginx(self, line: str, entry: LogEntry) -> LogEntry:
        match = APACHE_COMBINED_PATTERN.match(line)
        if not match:
            entry.is_parseable = False
            entry.parse_error = "Not in Apache/Nginx combined format"
            return entry

        entry.format = LogFormat.APACHE
        
        groups = match.groupdict()
        timestamp = parse_timestamp(groups.get('timestamp', ''))
        if timestamp:
            entry.timestamp = timestamp
        
        status = groups.get('status', '')
        if status:
            try:
                status_code = int(status)
                if status_code >= 500:
                    entry.level = LogLevel.ERROR
                elif status_code >= 400:
                    entry.level = LogLevel.WARN
                else:
                    entry.level = LogLevel.INFO
            except ValueError:
                pass
        
        method = groups.get('method', '')
        path = groups.get('path', '')
        protocol = groups.get('protocol', '')
        entry.message = f"{method} {path} {protocol}"
        
        entry.extra = {
            'ip': groups.get('ip', ''),
            'status': status,
            'size': groups.get('size', ''),
            'referer': groups.get('referer', ''),
            'user_agent': groups.get('user_agent', ''),
        }
        
        entry.is_parseable = True
        return entry

    def _parse_syslog(self, line: str, entry: LogEntry) -> LogEntry:
        if line.startswith('<'):
            match = SYSLOG_5424_PATTERN.match(line)
            if match:
                return self._parse_syslog_5424(match, entry)
            
            match = SYSLOG_3164_PATTERN.match(line)
            if match:
                return self._parse_syslog_3164(match, entry)
        
        entry.is_parseable = False
        entry.parse_error = "Not in syslog format"
        return entry

    def _parse_syslog_3164(self, match: re.Match, entry: LogEntry) -> LogEntry:
        entry.format = LogFormat.SYSLOG
        groups = match.groupdict()
        
        timestamp_str = groups.get('timestamp', '')
        timestamp = parse_timestamp(timestamp_str)
        if timestamp:
            from datetime import datetime
            now = datetime.now()
            timestamp = timestamp.replace(year=now.year)
            if timestamp.tzinfo is None:
                from datetime import timezone
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            entry.timestamp = timestamp
        
        priority = int(groups.get('priority', '0'))
        severity = priority % 8
        if severity <= 2:
            entry.level = LogLevel.ERROR
        elif severity <= 4:
            entry.level = LogLevel.WARN
        elif severity <= 6:
            entry.level = LogLevel.INFO
        else:
            entry.level = LogLevel.DEBUG
        
        entry.message = groups.get('message', '')
        entry.extra = {
            'hostname': groups.get('hostname', ''),
            'tag': groups.get('tag', ''),
            'pid': groups.get('pid', ''),
            'priority': priority,
        }
        
        entry.is_parseable = True
        return entry

    def _parse_syslog_5424(self, match: re.Match, entry: LogEntry) -> LogEntry:
        entry.format = LogFormat.SYSLOG
        groups = match.groupdict()
        
        timestamp_str = groups.get('timestamp', '')
        if timestamp_str and timestamp_str != '-':
            timestamp = parse_timestamp(timestamp_str)
            if timestamp:
                entry.timestamp = timestamp
        
        priority = int(groups.get('priority', '0'))
        severity = priority % 8
        if severity <= 2:
            entry.level = LogLevel.ERROR
        elif severity <= 4:
            entry.level = LogLevel.WARN
        elif severity <= 6:
            entry.level = LogLevel.INFO
        else:
            entry.level = LogLevel.DEBUG
        
        entry.message = groups.get('message', '')
        entry.extra = {
            'version': groups.get('version', ''),
            'hostname': groups.get('hostname', ''),
            'appname': groups.get('appname', ''),
            'procid': groups.get('procid', ''),
            'msgid': groups.get('msgid', ''),
            'structured_data': groups.get('structured_data', ''),
            'priority': priority,
        }
        
        entry.is_parseable = True
        return entry

    def _parse_plaintext(self, line: str, entry: LogEntry) -> LogEntry:
        match = PLAINTEXT_PATTERN.match(line)
        if match:
            entry.format = LogFormat.PLAINTEXT
            groups = match.groupdict()
            
            timestamp_str = groups.get('timestamp', '')
            timestamp = parse_timestamp(timestamp_str)
            if timestamp:
                entry.timestamp = timestamp
            
            level_str = groups.get('level') or groups.get('level2', '')
            if level_str:
                level = parse_log_level(f"[{level_str}]")
                if level != LogLevel.UNKNOWN:
                    entry.level = level
            
            entry.message = groups.get('message', '')
            entry.is_parseable = True
            return entry
        
        level = parse_log_level(line)
        timestamp = parse_timestamp(line)
        
        if timestamp or level != LogLevel.UNKNOWN:
            entry.format = LogFormat.PLAINTEXT
            if timestamp:
                entry.timestamp = timestamp
            if level != LogLevel.UNKNOWN:
                entry.level = level
            entry.message = line
            entry.is_parseable = True
            return entry
        
        entry.is_parseable = False
        entry.parse_error = "Not in plaintext log format"
        return entry

    def _parse_custom(self, line: str, entry: LogEntry) -> LogEntry:
        if not self.custom_pattern:
            entry.is_parseable = False
            entry.parse_error = "No custom pattern defined"
            return entry
        
        match = self.custom_pattern.match(line)
        if not match:
            entry.is_parseable = False
            entry.parse_error = "Does not match custom pattern"
            return entry
        
        entry.format = LogFormat.CUSTOM
        
        groups = match.groupdict()
        
        timestamp_field = self.custom_field_names.get('timestamp', 'timestamp')
        if timestamp_field in groups and groups[timestamp_field]:
            ts = parse_timestamp(str(groups[timestamp_field]))
            if ts:
                entry.timestamp = ts
        
        level_field = self.custom_field_names.get('level', 'level')
        if level_field in groups and groups[level_field]:
            lv = parse_log_level(str(groups[level_field]))
            if lv != LogLevel.UNKNOWN:
                entry.level = lv
        
        message_field = self.custom_field_names.get('message', 'message')
        if message_field in groups and groups[message_field]:
            entry.message = str(groups[message_field])
        else:
            entry.message = line
        
        standard_fields = {timestamp_field, level_field, message_field}
        entry.extra = {k: v for k, v in groups.items() if k not in standard_fields and v}
        
        entry.is_parseable = True
        return entry
