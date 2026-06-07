import re
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from .models import LogLevel


IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
PHONE_PATTERN = r'(?<!\d)(?:\+86[-\s]?)?1[3-9]\d[-\s]?\d{4}[-\s]?\d{4}(?!\d)'
ID_CARD_PATTERN = r'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b'
BANK_CARD_PATTERN = r'\b\d{16,19}\b'
TOKEN_PATTERN = r'(?:token|access_token|refresh_token|api_key|secret|password|passwd|pwd)[\s:=]+["\']?([^\s&"\',]+)["\']?'
SESSION_PATTERN = r'(?:session_id|sessionid|PHPSESSID|JSESSIONID)[\s:=]+["\']?([^\s&"\',]+)["\']?'
COOKIE_PATTERN = r'(?:Set-Cookie|Cookie):\s*([^\n]+)'

ID_CARD_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
ID_CARD_CHECK_CODES = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']

LOG_LEVEL_PATTERN = re.compile(
    r'\[(DEBUG|TRACE|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL)\]|'
    r'\b(DEBUG|TRACE|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL)\b',
    re.IGNORECASE
)

TIMESTAMP_PATTERNS = [
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'), '%Y-%m-%d %H:%M:%S'),
    (re.compile(r'\d{4}/\d{2}/\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?'), '%Y/%m/%d %H:%M:%S'),
    (re.compile(r'\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4}'), '%d/%b/%Y:%H:%M:%S %z'),
    (re.compile(r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'), '%b %d %H:%M:%S'),
    (re.compile(r'[A-Z][a-z]{2},\s+\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}'), '%a, %d %b %Y %H:%M:%S %z'),
]

APACHE_COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"$'
)

SYSLOG_3164_PATTERN = re.compile(
    r'^<(?P<priority>\d+)>'
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<tag>[^:\s\[]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)$'
)

SYSLOG_5424_PATTERN = re.compile(
    r'^<(?P<priority>\d+)>(?P<version>\d+)\s+'
    r'(?P<timestamp>-|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})))\s+'
    r'(?P<hostname>-|\S+)\s+'
    r'(?P<appname>-|\S+)\s+'
    r'(?P<procid>-|\S+)\s+'
    r'(?P<msgid>-|\S+)\s+'
    r'(?P<structured_data>-|\[.*?\])\s*'
    r'(?P<message>.*)$'
)

PLAINTEXT_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(?:\[(?P<level>[A-Z]+)\]|\b(?P<level2>[A-Z]+)\b)\s+'
    r'(?P<message>.*)$'
)


def sha256_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()[:length]


def hmac_sha256(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode('utf-8'), hashlib.sha256).hexdigest()


def luhn_check(card_number: str) -> bool:
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 2:
        return False
    if all(d == 0 for d in digits):
        return False
    check_sum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        check_sum += digit
    return check_sum % 10 == 0


def id_card_check(id_card: str) -> bool:
    if len(id_card) != 18:
        return False
    if not id_card[:17].isdigit():
        return False
    check_code = id_card[17].upper()
    if check_code not in '0123456789X':
        return False
    total = sum(int(id_card[i]) * ID_CARD_WEIGHTS[i] for i in range(17))
    return ID_CARD_CHECK_CODES[total % 11] == check_code


def is_id_field(field_name: Optional[str]) -> bool:
    if not field_name:
        return False
    field_lower = field_name.lower()
    id_keywords = ['id', 'seq', 'no', 'number', 'serial', 'uuid', 'guid']
    return any(kw in field_lower for kw in id_keywords)


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    ts = timestamp_str.strip()
    for pattern, fmt in TIMESTAMP_PATTERNS:
        match = pattern.search(ts)
        if match:
            matched_str = match.group(0).replace('T', ' ')
            try:
                dt = datetime.strptime(matched_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
                return dt
            except ValueError:
                try:
                    if 'Z' in matched_str or '+' in matched_str or matched_str.count('-') > 2:
                        dt = datetime.fromisoformat(matched_str.replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        else:
                            dt = dt.astimezone(timezone.utc)
                        return dt
                except ValueError:
                    continue
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except ValueError:
        pass
    return None


def parse_log_level(text: str) -> LogLevel:
    match = LOG_LEVEL_PATTERN.search(text)
    if match:
        level = (match.group(1) or match.group(2)).upper()
        try:
            return LogLevel[level]
        except KeyError:
            return LogLevel.UNKNOWN
    return LogLevel.UNKNOWN


def mask_value(value: str, keep_start: int = 3, keep_end: int = 4, mask_char: str = '*') -> str:
    if len(value) <= keep_start + keep_end:
        return mask_char * len(value)
    end_part = value[-keep_end:] if keep_end > 0 else ""
    return value[:keep_start] + mask_char * (len(value) - keep_start - keep_end) + end_part


def generalize_ip(ip: str) -> str:
    if ':' in ip:
        parts = ip.split(':')
        if len(parts) >= 2:
            return ':'.join(parts[:2]) + '::*'
        return ip
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.*.*"
    return ip


def generalize_email(email: str) -> str:
    if '@' not in email:
        return email
    _, domain = email.split('@', 1)
    return f"***@{domain}"


def find_overlaps(matches: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
    if not matches:
        return []
    matches.sort(key=lambda x: (x[0], -x[1]))
    result = [matches[0]]
    for start, end, value in matches[1:]:
        last_start, last_end, _ = result[-1]
        if start >= last_end:
            result.append((start, end, value))
        elif end - start > last_end - last_start:
            result[-1] = (start, end, value)
    return result
