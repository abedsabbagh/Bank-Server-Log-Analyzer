# ENCS3130 Linux Laboratory
# Bank Database Server Log Analyzer
# Student: Abdel Rahman Sabbagh

"""Data model for one bank server log entry."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEntry:
    """Store the fields extracted from one valid bank log line."""

    timestamp: datetime
    log_level: str
    session_id: str
    user: str
    client_ip: str
    module: str
    message: str
