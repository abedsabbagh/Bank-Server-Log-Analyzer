# ENCS3130 Linux Laboratory
# Bank Database Server Log Analyzer
# Student: Abdel Rahman Sabbagh

"""Functions used to parse the bank server log file."""

import logging
import re
from datetime import datetime
from typing import List, Optional, Tuple

from log_entry import LogEntry


# The project requires one regular expression for parsing the complete log line.
# Named groups are used so each field can be accessed by its name.
LOG_PATTERN = re.compile(
    r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+"
    r"\[(?P<log_level>INFO|WARNING|ERROR|CRITICAL)\]\s+"
    r"\[(?P<session_id>SESSION_\d+)\]\s+"
    r"\[(?P<user>[^\]]+)\]\s+"
    r"\[(?P<client_ip>\d{1,3}(?:\.\d{1,3}){3})\]\s+"
    r"\[(?P<module>AUTH|QUERY|TRANSACTION|BACKUP)\]\s*"
    r"-\s*(?P<message>.+)$"
)


def valid_ipv4(ip_address: str) -> bool:
    """Check that an IPv4 address has four numbers between 0 and 255."""
    parts = ip_address.split(".")

    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit():
            return False

        value = int(part)
        if value < 0 or value > 255:
            return False

    return True


def parse_log_line(line: str, line_number: int) -> Optional[LogEntry]:
    """Parse one line and return a LogEntry, or None when the line is invalid."""
    clean_line = line.rstrip("\n")
    match = LOG_PATTERN.match(clean_line)

    if match is None:
        logging.warning("Malformed log line %d: %s", line_number, clean_line)
        return None

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        logging.warning("Invalid timestamp on line %d: %s", line_number, clean_line)
        return None

    if not valid_ipv4(data["client_ip"]):
        logging.warning("Invalid IPv4 address on line %d: %s", line_number, clean_line)
        return None

    entry = LogEntry(
        timestamp,
        data["log_level"],
        data["session_id"],
        data["user"],
        data["client_ip"],
        data["module"],
        data["message"],
    )

    return entry


def read_log_file(file_name: str) -> Tuple[List[LogEntry], int, int]:
    """Read the log file and return entries, total lines, and malformed lines."""
    entries = []
    total_lines = 0
    malformed_lines = 0

    try:
        log_file = open(file_name, "r", encoding="utf-8")
    except FileNotFoundError:
        logging.error("Log file was not found: %s", file_name)
        raise
    except OSError as error:
        logging.error("Cannot open log file %s: %s", file_name, error)
        raise

    with log_file:
        line_number = 0

        for line in log_file:
            line_number += 1
            total_lines += 1

            entry = parse_log_line(line, line_number)

            if entry is None:
                malformed_lines += 1
            else:
                entries.append(entry)

    return entries, total_lines, malformed_lines
