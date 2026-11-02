# ENCS3130 Linux Laboratory
# Bank Database Server Log Analyzer
# Student: Abdel Rahman Sabbagh

"""Analysis services required by the Bank Database Server Log Analyzer project."""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from log_entry import LogEntry


def entry_timestamp(entry: LogEntry) -> datetime:
    """Return an entry timestamp. Used when sorting log entries."""
    return entry.timestamp


def session_first_event(session: Dict[str, Any]) -> datetime:
    """Return a session's first event time. Used when sorting sessions."""
    return session["first_event"]


class LogAnalyzer:
    """Analyze parsed bank log entries using the nine required services."""

    def __init__(self, entries: List[LogEntry], total_lines: int, malformed_lines: int) -> None:
        """Store the parsed data and keep events in chronological order."""
        self.entries = sorted(entries, key=entry_timestamp)
        self.total_lines = total_lines
        self.malformed_lines = malformed_lines

    def failed_login_report(self) -> Dict[str, Any]:
        """Service 1: count failed logins by IP and user and flag brute-force IPs."""
        failed_entries = []
        by_ip = {}
        by_user = {}
        brute_force_ips = {}

        for entry in self.entries:
            is_failed_login = False

            if entry.module == "AUTH" and entry.log_level == "ERROR":
                if re.search(r"failed login attempt", entry.message, re.IGNORECASE):
                    is_failed_login = True

            if is_failed_login:
                failed_entries.append(entry)

                if entry.client_ip not in by_ip:
                    by_ip[entry.client_ip] = 0
                by_ip[entry.client_ip] += 1

                if entry.user not in by_user:
                    by_user[entry.user] = 0
                by_user[entry.user] += 1

        for ip_address in by_ip:
            if by_ip[ip_address] >= 3:
                brute_force_ips[ip_address] = by_ip[ip_address]

        return {
            "total": len(failed_entries),
            "by_ip": by_ip,
            "by_user": by_user,
            "brute_force_ips": brute_force_ips,
            "entries": failed_entries,
        }

    def query_activity_summary(self) -> Dict[str, Any]:
        """Service 2: count QUERY events and classify SQL query types."""
        query_counts = {
            "SELECT": 0,
            "UPDATE": 0,
            "INSERT": 0,
            "DELETE": 0,
        }

        total_queries = 0
        other_queries = 0

        for entry in self.entries:
            if entry.module == "QUERY":
                total_queries += 1
                query_type = self._find_query_type(entry.message)

                if query_type is None:
                    other_queries += 1
                else:
                    query_counts[query_type] += 1

        return {
            "total": total_queries,
            "by_type": query_counts,
            "other": other_queries,
        }

    def slow_query_detector(self) -> List[Dict[str, Any]]:
        """Service 3: find WARNING entries related to slow queries."""
        slow_queries = []

        for entry in self.entries:
            if entry.module == "QUERY" and entry.log_level == "WARNING":
                if re.search(r"slow\s+query", entry.message, re.IGNORECASE):
                    query_data = {
                        "timestamp": entry.timestamp,
                        "user": entry.user,
                        "execution_time": self._extract_execution_time(entry.message),
                        "message": entry.message,
                    }
                    slow_queries.append(query_data)

        return slow_queries

    def transaction_report(self) -> Dict[str, Any]:
        """Service 4: summarize transactions and available transaction amounts."""
        deposits = 0
        withdrawals = 0
        declined = 0
        rollbacks = 0
        total_deposited = 0.0
        total_withdrawn = 0.0

        for entry in self.entries:
            if entry.module == "TRANSACTION":
                message = entry.message

                if re.search(r"\bdeposit(?:ed|s|ing)?\b", message, re.IGNORECASE):
                    deposits += 1
                    amount = self._extract_transaction_amount(message, "deposit")

                    if amount is not None:
                        total_deposited += amount

                if re.search(r"\bwithdraw(?:al|als|n|s|ing)?\b", message, re.IGNORECASE):
                    withdrawals += 1
                    amount = self._extract_transaction_amount(message, "withdraw")

                    if amount is not None:
                        total_withdrawn += amount

                if re.search(r"\bdeclin(?:e|ed|es|ing)\b", message, re.IGNORECASE):
                    declined += 1

                if re.search(r"\brollback\b|\brolled\s+back\b", message, re.IGNORECASE):
                    rollbacks += 1

        return {
            "deposits": deposits,
            "withdrawals": withdrawals,
            "declined": declined,
            "rollbacks": rollbacks,
            "total_deposited": total_deposited,
            "total_withdrawn": total_withdrawn,
        }

    def critical_events_report(self) -> List[LogEntry]:
        """Service 5: return all CRITICAL log entries."""
        critical_entries = []

        for entry in self.entries:
            if entry.log_level == "CRITICAL":
                critical_entries.append(entry)

        return critical_entries

    def user_activity_report(self, username: str) -> List[LogEntry]:
        """Service 6: return all actions of one user in chronological order."""
        user_entries = []
        searched_user = username.strip().lower()

        for entry in self.entries:
            if entry.user.lower() == searched_user:
                user_entries.append(entry)

        return user_entries

    def login_logout_session_report(self) -> List[Dict[str, Any]]:
        """Service 7: list sessions with login time, logout time, and duration."""
        sessions = {}

        for entry in self.entries:
            session_id = entry.session_id

            if session_id not in sessions:
                sessions[session_id] = {
                    "session_id": session_id,
                    "user": entry.user,
                    "client_ip": entry.client_ip,
                    "login_time": None,
                    "logout_time": None,
                    "first_event": entry.timestamp,
                }

            if self._is_successful_login(entry):
                if sessions[session_id]["login_time"] is None:
                    sessions[session_id]["login_time"] = entry.timestamp
                    sessions[session_id]["user"] = entry.user
                    sessions[session_id]["client_ip"] = entry.client_ip

            if self._is_logout(entry):
                sessions[session_id]["logout_time"] = entry.timestamp

        report = []

        for session_id in sessions:
            session = sessions[session_id]
            duration = None

            if session["login_time"] is not None and session["logout_time"] is not None:
                if session["logout_time"] >= session["login_time"]:
                    duration = session["logout_time"] - session["login_time"]

            report.append(
                {
                    "session_id": session["session_id"],
                    "user": session["user"],
                    "client_ip": session["client_ip"],
                    "login_time": session["login_time"],
                    "logout_time": session["logout_time"],
                    "duration": duration,
                    "first_event": session["first_event"],
                }
            )

        report.sort(key=session_first_event)
        return report

    def events_per_hour_report(self) -> Dict[int, int]:
        """Service 8: count how many events occurred in each hour of the day."""
        events_by_hour = {}

        for hour in range(24):
            events_by_hour[hour] = 0

        for entry in self.entries:
            hour = entry.timestamp.hour
            events_by_hour[hour] += 1

        return events_by_hour

    def general_log_summary(self) -> Dict[str, Any]:
        """Service 9: count log levels and determine the busiest module."""
        level_counts = {
            "INFO": 0,
            "WARNING": 0,
            "ERROR": 0,
            "CRITICAL": 0,
        }

        module_counts = {}

        for entry in self.entries:
            if entry.log_level in level_counts:
                level_counts[entry.log_level] += 1

            if entry.module not in module_counts:
                module_counts[entry.module] = 0
            module_counts[entry.module] += 1

        busiest_module = None
        busiest_count = 0

        for module in module_counts:
            if module_counts[module] > busiest_count:
                busiest_module = module
                busiest_count = module_counts[module]

        return {
            "total_lines": self.total_lines,
            "valid_events": len(self.entries),
            "malformed_lines": self.malformed_lines,
            "events_by_level": level_counts,
            "busiest_module": busiest_module,
            "busiest_module_count": busiest_count,
        }

    def _find_query_type(self, message: str) -> Optional[str]:
        """Find SELECT, UPDATE, INSERT, or DELETE in a QUERY message."""
        query_types = ["SELECT", "UPDATE", "INSERT", "DELETE"]

        for query_type in query_types:
            pattern = r"\b" + query_type + r"\b"

            if re.search(pattern, message, re.IGNORECASE):
                return query_type

        return None

    def _extract_execution_time(self, message: str) -> str:
        """Extract an execution time from a slow-query message when available."""
        patterns = [
            r"(?:execution\s*time|duration|took|completed\s+in)\s*[:=]?\s*"
            r"(\d+(?:\.\d+)?)\s*(ms|milliseconds?|s|sec|secs|seconds?)\b",
            r"slow\s+query.*?(\d+(?:\.\d+)?)\s*"
            r"(ms|milliseconds?|s|sec|secs|seconds?)\b",
        ]

        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)

            if match is not None:
                return match.group(1) + " " + match.group(2)

        return "N/A"

    def _extract_transaction_amount(self, message: str, transaction_type: str) -> Optional[float]:
        """Extract an amount from a deposit or withdrawal message when available."""
        number = r"(\d+(?:,\d{3})*(?:\.\d+)?)"

        if transaction_type == "deposit":
            transaction_word = r"deposit(?:ed|s|ing)?"
        else:
            transaction_word = r"withdraw(?:al|als|n|s|ing)?"

        patterns = [
            transaction_word
            + r"(?:\s+amount)?(?:\s+of)?\s*[:=]?\s*(?:USD\s*|\$)?"
            + number,
            r"amount\s*[:=]?\s*(?:USD\s*|\$)?" + number,
        ]

        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)

            if match is not None:
                amount_text = match.group(1).replace(",", "")

                try:
                    amount = float(amount_text)
                    return amount
                except ValueError:
                    return None

        return None

    def _is_successful_login(self, entry: LogEntry) -> bool:
        """Check whether an AUTH entry describes a successful login."""
        if entry.module != "AUTH" or entry.log_level != "INFO":
            return False

        patterns = [
            r"successful\s+login",
            r"login\s+successful",
            r"logged\s+in",
            r"authentication\s+successful",
        ]

        for pattern in patterns:
            if re.search(pattern, entry.message, re.IGNORECASE):
                return True

        return False

    def _is_logout(self, entry: LogEntry) -> bool:
        """Check whether an AUTH entry describes a logout."""
        if entry.module != "AUTH":
            return False

        if re.search(r"\blogout\b|logged\s+out", entry.message, re.IGNORECASE):
            return True

        return False
