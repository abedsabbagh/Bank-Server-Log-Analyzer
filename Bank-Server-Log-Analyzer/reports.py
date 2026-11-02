# ENCS3130 Linux Laboratory
# Bank Database Server Log Analyzer
# Student: Abdel Rahman Sabbagh

"""Text formatting functions for the nine analyzer services."""

from datetime import timedelta
from typing import Optional

from log_analyzer import LogAnalyzer
from log_entry import LogEntry


LINE = "=" * 70


def title(text: str) -> str:
    """Create a report heading."""
    return LINE + "\n" + text + "\n" + LINE


def format_time(entry: LogEntry) -> str:
    """Format a LogEntry timestamp."""
    return entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")


def format_duration(duration: Optional[timedelta]) -> str:
    """Convert a timedelta to HH:MM:SS."""
    if duration is None:
        return "N/A"

    total_seconds = int(duration.total_seconds())
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60

    return "%02d:%02d:%02d" % (hours, minutes, seconds)


def failed_login_text(analyzer: LogAnalyzer) -> str:
    """Format service 1."""
    data = analyzer.failed_login_report()
    lines = [title("1. Failed Login Report")]
    lines.append("Total failed login attempts: " + str(data["total"]))

    lines.append("\nGrouped by CLIENT_IP:")
    if len(data["by_ip"]) == 0:
        lines.append("  None")
    else:
        for ip_address in sorted(data["by_ip"]):
            text = "  " + ip_address + ": " + str(data["by_ip"][ip_address])
            if ip_address in data["brute_force_ips"]:
                text += "  <-- POSSIBLE BRUTE-FORCE SOURCE"
            lines.append(text)

    lines.append("\nGrouped by USER:")
    if len(data["by_user"]) == 0:
        lines.append("  None")
    else:
        for user in sorted(data["by_user"]):
            lines.append("  " + user + ": " + str(data["by_user"][user]))

    lines.append("\nFailed login entries:")
    if len(data["entries"]) == 0:
        lines.append("  None")
    else:
        for entry in data["entries"]:
            lines.append(
                "  "
                + format_time(entry)
                + " | IP="
                + entry.client_ip
                + " | USER="
                + entry.user
                + " | "
                + entry.message
            )

    return "\n".join(lines)


def query_summary_text(analyzer: LogAnalyzer) -> str:
    """Format service 2."""
    data = analyzer.query_activity_summary()
    lines = [title("2. Query Activity Summary")]
    lines.append("Total QUERY events: " + str(data["total"]))

    for query_type in ["SELECT", "UPDATE", "INSERT", "DELETE"]:
        lines.append("  " + query_type + ": " + str(data["by_type"][query_type]))

    lines.append("  Other/unclassified: " + str(data["other"]))
    return "\n".join(lines)


def slow_query_text(analyzer: LogAnalyzer) -> str:
    """Format service 3."""
    rows = analyzer.slow_query_detector()
    lines = [title("3. Slow Query Detector")]
    lines.append("Slow queries found: " + str(len(rows)))

    if len(rows) == 0:
        lines.append("  None")
    else:
        for row in rows:
            lines.append(
                "  "
                + row["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                + " | USER="
                + row["user"]
                + " | TIME="
                + row["execution_time"]
                + " | "
                + row["message"]
            )

    return "\n".join(lines)


def transaction_text(analyzer: LogAnalyzer) -> str:
    """Format service 4."""
    data = analyzer.transaction_report()
    lines = [title("4. Transaction Report")]
    lines.append("Deposits: " + str(data["deposits"]))
    lines.append("Withdrawals: " + str(data["withdrawals"]))
    lines.append("Declined transactions: " + str(data["declined"]))
    lines.append("Rollbacks: " + str(data["rollbacks"]))
    lines.append("Total deposited amount: %.2f" % data["total_deposited"])
    lines.append("Total withdrawn amount: %.2f" % data["total_withdrawn"])
    return "\n".join(lines)


def critical_events_text(analyzer: LogAnalyzer) -> str:
    """Format service 5."""
    entries = analyzer.critical_events_report()
    lines = [title("5. Critical Events Report")]
    lines.append("CRITICAL events found: " + str(len(entries)))

    if len(entries) == 0:
        lines.append("  None")
    else:
        for entry in entries:
            lines.append(
                "  "
                + format_time(entry)
                + " | "
                + entry.session_id
                + " | "
                + entry.user
                + " | "
                + entry.module
                + " | "
                + entry.message
            )

    return "\n".join(lines)


def user_activity_text(analyzer: LogAnalyzer, username: str) -> str:
    """Format service 6."""
    entries = analyzer.user_activity_report(username)
    lines = [title("6. User Activity Report - " + username)]
    lines.append("Actions found: " + str(len(entries)))

    if len(entries) == 0:
        lines.append("  Username not found or has no actions.")
    else:
        for entry in entries:
            lines.append(
                "  "
                + format_time(entry)
                + " | "
                + entry.log_level
                + " | "
                + entry.session_id
                + " | "
                + entry.client_ip
                + " | "
                + entry.module
                + " | "
                + entry.message
            )

    return "\n".join(lines)


def session_text(analyzer: LogAnalyzer) -> str:
    """Format service 7."""
    rows = analyzer.login_logout_session_report()
    lines = [title("7. Login/Logout Session Report")]
    lines.append("Sessions found: " + str(len(rows)))

    if len(rows) == 0:
        lines.append("  None")
    else:
        for row in rows:
            if row["login_time"] is None:
                login_time = "N/A"
            else:
                login_time = row["login_time"].strftime("%Y-%m-%d %H:%M:%S")

            if row["logout_time"] is None:
                logout_time = "N/A"
            else:
                logout_time = row["logout_time"].strftime("%Y-%m-%d %H:%M:%S")

            lines.append(
                "  "
                + row["session_id"]
                + " | USER="
                + row["user"]
                + " | IP="
                + row["client_ip"]
                + " | LOGIN="
                + login_time
                + " | LOGOUT="
                + logout_time
                + " | DURATION="
                + format_duration(row["duration"])
            )

    return "\n".join(lines)


def hourly_text(analyzer: LogAnalyzer) -> str:
    """Format service 8."""
    data = analyzer.events_per_hour_report()
    lines = [title("8. Events-per-Hour Report")]

    for hour in range(24):
        lines.append("  %02d:00-%02d:59 : %d" % (hour, hour, data[hour]))

    return "\n".join(lines)


def summary_text(analyzer: LogAnalyzer) -> str:
    """Format service 9."""
    data = analyzer.general_log_summary()
    lines = [title("9. General Log Summary")]
    lines.append("Total lines: " + str(data["total_lines"]))
    lines.append("Valid parsed events: " + str(data["valid_events"]))
    lines.append("Malformed/skipped lines: " + str(data["malformed_lines"]))
    lines.append("Events per log level:")

    for level in ["INFO", "WARNING", "ERROR", "CRITICAL"]:
        lines.append("  " + level + ": " + str(data["events_by_level"][level]))

    if data["busiest_module"] is None:
        lines.append("Busiest module: N/A")
    else:
        lines.append(
            "Busiest module: "
            + data["busiest_module"]
            + " ("
            + str(data["busiest_module_count"])
            + " events)"
        )

    return "\n".join(lines)


def full_report_text(analyzer: LogAnalyzer, username: Optional[str]) -> str:
    """Generate one exportable text report containing all nine services."""
    sections = [
        failed_login_text(analyzer),
        query_summary_text(analyzer),
        slow_query_text(analyzer),
        transaction_text(analyzer),
        critical_events_text(analyzer),
    ]

    if username is None or username.strip() == "":
        sections.append(
            title("6. User Activity Report")
            + "\nA username is required for this user-specific service."
        )
    else:
        sections.append(user_activity_text(analyzer, username))

    sections.append(session_text(analyzer))
    sections.append(hourly_text(analyzer))
    sections.append(summary_text(analyzer))

    return "\n\n".join(sections)
