# ENCS3130 Linux Laboratory
# Bank Database Server Log Analyzer
# Student: Abdel Rahman Sabbagh

"""Simple tests for the project using assert statements only."""

import logging

from log_analyzer import LogAnalyzer
from log_parser import read_log_file


def test_case_1() -> None:
    """Test normal activity: queries, slow query, transaction, user, session, and hours."""
    entries, total_lines, malformed_lines = read_log_file("test_cases/test_case_1.log")
    analyzer = LogAnalyzer(entries, total_lines, malformed_lines)

    # Service 2: Query Activity Summary
    query_report = analyzer.query_activity_summary()
    assert query_report["total"] == 2
    assert query_report["by_type"]["SELECT"] == 2

    # Service 3: Slow Query Detector
    slow_queries = analyzer.slow_query_detector()
    assert len(slow_queries) == 1
    assert slow_queries[0]["user"] == "user1"
    assert slow_queries[0]["execution_time"] == "900 ms"

    # Service 4: Transaction Report
    transaction_report = analyzer.transaction_report()
    assert transaction_report["deposits"] == 1
    assert transaction_report["withdrawals"] == 1
    assert transaction_report["declined"] == 1
    assert transaction_report["rollbacks"] == 1
    assert transaction_report["total_deposited"] == 300.0
    assert transaction_report["total_withdrawn"] == 50.0

    # Service 5: Critical Events Report
    critical_events = analyzer.critical_events_report()
    assert len(critical_events) == 1

    # Service 6: User Activity Report
    user_events = analyzer.user_activity_report("user1")
    assert len(user_events) == 8

    # Service 7: Login/Logout Session Report
    session_report = analyzer.login_logout_session_report()
    assert len(session_report) == 1
    assert session_report[0]["duration"].total_seconds() == 240

    # Service 8: Events-per-Hour Report
    hourly_report = analyzer.events_per_hour_report()
    assert hourly_report[10] == 8

    print("Test case 1: PASSED")


def test_case_2() -> None:
    """Test failed logins, brute force, critical events, malformed data, and summary."""
    entries, total_lines, malformed_lines = read_log_file("test_cases/test_case_2.log")
    analyzer = LogAnalyzer(entries, total_lines, malformed_lines)

    # Service 1: Failed Login Report
    login_report = analyzer.failed_login_report()
    assert login_report["total"] == 3
    assert login_report["by_ip"]["198.51.100.9"] == 3
    assert login_report["by_user"]["unknown"] == 3
    assert login_report["brute_force_ips"]["198.51.100.9"] == 3

    # Service 5: Critical Events Report
    critical_events = analyzer.critical_events_report()
    assert len(critical_events) == 1

    # Service 8: Events-per-Hour Report
    hourly_report = analyzer.events_per_hour_report()
    assert hourly_report[11] == 4

    # Service 9: General Log Summary
    summary = analyzer.general_log_summary()
    assert summary["total_lines"] == 5
    assert summary["valid_events"] == 4
    assert summary["malformed_lines"] == 1
    assert summary["events_by_level"]["ERROR"] == 3
    assert summary["events_by_level"]["CRITICAL"] == 1
    assert summary["busiest_module"] == "AUTH"

    print("Test case 2: PASSED")


if __name__ == "__main__":
    # Keep parser diagnostics in a file while testing, just like the main program.
    logging.basicConfig(
        filename="test_internal.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    test_case_1()
    test_case_2()
    print("All project tests passed.")
