# ENCS3130 Linux Laboratory
# Bank Database Server Log Analyzer
# Student: Abdel Rahman Sabbagh

"""Main program for the Bank Database Server Log Analyzer."""

import argparse
import logging
import sys
from typing import Optional

from log_analyzer import LogAnalyzer
from log_parser import read_log_file
from reports import (
    critical_events_text,
    failed_login_text,
    full_report_text,
    hourly_text,
    query_summary_text,
    session_text,
    slow_query_text,
    summary_text,
    transaction_text,
    user_activity_text,
)


REPORT_NAMES = [
    "failed-logins",
    "queries",
    "slow-queries",
    "transactions",
    "critical",
    "user",
    "sessions",
    "hourly",
    "summary",
    "all",
]


def configure_logging() -> None:
    """Write internal program warnings/errors to a separate diagnostic file."""
    logging.basicConfig(
        filename="analyzer_internal.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def create_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser required by the project."""
    parser = argparse.ArgumentParser(
        description="Analyze a bank database server log file."
    )

    parser.add_argument(
        "log_file",
        nargs="?",
        default="bank_server.log",
        help="Path of the bank server log file (default: bank_server.log)",
    )

    parser.add_argument(
        "-r",
        "--report",
        choices=REPORT_NAMES,
        help="Run one report directly instead of opening the interactive menu.",
    )

    parser.add_argument(
        "-u",
        "--user",
        help="Username used by the user activity report.",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Optional text file used to export the selected report.",
    )

    return parser


def load_analyzer(file_name: str) -> LogAnalyzer:
    """Parse the log file and create a LogAnalyzer object."""
    entries, total_lines, malformed_lines = read_log_file(file_name)
    return LogAnalyzer(entries, total_lines, malformed_lines)


def get_report(analyzer: LogAnalyzer, report_name: str, username: Optional[str]) -> str:
    """Return the selected non-interactive report."""
    if report_name == "failed-logins":
        return failed_login_text(analyzer)
    elif report_name == "queries":
        return query_summary_text(analyzer)
    elif report_name == "slow-queries":
        return slow_query_text(analyzer)
    elif report_name == "transactions":
        return transaction_text(analyzer)
    elif report_name == "critical":
        return critical_events_text(analyzer)
    elif report_name == "user":
        if username is None or username.strip() == "":
            raise ValueError("The --user option is required for the user report.")
        return user_activity_text(analyzer, username)
    elif report_name == "sessions":
        return session_text(analyzer)
    elif report_name == "hourly":
        return hourly_text(analyzer)
    elif report_name == "summary":
        return summary_text(analyzer)
    elif report_name == "all":
        return full_report_text(analyzer, username)

    raise ValueError("Unknown report name.")


def save_or_print(report: str, output_file: Optional[str]) -> None:
    """Display a report or export it to a text file."""
    if output_file is None:
        print(report)
        return

    try:
        file = open(output_file, "w", encoding="utf-8")
        with file:
            file.write(report)
            file.write("\n")
        print("Report saved to " + output_file)
    except OSError as error:
        logging.error("Cannot write report file %s: %s", output_file, error)
        print("Error: could not save the report.")


def print_menu() -> None:
    """Display the interactive menu."""
    print("\nBank Database Server Log Analyzer")
    print("---------------------------------")
    print("1. Failed Login Report")
    print("2. Query Activity Summary")
    print("3. Slow Query Detector")
    print("4. Transaction Report")
    print("5. Critical Events Report")
    print("6. User Activity Report")
    print("7. Login/Logout Session Report")
    print("8. Events-per-Hour Report")
    print("9. General Log Summary")
    print("10. Full Report")
    print("0. Exit")


def interactive_menu(analyzer: LogAnalyzer) -> None:
    """Allow the user to run every required service from a text-based menu."""
    while True:
        print_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            print(failed_login_text(analyzer))
        elif choice == "2":
            print(query_summary_text(analyzer))
        elif choice == "3":
            print(slow_query_text(analyzer))
        elif choice == "4":
            print(transaction_text(analyzer))
        elif choice == "5":
            print(critical_events_text(analyzer))
        elif choice == "6":
            username = input("Enter username: ").strip()
            if username == "":
                print("Username cannot be empty.")
            else:
                print(user_activity_text(analyzer, username))
        elif choice == "7":
            print(session_text(analyzer))
        elif choice == "8":
            print(hourly_text(analyzer))
        elif choice == "9":
            print(summary_text(analyzer))
        elif choice == "10":
            username = input(
                "Username for service 6 (press Enter if you want to skip it): "
            ).strip()
            report = full_report_text(analyzer, username if username != "" else None)

            output_file = input(
                "Output file name (press Enter to only display): "
            ).strip()
            save_or_print(report, output_file if output_file != "" else None)
        elif choice == "0":
            print("Program finished.")
            break
        else:
            print("Invalid choice. Please choose a number from 0 to 10.")


def main() -> int:
    """Program entry point."""
    configure_logging()
    parser = create_argument_parser()
    arguments = parser.parse_args()

    try:
        analyzer = load_analyzer(arguments.log_file)
    except FileNotFoundError:
        print("Error: log file was not found: " + arguments.log_file)
        return 1
    except OSError as error:
        print("Error while reading the log file: " + str(error))
        return 1

    if arguments.report is None:
        interactive_menu(analyzer)
        return 0

    try:
        report = get_report(analyzer, arguments.report, arguments.user)
        save_or_print(report, arguments.output)
    except ValueError as error:
        print("Error: " + str(error))
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
