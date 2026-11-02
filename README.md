# Bank Server Log Analyzer

A **command-line log analysis project** built with **Python and POSIX shell**. It reads a text-based bank-server event log and produces reports about authentication, database queries, transactions, and operational issues.

> **Portfolio note:** This is an academic log-analysis project using example log files. It is not connected to a bank or live financial system. Review any external logs for confidential or personal data before using them.

## Features

- **Failed logins:** Counts authentication failures by IP and user; identifies repeated attempts as potential brute-force activity.
- **Query activity:** Summarizes `SELECT`, `UPDATE`, `INSERT`, and `DELETE` events.
- **Slow queries:** Extracts query events with reported execution times.
- **Transactions:** Reports deposits, withdrawals, declined operations, and rollbacks.
- **Critical events:** Lists `CRITICAL` messages, such as failed backups.
- **User activity:** Filters events belonging to a selected user.
- **Sessions:** Summarizes login/logout activity and available session durations.
- **Hourly activity:** Counts events by hour.
- **General summary:** Reports total lines, valid events, malformed lines, log levels, and the busiest module.

## Technology

- **Python 3:** Standard library only (`argparse`, regular expressions, `datetime`, and file I/O).
- **POSIX shell:** Separate menu-based implementation; uses standard shell and common command-line utilities.
- **Testing:** Python assertion-based test cases for parsing and reporting behavior.

## Project files

```text
Bank-Server-Log-Analyzer/
├── main.py                 # Python CLI and interactive menu
├── log_analyzer.py         # Analysis and aggregation functions
├── log_entry.py            # Parsed log-entry representation
├── log_parser.py           # Log parsing and validation
├── reports.py              # Text report rendering
├── run_tests.py            # Python test runner
├── bank_log_analyzer.sh    # Alternative shell implementation
├── bank_server.log         # Small example input log
├── test_cases/
│   ├── test_case_1.log
│   └── test_case_2.log
└── .gitignore
```

## Run the Python analyzer

From this repository folder, with Python 3 installed:

```bash
# Interactive menu, using the included example file
python main.py

# Print one report without opening the menu
python main.py bank_server.log --report summary

# All reports, including activity for a selected username
python main.py bank_server.log --report all --user admin

# Export a report to a text file
python main.py bank_server.log --report slow-queries --output slow_queries.txt

# User-specific report
python main.py bank_server.log --report user --user admin
```

The positional input filename defaults to `bank_server.log`. Use `python3` instead of `python` on systems where the Python 3 command is named `python3`.

To see all options:

```bash
python main.py --help
```

## Run the shell version

The shell implementation uses an interactive menu. On Linux/macOS or in a shell environment such as Git Bash:

```bash
sh bank_log_analyzer.sh bank_server.log
```

Select a report number from the menu; select **11** to exit.

## Run the tests

```bash
python run_tests.py
```

Expected output:

```text
Test case 1: PASSED
Test case 2: PASSED
All project tests passed.
```

The tests cover query statistics, slow-query detection, transaction totals, critical events, user activity, session durations, repeated failed logins, and malformed input.

## Design and limitations

- The parser uses a regular expression for the expected log format and skips invalid lines while recording diagnostics in local files.
- The analysis is based on the **contents of an input log file**; it does not inspect an actual database or live server.
- Brute-force indicators and slow-query messages are based on simple log-event patterns rather than a full security-monitoring or database-profiling system.
- Example/test `.log` files are intentionally included; generated internal diagnostic logs are excluded from version control.

## Skills demonstrated

Python, shell scripting, text processing, regular expressions, command-line interfaces, structured event analysis, and automated testing.
