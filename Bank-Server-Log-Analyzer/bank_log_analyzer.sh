#!/bin/sh

# use a file passed to the script, otherwise use bank_server.log
if [ "$#" -gt 1 ]
then
    echo "Usage: $0 [log_file]"
    exit 1
fi

if [ "$#" -ge 1 ]
then
    LOG_FILE="$1"
else
    LOG_FILE="bank_server.log"
fi

# function to display our system choices
show_menu()
{
    echo
    echo
    echo "==================================="
    echo "=========Bank Log Analyzer========="
    echo "==================================="
    echo "1. Failed Login Report"
    echo "2. Query Activity Summary"
    echo "3. Slow Query Detection"
    echo "4. Transaction Report"
    echo "5. Critical Events Report"
    echo "6. User Activity Report"
    echo "7. Login/Logout Session Report"
    echo "8. Event-per-Hour Report"
    echo "9. Generate Log Summary"
    echo "10. Run ALL Reports"
    echo "11. Exit"
    echo "-----------------------------------"
    echo
    echo
}

# check that the log file exists and can be read
log_file_checking(){
if [ ! -f "$LOG_FILE" ]
then
    echo "ERROR: $LOG_FILE is not found."
    exit 1
fi

if [ ! -r "$LOG_FILE" ]
then
    echo "ERROR: $LOG_FILE is not readable."
    exit 1
fi
}

# task1
failed_login_report()
{
echo
echo "--------------------------------------------"
echo " -----Failed login Report-----"

failed=$(awk -F'[][]' '$4 == "ERROR" && $12 == "AUTH" && $13 ~ /Failed login attempt/ { print $0 }' "$LOG_FILE")

#checking if there are no failed login attempts
if [ -z "$failed" ]
then
    totalFailed=0
else
    totalFailed=$(echo "$failed" | wc -l)
fi

countIPs=$(echo "$failed" | cut -d " " -f 6 | tr -d '[]' | sort | uniq -c)
userCount=$(echo "$failed" | cut -d " " -f 5 | tr -d '[]' | sort | uniq -c)

echo "Total failed login attempts: $totalFailed "
echo
# if there are failed login attempts
if [ "$totalFailed" -gt 0 ]
then
    echo "Grouped by CLIENT_IP:"
    echo "$countIPs" | while read count ip
    do
        echo "    $ip : $count attempts"
    done
    echo
    echo "Grouped by USER:"
    echo "$userCount" | while read count user
    do
        echo "    $user : $count attempts"
    done
    echo
    echo "Possible Brute-Force Sources :(3 or more failed attempts)"

    bruteForce=$(echo "$countIPs" | awk '$1 >= 3 { print $2 }')

    if [ -z "$bruteForce" ]
    then
        echo "    None"
    else
        echo "$bruteForce" | while read ip
        do
            echo "    $ip"
        done
    fi
else
    echo "No failed login attempts found."
fi
echo "--------------------------------------------"
}

# task2
query_activity_summary()
{

query_file="/tmp/query_events_$$"
awk -F'[][]' '$12 == "QUERY" { print $0 }' "$LOG_FILE" > "$query_file"

totalQueries=$(wc -l < "$query_file")
Select=0
Update=0
Insert=0
Delete=0
Other=0

while IFS= read -r line
do
    message=$(echo "$line" | cut -d']' -f7- | tr '[a-z]' '[A-Z]')

    case "$message" in
        *SELECT*)
            Select=$((Select + 1))
            ;;
        *UPDATE*)
            Update=$((Update + 1))
            ;;
        *INSERT*)
            Insert=$((Insert + 1))
            ;;
        *DELETE*)
            Delete=$((Delete + 1))
            ;;
        *)
            Other=$((Other + 1))
            ;;
    esac
done < "$query_file"

echo "--------------------------------------------"
echo "Total QUERY events : $totalQueries"
echo
echo "Breakdown by query type:"
echo "    SELECT : $Select"
echo "    UPDATE : $Update"
echo "    INSERT : $Insert"
echo "    DELETE : $Delete"
echo "    OTHER  : $Other"

echo "--------------------------------------------"
rm -f "$query_file"
}

# task3
slow_query_detector()
{
echo "--------------------------------------------"
echo "Slow Query Detector"

# warning query lines that mention a slow query
slowQ=$(awk -F'[][]' '$4 == "WARNING" && $12 == "QUERY" { print $0 }' "$LOG_FILE" | grep -i "slow")

if [ -z "$slowQ" ]
then
   echo "No slow queries found."
else
    echo "$slowQ" | while IFS= read -r line
    do
        user=$(echo "$line" | cut -d " " -f 5 | tr -d '[]')
        exectime=$(echo "$line" | sed -n 's/.*[Ee]xecution time[ :=]*\([0-9][0-9.]*[[:space:]]*[A-Za-z]*\).*/\1/p')

        if [ -z "$exectime" ]
        then
            exectime="N/A"
        fi

        echo "    User: $user : Execution Time: $exectime"
        echo "    Entry: $line"
    done
fi

echo "--------------------------------------------"
}

# task4
transaction_report()
{
echo "--------------------------------------------"
echo "Transaction Report"

trans=$(awk -F'[][]' '$12 == "TRANSACTION" { print $0 }' "$LOG_FILE")

# count deposits/withdrawals separately from declined transactions and rollbacks
successfulDeposits=$(echo "$trans" | grep -i "Deposit" | grep -vi "declin" | grep -vi "rollback")
successfulWithdrawals=$(echo "$trans" | grep -i "Withdrawal" | grep -vi "declin" | grep -vi "rollback")
declinedLines=$(echo "$trans" | grep -i "declin")
rollbackLines=$(echo "$trans" | grep -i "rollback")

if [ -z "$successfulDeposits" ]; then depos=0; else depos=$(echo "$successfulDeposits" | wc -l); fi
if [ -z "$successfulWithdrawals" ]; then withdraw=0; else withdraw=$(echo "$successfulWithdrawals" | wc -l); fi
if [ -z "$declinedLines" ]; then declined=0; else declined=$(echo "$declinedLines" | wc -l); fi
if [ -z "$rollbackLines" ]; then rollback=0; else rollback=$(echo "$rollbackLines" | wc -l); fi

# extract amounts from either "Deposit/Withdrawal of ..." or "amount: ..." formats
depositamount=$(echo "$successfulDeposits" | sed -n \
    -e 's/.*[Dd]eposit of[[:space:]]*\([0-9][0-9,.]*\).*/\1/p' \
    -e 's/.*[Aa]mount[[:space:]]*[:=]*[[:space:]]*\([0-9][0-9,.]*\).*/\1/p' | tr -d ',')

withdrawamount=$(echo "$successfulWithdrawals" | sed -n \
    -e 's/.*[Ww]ithdrawal of[[:space:]]*\([0-9][0-9,.]*\).*/\1/p' \
    -e 's/.*[Aa]mount[[:space:]]*[:=]*[[:space:]]*\([0-9][0-9,.]*\).*/\1/p' | tr -d ',')

depositAmountCount=$(printf "%s\n" "$depositamount" | sed '/^$/d' | wc -l)
withdrawAmountCount=$(printf "%s\n" "$withdrawamount" | sed '/^$/d' | wc -l)

# awk adds the available amounts together
if [ "$depositAmountCount" -gt 0 ]
then
    totDeposit=$(echo "$depositamount" | awk '{sum += $1} END {printf "%.2f", sum}')
else
    totDeposit="N/A"
fi

if [ "$withdrawAmountCount" -gt 0 ]
then
    totWithdraw=$(echo "$withdrawamount" | awk '{sum += $1} END {printf "%.2f", sum}')
else
    totWithdraw="N/A"
fi

echo "    Deposits: $depos"
echo "    Withdrawals: $withdraw"
echo "    Declined Transactions: $declined"
echo "    Rollbacks: $rollback"
echo "    Total Deposited Amount: $totDeposit"
echo "    Total Withdrawn Amount: $totWithdraw"

if [ "$depositAmountCount" -lt "$depos" ]
then
    echo "    Note: Some deposit amounts were not available."
fi

if [ "$withdrawAmountCount" -lt "$withdraw" ]
then
    echo "    Note: Some withdrawal amounts were not available."
fi

echo "--------------------------------------------"
}

# task5
critical_events_report()
{
echo "--------------------------------------------"
echo "Critical Events Report"
echo
critical=$(awk -F'[][]' '$4 == "CRITICAL" { print $0 }' "$LOG_FILE")

if [ -z "$critical" ]
then
    criticalcount=0
    echo "No critical events found."
else
    echo "$critical"
    criticalcount=$(echo "$critical" | wc -l)
fi
echo
echo "Total Critical Events: $criticalcount"
echo
echo "--------------------------------------------"

}

# task6
user_activity_report()
{
echo "--------------------------------------------"
echo "----User Activity Report----"
echo "Enter the username "
IFS= read -r username

if [ -z "$username" ]
then
    echo "ERROR: Username cannot be empty."
else
    # match the structured USER field exactly
    useractivity=$(awk -F'[][]' -v target="$username" '
        $8 == target { print $0 }
    ' "$LOG_FILE" | sort)
    echo

    if [ -n "$useractivity" ]
    then
        echo "ALL Activities for $username :"
        echo "$useractivity"
        echo
    else
        echo "No activities found for $username "
    fi
fi
echo "--------------------------------------------"

}

# task7
# helper function to convert time [HH:MM:SS] into seconds
time_to_sec(){
time=$1

clock=$(echo "$time" | cut -d " " -f 2 | tr -d "]" )

# remove the leading zero to avoid arithmetic problems such as 08
hours=$(echo "$clock" | cut -d ":" -f 1 | sed 's/^0//')
min=$(echo "$clock" | cut -d ":" -f 2 | sed 's/^0//')
sec=$(echo "$clock" | cut -d ":" -f 3 | sed 's/^0//')

# make sure 00 does not become an empty value
[ -z "$hours" ] && hours=0
[ -z "$min" ] && min=0
[ -z "$sec" ] && sec=0

total=$((hours * 3600 + min * 60 + sec))
echo "$total"
}

# return 1 if the given year is a leap year, otherwise return 0
is_leap_year(){
year=$1

if [ $((year % 400)) -eq 0 ]
then
    echo 1
elif [ $((year % 100)) -eq 0 ]
then
    echo 0
elif [ $((year % 4)) -eq 0 ]
then
    echo 1
else
    echo 0
fi
}

# convert YYYY-MM-DD into a day number so sessions can span more than one day
date_to_days(){
datevalue=$1

year=$(echo "$datevalue" | cut -d "-" -f 1)
month=$(echo "$datevalue" | cut -d "-" -f 2 | sed 's/^0//')
day=$(echo "$datevalue" | cut -d "-" -f 3 | sed 's/^0//')

days=0
currentYear=1970

while [ "$currentYear" -lt "$year" ]
do
    leap=$(is_leap_year "$currentYear")
    if [ "$leap" -eq 1 ]
    then
        days=$((days + 366))
    else
        days=$((days + 365))
    fi
    currentYear=$((currentYear + 1))
done

currentMonth=1
while [ "$currentMonth" -lt "$month" ]
do
    case "$currentMonth" in
        1|3|5|7|8|10|12)
            monthDays=31
            ;;
        4|6|9|11)
            monthDays=30
            ;;
        2)
            leap=$(is_leap_year "$year")
            if [ "$leap" -eq 1 ]
            then
                monthDays=29
            else
                monthDays=28
            fi
            ;;
    esac

    days=$((days + monthDays))
    currentMonth=$((currentMonth + 1))
done

days=$((days + day - 1))
echo "$days"
}

session_report(){
echo "--------------------------------------------"
echo "--------Login/Logout Session Report--------------"
echo

# collect every SESSION_ID that appears in the log
sessions=$(cut -d " " -f 4 "$LOG_FILE" | tr -d '[]' | sort | uniq)

if [ -z "$sessions" ]
then
    echo "No sessions found."
    echo "--------------------------------------------"
    return
fi

for session in $sessions
do
    login=$(grep "\[$session\]" "$LOG_FILE" | grep "\[AUTH\]" | grep -i -e "Successful login" -e "login successful" -e "logged in" | sort | head -n 1)
    logout=$(grep "\[$session\]" "$LOG_FILE" | grep "\[AUTH\]" | grep -i -e "logout" -e "logged out" | sort | head -n 1)

    logintime=$(echo "$login" | cut -d " " -f 1,2 | tr -d '[]')
    logouttime=$(echo "$logout" | cut -d " " -f 1,2 | tr -d '[]')

    if [ -z "$logintime" ]
    then
        logintxt="N/A"
        durationtxt="N/A"
    else
        logintxt="$logintime"
    fi

    if [ -z "$logouttime" ]
    then
        logouttxt="N/A (still active or missing)"
        durationtxt="N/A"
    else
        logouttxt="$logouttime"

        if [ -n "$logintime" ]
        then
            loginDate=$(echo "$logintime" | cut -d " " -f 1)
            logoutDate=$(echo "$logouttime" | cut -d " " -f 1)

            loginTimesec=$(time_to_sec "$logintime")
            logoutTimesec=$(time_to_sec "$logouttime")

            # include the date in the calculation so sessions may span several days
            loginDay=$(date_to_days "$loginDate")
            logoutDay=$(date_to_days "$logoutDate")

            loginTotalSec=$((loginDay * 86400 + loginTimesec))
            logoutTotalSec=$((logoutDay * 86400 + logoutTimesec))
            duration=$((logoutTotalSec - loginTotalSec))

            if [ "$duration" -lt 0 ]
            then
                durationtxt="N/A"
            else
                days=$((duration / 86400))
                hours=$(( (duration % 86400) / 3600))
                minutes=$(( (duration % 3600) / 60))
                seconds=$((duration % 60))

                durationtxt="${days}d ${hours}h ${minutes}m ${seconds}s"
            fi
        fi
    fi

    echo "Session: $session"
    echo "Login: $logintxt : Logout: $logouttxt"
    echo "Duration: $durationtxt"
    echo
done

echo "--------------------------------------------"
}

# task8
event_per_hour_report()
{
echo "--------------------------------------------"
echo "---- Event per Hour Report ----"
echo

hourList=$(cut -d " " -f 2 "$LOG_FILE" | cut -d ":" -f 1)
hourNumber=0
peakCount=0
peakHours=""

while [ "$hourNumber" -le 23 ]
do
    hour=$(printf "%02d" "$hourNumber")
    count=$(printf "%s\n" "$hourList" | grep -c "^$hour$")

    echo "$hour:00 -->  $count event(s) "

    if [ "$count" -gt "$peakCount" ]
    then
        peakCount=$count
        peakHours=$hour
    elif [ "$count" -eq "$peakCount" ] && [ "$count" -gt 0 ]
    then
        peakHours="$peakHours $hour"
    fi

    hourNumber=$((hourNumber + 1))
done

echo
if [ "$peakCount" -eq 0 ]
then
    echo "Peak usage hour(s): N/A"
    echo "Peak event count: 0"
else
    echo "Peak usage hour(s): $peakHours"
    echo "Peak event count: $peakCount"
fi

echo "--------------------------------------------"
}

# task9
generate_summary()
{
echo "--------------------------------------------"

lines=$(wc -l < "$LOG_FILE")
echo "Total Log Lines = $lines"
echo

echo "Events per Log level:"
for level in INFO WARNING ERROR CRITICAL
do
    count=$(awk -F'[][]' -v target="$level" '$4 == target { count++ } END { print count + 0 }' "$LOG_FILE")
    echo "    $level : $count "
done

maxcount=0
maxmodule=""

if [ "$lines" -eq 0 ]
then
    echo
    echo "Busiest module: N/A -> 0 event(s)"
else
    for module in AUTH QUERY TRANSACTION BACKUP
    do
        count=$(awk -F'[][]' -v target="$module" '$12 == target { count++ } END { print count + 0 }' "$LOG_FILE")
        if [ "$count" -gt "$maxcount" ]
        then
            maxcount=$count
            maxmodule=$module
        elif [ "$count" -eq "$maxcount" ] && [ "$count" -gt 0 ]
        then
            maxmodule="$maxmodule $module"
        fi
    done
    echo
    echo "Busiest module(s): $maxmodule -> $maxcount event(s)"
fi
echo "--------------------------------------------"
}

# task10
run_all_reports()
{
echo "--------------------------------------------"

failed_login_report
echo "Press Enter to continue :)"
IFS= read -r dummy

query_activity_summary
echo "Press Enter to continue :)"
IFS= read -r dummy

slow_query_detector
echo "Press Enter to continue :)"
IFS= read -r dummy

transaction_report
echo "Press Enter to continue :)"
IFS= read -r dummy

critical_events_report
echo "Press Enter to continue :)"
IFS= read -r dummy

user_activity_report
echo "Press Enter to continue :)"
IFS= read -r dummy

session_report
echo "Press Enter to continue :)"
IFS= read -r dummy

event_per_hour_report
echo "Press Enter to continue :)"
IFS= read -r dummy

generate_summary

echo "ALL TASKS COMPLETED SUCCESSFULLY !"

echo "--------------------------------------------"
echo "--------------------------------------------"
echo "--------------------------------------------"
echo "--------------------------------------------"

}

# Main Program
log_file_checking

while true
do
    show_menu

    echo "Enter your choice [1-11]:"
    IFS= read -r choice

    case "$choice" in
        1)
            failed_login_report
            ;;
        2)
            query_activity_summary
            ;;
        3)
            slow_query_detector
            ;;
        4)
            transaction_report
            ;;
        5)
            critical_events_report
            ;;
        6)
            user_activity_report
            ;;
        7)
            session_report
            ;;
        8)
            event_per_hour_report
            ;;
        9)
            generate_summary
            ;;
        10)
            run_all_reports
            ;;
        11)
            echo "Exiting..."
            break
            ;;
        *)
            echo "Invalid choice"
            ;;
    esac
done
