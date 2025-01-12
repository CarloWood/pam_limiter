#! /bin/bash

# Regular expression for matching valid IP addresses.
IP_REGEX='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

# Current time in seconds since epoch.
NOW=$(date +%s)
# One week ago in seconds since epoch.
ONE_WEEK_AGO=$((NOW - 7*24*60*60))

# Process each file in the directory.
for file in /var/run/pam_limiter/*; do
    # Get just the filename (IP).
    ip=$(basename "$file")
    
    # Skip if filename doesn't match IP address pattern.
    [[ $ip =~ $IP_REGEX ]] || continue
    
    # Count lines in file.
    lines=$(wc -l < "$file")
    
    # Skip if less than 6 lines.
    [ "$lines" -lt 6 ] && continue
    
    # Get timestamp from last line and convert to seconds since epoch.
    last_timestamp=$(tail -n1 "$file" | cut -d' ' -f1,2)
    last_time_seconds=$(date -d "$last_timestamp" +%s)

    # If last entry is older than one week.
    if [ "$last_time_seconds" -lt "$ONE_WEEK_AGO" ]; then
        # Delete the file.
        /bin/rm "/var/run/pam_limiter/$ip"
        # Unban the IP number (clean up firewall).
        /usr/local/sbin/pam_limiter_trigger del "$ip"
    fi
done
