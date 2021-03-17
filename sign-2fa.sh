#!/bin/bash
set -e

echo "Polling for 2FA code..."
i=0
ret=1
while [ $ret -ne 0 ]; do
    if [ $i -gt 60 ]; then
        echo "Operation timed out"
        exit 1
    fi
    curl -sfL -H "Authorization: Bearer $SECRET_KEY" "$SECRET_URL/jobs/$JOB_ID/2fa" -o account_2fa.txt && ret=$? || ret=$?
    sleep 1
    ((i++))
done

echo "Entering 2FA code..."
export ACCOUNT_2FA="$(cat account_2fa.txt)"
osascript login2.applescript
