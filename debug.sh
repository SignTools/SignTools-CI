#!/bin/bash
set -eu -o pipefail -E

function anydesk() {
    echo "Preparing AnyDesk..."
    curl -sfL "https://download.anydesk.com/anydesk.dmg" -o anydesk.dmg
    hdiutil mount -quiet anydesk.dmg
    anydesk=/Volumes/AnyDesk/AnyDesk.app/Contents/MacOS/AnyDesk
    sudo $anydesk --service &
    password=$(hexdump -n 4 -v -e '/1 "%02X"' /dev/urandom)
    while ! echo "$password" | sudo $anydesk --set-password >/dev/null 2>&1; do
        sleep 1
    done
    $anydesk &
    echo -ne "AnyDesk ready! ID: $($anydesk --get-id) Password: $password\n"
    wait

}

function screenshot() {
    screencapture test.jpg
    echo "Uploading screenshot..."
    until curl https://bashupload.com -T test.jpg; do
        echo Error, sleeping
        sleep 1
    done
}

echo "=============================================="
screenshot
echo "=============================================="
