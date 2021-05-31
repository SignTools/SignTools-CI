#!/bin/bash
set -eu -o pipefail -E
curl="curl -sfL"

function debug() {
    echo "Preparing AnyDesk..."
    $curl "https://download.anydesk.com/anydesk.dmg" -o anydesk.dmg
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

echo "Obtaining files..."
# remove trailing slash and space
# shellcheck disable=SC2001
SECRET_URL=$(echo "$SECRET_URL" | sed 's|[/ ]*$||')
$curl -S -H "Authorization: Bearer $SECRET_KEY" "$SECRET_URL/jobs" | tar -x
cert_pass=$(cat cert_pass.txt)
sign_args=$(cat args.txt)
job_id=$(cat id.txt)
user_bundle_id=$(cat user_bundle_id.txt)
team_id=$(cat team_id.txt)
keychain_name=$(hexdump -n 8 -v -e '/1 "%02X"' /dev/urandom)
keychain_name="ios-signer-$keychain_name"

echo "Preparing for start..."
function cleanup() {
    # comment out for AnyDesk debug session:
    #debug

    error_code=$?
    set +e
    if [ $error_code -ne 0 ]; then
        $curl -S -H "Authorization: Bearer $SECRET_KEY" "$SECRET_URL/jobs/$job_id/fail"
    fi
    echo "Cleaning up..."
    if [[ -n "${default_keychain+x}" ]]; then
        security default-keychain -s "$default_keychain"
    fi
    # remove the $keychain_name entry from the keychain list, using its short name to match the full path
    # TODO: could there be a race condition between multiple instances of this script?
    # shellcheck disable=SC2001
    # shellcheck disable=SC2046
    eval security list-keychains -d user -s $(security list-keychains -d user | sed "s/\".*$keychain_name.*\"//")
    security delete-keychain "$keychain_name"
}
trap cleanup SIGINT SIGTERM EXIT

echo "Creating keychain..."
security create-keychain -p "1234" "$keychain_name"
security unlock-keychain -p "1234" "$keychain_name"
# shellcheck disable=SC2046
eval security list-keychains -d user -s $(security list-keychains -d user) "$keychain_name"

echo "Importing certificate..."
security import "cert.p12" -P "$cert_pass" -A -k "$keychain_name"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "1234" "$keychain_name" >/dev/null
identity=$(security find-identity -p appleID -v "$keychain_name" | head -n 1 | grep -o '".*"' | cut -d '"' -f 2)
if [ -z "$identity" ]; then
    echo "No valid code signing certificate found, aborting." >&2
    exit 1
fi

if [ ! -f "prov.mobileprovision" ]; then
    if [ ! -f "account_name.txt" ] || [ ! -f "account_pass.txt" ]; then
        echo "No provisioning profile found and no account provided, aborting." >&2
        exit 1
    fi
    if [ -z "$user_bundle_id" ]; then
        echo "Account found but no app bundle id provided, aborting." >&2
        exit 1
    fi

    killall Xcode >/dev/null 2>&1 || true
    rm "$HOME/Library/MobileDevice/Provisioning Profiles/"* >/dev/null 2>&1 || true

    default_keychain=$(security default-keychain | cut -d '"' -f 2)
    security default-keychain -s "$keychain_name"

    echo "Logging in (1/2)..."
    open "/Applications/Xcode.app"
    ACCOUNT_NAME=$(cat account_name.txt)
    ACCOUNT_PASS=$(cat account_pass.txt)
    export ACCOUNT_NAME ACCOUNT_PASS
    osascript login1.applescript

    printf '%s\n' \
        "Logging in (2/2)..." \
        "If you receive a two-factor authentication (2FA) code, please submit it to the web service."
    i=0
    code_entered=0
    while true; do
        if [ $i -gt 60 ]; then
            echo "Operation timed out" >&2
            exit 1
        elif osascript login3.applescript >/dev/null 2>&1; then
            echo "Logged in!"
            break
        elif [ $code_entered -eq 0 ] && $curl -H "Authorization: Bearer $SECRET_KEY" "$SECRET_URL/jobs/$job_id/2fa" -o account_2fa.txt; then
            echo "Entering 2FA code..."
            ACCOUNT_2FA="$(cat account_2fa.txt)"
            export ACCOUNT_2FA
            osascript login2.applescript
            code_entered=1
        fi
        sleep 1
        ((i++))
    done

    if ! osascript login4.applescript; then
        echo "Certificate is revoked. Please provide a new one." >&2
        exit 1
    fi

    killall Xcode

    sed -i "" -e "s/BUNDLE_ID_HERE_V9KP12/$user_bundle_id/g" SimpleApp/SimpleApp.xcodeproj/project.pbxproj
    sed -i "" -e "s/DEV_TEAM_HERE_J8HK5C/$team_id/g" SimpleApp/SimpleApp.xcodeproj/project.pbxproj
    open -a "/Applications/Xcode.app" SimpleApp/SimpleApp.xcodeproj

    echo "Waiting for provisioning profile to appear..."
    i=0
    while true; do
        if [ $i -gt 15 ]; then
            printf '%s\n' \
                "Operation timed out. Possible reasons:" \
                "- You haven't registered your device's UDID with the developer account" \
                "- You used an invalid or already existing bundle id" \
                "- You exceeded the 10 app ids per 7 days limit on free accounts" >&2
            exit 1
        elif ls "$HOME/Library/MobileDevice/Provisioning Profiles/"* >/dev/null 2>&1; then
            break
        fi
        sleep 1
        ((i++))
    done

    killall Xcode
    mv "$HOME/Library/MobileDevice/Provisioning Profiles/"* "prov.mobileprovision"
fi

echo "Signing..."
# shellcheck disable=SC2086
./xresign.sh -i unsigned.ipa -c "$identity" -p "prov.mobileprovision" $sign_args
mv unsigned-xresign.ipa file.ipa
rm unsigned.ipa

echo "Uploading..."
$curl -S -H "Authorization: Bearer $SECRET_KEY" -F "file=@file.ipa" -F "bundle_id=$(cat bundle_id.txt)" "$SECRET_URL/jobs/$job_id/signed"
