#!/bin/bash
set -e
CURL="curl -sfL"

echo "Obtaining files..."
$CURL -S -H "Authorization: Bearer $SECRET_KEY" "$SECRET_URL/jobs" | tar -x
CERT_PASS=$(cat cert_pass.txt)
SIGN_ARGS=$(cat args.txt)
JOB_ID=$(cat id.txt)
USER_BUNDLE_ID=$(cat user_bundle_id.txt)
KEYCHAIN_ID=$(hexdump -n 8 -v -e '/1 "%02X"' /dev/urandom)
KEYCHAIN_ID="ios-signer-$KEYCHAIN_ID"

echo "Creating keychain..."
function cleanup() {
    set +e
    # remove the $KEYCHAIN_ID entry from the keychain list, using its short name to match the full path
    # TODO: could there be a race condition between multiple instances of this script?
    eval security list-keychains -d user -s $(echo "$(security list-keychains -d user)" | sed "s/\".*$KEYCHAIN_ID.*\"//")
    security delete-keychain "$KEYCHAIN_ID"
}
trap cleanup SIGINT SIGTERM EXIT
security create-keychain -p "1234" "$KEYCHAIN_ID"
security unlock-keychain -p "1234" "$KEYCHAIN_ID"
eval security list-keychains -d user -s $(security list-keychains -d user) "$KEYCHAIN_ID"

echo "Importing certificate..."
security import "cert.p12" -P "$CERT_PASS" -A -k "$KEYCHAIN_ID"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "1234" "$KEYCHAIN_ID" >/dev/null
IDENTITY=$(security find-identity -p appleID -v "$KEYCHAIN_ID" | head -n 1 | grep -o '".*"' | cut -d '"' -f 2)
if [ -z "$IDENTITY" ]; then
    echo "No valid code signing certificate found, aborting." >&2
    exit 1
fi

if [ ! -f "prov.mobileprovision" ]; then
    if [ ! -f "account_name.txt" ] || [ ! -f "account_pass.txt" ]; then
        echo "No provisioning profile found and no account provided, aborting." >&2
        exit 1
    fi
    if [ -z "$USER_BUNDLE_ID" ]; then
        echo "Account found but no app bundle id provided, aborting." >&2
        exit 1
    fi

    killall Xcode >/dev/null 2>&1 || true
    rm "$HOME/Library/MobileDevice/Provisioning Profiles/"* >/dev/null 2>&1 || true

    echo "Logging in (1/2)..."
    echo >dummy.developerprofile
    # force Xcode to open the Accounts screen
    open -a "/Applications/Xcode.app" dummy.developerprofile
    export ACCOUNT_NAME=$(cat account_name.txt)
    export ACCOUNT_PASS=$(cat account_pass.txt)
    osascript login1.applescript

    echo "Logging in (2/2)..."
    echo "If you receive a two-factor authentication (2FA) code, please submit it to the web service."
    i=0
    ret=1
    while true; do
        if [ $i -gt 60 ]; then
            echo "Operation timed out" >&2
            exit 1
        fi
        if osascript login3.applescript >/dev/null 2>&1; then
            echo "Logged in!"
            break
        elif [ $ret -ne 0 ]; then
            $CURL -H "Authorization: Bearer $SECRET_KEY" "$SECRET_URL/jobs/$JOB_ID/2fa" -o account_2fa.txt && ret=0 || continue
            echo "Entering 2FA code..."
            export ACCOUNT_2FA="$(cat account_2fa.txt)"
            osascript login2.applescript
        fi
        sleep 1
        ((i++))
    done

    killall Xcode

    echo "Parsing certificate..."
    CERT_INFO=$(openssl pkcs12 -in cert.p12 -passin pass:"$CERT_PASS" -nokeys | openssl x509 -noout -subject)
    if echo "$CERT_INFO" | grep ', OU = .*, ' >/dev/null 2>&1; then
        TEAM_ID=$(echo "${CERT_INFO#*, OU = }" | cut -d',' -f1)
    elif echo "$CERT_INFO" | grep '\/OU=.*\/' >/dev/null 2>&1; then
        TEAM_ID=$(echo "${CERT_INFO#*\/OU=}" | cut -d'/' -f1)
    else
        echo "Unknown certificate dump format:" >&2
        echo "$CERT_INFO" >&2
        exit 1
    fi
    sed -i "" -e "s/BUNDLE_ID_HERE_V9KP12/$USER_BUNDLE_ID/g" SimpleApp/SimpleApp.xcodeproj/project.pbxproj
    sed -i "" -e "s/DEV_TEAM_HERE_J8HK5C/$TEAM_ID/g" SimpleApp/SimpleApp.xcodeproj/project.pbxproj
    open -a "/Applications/Xcode.app" SimpleApp/SimpleApp.xcodeproj

    echo "Waiting for provisioning profile to appear..."
    i=0
    ret=1
    while [ $ret -ne 0 ]; do
        if [ $i -gt 15 ]; then
            echo "Operation timed out. Possible reasons:" >&2
            echo "- You haven't registered your device's UDID with the developer account" >&2
            echo "- You used an invalid or already existing bundle id" >&2
            echo "- You exceeded the 10 app ids per 7 days limit on free accounts" >&2
            exit 1
        fi
        ls "$HOME/Library/MobileDevice/Provisioning Profiles/"* >/dev/null 2>&1 && ret=$? || ret=$?
        sleep 1
        ((i++))
    done

    killall Xcode
    mv "$HOME/Library/MobileDevice/Provisioning Profiles/"* "prov.mobileprovision"
fi

echo "Signing..."
./xresign.sh -i unsigned.ipa -c "$IDENTITY" -p "prov.mobileprovision" -w bundle_id.txt $SIGN_ARGS
rm unsigned.ipa
mv *.ipa file.ipa

echo "Uploading..."
$CURL -S -H "Authorization: Bearer $SECRET_KEY" -F "file=@file.ipa" -F "bundle_id=$(cat bundle_id.txt)" "$SECRET_URL/jobs/$JOB_ID/signed"
