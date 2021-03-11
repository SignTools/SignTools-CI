#!/bin/bash
set -e

echo "Obtaining files..."
curl -sS -L -H "Authorization: Bearer $SECRET_KEY" "$SECRET_URL/jobs" | tar -x
CERT_PASS=$(cat cert_pass.txt)
SIGN_ARGS=$(cat args.txt)
JOB_ID=$(cat id.txt)
USER_BUNDLE_ID=$(cat user_bundle_id.txt)
XRESIGN_VERSION="10dbcaefd68084d459bd392351ff2ce4934dabd3"
curl -sS -L "https://raw.githubusercontent.com/SignTools/XReSign/$XRESIGN_VERSION/XReSign/Scripts/xresign.sh" -o xresign.sh
chmod +x xresign.sh

echo "Creating keychain..."
security create-keychain -p "1234" "sign"
security unlock-keychain -p "1234" "sign"
security default-keychain -s "sign"

echo "Importing certificate..."
security import "cert.p12" -P "$CERT_PASS" -A
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "1234" >/dev/null 2>&1
IDENTITY=$(security find-identity -p appleID -v | grep -o '".*"' | cut -d '"' -f 2)

if [ ! -f "prov.mobileprovision" ]; then
    if [ ! -f "account_name.txt" ] || [ ! -f "account_pass.txt" ]; then
        echo "No provisioning profile found and no account provided, aborting."
        exit 1
    fi
    if [ -z "$USER_BUNDLE_ID" ]; then
        echo "Account found but no app bundle id provided, aborting."
        exit 1
    fi

    echo "Logging in (1/2)..."
    echo >dummy.developerprofile
    # force Xcode to open the Accounts screen
    open -a "/Applications/Xcode.app" dummy.developerprofile
    export ACCOUNT_NAME=$(cat account_name.txt)
    export ACCOUNT_PASS=$(cat account_pass.txt)
    osascript login1.applescript

    echo "Waiting for 2FA code..."
    i=0
    ret=1
    while [ $ret -ne 0 ]; do
        if [ $i -gt 60 ]; then
            echo "Operation timed out"
            exit 1
        fi
        curl -sL --fail -H "Authorization: Bearer $SECRET_KEY" "$SECRET_URL/jobs/$JOB_ID/2fa" -o account_2fa.txt && ret=$? || ret=$?
        sleep 1
        ((i++))
    done

    echo "Logging in (2/2)..."
    export ACCOUNT_2FA="$(cat account_2fa.txt)"
    osascript login2.applescript

    echo "Parsing certificate..."
    CERT_INFO=$(openssl pkcs12 -in cert.p12 -passin pass:"$CERT_PASS" -nokeys | openssl x509 -noout -subject)
    if echo "$CERT_INFO" | grep ', OU = .*, ' >/dev/null 2>&1; then
        TEAM_ID=$(echo "${CERT_INFO#*, OU = }" | cut -d',' -f1)
    elif echo "$CERT_INFO" | grep '\/OU=.*\/' >/dev/null 2>&1; then
        TEAM_ID=$(echo "${CERT_INFO#*\/OU=}" | cut -d'/' -f1)
    else
        echo "Unknown certificate dump format:"
        echo "$CERT_INFO"
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
            echo "Operation timed out. Possible reasons:"
            echo "- You haven't registered your device's UDID with the developer account"
            echo "- You used an invalid or already existing bundle id"
            echo "- You exceeded the 10 app ids per 7 days limit on free accounts"
            exit 1
        fi
        ls "$HOME/Library/MobileDevice/Provisioning Profiles/"* >/dev/null 2>&1 && ret=$? || ret=$?
        sleep 1
        ((i++))
    done

    cp "$HOME/Library/MobileDevice/Provisioning Profiles/"* "prov.mobileprovision"
fi

echo "Signing..."
./xresign.sh -i unsigned.ipa -c "$IDENTITY" -p "prov.mobileprovision" -w bundle_id.txt $SIGN_ARGS >/dev/null 2>&1
rm unsigned.ipa
mv *.ipa file.ipa

echo "Uploading..."
curl -sS -H "Authorization: Bearer $SECRET_KEY" -F "file=@file.ipa" -F "bundle_id=$(cat bundle_id.txt)" "$SECRET_URL/jobs/$JOB_ID/signed"
