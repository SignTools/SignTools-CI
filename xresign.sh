#!/bin/bash
set -e

while getopts i:c:p:b:dasn option; do
    case "${option}" in
    i) # path to input app to sign
        SOURCE_IPA=${OPTARG}
        ;;
    c) # Common Name (CN) of signing certificate in Keychain
        IDENTITY=${OPTARG}
        ;;
    p) # path to provisioning profile file (Optional)
        MOBILE_PROV=${OPTARG}
        ;;
    b) # new bundle id (Optional)
        BUNDLE_ID=${OPTARG}
        ;;
    d) # enable app debugging (get-task-allow) (Optional)
        ENABLE_DEBUG=1
        ;;
    a) # force enable support for all devices (Optional)
        ALL_DEVICES=1
        ;;
    s) # force enable file sharing through iTunes (Optional)
        FILE_SHARING=1
        ;;
    n) # set bundle id to mobile provisioning app id (Optional)
        ALIGN_APP_ID=1
        ;;
    \?)
        echo "Invalid option: -$OPTARG" >&2
        exit 1
        ;;
    :)
        echo "Missing argument for -$OPTARG" >&2
        exit 1
        ;;
    esac
done

# $1 - variable to check if empty
# $2 - message to show if variable was empty
function check_empty() {
    if [ -z "$1" ]; then
        echo "$2" >&2
        exit 1
    fi
}

echo "XReSign started"

check_empty "$SOURCE_IPA" "No input app provided (-i argument)"
check_empty "$IDENTITY" "No signing certificate provided (-c argument)"

TMP_DIR=$(hexdump -n 8 -v -e '/1 "%02X"' /dev/urandom)
TMP_DIR="xresign-tmp-$TMP_DIR"
APP_DIR="$TMP_DIR/app"

function cleanup() {
    set +e
    echo "Cleaning up"
    rm -r "$TMP_DIR"
}
trap cleanup SIGINT SIGTERM EXIT

mkdir -p "$APP_DIR"
if command -v 7z &>/dev/null; then
    echo "Extracting app using 7zip"
    7z x "$SOURCE_IPA" -o"$APP_DIR" >/dev/null
else
    echo "Extracting app using unzip"
    unzip -qo "$SOURCE_IPA" -d "$APP_DIR"
fi

APP_NAME=$(ls "$APP_DIR/Payload/")
check_empty "$APP_NAME" "No payload inside app"

if [ -z "$MOBILE_PROV" ]; then
    echo "Using app's existing provisioning profile"
else
    echo "Using user-provided provisioning profile"
    cp "$MOBILE_PROV" "$APP_DIR/Payload/$APP_NAME/embedded.mobileprovision"
fi

echo "Extracting entitlements from provisioning profile"
security cms -D -i "$APP_DIR/Payload/$APP_NAME/embedded.mobileprovision" >"$TMP_DIR/provisioning.plist"
/usr/libexec/PlistBuddy -x -c 'Print:Entitlements' "$TMP_DIR/provisioning.plist" >"$TMP_DIR/entitlements.plist"

/usr/libexec/PlistBuddy -c "Delete :get-task-allow" "$TMP_DIR/entitlements.plist" || true
if [ -n "$ENABLE_DEBUG" ]; then
    echo "Enabling app debugging"
    /usr/libexec/PlistBuddy -c "Add :get-task-allow bool true" "$TMP_DIR/entitlements.plist"
else
    echo "Disabled app debugging"
fi

APP_ID=$(/usr/libexec/PlistBuddy -c 'Print application-identifier' "$TMP_DIR/entitlements.plist")
TEAM_ID=$(/usr/libexec/PlistBuddy -c 'Print com.apple.developer.team-identifier' "$TMP_DIR/entitlements.plist")

if [[ -n "$ALIGN_APP_ID" ]]; then
    if [[ "$APP_ID" == "$TEAM_ID.*" ]]; then
        echo "WARNING: Not setting bundle id to provisioning profile's app id because the latter is wildcard" >&2
        # Otherwise bundle id would be "*", and while that happens to work, it is invalid and could
        # break in a future iOS update
    else
        echo "Setting bundle id to provisioning profile's app id $APP_ID"
        BUNDLE_ID="${APP_ID#*.}"
    fi
fi

echo "Building list of app components"
find -d "$APP_DIR" \( -name "*.app" -o -name "*.appex" -o -name "*.framework" -o -name "*.dylib" \) >"$TMP_DIR/components.txt"

var=$((0))
while IFS='' read -r line || [[ -n "$line" ]]; do
    echo "Processing component $line"

    if [[ "$line" == *".app" ]] || [[ "$line" == *".appex" ]]; then
        cp "$TMP_DIR/entitlements.plist" "$TMP_DIR/entitlements$var.plist"
        if [[ -n "$BUNDLE_ID" ]]; then
            if [[ "$line" == *".app" ]]; then
                EXTRA_ID="$BUNDLE_ID"
            else
                EXTRA_ID="$BUNDLE_ID.extra$var"
            fi
            echo "Setting bundle ID to $EXTRA_ID"
            /usr/libexec/PlistBuddy -c "Set:CFBundleIdentifier $EXTRA_ID" "$line/Info.plist"
        fi

        if [[ -n "$ALL_DEVICES" ]]; then
            echo "Force enabling support for all devices"
            /usr/libexec/PlistBuddy -c "Delete :UISupportedDevices" "$line/Info.plist" || true
            # https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html
            /usr/libexec/PlistBuddy -c "Delete :UIDeviceFamily" "$line/Info.plist" || true
            /usr/libexec/PlistBuddy -c "Add :UIDeviceFamily array" "$line/Info.plist"
            /usr/libexec/PlistBuddy -c "Add :UIDeviceFamily:0 integer 1" "$line/Info.plist"
            /usr/libexec/PlistBuddy -c "Add :UIDeviceFamily:1 integer 2" "$line/Info.plist"
        fi

        if [ -n "$FILE_SHARING" ]; then
            echo "Force enabling file sharing"
            /usr/libexec/PlistBuddy -c "Delete :UIFileSharingEnabled" "$line/Info.plist" || true
            /usr/libexec/PlistBuddy -c "Add :UIFileSharingEnabled bool true" "$line/Info.plist"
        fi

        EXTRA_ID=$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$line/Info.plist")
        if [[ "$APP_ID" == "$TEAM_ID.$EXTRA_ID" ]] || [[ "$APP_ID" == "$TEAM_ID.*" ]]; then
            echo "Setting entitlements app ID to $TEAM_ID.$EXTRA_ID"
            /usr/libexec/PlistBuddy -c "Set :application-identifier $TEAM_ID.$EXTRA_ID" "$TMP_DIR/entitlements$var.plist"
        else
            echo "WARNING: Provisioning profile's app ID $APP_ID doesn't match component's bundle ID $TEAM_ID.$EXTRA_ID" >&2
            echo "Leaving original entitlements - the app will run, but all entitlements will be broken!" >&2
        fi

        if [[ "$line" == *".app" ]]; then
            echo "Writing bundle id to file"
            echo "$EXTRA_ID" >bundle_id.txt
        fi

        /usr/bin/codesign --continue -f -s "$IDENTITY" --entitlements "$TMP_DIR/entitlements$var.plist" "$line"
    else
        # Entitlements of frameworks, etc. don't matter, so leave them (potentially) invalid
        echo "Signing with original entitlements"
        /usr/bin/codesign --continue -f -s "$IDENTITY" "$line"
    fi

    var=$((var + 1))
done <"$TMP_DIR/components.txt"

echo "Creating signed IPA"
# strip the extension: "Example.app" -> "Example"
SIGNED_IPA="$(basename "${SOURCE_IPA%.*}")"
SIGNED_IPA="$PWD/$SIGNED_IPA-xresign.ipa"
cd "$APP_DIR"
zip -qr "$SIGNED_IPA" -- *
cd - >/dev/null

echo "XReSign finished"
