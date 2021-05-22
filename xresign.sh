# !/bin/bash
set -e

usage="Usage: $(basename "$0") -i APP_PATH -c CERT_NAME [-epbdas ...]

-i  path to input app to sign
-c  Common Name of signing certificate in Keychain
-e  new entitlements to use for app (Optional)
-p  path to mobile provisioning file (Optional)
-b  new bundle id (Optional)
-d  enable app debugging (get-task-allow) (Optional)
-a  force enable support for all devices (Optional)
-s  force enable file sharing through iTunes (Optional)
-n  set bundle id to mobile provisioning app id (Optional)
-w  write bundle id to file (Optional)"

while getopts i:c:e:p:b:dasnw: option; do
    case "${option}" in
    i)
        SOURCEIPA=${OPTARG}
        ;;
    c)
        DEVELOPER=${OPTARG}
        ;;
    e)
        ENTITLEMENTS=${OPTARG}
        ;;
    p)
        MOBILEPROV=${OPTARG}
        ;;
    b)
        BUNDLEID=${OPTARG}
        ;;
    d)
        ENABLE_DEBUG=1
        ;;
    a)
        ALL_DEVICES=1
        ;;
    s)
        FILE_SHARING=1
        ;;
    n)
        ALIGN_APP_ID=1
        ;;
    w)
        BUNDLEID_SAVE_FILE=${OPTARG}
        ;;
    \?)
        echo "Invalid option: -$OPTARG" >&2
        echo "$usage" >&2
        exit 1
        ;;
    :)
        echo "Missing argument for -$OPTARG" >&2
        echo "$usage" >&2
        exit 1
        ;;
    esac
done

if [ -z "$SOURCEIPA" ] || [ -z "$DEVELOPER" ]; then
    echo "$usage" >&2
    exit 1
fi

echo "XReSign started"

OUTDIR=$(dirname "$SOURCEIPA")
OUTDIR="$PWD/$OUTDIR"
TMPDIR="$OUTDIR/tmp"
APPDIR="$TMPDIR/app"

mkdir -p "$APPDIR"
if command -v 7z &>/dev/null; then
    echo "Extracting app using 7zip"
    7z x "$SOURCEIPA" -o"$APPDIR" >/dev/null 2>&1
else
    echo "Extracting app using unzip"
    unzip -qo "$SOURCEIPA" -d "$APPDIR"
fi

APPLICATION=$(ls "$APPDIR/Payload/")

if [ -z "$MOBILEPROV" ]; then
    echo "Using app's existing provisioning profile"
else
    echo "Using user-provided provisioning profile"
    cp "$MOBILEPROV" "$APPDIR/Payload/$APPLICATION/embedded.mobileprovision"
fi

if [ -z "$ENTITLEMENTS" ]; then
    echo "Extracting entitlements from provisioning profile"
    security cms -D -i "$APPDIR/Payload/$APPLICATION/embedded.mobileprovision" >"$TMPDIR/provisioning.plist"
    /usr/libexec/PlistBuddy -x -c 'Print:Entitlements' "$TMPDIR/provisioning.plist" >"$TMPDIR/entitlements.plist"
else
    echo "Using user-provided entitlements"
    cp "$ENTITLEMENTS" "$TMPDIR/entitlements.plist"
fi

/usr/libexec/PlistBuddy -c "Delete :get-task-allow" "$TMPDIR/entitlements.plist" || true
if [ -n "$ENABLE_DEBUG" ]; then
    echo "Enabling app debugging"
    /usr/libexec/PlistBuddy -c "Add :get-task-allow bool true" "$TMPDIR/entitlements.plist"
else
    echo "Disabled app debugging"
fi

APP_ID=$(/usr/libexec/PlistBuddy -c 'Print application-identifier' "$TMPDIR/entitlements.plist")
TEAM_ID=$(/usr/libexec/PlistBuddy -c 'Print com.apple.developer.team-identifier' "$TMPDIR/entitlements.plist")

if [[ -n "$ALIGN_APP_ID" ]]; then
    if [[ "$APP_ID" == "$TEAM_ID.*" ]]; then
        echo "WARNING: Not setting bundle id to provisioning profile's app id because the latter is wildcard" >&2
        # Otherwise bundle id would be "*", and while that happens to work, it is invalid and could
        # break in a future iOS update
    else
        echo "Setting bundle id to provisioning profile's app id $APP_ID"
        BUNDLEID="${APP_ID#*.}"
    fi
fi

echo "Building list of app components"
find -d "$APPDIR" \( -name "*.app" -o -name "*.appex" -o -name "*.framework" -o -name "*.dylib" \) >"$TMPDIR/components.txt"

var=$((0))
while IFS='' read -r line || [[ -n "$line" ]]; do
    echo "Processing component $line"

    if [[ "$line" == *".app" ]] || [[ "$line" == *".appex" ]]; then
        cp "$TMPDIR/entitlements.plist" "$TMPDIR/entitlements$var.plist"
        if [[ -n "$BUNDLEID" ]]; then
            if [[ "$line" == *".app" ]]; then
                EXTRA_ID="$BUNDLEID"
            else
                EXTRA_ID="$BUNDLEID.extra$var"
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
            /usr/libexec/PlistBuddy -c "Set :application-identifier $TEAM_ID.$EXTRA_ID" "$TMPDIR/entitlements$var.plist"
        else
            echo "WARNING: Provisioning profile's app ID $APP_ID doesn't match component's bundle ID $TEAM_ID.$EXTRA_ID." >&2
            echo "Leaving original entitlements - the app will run, but all entitlements will be broken!" >&2
        fi

        if [ -n "$BUNDLEID_SAVE_FILE" ] && [[ "$line" == *".app" ]]; then
            echo "Writing bundle id to file"
            echo "$EXTRA_ID" >"$BUNDLEID_SAVE_FILE"
        fi

        /usr/bin/codesign --continue -f -s "$DEVELOPER" --entitlements "$TMPDIR/entitlements$var.plist" "$line"
    else
        # Entitlements of frameworks, etc. don't matter, so leave them (potentially) invalid
        echo "Signing with original entitlements"
        /usr/bin/codesign --continue -f -s "$DEVELOPER" "$line"
    fi

    var=$((var + 1))
done <"$TMPDIR/components.txt"

echo "Creating signed IPA"
cd "$APPDIR"
filename=$(basename "$APPLICATION")
filename="${filename%.*}-xresign.ipa"
zip -qr "../$filename" *
cd ..
mv "$filename" "$OUTDIR"

echo "Cleaning temporary files"
rm -rf "$APPDIR"
rm "$TMPDIR/components.txt"
rm "$TMPDIR/provisioning.plist" || true
rm "$TMPDIR/entitlements"*".plist"
if [ -z "$(ls -A "$TMPDIR")" ]; then
    rm -d "$TMPDIR"
fi

echo "XReSign finished"
