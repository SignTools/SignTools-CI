#!/bin/bash
set -e

while getopts i:c:p:b:dasn option; do
    case "${option}" in
    i) # path to input app to sign
        source_ipa=${OPTARG}
        ;;
    c) # Common Name (CN) of signing certificate in Keychain
        identity=${OPTARG}
        ;;
    p) # path to provisioning profile file (Optional)
        mobile_prov=${OPTARG}
        ;;
    b) # new bundle id (Optional)
        bundle_id=${OPTARG}
        ;;
    d) # enable app debugging (get-task-allow) (Optional)
        enable_debug=1
        ;;
    a) # force enable support for all devices (Optional)
        all_devices=1
        ;;
    s) # force enable file sharing through iTunes (Optional)
        file_sharing=1
        ;;
    n) # set bundle id to mobile provisioning app id (Optional)
        align_app_id=1
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

check_empty "$source_ipa" "No input app provided (-i argument)"
check_empty "$identity" "No signing certificate provided (-c argument)"

tmp_dir=$(hexdump -n 8 -v -e '/1 "%02X"' /dev/urandom)
tmp_dir="xresign-tmp-$tmp_dir"
app_dir="$tmp_dir/app"

function cleanup() {
    set +e
    echo "Cleaning up"
    rm -r "$tmp_dir"
}
trap cleanup SIGINT SIGTERM EXIT

mkdir -p "$app_dir"
if command -v 7z &>/dev/null; then
    echo "Extracting app using 7zip"
    7z x "$source_ipa" -o"$app_dir" >/dev/null
else
    echo "Extracting app using unzip"
    unzip -qo "$source_ipa" -d "$app_dir"
fi

app_name=$(ls "$app_dir/Payload/")
check_empty "$app_name" "No payload inside app"

if [ -z "$mobile_prov" ]; then
    echo "Using app's existing provisioning profile"
else
    echo "Using user-provided provisioning profile"
    cp "$mobile_prov" "$app_dir/Payload/$app_name/embedded.mobileprovision"
fi

echo "Extracting entitlements from provisioning profile"
security cms -D -i "$app_dir/Payload/$app_name/embedded.mobileprovision" >"$tmp_dir/provisioning.plist"
/usr/libexec/PlistBuddy -x -c 'Print:Entitlements' "$tmp_dir/provisioning.plist" >"$tmp_dir/entitlements.plist"

/usr/libexec/PlistBuddy -c "Delete :get-task-allow" "$tmp_dir/entitlements.plist" || true
if [ -n "$enable_debug" ]; then
    echo "Enabling app debugging"
    /usr/libexec/PlistBuddy -c "Add :get-task-allow bool true" "$tmp_dir/entitlements.plist"
else
    echo "Disabled app debugging"
fi

app_id=$(/usr/libexec/PlistBuddy -c 'Print application-identifier' "$tmp_dir/entitlements.plist")
team_id=$(/usr/libexec/PlistBuddy -c 'Print com.apple.developer.team-identifier' "$tmp_dir/entitlements.plist")

if [[ -n "$align_app_id" ]]; then
    if [[ "$app_id" == "$team_id.*" ]]; then
        echo "WARNING: Not setting bundle id to provisioning profile's app id because the latter is wildcard" >&2
        # Otherwise bundle id would be "*", and while that happens to work, it is invalid and could
        # break in a future iOS update
    else
        echo "Setting bundle id to provisioning profile's app id $app_id"
        bundle_id="${app_id#*.}"
    fi
fi

echo "Building list of app components"
find -d "$app_dir" \( -name "*.app" -o -name "*.appex" -o -name "*.framework" -o -name "*.dylib" \) >"$tmp_dir/components.txt"

var=$((0))
while IFS='' read -r line || [[ -n "$line" ]]; do
    echo "Processing component $line"

    if [[ "$line" == *".app" ]] || [[ "$line" == *".appex" ]]; then
        cp "$tmp_dir/entitlements.plist" "$tmp_dir/entitlements$var.plist"
        if [[ -n "$bundle_id" ]]; then
            if [[ "$line" == *".app" ]]; then
                extra_id="$bundle_id"
            else
                extra_id="$bundle_id.extra$var"
            fi
            echo "Setting bundle ID to $extra_id"
            /usr/libexec/PlistBuddy -c "Set:CFBundleIdentifier $extra_id" "$line/Info.plist"
        fi

        if [[ -n "$all_devices" ]]; then
            echo "Force enabling support for all devices"
            /usr/libexec/PlistBuddy -c "Delete :UISupportedDevices" "$line/Info.plist" || true
            # https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html
            /usr/libexec/PlistBuddy -c "Delete :UIDeviceFamily" "$line/Info.plist" || true
            /usr/libexec/PlistBuddy -c "Add :UIDeviceFamily array" "$line/Info.plist"
            /usr/libexec/PlistBuddy -c "Add :UIDeviceFamily:0 integer 1" "$line/Info.plist"
            /usr/libexec/PlistBuddy -c "Add :UIDeviceFamily:1 integer 2" "$line/Info.plist"
        fi

        if [ -n "$file_sharing" ]; then
            echo "Force enabling file sharing"
            /usr/libexec/PlistBuddy -c "Delete :UIFileSharingEnabled" "$line/Info.plist" || true
            /usr/libexec/PlistBuddy -c "Add :UIFileSharingEnabled bool true" "$line/Info.plist"
        fi

        extra_id=$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$line/Info.plist")
        if [[ "$app_id" == "$team_id.$extra_id" ]] || [[ "$app_id" == "$team_id.*" ]]; then
            echo "Setting entitlements app ID to $team_id.$extra_id"
            /usr/libexec/PlistBuddy -c "Set :application-identifier $team_id.$extra_id" "$tmp_dir/entitlements$var.plist"
        else
            echo "WARNING: Provisioning profile's app ID $app_id doesn't match component's bundle ID $team_id.$extra_id" >&2
            echo "Leaving original entitlements - the app will run, but all entitlements will be broken!" >&2
        fi

        if [[ "$line" == *".app" ]]; then
            echo "Writing bundle id to file"
            echo "$extra_id" >bundle_id.txt
        fi

        /usr/bin/codesign --continue -f -s "$identity" --entitlements "$tmp_dir/entitlements$var.plist" "$line"
    else
        # Entitlements of frameworks, etc. don't matter, so leave them (potentially) invalid
        echo "Signing with original entitlements"
        /usr/bin/codesign --continue -f -s "$identity" "$line"
    fi

    var=$((var + 1))
done <"$tmp_dir/components.txt"

echo "Creating signed IPA"
# strip the extension: "Example.app" -> "Example"
signed_ipa="$(basename "${source_ipa%.*}")"
signed_ipa="$PWD/$signed_ipa-xresign.ipa"
cd "$app_dir"
zip -qr "$signed_ipa" -- *
cd - >/dev/null

echo "XReSign finished"
