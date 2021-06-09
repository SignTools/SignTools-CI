#!/bin/bash
set -eu -o pipefail -E

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
        user_bundle_id=${OPTARG}
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
    if [[ -z "$1" ]]; then
        echo "$2" >&2
        exit 1
    fi
}

echo "XReSign started"

check_empty "$source_ipa" "No input app provided (-i argument)"
check_empty "$identity" "No signing certificate provided (-c argument)"
check_empty "$mobile_prov" "No provisioning profile provided (-p argument)"

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

app_payloads=("$app_dir/Payload/"*)
app_payload=${app_payloads[0]}
if [ ! -d "$app_payload" ]; then
    echo "No payload inside app" >&2
    exit 1
fi

echo "Using user-provided provisioning profile"
cp "$mobile_prov" "$app_payload/embedded.mobileprovision"

echo "Extracting entitlements from provisioning profile"
provisioning_plist="$tmp_dir/provisioning.plist"
user_entitlements_plist="$tmp_dir/entitlements.plist"
security cms -D -i "$app_payload/embedded.mobileprovision" >"$provisioning_plist"
/usr/libexec/PlistBuddy -x -c 'Print:Entitlements' "$provisioning_plist" >"$user_entitlements_plist"

/usr/libexec/PlistBuddy -c "Delete :get-task-allow" "$user_entitlements_plist" || true
if [[ -n "${enable_debug+x}" ]]; then
    echo "Enabling app debugging"
    /usr/libexec/PlistBuddy -c "Add :get-task-allow bool true" "$user_entitlements_plist"
else
    echo "Disabled app debugging"
fi

app_id=$(/usr/libexec/PlistBuddy -c 'Print application-identifier' "$user_entitlements_plist")
team_id=$(/usr/libexec/PlistBuddy -c 'Print com.apple.developer.team-identifier' "$user_entitlements_plist")

if [[ -n "${align_app_id+x}" ]]; then
    if [[ "$app_id" == "$team_id.*" ]]; then
        echo "WARNING: Not setting bundle id to provisioning profile's app id because the latter is wildcard" >&2
        # Otherwise bundle id would be "*", and while that happens to work, it is invalid and could
        # break in a future iOS update
    else
        echo "Setting bundle id to provisioning profile's app id $app_id"
        user_bundle_id="${app_id#*.}"
    fi
fi

echo "Building list of app components"
components=$(find "$app_payload" -depth \( -name "*.app" -o -name "*.appex" -o -name "*.framework" -o -name "*.dylib" \))

var=$((0))
while IFS='' read -r line || [[ -n "$line" ]]; do
    echo "Processing component $line"

    if [[ "$line" == *".app" ]] || [[ "$line" == *".appex" ]]; then
        info_plist="$line/Info.plist"
        entitlements_plist="$tmp_dir/entitlements$var.plist"
        cp "$user_entitlements_plist" "$entitlements_plist"

        if [[ -n "${user_bundle_id+x}" ]]; then
            if [[ "$line" == *".app" ]]; then
                bundle_id="$user_bundle_id"
            else
                bundle_id="$user_bundle_id.extra$var"
            fi
            echo "Setting bundle ID to $bundle_id"
            /usr/libexec/PlistBuddy -c "Set:CFBundleIdentifier $bundle_id" "$info_plist"
        fi

        if [[ -n "${all_devices+x}" ]]; then
            echo "Force enabling support for all devices"
            /usr/libexec/PlistBuddy -c "Delete :UISupportedDevices" "$info_plist" || true
            # https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html
            /usr/libexec/PlistBuddy -c "Delete :UIDeviceFamily" "$info_plist" || true
            /usr/libexec/PlistBuddy -c "Add :UIDeviceFamily array" "$info_plist"
            /usr/libexec/PlistBuddy -c "Add :UIDeviceFamily:0 integer 1" "$info_plist"
            /usr/libexec/PlistBuddy -c "Add :UIDeviceFamily:1 integer 2" "$info_plist"
        fi

        if [[ -n "${file_sharing+x}" ]]; then
            echo "Force enabling file sharing"
            /usr/libexec/PlistBuddy -c "Delete :UIFileSharingEnabled" "$info_plist" || true
            /usr/libexec/PlistBuddy -c "Add :UIFileSharingEnabled bool true" "$info_plist"
        fi

        bundle_id=$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$info_plist")
        if [[ "$app_id" == "$team_id.$bundle_id" ]] || [[ "$app_id" == "$team_id.*" ]]; then
            echo "Setting entitlements app ID to $team_id.$bundle_id"
            /usr/libexec/PlistBuddy -c "Set :application-identifier $team_id.$bundle_id" "$entitlements_plist"
        else
            printf '%s\n' \
                "WARNING: Provisioning profile's app ID $app_id doesn't match component's bundle ID $team_id.$bundle_id" \
                "Leaving original entitlements app ID - the app will run, but all entitlements will be broken!" >&2
        fi

        if [[ "$line" == *".app" ]]; then
            echo "Writing bundle id to file"
            echo "$bundle_id" >bundle_id.txt
        fi

        /usr/bin/codesign --continue -f -s "$identity" --entitlements "$entitlements_plist" "$line"
    else
        # Entitlements of frameworks, etc. don't matter, so leave them (potentially) invalid
        echo "Signing with original entitlements"
        /usr/bin/codesign --continue -f -s "$identity" "$line"
    fi

    var=$((var + 1))
done < <(printf '%s\n' "$components")

echo "Creating signed IPA"
# strip the extension: "Example.app" -> "Example"
signed_ipa="$(basename "${source_ipa%.*}")"
signed_ipa="$PWD/$signed_ipa-xresign.ipa"
cd "$app_dir"
zip -qr "$signed_ipa" -- *
cd - >/dev/null

echo "XReSign finished"
