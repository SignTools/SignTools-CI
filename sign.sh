#!/bin/bash
set -e

echo "Obtaining files..."
curl -sS -L -H "Authorization: Bearer $SECRET_KEY" "$SECRET_URL/jobs" | tar -x
CERT_PASS=$(cat pass.txt)
SIGN_ARGS=$(cat args.txt)
UPLOAD_ID=$(cat id.txt)
curl -sS -L "https://raw.githubusercontent.com/SignTools/XReSign/master/XReSign/Scripts/xresign.sh" --output xresign.sh
chmod +x xresign.sh

echo "Creating keychain..."
security create-keychain -p "1234" "sign"
security unlock-keychain -p "1234" "sign"
security default-keychain -s "sign"

echo "Importing certificate..."
security import "cert.p12" -P "$CERT_PASS" -A
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "1234" >/dev/null 2>&1
IDENTITY=$(security find-identity -p appleID -v | grep -o '".*"' | cut -d '"' -f 2)

echo "Signing..."
./xresign.sh -i unsigned.ipa -c "$IDENTITY" -p "prov.mobileprovision" $SIGN_ARGS >/dev/null 2>&1
rm unsigned.ipa
mv *.ipa file.ipa

echo "Uploading..."
curl -sS -H "Authorization: Bearer $SECRET_KEY" -F "file=@file.ipa" "$SECRET_URL/jobs/$UPLOAD_ID"
