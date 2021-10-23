#!/bin/bash
set -eu -o pipefail -E

OLD_WD="$PWD"
git clone https://github.com/SignTools/Azule ~/Azule
cd ~/Azule
git reset --hard f7565d92dbd4d46925c99f9f224a86a5e0def9ee
set +u
source azule-functions
set -u
setup-azule
cd "$OLD_WD"

azule -i unsigned.ipa -o . -n tweaked -f "$@"
if [ ! -f tweaked.ipa ]; then
    exit 1
fi
mv tweaked.ipa unsigned.ipa
