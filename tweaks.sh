#!/bin/bash
set -eu -o pipefail -E

OLD_WD="$PWD"
git clone https://github.com/SignTools/Azule ~/Azule
cd ~/Azule
git reset --hard ebd6d48cd980fbbc7b460bf49ef35e6dc21604ad
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
