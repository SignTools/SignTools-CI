#!/bin/bash
set -eu -o pipefail -E

echo "=============================================="
screencapture test.jpg
echo "Uploading screenshot..."
i=10
until curl https://bashupload.com -T test.jpg || [ $i == 0 ]; do
    echo "Error, sleeping"
    sleep 1
    i=$((i-1))
done

if [ $i == 0 ]; then
    echo "Error uploading screenshot"
fi
echo "=============================================="
