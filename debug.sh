#!/bin/bash
set -eu -o pipefail -E

echo "=============================================="

screencapture test.jpg
echo "Uploading screenshot..."
until curl https://bashupload.com -T test.jpg; do
    echo "Error, sleeping"
    sleep 1
done

echo "=============================================="
