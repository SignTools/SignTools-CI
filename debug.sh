#!/bin/bash
set -eu -o pipefail -E

echo "=============================================="

screencapture test.png
echo "Uploading screenshot..."
if ! curl -w "\n" --upload-file test.png "https://transfer.sh/$(openssl rand -hex 8).png"; then
    echo "Error uploading screenshot"
fi

echo "=============================================="
