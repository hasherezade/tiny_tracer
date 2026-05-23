#!/bin/bash
# find_sdk_lib.sh - locate Windows SDK kernel32.lib
# Usage: bash find_sdk_lib.sh [optional_sdk_root]

SEARCH_DIR="$1"

if [ -z "$SEARCH_DIR" ]; then
    # Mirror the batch script fallback logic
    for candidate in \
        "/c/Program Files (x86)/Windows Kits" \
        "/c/Program Files/Windows Kits" \
        "$(cygpath -u "$PROGRAMFILES" 2>/dev/null)/Windows Kits"
    do
        if [ -d "$candidate" ]; then
            SEARCH_DIR="$candidate"
            echo "Using SDK path: $SEARCH_DIR"
            break
        fi
    done
fi

if [ -z "$SEARCH_DIR" ] || [ ! -d "$SEARCH_DIR" ]; then
    echo "Windows Kits directory not found!"
    echo "Usage: $0 [path_to_Windows_Kits]"
    exit 1
fi

# Use glob instead of find — more reliable with special characters in MSYS2
SDK_LIB=""
for f in "$SEARCH_DIR"/*/Lib/*/um/x64/kernel32.lib; do
    if [ -f "$f" ]; then
        SDK_LIB="$f"
    fi
done

if [ -n "$SDK_LIB" ]; then
    SHORT_PATH=$(cygpath -m -s "$SDK_LIB")
    echo "WINDOWS_SDK_KERNEL32 := $SHORT_PATH" > sdk_lib.mk
    echo "Found: $SHORT_PATH"
else
    echo "kernel32.lib not found under: $SEARCH_DIR"
    exit 1
fi
