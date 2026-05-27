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

SDK_LIB_X64=""
SDK_LIB_X86=""

for f in "$SEARCH_DIR"/*/Lib/*/um/x64/kernel32.lib; do
    if [ -f "$f" ]; then
        SDK_LIB_X64="$f"
    fi
done

for f in "$SEARCH_DIR"/*/Lib/*/um/x86/kernel32.lib; do
    if [ -f "$f" ]; then
        SDK_LIB_X86="$f"
    fi
done

if [ -n "$SDK_LIB_X64" ] && [ -n "$SDK_LIB_X86" ]; then
    SHORT_X64=$(cygpath -m -s "$SDK_LIB_X64")
    SHORT_X86=$(cygpath -m -s "$SDK_LIB_X86")

    {
        echo "WINDOWS_SDK_KERNEL32_X64 := $SHORT_X64"
        echo "WINDOWS_SDK_KERNEL32_X86 := $SHORT_X86"
    } > sdk_lib.mk

    echo "Found x64: $SHORT_X64"
    echo "Found x86: $SHORT_X86"
else
    echo "kernel32.lib not found for both x64 and x86 under: $SEARCH_DIR"
    exit 1
fi
