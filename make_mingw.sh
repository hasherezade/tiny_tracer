#!/bin/bash

TT_BUILD_32=TinyTracer32.dll
TT_BUILD_64=TinyTracer64.dll

TT_32=./obj-ia32/$TT_BUILD_32
TT_64=./obj-intel64/$TT_BUILD_64

TARGET_DIR=./install32_64

if [ -f $TT_32 ]; then
  rm $TT_32
fi
if [ -f $TT_64 ]; then
  rm $TT_64
fi

if [ -f $TARGET_DIR/$TT_BUILD_32 ]; then
  rm $TARGET_DIR/$TT_BUILD_32
fi
if [ -f $TARGET_DIR/$TT_BUILD_64 ]; then
  rm $TARGET_DIR/$TT_BUILD_64
fi

mingw32-make all TARGET=ia32
mingw32-make all TARGET=intel64

APP_TYPE32=$(file "$TT_32")
APP_TYPE64=$(file "$TT_64")

if [[ $APP_TYPE64 == *"PE32+ executable"* ]];
then
    echo "[+] 64 bit build ok."
    cp "$TT_64" $TARGET_DIR/$TT_BUILD_64
    if [[ $? == 0 ]];
    then
    	echo "[+] 64 bit install ok."
    else
    	echo "ERROR: 64 bit install failed."
    fi
else
    echo "ERROR: Could not build the 64-bit TinyTracer"
fi

if [[ $APP_TYPE32 == *"PE32 executable"* ]];
then
    echo "[+] 32 bit build ok."
    cp "$TT_32" $TARGET_DIR/$TT_BUILD_32
    if [[ $? == 0 ]];
    then
    	echo "[+] 32 bit install ok."
    else
    	echo "ERROR: 32 bit install failed."
    fi
else
    echo "ERROR: Could not build the 32-bit TinyTracer"
fi

