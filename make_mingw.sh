#!/bin/bash

mingw32-make all TARGET=ia32
mingw32-make all TARGET=intel64

TT_32=./obj-ia32/TinyTracer32.dll
TT_64=./obj-intel64/TinyTracer64.dll
 
APP_TYPE32=$(file "$TT_32")
APP_TYPE64=$(file "$TT_64")

if [[ $APP_TYPE64 == *"PE32+ executable"* ]];
then
    echo "[+] 64 bit build ok."
    cp "$TT_64" ./install32_64/TinyTracer64.dll
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
    cp "$TT_32" ./install32_64/TinyTracer32.dll
    if [[ $? == 0 ]];
    then
    	echo "[+] 32 bit install ok."
    else
    	echo "ERROR: 32 bit install failed."
    fi
else
    echo "ERROR: Could not build the 32-bit TinyTracer"
fi

