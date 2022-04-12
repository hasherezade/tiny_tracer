#!/bin/bash
 
make all TARGET=ia32
make all TARGET=intel64
 
TT_32=./obj-ia32/TinyTracer.so 
TT_64=./obj-intel64/TinyTracer.so
 
APP_TYPE32=`file $TT_32`
APP_TYPE64=`file $TT_64`

if [[ $APP_TYPE64 == *"ELF 64-bit"* ]];
then
    echo "[+] 64 bit build ok."
    cp ./obj-intel64/TinyTracer.so ./install32_64/TinyTracer64.so
    if [[ $? == 0 ]];
    then
    	echo "[+] 64 bit install ok."
    else
    	echo "ERROR: 64 bit install failed."
    fi
else
    echo "ERROR: Could not build the 64-bit TinyTracer"
fi

if [[ $APP_TYPE32 == *"ELF 32-bit"* ]];
then
    echo "[+] 32 bit build ok."
    cp ./obj-ia32/TinyTracer.so ./install32_64/TinyTracer32.so
    if [[ $? == 0 ]];
    then
    	echo "[+] 32 bit install ok."
    else
    	echo "ERROR: 32 bit install failed."
    fi
else
    echo "ERROR: Could not build the 32-bit TinyTracer"
fi

