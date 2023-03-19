 #!/bin/bash
 
<< 'MULTILINE-COMMENT'

Linux runner for Tiny Tracer
1. Download the latest Intel Pin, and unpack it into your home directory, under the name "pin"
2. Compile tiny_tracer in both 64 and 32 bit version:
   + Make sure that tiny_tracer source is in ~/pin/source/tools/tiny_tracer
   + Go to tiny_tracer directory
   + Issue `make_linux.sh` to compile both 32-bit and 64-bit version.
     If everything went fine, you will obtain: `TinyTracer32.so` and: `TinyTracer64.so` in the `install32_64` directory.
3. Now you can use the current script (`tiny_runner.sh`) to run your apps via TinyTracer.
4. To make the script runnable from any directory, you can add a symbolic link to your local `bin` directory. Example:
   ln -s $HOME/pin/source/tools/tiny_tracer/install32_64/tiny_runner.sh ~/bin/tiny_runner.sh
5. Optionally, you can also create a link to the directory with `tiny_tracer` configuration, to have an easy access to them. For example:
   ln -s $HOME/pin/source/tools/tiny_tracer/install32_64/ $HOME/Desktop/install32_64
MULTILINE-COMMENT

echo "Linux runner for Tiny Tracer"
echo "Usage: <target_app> [target_module*]"
echo "*-optional; default: target app's main module"
 
if [ -z "$1" ]; then
  echo "ERROR: Target app not supplied."
  exit
fi

TARGET_APP=$1
echo "PIN is trying to run the app: "$TARGET_APP

# TRACED_MODULE - by default it is the main module, but it can be also a DLL within the traced process
TRACED_MODULE=$TARGET_APP

if [ -n "$2" ]; then
  TRACED_MODULE=$2
fi

TRACED_MODULE_BASENAME=`basename $TRACED_MODULE`

if [ -z "$TRACED_MODULE_BASENAME" ]; then
  echo "ERROR: Invalid path to the traced module: "$TRACED_MODULE
  exit
fi

echo "Traced Module Name: $TRACED_MODULE_BASENAME";

#The arguments that you want to pass to the run executable
EXE_ARGS=""

TAG_FILE=$TRACED_MODULE".tag"

# PIN_DIR is your root directory of Intel Pin
PIN_DIR=$HOME"/pin/"

#PIN_TOOLS_DIR is your directory with this script and the Pin Tools
PIN_TOOLS_DIR=$PIN_DIR"/source/tools/tiny_tracer/install32_64/"

# The ini file specifying the settings of the tracer
SETTINGS_FILE=$PIN_TOOLS_DIR"/TinyTracer.ini"

# WATCH_BEFORE - a file with a list of functions which's parameters will be logged before execution
# The file must be a list of records in a format: `[module_name];[func_name];[parameters_count]`
# or, in case of tracing syscalls: `<SYSCALL>;[syscall number];[parameters_count]` (where "<SYSCALL>" is a constant keyword)
WATCH_BEFORE=$PIN_TOOLS_DIR"/params.txt"

# SYSCALLS_TABLE - a CSV file, mapping syscall ID to a function name. Format: [syscallID:hex],[functionName]
SYSCALLS_TABLE=$PIN_TOOLS_DIR"/linux_syscalls.txt"

PINTOOL32=$PIN_TOOLS_DIR"/TinyTracer32.so"
PINTOOL64=$PIN_TOOLS_DIR"/TinyTracer64.so"
PINTOOL=$PINTOOL64

APP_TYPE=`file $TARGET_APP`

ELF_64="ELF 64-bit"
ELF_32="ELF 32-bit"

if [[ $APP_TYPE == *"$ELF_64"* ]];
then
    echo "The app is 64 bit."
    PINTOOL=$PINTOOL64
elif [[ $APP_TYPE == *"$ELF_32"* ]];
then
    echo "The app is 32 bit."
    PINTOOL=$PINTOOL32
else
    echo "ERROR: Not supported file type."
    exit
fi

$PIN_DIR/pin -t $PINTOOL -s $SETTINGS_FILE -b $WATCH_BEFORE -m $TRACED_MODULE_BASENAME -o $TAG_FILE -l $SYSCALLS_TABLE -- $TARGET_APP $EXE_ARGS
