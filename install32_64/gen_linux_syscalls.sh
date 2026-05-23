#!/bin/sh
# gen_linux_syscalls.sh
# Emit the host architecture's syscall table as "0xNN,name" (sorted by number),
# mirroring the Windows ntdll dump format.
#
# Strategy:
#   1. Ask the C preprocessor for every __NR_* macro defined on this host.
#   2. Let the compiler EVALUATE each macro to a real integer (so arch quirks
#      such as MIPS base offsets, __NR3264_* selectors, etc. resolve correctly).
#   3. Sort by number and format.
#
# Usage:
#   ./gen_linux_syscalls.sh            > syscalls.csv   # hex (default)
#   ./gen_linux_syscalls.sh --dec      > syscalls.csv   # decimal numbers
#   CC=aarch64-linux-gnu-gcc ./gen_linux_syscalls.sh     # cross-target
set -eu

CC="${CC:-cc}"
FMT=hex
[ "${1:-}" = "--dec" ] && FMT=dec

# 1. Candidate syscall names from the host headers. We strip the literal "__NR_"
#    prefix; "__NR3264_*" helpers don't match that prefix and are skipped here.
names=$(printf '#include <sys/syscall.h>\n' | "$CC" -E -dM -x c - \
        | sed -n 's/^#define __NR_\([A-Za-z0-9_]*\).*/\1/p' \
        | sort -u \
        | grep -Evi '^(syscalls|arch_specific_syscall|syscall_base|oabi_syscall_base|base|linux|linux_syscalls)$')

# 2. Generate a tiny program that prints "<dec>,<name>" for each defined name.
tmpc=$(mktemp); tmpb=$(mktemp)
trap 'rm -f "$tmpc" "$tmpb"' EXIT
{
  echo '#include <sys/syscall.h>'
  echo '#include <stdio.h>'
  echo 'int main(void){'
  printf '%s\n' "$names" | while IFS= read -r n; do
    [ -n "$n" ] || continue
    printf '#ifdef __NR_%s\n  printf("%%ld,%s\\n",(long)__NR_%s);\n#endif\n' "$n" "$n" "$n"
  done
  echo '  return 0; }'
} > "$tmpc"
"$CC" -x c -o "$tmpb" "$tmpc"

# 3. Sort numerically, then format.
if [ "$FMT" = hex ]; then
  "$tmpb" | sort -t, -k1,1n | awk -F, '{printf "0x%x,%s\n",$1,$2}'
else
  "$tmpb" | sort -t, -k1,1n
fi
