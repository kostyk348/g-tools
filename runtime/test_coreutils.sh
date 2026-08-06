#!/bin/bash
# Батарея coreutils: с shim и без, сравнение вывода и exit code
# Использование: ./test_coreutils.sh [file]
SHIM=./build/libg_io.so
DIR=/home/lain/g-tools
F="${1:-$DIR/README.md}"
BIG="${2:-/home/lain/dso/model/model.dso}"
pass=0; fail=0

run_cmp() {
    local name="$1"; shift
    local out1 out2 rc1 rc2
    out1=$("$@" 2>/dev/null); rc1=$?
    out2=$(LD_PRELOAD=$SHIM "$@" 2>/dev/null); rc2=$?
    if [ "$out1" == "$out2" ] && [ $rc1 -eq $rc2 ]; then
        echo "PASS  $name"; pass=$((pass+1))
    else
        echo "FAIL  $name (rc=$rc1/$rc2)"; fail=$((fail+1))
        [ "$out1" != "$out2" ] && diff <(echo "$out1") <(echo "$out2") | head -3
    fi
}

echo "== базовые чтения ($F) =="
run_cmp "cat"           cat "$F"
run_cmp "head -5"       head -5 "$F"
run_cmp "tail -3"       tail -3 "$F"
run_cmp "wc -c"         wc -c "$F"
run_cmp "wc -l"         wc -l "$F"
run_cmp "wc -w"         wc -w "$F"
run_cmp "od -c (20)"    od -c -N 40 "$F"
run_cmp "md5sum"        md5sum "$F"
run_cmp "sha256sum"     sha256sum "$F"
run_cmp "strings"       strings "$F" | head -5
run_cmp "grep -c"       grep -c "the" "$F"
run_cmp "grep -n"       grep -n "SIMD" "$F"
run_cmp "nl -ba"        nl -ba "$F" | head -5
run_cmp "sed -n 1,3p"   sed -n '1,3p' "$F"
run_cmp "tr (pipe)"     cat "$F" | tr 'a-z' 'A-Z' | head -3

echo "== сравнение файлов =="
run_cmp "cmp"           cmp "$DIR/README.md" "$F"
run_cmp "diff (same)"   diff "$DIR/README.md" "$F"

echo "== бинарник ($BIG) =="
run_cmp "wc -c big"     wc -c "$BIG"
run_cmp "md5sum big"    md5sum "$BIG"
run_cmp "sha256 big"    sha256sum "$BIG"

echo "== утилиты, читающие /proc и системные =="
run_cmp "ls -la"        ls -la "$DIR/build" | head -5
run_cmp "uname -a"      uname -a
run_cmp "date"          date +%s
run_cmp "cat /proc/version" cat /proc/version

echo "== cp / mv =="
rm -f /tmp/opencode/cp_test.bin
cp "$BIG" /tmp/opencode/cp_test.bin 2>/dev/null; rc1=$?
rm -f /tmp/opencode/cp_test.bin
LD_PRELOAD=$SHIM cp "$BIG" /tmp/opencode/cp_test.bin 2>/dev/null; rc2=$?
if [ $rc1 -eq $rc2 ] && cmp -s "$BIG" /tmp/opencode/cp_test.bin; then
    echo "PASS  cp big"; pass=$((pass+1))
else
    echo "FAIL  cp big (rc=$rc1/$rc2)"; fail=$((fail+1))
fi
rm -f /tmp/opencode/cp_test.bin

echo
echo "== ИТОГО: PASS=$pass FAIL=$fail =="
