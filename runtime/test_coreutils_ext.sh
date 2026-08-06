#!/bin/bash
# Расширенная батарея: текстовые утилиты, сжатие, крипто-хеши
SHIM=./build/libg_io.so
DIR=/home/lain/g-tools
F="$DIR/README.md"
BIG=/home/lain/dso/model/model.dso
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
        [ "$out1" != "$out2" ] && echo "  несовпадение вывода" | head -1
    fi
}

echo "== текстовые утилиты =="
run_cmp "sort"           sort "$F" | head -3
run_cmp "sort -u (-r)"   sort -r "$F" | head -3
run_cmp "sort -k2"       sort -k2 "$F" | head -3
run_cmp "uniq"           cat "$F" | uniq | head -3
run_cmp "uniq -c"        cat "$F" | uniq -c | head -3
run_cmp "cut -c1-20"     cut -c1-20 "$F"
run_cmp "cut -d: -f1"    cut -d: -f1 /etc/passwd | head -3
run_cmp "awk"            awk '{print NR, NF}' "$F" | head -3
run_cmp "rev"            rev "$F" | head -3
run_cmp "cat -n"         cat -n "$F" | head -3
run_cmp "tac"            tac "$F" | head -3
run_cmp "tr"             tr -d ' ' < "$F" | head -3
run_cmp "fold -w20"      fold -w 20 "$F" | head -3
run_cmp "paste"          paste "$F" "$F" | head -3
run_cmp "join"           join "$F" "$F" | head -3

echo "== hex/кодирование =="
run_cmp "xxd (20)"       xxd -l 64 "$F"
run_cmp "od -Ax -tx1"    od -Ax -tx1 -N 32 "$F"
run_cmp "base64"         base64 "$F" | head -3
run_cmp "base64 -d"      base64 "$F" | base64 -d | head -2
run_cmp "uuencode"       base64 "$F" | wc -c

echo "== хеши =="
run_cmp "sha1sum"        sha1sum "$F"
run_cmp "sha512sum"      sha512sum "$F"
run_cmp "b2sum"          b2sum "$F" 2>/dev/null
run_cmp "cksum"          cksum "$F"

echo "== поиск =="
run_cmp "grep -i"        grep -i "simd" "$F"
run_cmp "grep -v"        grep -v "a" "$F" | head -3
run_cmp "grep -o"        grep -o "g_[a-z]*" "$F"
run_cmp "grep -c word"   grep -c "the" "$F"

echo "== бинарник =="
run_cmp "xxd big(-N5K)"  xxd -l 4096 "$BIG"
run_cmp "strings big"    strings "$BIG" | head -3
run_cmp "tail -c big"    tail -c 64 "$BIG" | md5sum

echo
echo "== ИТОГО: PASS=$pass FAIL=$fail =="