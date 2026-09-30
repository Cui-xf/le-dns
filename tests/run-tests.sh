#!/usr/bin/env bash
# 测试运行器。用法：bash tests/run-tests.sh [test_xxx.sh]
cd "$(dirname "$0")" || exit 1

# 整轮测试的私有临时目录，跑完自动删除。
#
# 为什么不是 /tmp 下的固定路径：
#   1) 固定路径跑完没人删，每次都在 /tmp 留残留
#      （此前实测：test_acme.sh 5 个 + test_cf.sh 1 个，一共 6 个文件）。
#   2) 固定路径可被本机其他用户【预先创建成符号链接】，让测试写到 /tmp 之外。
#      le-dns.sh 自己已经为这个原因把中转文件名改成了 $TMP_DIR 下的确定性路径
#      （CWE-377），测试没道理比自己测的代码更松。
#   3) 两份测试并发跑会互踩同一批文件。
#
# 必须在 source 任何 test_*.sh 之前建立：那些文件在【文件作用域】就引用它。
# 必须 export：部分用例会 spawn bash -c 子进程（见 test_acme.sh 的中转文件用例）。
LE_TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/le-dns-test.XXXXXX") || exit 1
export LE_TEST_TMP
# shellcheck disable=SC2064
trap 'rm -rf "$LE_TEST_TMP"' EXIT

PASS=0
FAIL=0
SKIP=0

assert_eq() { # <描述> <期望> <实际>
  if [ "$2" = "$3" ]; then
    PASS=$((PASS + 1))
    printf '  ok   %s\n' "$1"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL %s\n    期望: [%s]\n    实际: [%s]\n' "$1" "$2" "$3"
  fi
}

assert_ne() { # <描述> <不应等于> <实际>
  if [ "$2" != "$3" ]; then
    PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"
  else
    FAIL=$((FAIL + 1)); printf '  FAIL %s\n    不该等于: [%s]\n' "$1" "$2"
  fi
}

assert_ok() { # <描述> <命令...>  断言退出码为 0
  local desc=$1; shift
  if "$@" >/dev/null 2>&1; then
    PASS=$((PASS + 1)); printf '  ok   %s\n' "$desc"
  else
    FAIL=$((FAIL + 1)); printf '  FAIL %s (退出码非 0)\n' "$desc"
  fi
}

. ../le-dns.sh
set +e   # 断言需要捕获失败，关掉 set -e

# base64url 解码（测试工具，放在运行器里而不是某个 test_*.sh 里）。
#
# 放这里的理由：运行器支持 `bash tests/run-tests.sh test_acme.sh` 只跑单个文件
# （brief 里的 RED/GREEN 循环就是这么写的），而只跑单文件时其他文件不会被 source。
# 若把它放在 test_jws.sh，单跑 test_acme.sh 就会因 b64url_decode 未定义而失败 ——
# 看起来像被测代码坏了，实际是测试工具没加载。
#
# 必须先补 padding：openssl base64 -d 遇到未 padding 的输入不会报错，
# 而是【静默丢掉最后一个字节】且退出码仍为 0。
# 实测 '{"..."}' 这样的输入解出来会少掉结尾的 '}'，
# diff 看起来像内容错了，完全没有线索指向 padding。
b64url_decode() {
  local v=$1 pad i
  pad=$(( (4 - ${#v} % 4) % 4 ))
  for ((i = 0; i < pad; i++)); do v="$v="; done
  printf '%s' "$v" | tr '_-' '/+' | openssl base64 -d -A 2>/dev/null
}

files="${1:-test_base.sh test_json.sh test_jws.sh test_acme.sh test_cf.sh test_config.sh test_renew.sh}"
for f in $files; do
  # 文件不存在时继续（后续任务会逐个补上这些测试文件），但必须显式报出来：
  # 原来的静默 continue 会让"改名 / 误删 / cd 到错目录"表现成假绿。
  if [ ! -f "$f" ]; then
    printf '\n== %s == (SKIP 文件不存在)\n' "$f"
    SKIP=$((SKIP + 1))
    continue
  fi
  printf '\n== %s ==\n' "$f"
  # shellcheck disable=SC1090
  . "./$f"
done

printf '\n--------------------------------\n通过 %d，失败 %d\n' "$PASS" "$FAIL"
# SKIP 只作提示，不参与退出码：退出码仍然只由 FAIL 决定。
if [ "$SKIP" -gt 0 ]; then
  printf '跳过 %d 个不存在的测试文件\n' "$SKIP"
fi
[ "$FAIL" -eq 0 ]
