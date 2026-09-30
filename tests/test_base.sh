# 基础层测试。RFC 4648 测试向量。
test_b64url_str() {
  assert_eq "空字符串" "" "$(b64url_str '')"
  assert_eq "f" "Zg" "$(b64url_str 'f')"
  assert_eq "fo" "Zm8" "$(b64url_str 'fo')"
  assert_eq "foo" "Zm9v" "$(b64url_str 'foo')"
  assert_eq "foob" "Zm9vYg" "$(b64url_str 'foob')"
  assert_eq "hello world" "aGVsbG8gd29ybGQ" "$(b64url_str 'hello world')"
}

test_b64url_no_padding_and_urlsafe() {
  # 0xfb 0xff 在标准 base64 里是 "+/8="，base64url 必须是 "-_8"
  local actual
  actual=$(printf '\xfb\xff' | b64url)
  assert_eq "url safe 替换 +/ 为 -_" "-_8" "$actual"
  case "$actual" in
    *=*) assert_eq "不含 padding" "无 padding" "含 padding" ;;
    *)   assert_eq "不含 padding" "无 padding" "无 padding" ;;
  esac
}

test_b64url_file() {
  printf 'foo' > "$LE_TEST_TMP/le_test_b64.txt"
  assert_eq "文件输入" "Zm9v" "$(b64url_file "$LE_TEST_TMP/le_test_b64.txt")"
  rm -f "$LE_TEST_TMP/le_test_b64.txt"
}

test_hex2bin() {
  # 必须走管道比较，不能用 $() —— 二进制可能含 NUL 和换行
  assert_eq "单字节" "ff" "$(hex2bin 'ff' | od -An -tx1 | tr -d ' \n')"
  assert_eq "多字节" "e58313ac" "$(hex2bin 'E58313AC' | od -An -tx1 | tr -d ' \n')"
  assert_eq "含 NUL 字节" "000a0d" "$(hex2bin '000a0d' | od -An -tx1 | tr -d ' \n')"
  assert_eq "大写与小写等价" \
    "$(hex2bin 'abcdef' | od -An -tx1 | tr -d ' \n')" \
    "$(hex2bin 'ABCDEF' | od -An -tx1 | tr -d ' \n')"
  assert_eq "空输入" "" "$(hex2bin '' | od -An -tx1 | tr -d ' \n')"
}

test_sha256_b64url() {
  # 已知向量：SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  assert_eq "空串的 SHA-256" \
    "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU" \
    "$(printf '' | sha256_b64url)"
  assert_eq "abc 的 SHA-256" \
    "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" \
    "$(printf 'abc' | sha256_b64url)"
}

test_need_cmd() {
  assert_ok "存在的命令" need_cmd openssl
  assert_ok "存在的命令多个" need_cmd openssl curl
  # 不存在的命令必须让脚本退出且退出码为 1
  ( need_cmd definitely_not_a_real_command_xyz ) >/dev/null 2>&1
  assert_eq "缺失命令时退出码为 1" "1" "$?"
}

# ---------- 跨平台兼容性 ----------
# 这些断言把"开发机 macOS / 生产 Linux"的差异锁死在第一个任务里，
# 避免后面某个不起眼的地方踩到 bash 3.2 的坑。

test_stat_mode_portable() {
  # file_mode 必须先试 GNU 写法再回退 BSD 写法
  local f="$LE_TEST_TMP/le_test_stat.txt"
  printf 'x' > "$f"; chmod 600 "$f"
  assert_eq "600 文件" "600" "$(file_mode "$f")"
  chmod 644 "$f"
  assert_eq "644 文件" "644" "$(file_mode "$f")"
  chmod 640 "$f"
  assert_eq "640 文件" "640" "$(file_mode "$f")"
  rm -f "$f"
  # 不存在的文件必须失败而不是返回垃圾
  ( file_mode /tmp/definitely_missing_xyz ) >/dev/null 2>&1
  assert_ne "不存在的文件返回非 0" "0" "$?"
}

test_empty_array_expansion_is_safe() {
  # bash 3.2 + set -u 下 "${a[@]}" 展开空数组会直接终止脚本。
  # 整个脚本依赖 set -u，所以保护写法必须生效。
  local out
  out=$(bash -c 'set -euo pipefail; a=(); for x in ${a[@]+"${a[@]}"}; do echo "$x"; done; echo survived' 2>&1)
  assert_eq "受保护的空数组展开不中断" "survived" "$out"

  # 记录当前 bash 是否会因未保护的空数组展开而中断。
  # 这是环境信息，不是断言 —— 两种行为都合法，取决于 bash 版本。
  local bad
  bad=$(bash -c 'set -euo pipefail; a=(); for x in "${a[@]}"; do echo "$x"; done; echo survived' 2>&1)
  case "$bad" in
    *survived*) printf '  info 当前 bash（%s）不限制空数组展开\n' "$BASH_VERSION" ;;
    *) printf '  info 当前 bash（%s）限制空数组展开，保护写法是必需的\n' "$BASH_VERSION" ;;
  esac
}

test_no_unbraced_var_before_multibyte() {
  # $VAR 后紧跟非 ASCII 字符时，UTF-8 locale 下 bash 会把多字节字符
  # 当成变量名的一部分：`$url（` 被解析成变量名 `url（`，set -u 下报
  # unbound variable —— 整条错误消息一个字都打不出来。
  # 实测全部全角标点都触发，半角安全；$1 / $? / $$ / $* / $@ 安全。
  #
  # 这是静态检查（用 C locale 让 [^ -~] 匹配非 ASCII 字节），
  # 因为这类问题只在错误路径 + UTF-8 环境下才动态暴露，
  # 二者同时满足的概率很低，靠动态测试覆盖不现实。
  # 只扫描 le-dns.sh 的非注释行。
  local hits
  hits=$(LC_ALL=C grep -nE '\$[A-Za-z_][A-Za-z0-9_]*[^ -~]' ../le-dns.sh 2>/dev/null |
    grep -vE ':[[:space:]]*#' || true)
  assert_eq "无非 ASCII 字符前的裸 \$VAR" "" "$hits"
}

test_bash_version_reported() {
  # 只作记录：测试必须在 bash 3.2 上跑过，才能宣称脚本兼容 3.2
  assert_ok "bash 可用" command -v bash
  printf '  info 当前测试用的 bash：%s\n' "$BASH_VERSION"
}

test_log_survives_missing_log_dir() {
  local out
  out=$(bash -c '
    set -euo pipefail
    . ../le-dns.sh
    LOG_FILE=/nonexistent-log-dir-xyz/le-dns.log
    die "这条错误必须清晰可见"
  ' 2>&1)
  case "$out" in
    *"这条错误必须清晰可见"*) assert_eq "错误信息被打印" "ok" "ok" ;;
    *) assert_eq "错误信息被打印" "present" "MISSING" ;;
  esac
  case "$out" in
    *"No such file or directory"*) assert_eq "不应有原生重定向错误" "clean" "NOISY: $out" ;;
    *) assert_eq "不应有原生重定向错误" "clean" "clean" ;;
  esac
}

test_b64url_str
test_b64url_no_padding_and_urlsafe
test_b64url_file
test_hex2bin
test_sha256_b64url
test_need_cmd
test_stat_mode_portable
test_empty_array_expansion_is_safe
test_no_unbraced_var_before_multibyte
test_bash_version_reported
test_log_survives_missing_log_dir
