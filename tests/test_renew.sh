test_renew_needed_matrix() {
  local d="$LE_TEST_TMP/le_test_renew"
  rm -rf "$d"; mkdir -p "$d"
  local k="$d/k.pem" c="$d/c.pem"

  # 1. 证书不存在 → 需要续期
  renew_needed "$d/missing.pem"
  assert_eq "文件不存在时需要续期" "0" "$?"

  # 2. 已损坏的证书 → 需要续期（不能因为解析失败就崩溃）
  printf 'garbage\n' > "$d/broken.pem"
  renew_needed "$d/broken.pem"
  assert_eq "损坏文件需要续期" "0" "$?"

  # 3. 剩余 90 天 → 不需要续期
  openssl genrsa -out "$k" 2048 2>/dev/null
  openssl req -new -x509 -key "$k" -subj "/CN=example.com" -days 90 -out "$c" 2>/dev/null
  RENEW_BEFORE_DAYS=30
  renew_needed "$c"
  assert_eq "剩余 90 天时不需要续期" "1" "$?"

  # 4. 剩余 1 天 → 需要续期
  openssl req -new -x509 -key "$k" -subj "/CN=example.com" -days 1 -out "$d/short.pem" 2>/dev/null
  renew_needed "$d/short.pem"
  assert_eq "剩余 1 天时需要续期" "0" "$?"

  # 5. 阈值可配：把阈值设成 200 天，90 天的证书也应被判为需要续期
  RENEW_BEFORE_DAYS=200
  renew_needed "$c"
  assert_eq "阈值 200 天时 90 天证书需要续期" "0" "$?"
  RENEW_BEFORE_DAYS=30

  rm -rf "$d"
}

test_write_certs_atomic_splits_chain() {
  local d="$LE_TEST_TMP/le_test_certs"
  rm -rf "$d"; mkdir -p "$d"
  local k="$d/k.pem"
  openssl genrsa -out "$k" 2048 2>/dev/null

  # 造一条两级链：叶子 + 中间
  openssl req -new -x509 -key "$k" -subj "/CN=leaf" -days 90 -out "$d/leaf.pem" 2>/dev/null
  openssl req -new -x509 -key "$k" -subj "/CN=intermediate" -days 90 -out "$d/inter.pem" 2>/dev/null
  cat "$d/leaf.pem" "$d/inter.pem" > "$d/fullchain.src"

  write_certs_atomic "$d" "$d/fullchain.src" "$k"

  assert_ok "fullchain.pem 已写入" test -f "$d/fullchain.pem"
  assert_ok "cert.pem 已写入" test -f "$d/cert.pem"
  assert_ok "chain.pem 已写入" test -f "$d/chain.pem"
  assert_ok "privkey.pem 已写入" test -f "$d/privkey.pem"

  # cert.pem 只能含一张证书
  assert_eq "cert.pem 含 1 张证书" "1" \
    "$(grep -c 'BEGIN CERTIFICATE' "$d/cert.pem")"
  # chain.pem 只含中间证书，不含叶子
  assert_eq "chain.pem 含 1 张证书" "1" \
    "$(grep -c 'BEGIN CERTIFICATE' "$d/chain.pem")"
  # fullchain 两张
  assert_eq "fullchain.pem 含 2 张证书" "2" \
    "$(grep -c 'BEGIN CERTIFICATE' "$d/fullchain.pem")"

  # 原子性：临时目录不能残留。
  #
  # ★ 模式必须是 '.tmp.*'，不能是 '*.tmp'。
  # write_certs_atomic 的临时目录名是 "$dir/.tmp.XXXXXX"，
  # 而 '*.tmp' 要求名字【以 .tmp 结尾】—— 它永远匹配不到，断言恒真、零信息量。
  # （同一文件里 test_write_certs_atomic_single_cert_chain 用的是 '.tmp.*'，
  #   两处不一致，必有一错；这里按后者统一。）
  #
  # 反向确认：先造一个同名诱饵，证明这条断言真的看得见残留，
  # 否则把模式写错时它会静默退化成空断言 —— 而这类退化没有任何征兆。
  mkdir -p "$d/.tmp.PROBE"
  assert_ne "反向确认：'.tmp.*' 确实能匹配到残留" "" \
    "$(find "$d" -name '.tmp.*' 2>/dev/null)"
  rmdir "$d/.tmp.PROBE"
  assert_eq "无 .tmp 残留" "" "$(find "$d" -name '.tmp.*' 2>/dev/null)"

  # 私钥权限必须是 600
  assert_eq "privkey 权限 600" "-rw-------" "$(ls -l "$d/privkey.pem" | cut -c1-10)"

  rm -rf "$d"
}

test_write_certs_atomic_overwrites_cleanly() {
  local d="$LE_TEST_TMP/le_test_certs2"
  rm -rf "$d"; mkdir -p "$d"
  local k="$d/k.pem"
  openssl genrsa -out "$k" 2048 2>/dev/null
  openssl req -new -x509 -key "$k" -subj "/CN=a" -days 90 -out "$d/a.pem" 2>/dev/null
  cat "$d/a.pem" > "$d/f1"
  write_certs_atomic "$d" "$d/f1" "$k"

  openssl req -new -x509 -key "$k" -subj "/CN=b" -days 90 -out "$d/b.pem" 2>/dev/null
  cat "$d/b.pem" > "$d/f2"
  write_certs_atomic "$d" "$d/f2" "$k"

  # 第二次写入必须完整覆盖，不能残留第一次的内容
  assert_eq "覆盖后只剩 1 张证书" "1" \
    "$(grep -c 'BEGIN CERTIFICATE' "$d/cert.pem")"
  assert_ok "覆盖后的证书是新的" \
    openssl x509 -in "$d/cert.pem" -noout -subject -nameopt multiline 2>/dev/null

  rm -rf "$d"
}

test_run_reload_runs_in_both_envs() {
  # 两个环境都执行 RELOAD_CMD —— 命令来自各自的配置文件。
  #
  # 环境隔离靠的是路径两两不相交（staging 绝不碰生产目录），不是靠跳过 reload。
  # 跳过它反而有害：测试环境里那条 reload 永远得不到执行，
  # 而它最容易配错，也最容易在真实续期时把服务搞挂。
  #
  # 这条用例对 IS_STAGING 的两个取值都断言"执行了"，
  # 所以任何形式的"按环境跳过"都会被它挡下。
  local marker="$LE_TEST_TMP/le_test_reload_marker"
  RELOAD_CMD="touch $marker"

  rm -f "$marker"
  IS_STAGING=1
  run_reload
  assert_ok "staging 下也执行 reload" test -f "$marker"

  rm -f "$marker"
  IS_STAGING=0
  run_reload
  assert_ok "生产下同样执行 reload" test -f "$marker"

  # 未配置时必须跳过 —— 不能把空字符串交给 sh -c
  # （`sh -c ""` 返回 0，看着没事，但一旦 RELOAD_CMD 只含空白就会出事）
  rm -f "$marker"
  RELOAD_CMD=""
  run_reload
  assert_eq "未配置时不执行" "" "$(ls "$marker" 2>/dev/null)"
}

test_cleanup_is_idempotent() {
  # 清理函数必须可以重复调用而不报错（trap EXIT 与显式调用可能都触发）
  CF_RECORDS=""
  CF_ZONE_ID=""
  cleanup_records
  assert_eq "空状态下清理不报错" "0" "$?"
  cleanup_records
  assert_eq "重复清理不报错" "0" "$?"
}

test_on_exit_removes_workdir_and_is_idempotent() {
  # on_exit 是全脚本唯一的退出清理入口，必须同时清掉 DNS 记录和中间产物目录。
  TMP_DIR=$(mktemp -d)
  printf 'x' > "$TMP_DIR/somefile"
  assert_ok "临时目录存在" test -d "$TMP_DIR"

  CF_RECORDS=""
  on_exit
  assert_ok "on_exit 删除了中间产物目录" test ! -d "$TMP_DIR"

  # 重复调用（例如 trap 与显式调用都触发）不能报错
  on_exit
  assert_eq "重复 on_exit 不报错" "0" "$?"

  TMP_DIR=""
  on_exit
  assert_eq "TMP_DIR 为空时 on_exit 不报错" "0" "$?"
}

test_setup_workdir_is_idempotent() {
  TMP_DIR=""
  CERT_PRIVKEY_NEW=""
  setup_workdir
  local first="$TMP_DIR"
  assert_ok "创建了工作目录" test -d "$first"
  assert_eq "私钥路径指向工作目录" "$first/domain.key" "$CERT_PRIVKEY_NEW"

  # 二次调用必须复用同一个目录，否则第二次会新建目录并泄漏第一个
  setup_workdir
  assert_eq "二次调用复用同一目录" "$first" "$TMP_DIR"

  rm -rf "$TMP_DIR"
  TMP_DIR=""
}

# 注：test_single_exit_trap 不在本任务 —— 唯一那处 EXIT trap 由 Task 9 的
# main 添加，本任务结束时脚本里 trap 数量是 0，在这里断言必然失败。
# 它定义并调用都在 Task 9。（计划早前的版本把它留了一份在此处，是个陷阱：
# 定义就写在上面的调用列表旁边，实现者很容易顺手加进去然后挂掉。）

test_write_certs_atomic_single_cert_chain() {
  # 链里只有叶子证书时（没有中间证书），chain.pem 必须是【空的】而非【不存在】。
  # awk 的 `print > file` 只在真正写入时才创建文件 ——
  # 少了预创建那两个 `: >`，cat 与 mv 都会以 "No such file or directory"
  # 失败并触发 set -e，整个写盘步骤崩掉。
  local d="$LE_TEST_TMP/le_test_single"
  rm -rf "$d"; mkdir -p "$d"
  local k="$d/k.pem"
  openssl genrsa -out "$k" 2048 2>/dev/null
  openssl req -new -x509 -key "$k" -subj "/CN=leaf" -days 90 -out "$d/leaf.pem" 2>/dev/null

  write_certs_atomic "$d" "$d/leaf.pem" "$k"

  assert_ok "fullchain.pem 已写入" test -f "$d/fullchain.pem"
  assert_ok "chain.pem 存在（可为空但不可缺失）" test -f "$d/chain.pem"
  assert_eq "chain.pem 为空" "0" "$(wc -c < "$d/chain.pem" | tr -d ' ')"
  assert_eq "cert.pem 含 1 张证书" "1" "$(grep -c 'BEGIN CERTIFICATE' "$d/cert.pem")"
  assert_eq "fullchain.pem 含 1 张证书" "1" "$(grep -c 'BEGIN CERTIFICATE' "$d/fullchain.pem")"
  assert_eq "私钥权限 600" "-rw-------" "$(ls -l "$d/privkey.pem" | cut -c1-10)"
  # 临时目录不能残留
  assert_eq "无 .tmp 残留" "" "$(find "$d" -name '.tmp.*' 2>/dev/null)"
  rm -rf "$d"
}

test_cleanup_continues_after_failure() {
  # cf_del_txt 内部的 cf_api 失败时会 die，而 die 用的是 exit ——
  # exit 终结的是【整个管道子 shell】，不是当前那条命令。
  # 所以若直接调用 cf_del_txt，一条记录删除失败会让后面所有记录都不再清理，
  # 垃圾 TXT 记录泄漏在线上 DNS 里（设计文档警告过的那种）。
  # cleanup_records 用 () 包住调用，exit 便只终结那个子 shell。
  CF_RECORDS="z1:r1
z1:r2
z1:r3"

  local calls="$LE_TEST_TMP/le_test_cleanup_calls"
  : > "$calls"

  # 用打桩顶掉真实实现：对 r2 模拟 die 的 exit 1
  cf_del_txt() {
    printf '%s\n' "$2" >> "$calls"
    if [ "$2" = "r2" ]; then exit 1; fi
    return 0
  }

  cleanup_records

  local n
  n=$(grep -c . "$calls" 2>/dev/null || echo 0)
  assert_eq "三条记录都被尝试清理" "3" "$n"
  assert_eq "第一条被清理" "r1" "$(sed -n 1p "$calls")"
  assert_eq "第三条也被清理（未被中途跳过）" "r3" "$(sed -n 3p "$calls")"
  assert_eq "清理后 CF_RECORDS 已清空" "" "$CF_RECORDS"
  rm -f "$calls"
}

test_renew_needed_matrix
test_write_certs_atomic_splits_chain
test_write_certs_atomic_single_cert_chain
test_write_certs_atomic_overwrites_cleanly
test_run_reload_runs_in_both_envs
test_cleanup_is_idempotent
test_cleanup_continues_after_failure
test_on_exit_removes_workdir_and_is_idempotent
test_setup_workdir_is_idempotent
