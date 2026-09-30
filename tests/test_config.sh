test_derive_paths_production() {
  LE_ENV=production
  BASE_DIR=/etc/le-dns
  derive_paths
  assert_eq "生产账号密钥" "/etc/le-dns/accounts/production/account.key" "$ACCOUNT_KEY"
  assert_eq "生产账号 kid" "/etc/le-dns/accounts/production/account.json" "$ACCOUNT_JSON"
  assert_eq "生产证书根目录" "/etc/le-dns/certs/production" "$CERT_ROOT"
  assert_eq "生产日志" "/etc/le-dns/logs/le-dns.log" "$LOG_FILE"
  assert_eq "生产配置文件" "/etc/le-dns/le-dns.conf" "$CONF_FILE"
  assert_eq "生产 ACME 端点" \
    "https://acme-v02.api.letsencrypt.org/directory" "$ACME_DIRECTORY"
}

test_derive_paths_staging() {
  LE_ENV=staging
  BASE_DIR=/etc/le-dns
  derive_paths
  assert_eq "测试账号密钥" "/etc/le-dns/accounts/staging/account.key" "$ACCOUNT_KEY"
  assert_eq "测试证书根目录" "/etc/le-dns/certs/staging" "$CERT_ROOT"
  assert_eq "测试日志" "/etc/le-dns/logs/le-dns-staging.log" "$LOG_FILE"
  assert_eq "测试配置文件" "/etc/le-dns/le-dns-staging.conf" "$CONF_FILE"
  assert_eq "测试 ACME 端点" \
    "https://acme-staging-v02.api.letsencrypt.org/directory" "$ACME_DIRECTORY"
}

test_env_isolation_is_complete() {
  # 环境隔离的核心断言：两个环境推导出的路径集合必须完全不相交
  LE_ENV=production; BASE_DIR=/etc/le-dns; derive_paths
  local p_key="$ACCOUNT_KEY" p_cert="$CERT_ROOT" p_conf="$CONF_FILE" p_log="$LOG_FILE"
  LE_ENV=staging; derive_paths
  assert_ne "账号密钥不重合" "$p_key" "$ACCOUNT_KEY"
  assert_ne "证书目录不重合" "$p_cert" "$CERT_ROOT"
  assert_ne "配置文件不重合" "$p_conf" "$CONF_FILE"
  assert_ne "日志不重合" "$p_log" "$LOG_FILE"
}

test_parse_args_staging_switch() {
  LE_ENV=""
  CONF_OVERRIDE=""
  DOMAIN_ARGS=""
  CMD=""
  parse_args --staging
  assert_eq "--staging 设 LE_ENV" "staging" "$LE_ENV"
}

test_parse_args_default_production() {
  LE_ENV=""
  CONF_OVERRIDE=""
  DOMAIN_ARGS=""
  CMD=""
  parse_args
  assert_eq "默认是 production" "production" "$LE_ENV"
}

test_parse_args_domains() {
  LE_ENV=""; CONF_OVERRIDE=""; DOMAIN_ARGS=""; CMD=""
  parse_args -d example.com -d '*.example.com'
  assert_eq "收集域名到 DOMAIN_ARGS" "example.com *.example.com" "$DOMAIN_ARGS"
  # 通配符必须原样保留，含星号和点。
  #
  # ★ 这条原写成
  #     assert_ok "..." printf '%s' "$DOMAIN_ARGS" | grep -qF '*'
  #   是【完全隐形】的断言：整行是一条管道，于是 assert_ok 跑在管道的
  #   子 shell 里 —— 它的 PASS 自增丢在子 shell 中（父 shell 的计数不变），
  #   而它打印的那行 "ok" 又被 grep -q 吞掉。终端上看不见、计数也不增加，
  #   断言在或不在完全等价。已实测：该写法下 PASS 计数为 0。
  #   用 assert_eq 直接比对取值，既可见又计入。
  assert_eq "通配符原样保留（含星号与点）" "*.example.com" \
    "$(printf '%s' "$DOMAIN_ARGS" | cut -d' ' -f2)"
  # 反向确认：确实只解析出两个域名，而不是把通配符拆成了别的个数
  assert_eq "域名个数" "2" "$(printf '%s' "$DOMAIN_ARGS" | wc -w | tr -d ' ')"
}

test_parse_args_subcommands() {
  LE_ENV=""; CONF_OVERRIDE=""; DOMAIN_ARGS=""; CMD=""
  parse_args issue
  assert_eq "issue 子命令" "issue" "$CMD"
  LE_ENV=""; CMD=""
  parse_args --check
  assert_eq "--check 子命令" "check" "$CMD"
  LE_ENV=""; CMD=""
  parse_args
  assert_eq "无参数默认 issue" "issue" "$CMD"
}

test_parse_args_config_override_does_not_change_env() {
  LE_ENV=""; CONF_OVERRIDE=""; DOMAIN_ARGS=""; CMD=""
  parse_args -c /tmp/custom.conf
  assert_eq "-c 覆盖配置路径" "/tmp/custom.conf" "$CONF_OVERRIDE"
  assert_eq "-c 不改变环境归属" "production" "$LE_ENV"
}

test_parse_args_force_semantics() {
  # --force 只在 issue 下有意义（--check/--init/--install-cron 都不签发）。
  # 静默吃掉一个开关是本项目最忌讳的一类缺陷：用户会以为已经强制过了，
  # 实际走的是另一条路，且没有任何提示。
  local out
  out=$( ( LE_ENV=""; CMD=""; FORCE=0; parse_args --check --force ) 2>&1 )
  case "$out" in
    *"只能配合 issue"*) assert_eq "--check --force 被拒绝" "ok" "ok" ;;
    *) assert_eq "--check --force 被拒绝" "含「只能配合 issue」" "$out" ;;
  esac

  # 反向确认：issue --force 必须放行（否则上一条可能只是"凡 --force 必拒"）
  LE_ENV=""; CMD=""; FORCE=0
  parse_args issue --force
  assert_eq "issue --force 被接受" "issue" "$CMD"
  assert_eq "FORCE 已置位" "1" "$FORCE"

  # 裸 --force 也要放行：CMD 默认成 issue，等价于 issue --force
  LE_ENV=""; CMD=""; FORCE=0
  parse_args --force
  assert_eq "裸 --force 默认成 issue" "issue" "$CMD"

  # 参数顺序不该影响结果
  LE_ENV=""; CMD=""; FORCE=0
  parse_args --force issue
  assert_eq "--force 写在 issue 之前同样被接受" "issue" "$CMD"

  # 不用手工复位：parse_args 每次调用都会重置自己的输出量
  # （见 test_parse_args_resets_its_own_state）。
}

test_parse_args_resets_its_own_state() {
  # parse_args 的产物是全局量，必须在每次调用开头复位 —— 否则同一 shell 里
  # 第二次调用会继承上一次的结果，函数的输出就取决于"上一次谁调用过它"。
  #
  # 生产里每个进程只调一次，所以这类泄漏平时看不见；但它有实际后果：
  # 实测踩过 —— `parse_args issue --force` 之后再调 `parse_args --staging --check`，
  # FORCE 残留成 1，撞上 --force 校验而误报「--force 只能配合 issue 使用」，
  # 报的还是个和实际命令毫不相干的错。
  #
  # 整段跑在子 shell 里并把结果一次性打出来：这几步里有 die 敏感的路径，
  # 直接在主 shell 里调的话，一旦回归会让 die 杀掉整个测试运行器 ——
  # 表现为整套测试没了汇总，而不是一条 FAIL。实测踩过。
  local out
  out=$( (
    LE_ENV=""; CMD=""; FORCE=0
    parse_args issue --force
    printf '第1次 CMD=%s FORCE=%s\n' "$CMD" "$FORCE"
    parse_args --staging --check
    printf '第2次 CMD=%s FORCE=%s ENV=%s\n' "$CMD" "$FORCE" "$LE_ENV"
    parse_args --check
    parse_args
    printf '第3次 CMD=%s\n' "$CMD"
  ) 2>&1 )
  assert_eq "每次调用都从干净状态开始" \
"第1次 CMD=issue FORCE=1
第2次 CMD=check FORCE=0 ENV=staging
第3次 CMD=issue" "$out"
}

test_check_config_perms_rejects_loose() {
  local f="$LE_TEST_TMP/le_test_conf_loose.conf"
  printf 'CF_API_TOKEN="x"\n' > "$f"
  chmod 644 "$f"
  ( check_config_perms "$f" ) >/dev/null 2>&1
  assert_eq "644 权限被拒绝" "1" "$?"
  chmod 600 "$f"
  assert_ok "600 权限被接受" check_config_perms "$f"
  rm -f "$f"
}

test_load_config_parses_values() {
  local f="$LE_TEST_TMP/le_test_conf_ok.conf"
  cat > "$f" <<'EOF'
# 注释行
DOMAINS="example.com *.example.com"
CF_API_TOKEN="token123"
RELOAD_CMD="systemctl reload nginx"
RENEW_BEFORE_DAYS=30
DNS_WAIT_TIMEOUT=120
KEY_TYPE=rsa2048
ACCOUNT_EMAIL=""
EOF
  chmod 600 "$f"
  load_config "$f"
  assert_eq "CF_API_TOKEN" "token123" "$CF_API_TOKEN"
  assert_eq "RELOAD_CMD" "systemctl reload nginx" "$RELOAD_CMD"
  assert_eq "RENEW_BEFORE_DAYS" "30" "$RENEW_BEFORE_DAYS"
  assert_eq "KEY_TYPE" "rsa2048" "$KEY_TYPE"
  rm -f "$f"
}

test_load_config_rejects_missing_token() {
  local f="$LE_TEST_TMP/le_test_conf_notoken.conf"
  printf 'DOMAINS="example.com"\nCF_API_TOKEN=""\n' > "$f"
  chmod 600 "$f"
  ( load_config "$f" ) >/dev/null 2>&1
  assert_eq "空 Token 被拒绝" "1" "$?"
  rm -f "$f"
}

test_load_config_does_not_glob_domains() {
  # ★ 分词时必须关掉 pathname expansion。
  #
  # load_config 用【不加引号】的 DOMAINS=($domain_list) 分词，所以配置里的
  # 通配符域名会被 cwd 下的同名文件展开：
  #   DOMAINS="example.com *.example.com"  →  example.com mail.example.com
  # 通配符域名静默消失，订单里多出一个不该有的域名 —— 证书不覆盖
  # *.example.com，而报错会以 rejectedIdentifier 出现在 ACME 那边，
  # 指向「这个域名不属于你」，完全指不到真正的原因。
  #
  # 必须让 cwd 里【真的有】那个诱饵文件，否则用例没有牙齿
  # （cwd 里没有匹配文件时，不关 globbing 也能得到正确结果）。
  local d="$LE_TEST_TMP/le_test_glob"
  rm -rf "$d"; mkdir -p "$d"
  printf '' > "$d/mail.example.com"
  printf 'DOMAINS="example.com *.example.com"\nCF_API_TOKEN="x"\n' > "$d/le-dns.conf"
  chmod 600 "$d/le-dns.conf"

  # 先 source（此时 cwd 还是 tests/），再 cd 到诱饵目录后调 load_config。
  # 多带一个 `_` 作为 $0 占位，lib 与 dir 落在 $1 / $2。
  local out
  out=$(bash -c '
    set -euo pipefail
    . "$1"
    cd "$2"
    DOMAIN_ARGS=""
    load_config "$2/le-dns.conf"
    printf "%s\n" ${DOMAINS[@]+"${DOMAINS[@]}"}
  ' _ "$PWD/../le-dns.sh" "$d" 2>&1)

  assert_eq "域名个数仍为 2" "2" "$(printf '%s\n' "$out" | grep -c .)"
  # 用 ${DOMAINS[@]+...} 展开：bash 3.2 + set -u 下空数组会终止脚本
  assert_eq "通配符域名原样保留（未被 cwd 里的同名文件替换）" "*.example.com" \
    "$(printf '%s\n' "$out" | sed -n 2p)"

  rm -rf "$d"
}

test_cmd_init_writes_template_with_600() {
  # cmd_init 是用户在服务器上跑的第一条命令，它必须：
  #   1. 生成配置文件（否则后面全部无从谈起）
  #   2. 权限 600（含 Cloudflare Token；权限不对 load_config 会直接拒绝）
  #   3. 模板里含全部配置项（少一项，用户照模板填完仍跑不起来）
  #   4. 已存在时不覆盖 —— 覆盖掉用户填好的 Token 是灾难性的
  local d="$LE_TEST_TMP/le_test_init"
  rm -rf "$d"

  LE_DNS_BASE="$d" bash -c '
    set -euo pipefail
    . "$1"
    LE_ENV=production
    cmd_init
  ' _ "$PWD/../le-dns.sh" >/dev/null 2>&1 || true

  assert_ok "配置模板已生成" test -f "$d/le-dns.conf"
  assert_eq "模板权限为 600" "600" "$(file_mode "$d/le-dns.conf")"

  # 模板必须含全部配置项。这条不是形式主义：模板与 load_config 读取的键
  # 是两份真相，少一项时用户照模板填完仍然跑不起来。
  local k
  for k in DOMAINS CF_API_TOKEN RELOAD_CMD RENEW_BEFORE_DAYS \
           DNS_WAIT_TIMEOUT KEY_TYPE ACCOUNT_EMAIL; do
    assert_ok "模板含 ${k}" grep -q "^${k}=" "$d/le-dns.conf"
  done

  # 幂等且不覆盖：再跑一次，原有内容必须保留
  printf '# SENTINEL\n' >> "$d/le-dns.conf"
  LE_DNS_BASE="$d" bash -c '
    set -euo pipefail
    . "$1"
    LE_ENV=production
    cmd_init
  ' _ "$PWD/../le-dns.sh" >/dev/null 2>&1 || true
  assert_ok "已存在时不覆盖（原有内容保留）" grep -q 'SENTINEL' "$d/le-dns.conf"

  rm -rf "$d"
}

test_cmd_check_rejects_missing_config() {
  # 配置文件不存在时 --check 必须【以非 0 退出】并指出该做什么，
  # 而不是继续往下走到 cf_api —— 那会以误导性的「Token 不可用」收场，
  # 而用户真正需要知道的是"先运行 --init"。
  local d="$LE_TEST_TMP/le_test_check_missing"
  rm -rf "$d"; mkdir -p "$d"

  local out rc=0
  out=$(LE_DNS_BASE="$d" bash -c '
    set -euo pipefail
    . "$1"
    LE_ENV=production
    cmd_check
  ' _ "$PWD/../le-dns.sh" 2>&1) || rc=$?

  assert_eq "缺配置时退出码为 1" "1" "$rc"
  case "$out" in
    *"先运行 --init"*) assert_eq "提示先运行 --init" "ok" "ok" ;;
    *) assert_eq "提示先运行 --init" "提示缺失" "$out" ;;
  esac

  rm -rf "$d"
}

test_cmd_check_reports_unreachable_doh() {
  # ★ 这条守的是 --check 的「端点不可达」路径 —— 也正是 --check 存在的意义：
  #   用户网络不通时给出可操作的提示，而不是打印完标题就没了下文。
  #
  # _http 失败时会 die（= exit），而 **exit 在 if 条件里不会被抑制**。
  # 所以那段 DoH 探测必须写成 `if ( _http ... ); then` —— 少了括号，
  # 脚本会在条件求值时当场终止，else 分支永远不可达（第 31 个缺陷）。
  # 这段代码此前【没有任何测试守护】：去掉括号不会有任何用例失败，
  # 因为 test_exit_in_if_condition_is_not_suppressed 固化的是 shell 语义，
  # 不是 cmd_check 的实际写法。
  #
  # 桩必须用 exit 而不是 return：只有 exit 才能复现 die 的语义。
  # 用 return 1 的话，括号在或不在都能走到 else，这条用例就没有牙齿了。
  local d="$LE_TEST_TMP/le_test_check"
  rm -rf "$d"; mkdir -p "$d"
  printf 'DOMAINS="example.com"\nCF_API_TOKEN="x"\n' > "$d/le-dns.conf"
  chmod 600 "$d/le-dns.conf"

  local out
  out=$(LE_DNS_BASE="$d" bash -c '
    set -euo pipefail
    . "$1"
    LE_ENV=production
    _http() { printf "[ERROR] HTTP 请求失败：模拟的根因（curl 退出码 7）\n" >&2; exit 1; }
    cmd_check
  ' _ "$PWD/../le-dns.sh" 2>&1) || true

  case "$out" in
    *"不可达"*) assert_eq "DoH 不可达时 else 分支可达" "ok" "ok" ;;
    *) assert_eq "DoH 不可达时 else 分支可达" "reachable" "$out" ;;
  esac
  # 反向确认：报告必须走到末尾，而不是被中途的 exit 杀掉
  case "$out" in
    *"自检未通过"*) assert_eq "报告走到末尾（未被 exit 打断）" "ok" "ok" ;;
    *) assert_eq "报告走到末尾（未被 exit 打断）" "reached" "$out" ;;
  esac

  # cf_api 的真实失败原因不能丢：--check 是远程排查的唯一线索，
  # 把 Token 无效 / 缺 Zone:Zone:Read / 被限流 全归成同一句
  # 「Token 不可用」，用户拿不到任何可操作的信息。
  case "$out" in
    *"服务端返回"*) assert_eq "带出服务端的真实错误" "ok" "ok" ;;
    *) assert_eq "带出服务端的真实错误" "含服务端原因" "$out" ;;
  esac
  # --check 要打印脚本自身版本：远程排障时第一件要确认的事就是
  # "对方跑的是哪一版"。这条同时让 LE_DNS_VERSION 不再是没人引用的死常量。
  case "$out" in
    *"le-dns 版本："*) assert_eq "打印脚本版本" "ok" "ok" ;;
    *) assert_eq "打印脚本版本" "含版本行" "$out" ;;
  esac
  # ★ 而且必须是【全部】捕获行，不能只取最后一行。
  # 桩特意打印一行根因再 exit，所以捕获到的是两行：
  #   第一行 = 桩打印的根因，最后一行 = cf_api 那句"原始响应：（空）"。
  # 只取末行就会把根因丢掉 —— 这个坑是本条修复自身引入的（第一版用了
  # `tail -n1`，实测把"curl 退出码 7"整行吃掉了）。
  case "$out" in
    *"模拟的根因"*) assert_eq "根因行未被截断丢弃" "ok" "ok" ;;
    *) assert_eq "根因行未被截断丢弃" "含根因行" "$out" ;;
  esac

  rm -rf "$d"
}

test_functions_survive_set_e() {
  # 函数体的最后一条语句若是 `[ ... ] && ...`，条件为假时函数返回 1，
  # 调用方在 set -e 下会当场终止脚本。
  #
  # 这个测试必须在一个【显式开启 set -e】的子进程里跑：
  # run-tests.sh 在 source 脚本后执行了 set +e（断言要捕获失败），
  # 所以这整类 bug 在普通测试里完全隐形 —— 上面的 test_parse_args_*
  # 即使实现有这个问题也照样通过。
  #
  # 具体守的是：derive_paths 在不传 -c 时（最常见）返回 0；
  # parse_args 在子命令已给出时（如 issue，cron 每天走的路径）返回 0。
  local out
  out=$(bash -c '
    set -euo pipefail
    . ../le-dns.sh
    BASE_DIR=/etc/le-dns

    LE_ENV=production; CONF_OVERRIDE=""; derive_paths
    parse_args                       # 无参数 → issue
    parse_args issue                 # 子命令已给出
    parse_args issue --force         # 子命令 + 开关
    parse_args --staging             # 切环境
    parse_args --staging --check     # 开关 + 子命令
    parse_args -c /tmp/x.conf        # 覆盖路径
    parse_args -d example.com        # 带域名
    echo survived
  ' 2>&1)
  assert_eq "derive_paths/parse_args 在 set -e 下不中断" "survived" "$out"
}

test_set_cert_dir_includes_primary_domain() {
  # 设计文档第 4 节：证书目录是 certs/<env>/<主域名>/，
  # 不是 certs/<env>/ 本身。cmd_issue 写盘与 cmd_issue_checked 查找都用 CERT_DIR，
  # 少了域名这一层会让续期永远找不到证书，从而每次都重新签发。
  LE_ENV=production
  BASE_DIR=/etc/le-dns
  derive_paths

  DOMAINS=(example.com '*.example.com')
  set_cert_dir
  assert_eq "证书目录含主域名" "/etc/le-dns/certs/production/example.com" "$CERT_DIR"

  # 通配符主域名必须剥掉 *. 前缀
  DOMAINS=('*.example.com')
  set_cert_dir
  assert_eq "通配符主域名剥掉 *. 前缀" "/etc/le-dns/certs/production/example.com" "$CERT_DIR"

  # staging 同样带域名，且与生产不重合
  LE_ENV=staging
  derive_paths
  DOMAINS=(example.com)
  set_cert_dir
  assert_eq "staging 证书目录" "/etc/le-dns/certs/staging/example.com" "$CERT_DIR"

  # DOMAINS 为空必须报错而不是静默产出 /certs/production/
  DOMAINS=()
  ( set_cert_dir ) >/dev/null 2>&1
  assert_eq "DOMAINS 为空时报错退出" "1" "$?"
}

test_ensure_dirs_handles_unset_cert_dir() {
  # --init 的职责是【生成】配置文件，那时还没有 DOMAINS，CERT_DIR 算不出来。
  # ensure_dirs 必须建 CERT_ROOT（环境级）而不能碰 CERT_DIR ——
  # 否则 mkdir 收到空参数，报 "mkdir: : No such file or directory"，
  # 且 certs 目录根本不会被创建（--init 看起来"部分成功"）。
  local d="$LE_TEST_TMP/le_test_ensuredirs"
  rm -rf "$d"
  BASE_DIR="$d"
  LE_ENV=production
  derive_paths
  CERT_DIR=""      # 模拟 --init 时的状态
  ensure_dirs

  assert_ok "账号目录已建" test -d "$d/accounts/production"
  assert_ok "证书根目录已建" test -d "$d/certs/production"
  assert_ok "日志目录已建" test -d "$d/logs"
  rm -rf "$d"
}

test_ensure_cert_dir_rejects_empty() {
  # ensure_cert_dir 在未调用 set_cert_dir 时必须以【清晰信息】报错，
  # 而不是把空字符串传给 mkdir。
  #
  # ★ 只断言 rc=1 是不够的：没有守卫时 `mkdir -p ""` 同样返回 1
  #   （本机实测），所以那条断言对"守卫是否存在"没有判别力，
  #   而 stderr 又被丢进 /dev/null —— "清晰信息"这一半根本没被验证。
  #   这里把输出捕下来，断言它指出真正的原因。
  CERT_DIR=""
  local out rc=0
  out=$( ( ensure_cert_dir ) 2>&1 ) || rc=$?

  assert_eq "CERT_DIR 为空时退出码为 1" "1" "$rc"
  case "$out" in
    *"set_cert_dir"*) assert_eq "报错指向真正的原因" "ok" "ok" ;;
    *) assert_eq "报错指向真正的原因" "含 set_cert_dir 的提示" "$out" ;;
  esac
}

test_exit_in_if_condition_is_not_suppressed() {
  # 模式测试：把一条 shell 语义固定下来，因为它在本计划里被踩过两次 ——
  #
  #   exit 在 if 条件里【不会被抑制】。一个内部调用 die（= exit）的函数
  #   直接出现在 if 条件里时，脚本会当场终止，而 else 分支永远不可达。
  #
  # 踩过的地方：
  #   - cmd_check 的 DoH 探测：_http 失败时直接杀掉 --check，
  #     而"端点不可达"的提示恰恰是 --check 存在的意义 → 必须写成 ( _http ... )
  #   - cleanup_records：cf_del_txt 内部的 cf_api 失败时会终结整个
  #     管道子 shell，导致后续记录不再清理 → 必须写成 ( cf_del_txt ... )
  #
  # 对照 doh_txt_visible 的 `resp=$(_http ...) || return 1` ——
  # $(...) 与 () 都能把 exit 关在子 shell 里，思路相同。
  local out

  # 裸调用：脚本直接死，else 不可达，连 survived 都打不出来
  out=$(bash -c '
    set -euo pipefail
    f() { exit 1; }
    if f >/dev/null 2>&1; then echo reachable; else echo unreachable; fi
    echo survived
  ' 2>&1)
  assert_eq "裸调用时脚本当场终止" "" "$out"

  # 括号包裹：else 可达且脚本存活
  out=$(bash -c '
    set -euo pipefail
    f() { exit 1; }
    if ( f ) >/dev/null 2>&1; then echo reachable; else echo unreachable; fi
    echo survived
  ' 2>&1)
  assert_eq "括号包裹后 else 可达且脚本存活" "unreachable
survived" "$out"
}

test_load_config_rejects_crlf() {
  # CRLF 配置文件会让行尾的 \r 进入变量值：
  #   DOMAINS="a.com *.a.com"  →  第二个域名变成 "*.a.com\r"
  # 挑战记录名因此成为 "_acme-challenge.a.com\r" ——
  # Cloudflare 那边建一条名字带回车符的记录，ACME 永远校验不过，
  # 而报错是"授权超时"，记录名在终端里看起来完全正常。
  # 最难排查的一类：不报错，只是结果错。
  local f="$LE_TEST_TMP/le_test_crlf.conf"
  printf 'DOMAINS="a.com"\r\nCF_API_TOKEN="x"\r\n' > "$f"
  chmod 600 "$f"
  local out rc=0
  out=$( ( load_config "$f" ) 2>&1 ) || rc=$?
  assert_eq "CRLF 配置被拒绝" "1" "$rc"

  # ★ 更强的一条：把错误信息里给的修复命令【原样执行一遍】，确认它真的修得好。
  #
  # 这条守的是"唯一的指引本身是坏的"这类缺陷：原建议写的是
  #     sed -i 's/\r$//' <file>
  # 而 BSD sed 的 -i 需要 extension 参数，macOS 上实测直接报错
  # （sed: 1: "...": command c expects \ followed by text，rc=1），GNU 上却正常。
  # 偏偏 macOS 就是 CRLF 配置最常见的来源（跨平台拷贝/编辑）——
  # 于是这段指引在它最该起作用的那个平台上恰好是坏的，
  # 而用户此时已经卡住了，只会以为"按提示做也没用"。
  local fixcmd
  fixcmd=$(printf '%s\n' "$out" | sed 's/.*请先转换：//')
  eval "$fixcmd" >/dev/null 2>&1
  assert_eq "建议的修复命令确实去掉了 CR" "0" \
    "$(LC_ALL=C grep -c $'\r' "$f" 2>/dev/null || true)"

  # 反向：LF 配置必须被接受，确认不是因为别的原因失败
  printf 'DOMAINS="a.com"\nCF_API_TOKEN="x"\n' > "$f"
  chmod 600 "$f"
  assert_ok "LF 配置被接受" load_config "$f"
  rm -f "$f"
}

test_derive_paths_production
test_derive_paths_staging
test_env_isolation_is_complete
test_set_cert_dir_includes_primary_domain
test_ensure_dirs_handles_unset_cert_dir
test_ensure_cert_dir_rejects_empty
test_exit_in_if_condition_is_not_suppressed
test_load_config_rejects_crlf
test_parse_args_staging_switch
test_parse_args_default_production
test_parse_args_domains
test_parse_args_subcommands
test_parse_args_config_override_does_not_change_env
test_parse_args_force_semantics
test_parse_args_resets_its_own_state
test_check_config_perms_rejects_loose
test_load_config_parses_values
test_load_config_rejects_missing_token
test_load_config_does_not_glob_domains
test_cmd_init_writes_template_with_600
test_cmd_check_rejects_missing_config
test_cmd_check_reports_unreachable_doh
test_functions_survive_set_e
test_install_cron_uses_script_path() {
  local out="$LE_TEST_TMP/le_test_cron.txt"
  LE_ENV=production
  BASE_DIR=/etc/le-dns
  derive_paths
  SCRIPT_PATH=/usr/local/bin/le-dns.sh
  render_cron_line > "$out"
  # 必须包含 17 分而非 0 分（避开整点的全球竞争）
  assert_ok "cron 分钟为 17" grep -q '^17 3 \* \* \*' "$out"
  # 断言命令动作本身（issue + 重定向），不依赖路径与 issue 之间有没有引号
  assert_ok "cron 调用 issue" grep -qE 'issue >/dev/null 2>&1' "$out"
  # 反向确认：不能再出现 renew（它已不是合法子命令，写进去等于让续期天天失败）
  assert_eq "cron 行不含 renew" "" "$(grep 'renew' "$out" || true)"
  assert_ok "cron 使用脚本自身路径" grep -q '/usr/local/bin/le-dns.sh' "$out"
  # cron 行里不能出现任何密钥
  assert_eq "cron 行不含 token" "" "$(grep -i 'token\|CF_API' "$out" || true)"
  rm -f "$out"
}

test_install_cron_quotes_path_with_spaces() {
  # cron 的命令字段是整行剩余部分交给 /bin/sh -c 执行的，所以引号有效。
  #
  # 路径必须整体加引号：脚本可以待在任意目录（resolve_script_path 的全部
  # 意义就在于此），而目录名带空格时，不加引号的 cron 会去执行 "/home/my"、
  # 把 "app/le-dns/le-dns.sh" 当成它的参数。
  #
  # 后果尤其隐蔽：cron 行末尾是 >/dev/null 2>&1，这个失败【一点痕迹都不留】，
  # 表现为"续期莫名其妙没跑"，而 /etc/cron.d/le-dns 看起来完全正常。
  local out="$LE_TEST_TMP/le_test_cron_space.txt"
  LE_ENV=production
  BASE_DIR=/etc/le-dns
  derive_paths
  SCRIPT_PATH="/home/my app/le-dns/le-dns.sh"
  render_cron_line > "$out"
  assert_ok "含空格的路径被引号整体包住" \
    grep -qF '"/home/my app/le-dns/le-dns.sh" issue' "$out"
  rm -f "$out"
  SCRIPT_PATH=""
}

test_install_cron_reflects_actual_path() {
  local out="$LE_TEST_TMP/le_test_cron2.txt"
  LE_ENV=production
  BASE_DIR=/etc/le-dns
  derive_paths
  SCRIPT_PATH=/home/cxf/le-dns/le-dns.sh
  render_cron_line > "$out"
  assert_ok "使用实际脚本路径而非硬编码" grep -q '/home/cxf/le-dns/le-dns.sh' "$out"
  rm -f "$out"
}

test_usage_documents_both_environments() {
  local out="$LE_TEST_TMP/le_test_usage.txt"
  usage > "$out" 2>&1
  assert_ok "文档提到 staging 调试流程" grep -q -- '--staging' "$out"
  assert_ok "文档提到一次性命令" grep -q -- '--init' "$out"
  assert_ok "文档提到定时任务" grep -q -- '--install-cron' "$out"
  assert_ok "文档提到自检" grep -q -- '--check' "$out"
  assert_ok "文档警告生产配额" grep -q '配额' "$out"
  rm -f "$out"
}

test_single_exit_trap() {
  # trap 是覆盖语义：脚本里只能有一处 "trap ... EXIT"。
  # 多于一处意味着先设的会被顶掉，清理逻辑静默失效 ——
  # 这正是设计评审时揪出的 bug（cmd_issue 的 trap 顶掉了 main 的 trap）。
  local count
  count=$(grep -c '^[[:space:]]*trap .*EXIT' ../le-dns.sh 2>/dev/null || echo 0)
  assert_eq "全脚本只有一个 EXIT trap" "1" "$count"
}

test_main_has_exit_trap() {
  # main 必须挂 on_exit，否则失败路径不清理 DNS 记录（边界情况 ③）
  assert_ok "main 里挂了 on_exit trap" \
    grep -q 'trap on_exit EXIT' ../le-dns.sh
}

test_check_path_has_tmp_dir() {
  # ★ --check 也要发 HTTP 请求（cf_api 验 Token，再发一次 DoH 探测），
  # 而 _ensure_http_tmp 要求 TMP_DIR 已初始化 ——
  # 所以 main 必须在【命令分发之前】调用 setup_workdir。
  #
  # 若把它留在 case 之后，--check 一进 cf_api 就会以
  #   "_ensure_http_tmp: TMP_DIR 未初始化（应先调用 setup_workdir）"
  # 中止，而那两个错误分支会把它分别报成「Token 不可用」与「DoH 不可达」——
  # 两条消息都把矛头指向用户的网络与配置，真正的原因却是脚本自己。
  # 这恰好摧毁了 --check 存在的意义：它是远程排查的唯一线索。
  #
  # 手法与套件里替换 _http 注入 fixture 相同：把叶子命令 cmd_check 换成
  # 做判定的桩，测的是 main 的分发顺序本身。
  #
  # ★ 判定必须在【桩里】做，不能把原样值带出来比。
  # 这条用例最初写成 `assert_ne "TMP_DIR=[]" "$out"` —— 那是空断言：
  # TMP_DIR 在文件作用域被声明为空串，而桩用 ${TMP_DIR:-UNSET} 打印，
  # 空值会走 :- 分支打成 "TMP_DIR=[UNSET]"，于是被比较的两个串
  # 永远不可能相等，断言恒过。已实测确认（把 setup_workdir 挪回 case
  # 之后，该断言照样通过）。把判定放进桩里，失败信息里也照样带着实际值。
  local out
  out=$(bash -c '
    set -euo pipefail
    . ../le-dns.sh
    cmd_check() {
      case "${TMP_DIR:-}" in
        /*) printf "TMP_DIR=ok\n" ;;
        *)  printf "TMP_DIR=missing:[%s]\n" "${TMP_DIR:-UNSET}" ;;
      esac
      return 0
    }
    main --check
  ' 2>&1 | grep "^TMP_DIR=")

  assert_eq "check 路径下 TMP_DIR 已建立（绝对路径）" "TMP_DIR=ok" "$out"
}

test_install_cron_uses_script_path
test_install_cron_reflects_actual_path
test_install_cron_quotes_path_with_spaces
test_usage_documents_both_environments
test_single_exit_trap
test_main_has_exit_trap
test_check_path_has_tmp_dir
