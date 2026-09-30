# ACME 协议层测试。通过替换 _http 注入 fixture，不产生任何网络请求。
ACCOUNT_KEY_FOR_TEST="$LE_TEST_TMP/le_test_account.key"
[ -f "$ACCOUNT_KEY_FOR_TEST" ] || openssl genrsa -out "$ACCOUNT_KEY_FOR_TEST" 2048 2>/dev/null

# ACME 层依赖的两个全局量，生产里由 Task 7 的 derive_paths 赋值，
# 但本任务的测试必须先于 Task 7 存在，且 set -u 下未赋值会直接终止脚本。
#   ACME_DIRECTORY —— acme_dir() 拉取目录用的 URL
#   ACCOUNT_JSON   —— acme_new_account() 写 kid 的目标路径
# 少任何一个，第一个用例就会让整个运行器死掉。
ACME_DIRECTORY="https://acme-staging-v02.api.letsencrypt.org/directory"
ACCOUNT_JSON="$LE_TEST_TMP/le_test_account.json"

HTTP_HEADER_FILE="$LE_TEST_TMP/le_test_headers.txt"

# 记录每次 _http 调用的参数与【请求体】，供断言检查。
# 注意不能借用脚本里 curl -o 指向的那个【响应体】文件来存请求体 —— 语义不同；
# 且 mock 若不写它，读到的会是上次运行的残留或干脆不存在，
# 断言结果随文件是否残留而变（flaky）。
HTTP_CALLS_FILE="$LE_TEST_TMP/le_test_calls.txt"
HTTP_REQUEST_FILE="$LE_TEST_TMP/le_test_request.txt"

# 可控的 authz 响应。空串时 mock 照旧回放 fixtures/authz.json，
# 因此其他用例的行为完全不变；只有轮询相关用例需要它 ——
# 授权在不同阶段（pending / valid / invalid）的响应 fixture 表达不了。
AUTHZ_RESPONSE=""

# mock：按 URL 返回预设响应
_http() {
  local method=$1 url=$2 body=$3
  printf '%s %s\n' "$method" "$url" >> "$HTTP_CALLS_FILE"
  printf '%s' "$body" > "$HTTP_REQUEST_FILE"
  case "$url" in
    */directory)
      printf 'HTTP/2 200\r\nReplay-Nonce: dir-nonce\r\n\r\n' > "$HTTP_HEADER_FILE"
      # 路径不带 $(dirname "$0")：run-tests.sh 已经 cd 到 tests/，
      # 而 $0 仍是 "tests/run-tests.sh"，dirname 会再叠一层，
      # 变成 tests/tests/fixtures/ 而找不到文件（文档规定的调用方式
      # `bash tests/run-tests.sh` 下必挂）。用 cwd 相对路径两种调用方式都成立。
      cat "fixtures/directory.json"
      ;;
    */new-nonce)
      printf 'HTTP/2 200\r\nReplay-Nonce: fresh-nonce-1\r\n\r\n' > "$HTTP_HEADER_FILE"
      ;;
    */new-acct)
      printf 'HTTP/2 201\r\nLocation: https://acme/acct/12345\r\nReplay-Nonce: after-acct\r\n\r\n' > "$HTTP_HEADER_FILE"
      printf '{"status":"valid","contact":[]}'
      ;;
    */new-order)
      printf 'HTTP/2 201\r\nLocation: https://acme/order/1\r\nReplay-Nonce: after-order\r\n\r\n' > "$HTTP_HEADER_FILE"
      # 从 fixture 读，不要内联一份相同内容 ——
      # 否则同一个响应有两份真相，改一处忘另一处不会被任何测试发现。
      cat "fixtures/order.json"
      ;;
    */authz/1)
      printf 'HTTP/2 200\r\nReplay-Nonce: after-authz1\r\n\r\n' > "$HTTP_HEADER_FILE"
      if [ -n "$AUTHZ_RESPONSE" ]; then
        printf '%s' "$AUTHZ_RESPONSE"
      else
        cat "fixtures/authz.json"
      fi
      ;;
    *) printf 'HTTP/2 404\r\n\r\n' > "$HTTP_HEADER_FILE" ;;
  esac
  return 0
}

reset_acme_state() {
  : > "$HTTP_CALLS_FILE"
  : > "$HTTP_REQUEST_FILE"
  NONCE=""
  ACCOUNT_KID=""
  # 必须把全部 ACME_* 缓存一起清掉：acme_nonce 依赖 ACME_NEW_NONCE，
  # 若只清 ACME_DIR_JSON，测试就会隐式依赖"前一个用例恰好跑过 acme_dir"
  # 这种执行顺序，单独跑或用例重排都会挂。
  ACME_DIR_JSON=""
  ACME_NEW_NONCE=""
  ACME_NEW_ACCOUNT=""
  ACME_NEW_ORDER=""
}

test_acme_dir_parses_endpoints() {
  reset_acme_state
  acme_dir >/dev/null
  assert_eq "newNonce" \
    "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce" "$ACME_NEW_NONCE"
  assert_eq "newAccount" \
    "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct" "$ACME_NEW_ACCOUNT"
  assert_eq "newOrder" \
    "https://acme-staging-v02.api.letsencrypt.org/acme/new-order" "$ACME_NEW_ORDER"
}

test_acme_nonce_from_head() {
  reset_acme_state
  # 显式调用 acme_dir 建立 ACME_NEW_NONCE，不依赖"前一个用例恰好跑过它"
  acme_dir >/dev/null
  acme_nonce >/dev/null
  assert_eq "从 Replay-Nonce 头取 nonce" "fresh-nonce-1" "$NONCE"
  assert_eq "用的是 HEAD 方法" "HEAD https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce" \
    "$(grep '/new-nonce' "$HTTP_CALLS_FILE")"
}

test_http_header_missing_returns_empty_not_failure() {
  # 头不存在时 http_header 必须输出空串并【返回 0】。
  #
  # 返回非 0 的后果：`KID=$(http_header Location)` 这类赋值式命令替换
  # 在 set -e + pipefail 下会让脚本当场终止，紧随其后的
  #   die "账号注册失败，未返回 Location 头"
  # 永远执行不到；acme_nonce 的 die、acme_post 里"没带头也可以容忍"的
  # 分支同样变成死代码。三处错误守卫全部失效。
  #
  # 必须在【显式开启 set -e】的子进程里验证：运行器跑在 set +e 下，
  # 普通用例根本看不见返回码的差别，这也是这个 bug 能一路隐身的原因。
  printf 'HTTP/2 400\r\nContent-Type: application/json\r\n\r\n' > "$HTTP_HEADER_FILE"
  # 前置断言：中转文件必须真的存在。
  # 少了它，下面那条断言分不清两种"输出空串"：
  #   （a）文件在、但没有 Location 头  ← 要测的
  #   （b）文件根本不存在，grep 失败   ← 假绿
  # （b）曾经是会发生的：本文件顶部已经定义过 $HTTP_HEADER_FILE，
  # 而这里又写了一份同样的字面量 —— 两份真相，改一处忘另一处就变成（b）。
  assert_ok "中转文件已建立" test -f "$HTTP_HEADER_FILE"
  local out
  # 中转文件路径必须【传进去】，不能再写一份字面量。
  out=$(bash -c '
    set -euo pipefail
    . ../le-dns.sh
    HTTP_HEADER_FILE=$1
    v=$(http_header Location)
    echo "survived:[$v]"
  ' _ "$HTTP_HEADER_FILE" 2>&1)
  assert_eq "无该头时不终止脚本且输出空串" "survived:[]" "$out"

  # 反向：有该头时必须正常取到值（确认断言不是因为函数永远返回空而通过）
  printf 'HTTP/2 201\r\nLocation: https://acme/acct/9\r\n\r\n' > "$HTTP_HEADER_FILE"
  assert_eq "有该头时正常取值" "https://acme/acct/9" "$(http_header Location)"
}

test_http_failure_reports_real_curl_code() {
  # curl 失败时 die 的报错必须带上【真实的】curl 退出码。这条测试同时守两个坑：
  #   1. `if ! curl ...; then die "...（curl 退出码 $?）"` —— $? 是取反后的值，
  #      恒为 0，报错会打印"curl 退出码 0"，排障时被假数字带偏；
  #   2. 报错串里 `$url（` 这种【变量后紧跟全角字符】的写法，在 UTF-8 locale 下
  #      bash 会把全角字节并进变量名，set -u 下直接变成
  #      `url（: unbound variable`，真正的报错一个字都打不出来。
  # 用 shell 函数顶掉 curl：零网络、零依赖、不依赖端口是否被占用。
  # 真实 _http 需要 TMP_DIR（生产里由 setup_workdir 创建）。
  # 这里由测试自己提供并在外层清理 —— 子 shell 会 die，不能指望它收尾。
  local out td
  td=$(mktemp -d); chmod 700 "$td"
  # TMP_DIR 必须在 source 之后设：脚本在文件作用域把它声明为空串
  # （Task 8 起），用环境前缀注入会被那句声明覆盖掉。
  out=$(bash -c '
    set -euo pipefail
    curl() { return 7; }
    . ../le-dns.sh
    TMP_DIR=$1
    _http GET "http://acme.invalid/directory" ""
  ' _ "$td" 2>&1) || true
  rm -rf "$td"
  case "$out" in
    *"curl 退出码 7"*) assert_eq "报错带真实 curl 退出码" "ok" "ok" ;;
    *) assert_eq "报错带真实 curl 退出码" "含 'curl 退出码 7'" "$out" ;;
  esac
}

test_acme_new_account_stores_kid() {
  reset_acme_state
  acme_dir >/dev/null
  acme_nonce >/dev/null
  ACME_NEW_ACCOUNT="https://acme/new-acct"
  NONCE="n1"
  ACCOUNT_KEY="$ACCOUNT_KEY_FOR_TEST"
  acme_new_account >/dev/null
  assert_eq "从 Location 头取 kid" "https://acme/acct/12345" "$ACCOUNT_KID"
}

test_acme_post_uses_kid_after_registration() {
  reset_acme_state
  NONCE="n1"
  ACCOUNT_KEY="$ACCOUNT_KEY_FOR_TEST"
  ACCOUNT_KID="https://acme/acct/12345"
  acme_post "https://acme/new-order" '{}' 0 >/dev/null

  # 从 mock 记录的【请求体】里取 JWS，再解出 protected 头。
  # 单独用 HTTP_REQUEST_FILE 记录请求体：_http 里 curl -o 指向的是
  # 【响应体】文件，语义不同，不能混用。
  local jws prot decoded
  jws=$(cat "$HTTP_REQUEST_FILE")
  assert_ne "请求体是 JWS" "" "$jws"
  prot=$(json_str "$jws" protected)
  decoded=$(b64url_decode "$prot")   # 必须补 padding，见 Task 3 的 b64url_decode
  assert_ne "protected 含 kid" "" "$(json_str "$decoded" kid)"
  assert_eq "kid 值正确" "https://acme/acct/12345" "$(json_str "$decoded" kid)"
  # use_jwk=0 时不能带 jwk 字段。
  # 不能用 json_str 查 —— jwk 的值是【对象】不是字符串，json_str 只取字符串值，
  # 对对象恒返回空，那样的断言会恒真（假断言），起不到检查作用。
  case "$decoded" in
    *'"jwk"'*) assert_eq "不含 jwk" "absent" "present" ;;
    *)         assert_eq "不含 jwk" "absent" "absent" ;;
  esac
}

test_acme_post_uses_jwk_for_new_account() {
  reset_acme_state
  NONCE="n1"
  ACCOUNT_KEY="$ACCOUNT_KEY_FOR_TEST"
  acme_post "https://acme/new-acct" '{"termsOfServiceAgreed":true}' 1 >/dev/null
  assert_ok "new-account 请求已发出" grep -q '/new-acct' "$HTTP_CALLS_FILE"

  # use_jwk=1 时必须带 jwk 且不带 kid —— 与上面 kid 那条互为反向，
  # 两条一起才能证明 use_jwk 这个分支参数真的生效（只查 URL 查不出这个）
  local decoded
  decoded=$(b64url_decode "$(json_str "$(cat "$HTTP_REQUEST_FILE")" protected)")
  # jwk 是对象值，只能用子串匹配，不能用 json_str（它只取字符串值）
  case "$decoded" in
    *'"jwk"'*) assert_eq "protected 含 jwk" "present" "present" ;;
    *)         assert_eq "protected 含 jwk" "present" "absent" ;;
  esac
  assert_eq "不含 kid" "" "$(json_str "$decoded" kid)"
}

test_normalize_and_record_name() {
  assert_eq "去掉通配符前缀" "example.com" "$(normalize_domain '*.example.com')"
  assert_eq "普通域名不变" "example.com" "$(normalize_domain 'example.com')"
  assert_eq "子域通配符" "sub.example.com" "$(normalize_domain '*.sub.example.com')"
  # 边界情况 ①：通配符与裸域必须映射到同一个记录名
  assert_eq "通配符的记录名" "_acme-challenge.example.com" \
    "$(challenge_record_name '*.example.com')"
  assert_eq "裸域的记录名" "_acme-challenge.example.com" \
    "$(challenge_record_name 'example.com')"
}

test_acme_dns01_selection() {
  local authz dns01
  authz=$(cat "fixtures/authz.json")
  dns01=$(acme_dns01_of "$authz")
  # 必须挑出 dns-01，而不是第一个出现的 http-01
  assert_eq "选中的是 dns-01 的 token" "dnsTokenBBB" "$(printf '%s' "$dns01" | cut -f1)"
  assert_eq "选中的是 dns-01 的 url" "https://acme/chal/dns/1" "$(printf '%s' "$dns01" | cut -f2)"
}

test_acme_key_authz_is_deterministic() {
  ACCOUNT_KEY="$LE_TEST_TMP/le_test_account.key"
  local v1 v2
  v1=$(acme_key_authz "somtoken")
  v2=$(acme_key_authz "somtoken")
  assert_eq "同一 token 的 TXT 值可重现" "$v1" "$v2"
  # TXT 值是 SHA-256 的 base64url，长度固定 43
  assert_eq "TXT 值长度" "43" "$(printf '%s' "$v1" | wc -c | tr -d ' ')"
  # 不同 token 必须得到不同值
  assert_ne "不同 token 值不同" "$v1" "$(acme_key_authz 'othertoken')"
}

test_acme_key_authz_matches_rfc_formula() {
  # 独立按 RFC 8555 第 8.4 节复算一遍：b64url(sha256(token + "." + thumbprint))
  ACCOUNT_KEY="$LE_TEST_TMP/le_test_account.key"
  local tp expected actual
  tp=$(jwk_thumbprint "$ACCOUNT_KEY")
  expected=$(printf '%s' "mytoken.$tp" | sha256_b64url)
  actual=$(acme_key_authz "mytoken")
  assert_eq "TXT 值符合 RFC 8555 公式" "$expected" "$actual"
}

test_order_groups_same_record_name() {
  # 边界情况 ① 的一半：裸域 + 通配符必须映射到【同一个记录名】。
  # 另一半（两条记录的值必须不同）由这里直接断言 ——
  # 完整性来自 test_acme_key_authz_* 的 token 不同，但那不是本用例守的；
  # 只测记录名相同会让注释比断言承诺得多。
  local names
  names="$(challenge_record_name 'example.com')
$(challenge_record_name '*.example.com')"
  assert_eq "两个域名映射到同一记录名" 1 \
    "$(printf '%s\n' "$names" | sort -u | wc -l | tr -d ' ')"

  # 同名但值必须不同 —— 否则 ACME 按值匹配时会认错
  ACCOUNT_KEY="$LE_TEST_TMP/le_test_account.key"
  assert_ne "两条记录的值必须不同" \
    "$(acme_key_authz 'tokenForApex')" \
    "$(acme_key_authz 'tokenForWildcard')"
}

test_acme_new_order_builds_identifiers() {
  reset_acme_state
  ACCOUNT_KEY="$ACCOUNT_KEY_FOR_TEST"
  ACCOUNT_KID="https://acme/acct/12345"
  DOMAINS=(example.com '*.example.com')
  acme_new_order >/dev/null

  assert_eq "订单 URL 取自 Location 头" "https://acme/order/1" "$ORDER_URL"
  assert_eq "finalize URL" "https://acme/finalize/1" "$ORDER_FINALIZE"
  assert_eq "authorization 个数" "2" \
    "$(printf '%s\n' "$ORDER_AUTHZ_URLS" | wc -l | tr -d ' ')"

  # 请求体是 JWS，identifiers 在 payload 里，必须解出来才能验证。
  # 不验这一段，「通配符是否原样保留」这个关键性质就无人看守 ——
  # 星号被 shell 展开或被剥掉都会让你签到错误的域名上。
  local decoded
  decoded=$(b64url_decode "$(json_str "$(cat "$HTTP_REQUEST_FILE")" payload)")
  case "$decoded" in
    *'"value":"example.com"'*) assert_eq "含裸域 identifier" "present" "present" ;;
    *) assert_eq "含裸域 identifier" "present" "absent" ;;
  esac
  case "$decoded" in
    *'"value":"*.example.com"'*) assert_eq "通配符原样保留星号" "present" "present" ;;
    *) assert_eq "通配符原样保留星号" "present" "absent" ;;
  esac
  # 构建 identifiers 时用了 `${identifiers%,}` 去尾逗号，必须验证真的去掉了
  case "$decoded" in
    *',]'*) assert_eq "identifiers 无尾逗号" "clean" "trailing comma" ;;
    *) assert_eq "identifiers 无尾逗号" "clean" "clean" ;;
  esac
}

test_acme_dns01_of_returns_nonzero_when_absent() {
  # 调用方写的是 `if ! dns01=$(acme_dns01_of "$authz"); then die ...; fi`，
  # 依赖这个函数在找不到 dns-01 时返回非 0。
  # 若它改成 return 0，调用方会拿着空 token 继续跑，
  # 算出错误的 TXT 值，然后 ACME 校验失败。
  local no_dns='{"status":"pending","challenges":[{"type":"http-01","url":"https://acme/c/h","token":"t"}]}'
  ( acme_dns01_of "$no_dns" ) >/dev/null 2>&1
  assert_eq "没有 dns-01 时返回非 0" "1" "$?"

  # 反向确认：有 dns-01 时必须返回 0
  local with_dns='{"status":"pending","challenges":[{"type":"dns-01","url":"https://acme/c/d","token":"t"}]}'
  assert_ok "有 dns-01 时返回 0" acme_dns01_of "$with_dns"
}

test_account_json_declared_at_file_scope() {
  # 与 CERT_URL 完全同类的一个隐患：ACCOUNT_JSON 只在 derive_paths 里赋值，
  # 而 acme_new_account 把它当【重定向目标】用（> "$ACCOUNT_JSON"）。
  # set -u 下展开未赋值的变量会让 bash 终止整个 shell，且是在重定向阶段 ——
  # 报错位置极不直观（用户看到的是 "ACCOUNT_JSON: unbound variable"，
  # 而不是"账号注册失败"）。
  #
  # 必须在子进程里验证：运行器只关掉了 -e，-u 仍然生效，
  # 而这里要测的正是 set -u 下的行为。
  local out
  out=$(bash -c '
    set -euo pipefail
    . ../le-dns.sh
    printf "ACCOUNT_JSON=[%s]\n" "$ACCOUNT_JSON"
  ' 2>&1)
  assert_eq "ACCOUNT_JSON 已在文件作用域声明为空" "ACCOUNT_JSON=[]" "$out"
}

test_acme_download_cert_requires_cert_url() {
  # CERT_URL 未赋值时 acme_download_cert 必须以清晰方式失败，
  # 而不是让整个脚本以 unbound variable 中止得莫名其妙。
  # 恒返回 0（表示"变量已声明"）才算通过初始化的意义 ——
  # 声明为空的目的是让 set -u 不报错，把错误留到真正使用处。
  local out
  out=$(bash -c '
    set -euo pipefail
    . ../le-dns.sh
    echo "CERT_URL=[${CERT_URL}]"
  ' 2>&1)
  assert_eq "CERT_URL 已在文件作用域声明为空" "CERT_URL=[]" "$out"

  # 声明为空只是手段，真正的目的是让错误在【使用处】以看得懂的方式出现。
  # 这里把使用处也固化下来：CERT_URL 为空时 acme_download_cert 会走到
  # _http，curl 拿到空 URL 后失败，最终是
  #   die "HTTP 请求失败：POST （curl 退出码 N）"
  # —— 指向 HTTP 层而不是 shell 的 unbound variable。
  # 必须在 bash -c 里跑：本文件的 _http 已被 mock 顶掉，拿不到真实 curl 行为。
  # 同上：真实 _http 需要 TMP_DIR。
  local called td2
  td2=$(mktemp -d); chmod 700 "$td2"
  called=$(bash -c '
    set -euo pipefail
    . ../le-dns.sh
    TMP_DIR=$1
    acme_download_cert
  ' _ "$td2" 2>&1) || true
  rm -rf "$td2"
  case "$called" in
    *'HTTP 请求失败'*) assert_eq "CERT_URL 为空时在 HTTP 层清晰失败" "present" "present" ;;
    *) assert_eq "CERT_URL 为空时在 HTTP 层清晰失败" "present" "$called" ;;
  esac
}

test_acme_poll_authz_uses_authzs_own_status() {
  # 授权自身的 status 与每个 challenge 的 status 同名。
  # 取到【最后一个】status（贪婪匹配）时，DNS-01 通过后 authz 是 valid
  # 而 http-01/tls-alpn-01 仍是 pending，于是永远等不到 valid，
  # 睡满 180 秒后报「授权校验超时」—— 每次正式签发都失败，且指不到真正原因。
  AUTHZ_RESPONSE='{"identifier":{"type":"dns","value":"example.com"},"status":"valid","challenges":[{"type":"http-01","status":"pending","token":"a"},{"type":"dns-01","status":"valid","token":"b"},{"type":"tls-alpn-01","status":"pending","token":"c"}]}'
  # ★ 不能写成 assert_ok "..." acme_poll_authz "$url"：assert_ok 在当前 shell
  # 里执行命令，而 acme_poll_authz 的失败路径是 die（= exit）—— exit 不受
  # if 条件抑制。一旦回归发生，得到的不是一条 FAIL，而是先睡满 60×3=180 秒
  # （运行器没有任何超时机制），再让 run-tests.sh 当场退出：
  # 汇总行与后续测试文件全被吞掉，且 assert_ok 把 stderr 也重定向到了
  # /dev/null，连 die 的报错都看不到 —— 只剩一次静默中断。
  # 所以每一处调用都必须放进子 shell 并接住输出。
  local out
  out=$( ( acme_poll_authz "https://acme/authz/1" ) 2>&1 )
  assert_eq "授权自身 valid 时轮询立即成功" "" "$out"
  # 反向确认 fixture 里确实存在同名干扰键：取【最后一个】status 必须不是 valid。
  # 否则一旦 fixture 退化（挑战不再带 status），上面那条断言在贪婪匹配下
  # 也会通过，守卫就失效了 —— 这正是 test_json.sh 里同款断言的理由。
  assert_ne "fixture 的末位 status 确为干扰项" "valid" \
    "$(printf '%s' "$AUTHZ_RESPONSE" | grep -o '"status":"[^"]*"' |
      tail -n1 | sed 's/.*://; s/"//g')"

  # 反向：授权 invalid 而挑战仍是 pending —— 取错 status 会把失败当成
  # "还在处理中"，一路睡到超时，报出「授权校验超时」，
  # 真正的原因（DNS 记录不对）一个字都看不到。
  AUTHZ_RESPONSE='{"status":"invalid","challenges":[{"type":"dns-01","status":"pending","error":{"type":"urn:ietf:params:acme:error:dns","detail":"no TXT record found at _acme-challenge.example.com"},"token":"b"}]}'
  # 反向确认：末位 status 是 pending —— 贪婪读取会拿到它，
  # 于是把"已失败"误判成"还在处理中"，睡到超时。
  assert_eq "fixture 的末位 status 是 pending（贪婪读取会漏判）" "pending" \
    "$(printf '%s' "$AUTHZ_RESPONSE" | grep -o '"status":"[^"]*"' |
      tail -n1 | sed 's/.*://; s/"//g')"
  out=$( ( acme_poll_authz "https://acme/authz/1" ) 2>&1 )
  case "$out" in
    *'no TXT record found at _acme-challenge.example.com'*)
      assert_eq "invalid 时报出 error.detail 原文" "present" "present" ;;
    *) assert_eq "invalid 时报出 error.detail 原文" "present" "$out" ;;
  esac
  case "$out" in
    *'授权校验超时'*) assert_eq "invalid 不被误当作 pending" "不超时" "超时" ;;
    *) assert_eq "invalid 不被误当作 pending" "不超时" "不超时" ;;
  esac
  AUTHZ_RESPONSE=""
}

test_make_csr_builds_san_with_wildcard() {
  # make_csr 用临时 openssl.cnf 而不是 -addext（CentOS 7 的 openssl 1.0.2
  # 不支持 -addext）。这条同时守三件事：产出的是 DER、SAN 里的星号
  # 原样保留（被剥掉就会签到错误的域名上）、CN 取第一个域名并去星号。
  # 通配符必须放在【第一位】：CN 取的是第一个域名，
  # 若首个域名本来就是裸域，CN 断言在实现里有没有 normalize_domain 都成立
  # （假守卫）。把星号放前面，CN 断言才真的在守"去星号"。
  local dir txt
  dir=$(mktemp -d)
  make_csr "$ACCOUNT_KEY_FOR_TEST" "$dir/r.csr.der" '*.example.com' example.com \
    >/dev/null 2>&1
  assert_eq "make_csr 退出码 0" "0" "$?"
  assert_eq "产出 DER（首字节 0x30）" "30" \
    "$(od -An -tx1 -N1 "$dir/r.csr.der" 2>/dev/null | tr -d ' ')"
  txt=$(openssl req -inform DER -in "$dir/r.csr.der" -noout -text 2>/dev/null)
  case "$txt" in
    *'DNS:*.example.com'*) assert_eq "SAN 保留通配符星号" "present" "present" ;;
    *) assert_eq "SAN 保留通配符星号" "present" "absent" ;;
  esac
  case "$txt" in
    *'DNS:example.com'*) assert_eq "SAN 含裸域" "present" "present" ;;
    *) assert_eq "SAN 含裸域" "present" "absent" ;;
  esac
  # OpenSSL 3 与 LibreSSL 的 subject 输出格式不同（CN=x / CN = x），两种都接受
  case "$txt" in
    *'CN=example.com'*|*'CN = example.com'*)
      assert_eq "CN 为第一个域名（去星号）" "present" "present" ;;
    *) assert_eq "CN 为第一个域名（去星号）" "present" "$txt" ;;
  esac
  rm -rf "$dir"
}

test_make_csr_error_path_is_visible_and_cleans_up() {
  # A2：openssl 的 stderr 被 2>/dev/null 吞掉，若不显式检查退出码，
  # set -e 下它的失败会直接终止脚本 —— 于是 rm -f "$cnf" 不执行
  # （临时 cnf 泄漏），下面那句 die 成为死代码：用户只看到静默退出，
  # 没有任何解释。
  #
  # 必须显式开 set -e 跑：运行器是 set +e，普通用例根本看不见退出码的差别
  # （与 test_http_header_missing_returns_empty_not_failure 同款理由）。
  # 用 shell 函数顶掉 mktemp，把临时 cnf 固定到可检查的目录 ——
  # 与测试里用 _http / curl 顶掉网络是同一手法，零依赖、不碰系统临时目录
  # （macOS 的 mktemp 忽略 TMPDIR，没法用 TMPDIR 重定向）。
  local tdir out rc
  tdir=$(mktemp -d)
  mktemp() { local f="$tdir/cnf.$$"; : > "$f"; printf '%s' "$f"; }
  out=$( ( set -euo pipefail; make_csr "$tdir/missing.key" "$tdir/bad.der" example.com ) 2>&1 )
  rc=$?
  unset -f mktemp

  assert_eq "失败时退出码为 1" "1" "$rc"
  assert_ne "坏密钥时给出可见的报错而不是静默退出" "" "$out"
  case "$out" in
    *'CSR 生成失败'*) assert_eq "报错说明是 CSR 生成失败" "present" "present" ;;
    *) assert_eq "报错说明是 CSR 生成失败" "present" "$out" ;;
  esac
  assert_eq "失败时临时 cnf 已清理（不泄漏）" "0" \
    "$(ls -A "$tdir" 2>/dev/null | grep -c '^cnf\.')"
  rm -rf "$tdir"
}

test_http_tmp_lives_in_tmp_dir() {
  # 中转文件必须落在 TMP_DIR 里（mktemp -d 创建 + chmod 700），
  # 不能是 /tmp/le-dns-headers.$$ 这类可预测路径 ——
  # /tmp 全局可写而 $$ 可枚举、会回绕，构成符号链接攻击面（CWE-377）。
  # 实测：预先把该路径建成符号链接后，脚本确实覆写了链接指向的任意文件。
  # 而本脚本可能以 root 运行（--install-cron），风险被放大。
  #
  # 落在 TMP_DIR 里还顺带解决了另外两件事：路径是确定性的，
  # 所以子 shell 里算出的是同一对（不会每次 _http 调用都新建一对）；
  # 清理就是 on_exit 里已有的 rm -rf "$TMP_DIR"（不需要额外记账）。
  local out
  out=$(bash -c '
    set -euo pipefail
    . ../le-dns.sh
    TMP_DIR=$(mktemp -d); chmod 700 "$TMP_DIR"
    _ensure_http_tmp
    printf "%s\n%s\n" "$HTTP_HEADER_FILE" "$TMP_DIR"
    rm -rf "$TMP_DIR"
  ' 2>&1)
  local hf td
  hf=$(printf '%s\n' "$out" | sed -n 1p)
  td=$(printf '%s\n' "$out" | sed -n 2p)

  case "$hf" in
    "$td"/*) assert_eq "中转文件位于 TMP_DIR 内" "ok" "ok" ;;
    *) assert_eq "中转文件位于 TMP_DIR 内" "$td/..." "GOT: $hf" ;;
  esac
  case "$hf" in
    *le-dns-headers*|*le-dns-body*)
      assert_eq "不得使用可预测的 /tmp 路径" "in-TMP_DIR" "PREDICTABLE: $hf" ;;
    *) assert_eq "不得使用可预测的 /tmp 路径" "ok" "ok" ;;
  esac
}

test_http_tmp_path_is_deterministic_across_subshells() {
  # ★ 这条守的是本文件头等重要的那个陷阱。
  #
  # _http 几乎总是跑在 $() 里，于是函数体在子 shell 中执行。
  # 若中转文件是在 _ensure_http_tmp 里各自 mktemp 的，子 shell 里
  # 创建的路径回不到父 shell，而且【每次 _http 调用都会新建一对】——
  # 一次签发约 15 次调用就是 30 个泄漏文件，父 shell 还无从登记。
  #
  # 落在 TMP_DIR 里则路径由 TMP_DIR 唯一确定，任何子 shell 算出的
  # 都是同一对。这条断言就是验证这一点。
  #
  # ★ 必须比较【两个互相独立的子 shell】，不能比较「父 shell 与子 shell」。
  #
  # 后者是假信心：父 shell 先直接调用一次后，子 shell 继承到非空的
  # $HTTP_HEADER_FILE，走的是函数开头那个早退分支，返回的是继承来的值 ——
  # 于是【即使实现是各自 mktemp 的随机路径，这条断言也照样通过】。
  # 实测确认过：把 _ensure_http_tmp 换回 mktemp 版本，父/子版本通过，
  # 而下面这个独立子 shell 版本失败。
  #
  # 两个互不相干的子 shell 之间一致，只能来自路径本身的确定性，
  # 无法由继承解释 —— 这才是真正守住回归的量。
  local out
  out=$(bash -c '
    set -euo pipefail
    . ../le-dns.sh
    TMP_DIR=$(mktemp -d); chmod 700 "$TMP_DIR"
    sub_a=$( ( _ensure_http_tmp; printf "%s" "$HTTP_HEADER_FILE" ) )
    sub_b=$( ( _ensure_http_tmp; printf "%s" "$HTTP_HEADER_FILE" ) )
    printf "%s\n%s\n" "$sub_a" "$sub_b"
    rm -rf "$TMP_DIR"
  ' 2>&1)
  assert_eq "两个独立子 shell 算出的中转路径相同" \
    "$(printf '%s\n' "$out" | sed -n 1p)" \
    "$(printf '%s\n' "$out" | sed -n 2p)"
  # 反向确认：两个子 shell 真的都算出了路径（而不是都为空 ——
  # 那会让上一条在函数整个坏掉时也通过）
  assert_ne "子 shell 确实算出了路径" "" "$(printf '%s\n' "$out" | sed -n 1p)"
}

test_acme_dns01_of_handles_validated_challenge() {
  # 真机回归（--force 重跑必现）：授权被 Let's Encrypt 复用、已是 valid 时，
  # 挑战带着 validationRecord 嵌套对象。旧实现取不到 dns-01，cmd_issue 当场 die。
  local authz dns01
  authz=$(cat "fixtures/authz-valid.json")
  dns01=$(acme_dns01_of "$authz")
  assert_eq "取到 token" \
    "w7N7T2_1ae7-FoZsUSjiW_piWuwgeGtZx7Rf-JzArO0" "$(printf '%s' "$dns01" | cut -f1)"
  assert_eq "取到 challenge url" \
    "https://acme-staging-v02.api.letsencrypt.org/acme/chall/345480823/5176930983/CQleKw" \
    "$(printf '%s' "$dns01" | cut -f2)"
}

test_authz_action() {
  # 已 valid 的授权不需要再建任何 TXT 记录 —— Let's Encrypt 会复用 30 天内
  # 校验过的授权，此时重跑（或 --force）必须跳过，而不是重做一遍挑战。
  local valid pending mixed invalid
  valid=$(cat "fixtures/authz-valid.json")
  assert_eq "valid 的授权应跳过" "skip" "$(authz_action "$valid")"

  pending='{"status":"pending","challenges":[]}'
  assert_eq "pending 的授权要走挑战" "challenge" "$(authz_action "$pending")"

  # 必须取【顶层】status。若取到挑战自身的 status（同为 valid），
  # 一个 pending 的授权会被误判成 skip，挑战被整个跳过，
  # finalize 必然失败，而报错会指向 Let's Encrypt 而不是这里。
  mixed='{"status":"pending","challenges":[{"type":"dns-01","status":"valid","token":"t","url":"u"}]}'
  assert_eq "取顶层 status 而非挑战的" "challenge" "$(authz_action "$mixed")"

  invalid='{"status":"invalid","challenges":[]}'
  assert_eq "invalid 的授权应报错" "invalid" "$(authz_action "$invalid")"
}

test_cmd_issue_skips_already_valid_authz() {
  # 真机回归的端到端版本，复刻用户实际遇到的那次失败。
  #
  # 场景：对刚签成功的域名再签发一次（--force 重跑 / 提前续期）。
  # Let's Encrypt 复用 30 天内校验过的授权，新订单直接返回 status=valid 的
  # authorization，其挑战带 validationRecord 嵌套对象。
  # 旧实现走到这里当场 die：「授权 ... 里没有 dns-01 挑战」——
  # 而那条报错的原文里就印着 dns-01。
  #
  # 断言两件事：一条 TXT 记录都不建，且一路走到 finalize 而不是中途 die。
  local base="$LE_TEST_TMP/e2e" cf_log="$LE_TEST_TMP/e2e-cf.txt" out
  rm -f "$cf_log"
  mkdir -p "$base/accounts/staging" "$base/logs"
  gen_rsa_key "$base/accounts/staging/account.key" 2048
  printf '{"kid":"https://acme/acct/12345"}' > "$base/accounts/staging/account.json"
  cat > "$base/le-dns-staging.conf" <<'EOF'
DOMAINS="cxf.qzz.io *.cxf.qzz.io"
CF_API_TOKEN="tok"
RELOAD_CMD="true"
RENEW_BEFORE_DAYS=30
DNS_WAIT_TIMEOUT=5
KEY_TYPE=rsa2048
ACCOUNT_EMAIL=""
EOF
  chmod 600 "$base/le-dns-staging.conf"

  # LE_DNS_BASE 把 BASE_DIR 整个挪进临时目录，绝不碰 /etc/le-dns。
  out=$(LE_DNS_BASE="$base" E2E_CF_LOG="$cf_log" bash -c '
    set -euo pipefail
    . ../le-dns.sh
    LE_ENV=staging

    _http() {
      _ensure_http_tmp
      local method=$1 url=$2 body=$3
      case "$url" in
        */directory)
          printf "HTTP/2 200\r\nReplay-Nonce: n1\r\n\r\n" > "$HTTP_HEADER_FILE"
          cat "fixtures/directory.json" ;;
        */new-nonce)
          printf "HTTP/2 200\r\nReplay-Nonce: n1\r\n\r\n" > "$HTTP_HEADER_FILE" ;;
        */new-order)
          printf "HTTP/2 201\r\nLocation: https://acme/order/1\r\nReplay-Nonce: n2\r\n\r\n" > "$HTTP_HEADER_FILE"
          cat "fixtures/order.json" ;;
        */authz/*)
          printf "HTTP/2 200\r\nReplay-Nonce: n3\r\n\r\n" > "$HTTP_HEADER_FILE"
          cat "fixtures/authz-valid.json" ;;
        *) printf "HTTP/2 404\r\n\r\n" > "$HTTP_HEADER_FILE" ;;
      esac
      return 0
    }

    cf_find_zone() { CF_ZONE_ID=z1; CF_ZONE_NAME=qzz.io; }
    cf_add_txt() { printf "ADD %s\n" "$2" >> "$E2E_CF_LOG"; printf "rec_1"; }
    cf_del_txt() { printf "DEL %s\n" "$1" >> "$E2E_CF_LOG"; }
    wait_dns_visible() { :; }

    make_csr() { :; }
    acme_finalize() { printf "REACHED_FINALIZE\n"; }
    acme_download_cert() { printf "%s\n" "-----BEGIN CERTIFICATE-----" "MIIB" "-----END CERTIFICATE-----"; }
    write_certs_atomic() { :; }
    run_reload() { :; }

    cmd_issue
  ' 2>&1) || true

  # 1. 没有建过任何 TXT 记录 —— 已 valid 的授权不需要挑战
  assert_eq "已 valid 的授权不建 TXT 记录" "no" \
    "$([ -f "$cf_log" ] && printf yes || printf no)"
  # 2. 走到了 finalize，而不是中途 die
  case "$out" in
    *REACHED_FINALIZE*) assert_eq "走到了 finalize 而非中途 die" "ok" "ok" ;;
    *) assert_eq "走到了 finalize 而非中途 die" "含 REACHED_FINALIZE" "$out" ;;
  esac
  # 3. 两个授权都被识别为已有效
  assert_eq "两个授权都被跳过" "2" "$(printf '%s\n' "$out" | grep -c '授权已有效')"
  # 4. 反向确认：旧实现的那句误报不能出现
  case "$out" in
    *"没有 dns-01 挑战"*) assert_eq "不再误报没有 dns-01" "不应出现该报错" "$out" ;;
    *) assert_eq "不再误报没有 dns-01" "ok" "ok" ;;
  esac
}

test_acme_dir_parses_endpoints
test_acme_nonce_from_head
test_http_header_missing_returns_empty_not_failure
test_http_failure_reports_real_curl_code
test_acme_new_account_stores_kid
test_acme_post_uses_kid_after_registration
test_acme_post_uses_jwk_for_new_account

test_normalize_and_record_name
test_acme_dns01_selection
test_acme_dns01_of_returns_nonzero_when_absent
test_acme_new_order_builds_identifiers
test_acme_key_authz_is_deterministic
test_acme_key_authz_matches_rfc_formula
test_order_groups_same_record_name
test_account_json_declared_at_file_scope
test_acme_download_cert_requires_cert_url
test_acme_poll_authz_uses_authzs_own_status
test_make_csr_builds_san_with_wildcard
test_make_csr_error_path_is_visible_and_cleans_up
test_http_tmp_lives_in_tmp_dir
test_http_tmp_path_is_deterministic_across_subshells
test_acme_dns01_of_handles_validated_challenge
test_authz_action
test_cmd_issue_skips_already_valid_authz
