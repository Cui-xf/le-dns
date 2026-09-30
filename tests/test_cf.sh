CF_TEST_CALLS="$LE_TEST_TMP/le_cf_calls.txt"

# mock Cloudflare API 的实体。
# 单独成函数是为了让用例能临时顶掉 _http 之后再还原（见下方转发壳）。
cf_mock_http() {
  local method=$1 url=$2 body=$3
  printf '%s %s\n' "$method" "$url" >> "$CF_TEST_CALLS"

  if printf '%s' "$url" | grep -q 'dns-query'; then
    # DoH 响应：只能按查询的 fqdn 分支。
    #
    # ★ 不能按“待查的值”分支 —— 值不在 URL 里。
    #   doh_txt_visible 发出的请求是
    #     https://cloudflare-dns.com/dns-query?name=<fqdn>&type=TXT
    #   URL 中只有 fqdn，被查的 TXT 值是函数的第二个参数，根本没进 URL。
    #   写成 `*VISIBLE*)` 这种分支会永远不匹配，落到 *) 返回 {"Status":0}，
    #   于是“值可见”用例必挂 —— 本计划最初就是这么错的，被预演抓出来。
    case "$url" in
      *DASHTEST*)
        # 返回一个以 - 开头的 TXT 值，用于验证 grep 的 `--` 保护
        printf '{"Status":0,"Answer":[{"name":"_acme-challenge.DASHTEST.example.com","type":16,"data":"\\"-VISIBLE\\""}]}'
        ;;
      *)
        # 默认 fqdn 返回不含 - 前缀的值
        printf '{"Status":0,"Answer":[{"name":"_acme-challenge.example.com","type":16,"data":"\\"VISIBLE\\""}]}'
        ;;
    esac
    return 0
  fi

  case "$url" in
    *'/zones?name=sub.example.com'*)
      printf 'HTTP/2 200\r\n\r\n'
      printf '{"success":true,"result":[]}'
      ;;
    *'/zones?name=example.com'*)
      printf 'HTTP/2 200\r\n\r\n'
      printf '{"success":true,"result":[{"id":"zone_example","name":"example.com"}]}'
      ;;
    *'/dns_records'*)
      if [ "$method" = "POST" ]; then
        printf 'HTTP/2 200\r\n\r\n'
        printf '{"success":true,"result":{"id":"rec_001","name":"_acme-challenge.example.com"}}'
      else
        printf 'HTTP/2 200\r\n\r\n'
        printf '{"success":true,"result":{"id":"rec_001"}}'
      fi
      ;;
    *) printf 'HTTP/2 200\r\n\r\n'; printf '{"success":true,"result":[]}' ;;
  esac
  return 0
}

# 转发到 mock 实体。用例临时顶掉 _http 后，用这一行即可恢复：
#   _http() { cf_mock_http "$@"; }
_http() { cf_mock_http "$@"; }

test_cf_zone_candidates() {
  local actual
  actual=$(cf_zone_candidates 'a.b.example.com')
  assert_eq "候选个数" "3" "$(printf '%s\n' "$actual" | wc -l | tr -d ' ')"
  assert_eq "第一个最具体" "a.b.example.com" "$(printf '%s\n' "$actual" | sed -n 1p)"
  assert_eq "第二个" "b.example.com" "$(printf '%s\n' "$actual" | sed -n 2p)"
  assert_eq "第三个最宽泛" "example.com" "$(printf '%s\n' "$actual" | sed -n 3p)"
  # 通配符前缀要先剥掉
  assert_eq "通配符域名" "example.com" "$(cf_zone_candidates '*.example.com' | sed -n 1p)"
}

test_cf_find_zone_falls_back() {
  : > "$CF_TEST_CALLS"
  CF_ZONE_CACHE=""
  CF_API_TOKEN="fake"
  # 直接调用（不包 $()）：结果经全局量返回，见 cf_find_zone 的注释
  cf_find_zone 'sub.example.com'
  assert_eq "zone id" "zone_example" "$CF_ZONE_ID"
  assert_eq "zone name" "example.com" "$CF_ZONE_NAME"
  # 必须先试 sub.example.com 再回退到 example.com
  assert_ok "先查最具体" grep -q 'name=sub.example.com' "$CF_TEST_CALLS"
  assert_ok "再回退一级" grep -q 'name=example.com' "$CF_TEST_CALLS"
}

test_cf_find_zone_caches() {
  : > "$CF_TEST_CALLS"
  CF_ZONE_CACHE=""
  CF_API_TOKEN="fake"
  cf_find_zone 'sub.example.com' >/dev/null
  local first_count
  first_count=$(wc -l < "$CF_TEST_CALLS" | tr -d ' ')
  cf_find_zone 'sub.example.com' >/dev/null
  assert_eq "第二次命中缓存，不再请求" "$first_count" "$(wc -l < "$CF_TEST_CALLS" | tr -d ' ')"
}

test_cf_add_txt_returns_record_id() {
  CF_API_TOKEN="fake"
  local rid
  rid=$(cf_add_txt 'zone_example' '_acme-challenge.example.com' 'valueX')
  assert_eq "返回记录 id" "rec_001" "$rid"
}

test_cf_del_txt_by_id_only() {
  : > "$CF_TEST_CALLS"
  CF_API_TOKEN="fake"
  cf_del_txt 'zone_example' 'rec_001'
  # 边界情况 ②：必须按 id 删，URL 里不能只出现记录名
  assert_ok "按 id 删除" grep -q 'dns_records/rec_001' "$CF_TEST_CALLS"
  assert_ok "使用 DELETE 方法" grep -q '^DELETE' "$CF_TEST_CALLS"
}

test_doh_txt_visible() {
  assert_ok "值可见" doh_txt_visible '_acme-challenge.example.com' 'VISIBLE'
  # 值不存在时必须返回非 0，否则会过早触发校验
  ( doh_txt_visible '_acme-challenge.example.com' 'NOTTHERE' ) >/dev/null 2>&1
  assert_eq "值不可见时返回非 0" "1" "$?"
}

test_doh_txt_visible_handles_leading_dash() {
  # base64url 的字母表含 `-`，challenge 值可能以它开头
  # （SHA-256 摘要的 base64url 首字符在 64 个符号上均匀分布，约 1/64）。
  # 不加 `--` 时 grep 会把值当成选项解析，后果取决于后面的字母：
  #   -V 开头 → 当成 --version，返回 0（假阳性：报告记录已生效，实际不在）
  #   其他    → "invalid option"，返回 2
  # 这里是"随机失败"型缺陷：约 3% 的签发撞上，其余时候一切正常。
  #
  # fixture 特意选了 -V 开头，因为那是最危险的一种（假阳性而非报错），
  # 也是最容易被"反正会报错"的直觉放过的一种。
  assert_ok "以 -V 开头的值也能正确匹配" \
    doh_txt_visible '_acme-challenge.DASHTEST.example.com' '-VISIBLE'
  # 反向：不存在的值仍须返回非 0（确认这条断言真的在做子串匹配，
  # 而不是被 grep 的选项解析搅成"恒真"）
  ( doh_txt_visible '_acme-challenge.DASHTEST.example.com' '-NOTPRESENT' ) >/dev/null 2>&1
  assert_eq "以 - 开头的值不存在时仍返回非 0" "1" "$?"
}

test_cf_find_zone_cache_requires_direct_call() {
  # ★ 这条守的是一个【调用约定】，不是函数本身的行为。
  #
  # cf_find_zone 靠写全局量把结果交出去，要求调用方直接调用。
  # 若写成 `x=$(cf_find_zone ...)`，函数进子 shell，它对 CF_ZONE_CACHE
  # 的更新在父 shell 里丢失 —— 缓存退化成死优化。
  #
  # 关键在于：单纯"缓存能用吗"的测试【抓不到】这个问题。
  # 它若用直接调用去验，会通过；而真实代码里的缓存从未生效过。
  # 本计划最初就是这个状态，由 Task 6 的实现者发现。
  #
  # 所以这里反向断言：用 $() 调用时父 shell 的缓存必须是空的。
  : > "$CF_TEST_CALLS"
  CF_ZONE_CACHE=""
  CF_API_TOKEN="fake"
  local sink
  sink=$(cf_find_zone 'sub.example.com')
  assert_eq "用 \$() 调用时缓存不写入父 shell" "" "$CF_ZONE_CACHE"

  # 反向确认：直接调用时缓存【必须】写入，
  # 否则上一条会在"缓存功能整个坏掉"时也通过
  CF_ZONE_CACHE=""
  cf_find_zone 'sub.example.com' >/dev/null
  assert_ne "直接调用时缓存写入父 shell" "" "$CF_ZONE_CACHE"
}

test_cf_find_zone_propagates_api_failure() {
  # Token 无效时 cf_api 会 die。它跑在 $() 里，exit 只终结那个子 shell，
  # 若 cf_find_zone 不作处理，会逐候选试完再以
  #   "找不到域名 X 对应的 Cloudflare zone"
  # 收尾 —— 把"Token 无效"误导成"域名不在 Cloudflare 上"。
  #
  # ★ 只断言"退出码是 1"是【没有牙齿】的：接住失败返回 1，
  #   和不接住、试完所有候选最后由末尾那句 die 收尾，
  #   两者退出码都是 1。实测：把
  #     if ! resp=$(cf_api ...); then return 1; fi
  #   换成裸的 resp=$(cf_api ...)，本用例照样通过。
  #   而那个 guard 真正保护的是下面两件事，所以必须把它们断言出来：
  #     (a) 只花一次 API 调用 —— 不接住就会对每个候选各发一次请求
  #         （sub.example.com → example.com，实测 1 次变 2 次）；
  #     (b) 用户看到的最后一条消息是 Cloudflare 的真实原因（Invalid token），
  #         而不是误导性的"找不到域名"。
  : > "$CF_TEST_CALLS"
  CF_ZONE_CACHE=""
  CF_API_TOKEN="fake"
  _http() {
    printf 'GET /zones\n' >> "$CF_TEST_CALLS"
    printf '{"success":false,"errors":[{"code":10000,"message":"Invalid token"}]}'
  }
  local err rc
  # 2>&1 >/dev/null：只捞 stderr（die 的出口），丢掉 stdout。
  # 外层那个 ( ) 不能省 —— die 会 exit，不能让它直接带走测试进程。
  err=$( ( cf_find_zone 'sub.example.com' ) 2>&1 >/dev/null )
  rc=$?
  assert_eq "API 失败时向上传播（rc=1）" "1" "$rc"
  # (a) 失败即返回，不逐候选重试
  assert_eq "失败后只花一次 API 调用（不逐候选重试）" "1" \
    "$(wc -l < "$CF_TEST_CALLS" | tr -d ' ')"
  # (b) stderr 里有 Cloudflare 的真实原因
  case "$err" in
    *'Invalid token'*) assert_eq "stderr 保留 Cloudflare 的真实错误" "ok" "ok" ;;
    *) assert_eq "stderr 保留 Cloudflare 的真实错误" "Invalid token" "GOT: $err" ;;
  esac
  # (b) 且没有被"域名不在 Cloudflare 上"这条误导性消息盖住
  case "$err" in
    *'找不到域名'*) assert_eq "不得误导成域名不在 Cloudflare 上" "no-misleading-die" "GOT: $err" ;;
    *) assert_eq "不得误导成域名不在 Cloudflare 上" "ok" "ok" ;;
  esac

  # 恢复 mock 并反向确认：正常路径必须成功，否则上一条是恒真
  _http() { cf_mock_http "$@"; }
  CF_ZONE_CACHE=""
  assert_ok "正常 mock 下仍能成功" cf_find_zone 'sub.example.com'
}

test_cf_zone_candidates
test_cf_find_zone_falls_back
test_cf_find_zone_cache_requires_direct_call
test_cf_find_zone_propagates_api_failure
test_cf_find_zone_caches
test_cf_add_txt_returns_record_id
test_cf_del_txt_by_id_only
test_doh_txt_visible
test_doh_txt_visible_handles_leading_dash
