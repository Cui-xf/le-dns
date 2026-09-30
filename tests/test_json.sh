ORDER_JSON='{"status":"pending","finalize":"https://acme/finalize/1","authorizations":["https://acme/authz/1","https://acme/authz/2"]}'
AUTHZ_JSON='{"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[{"type":"http-01","url":"https://acme/chal/http","token":"httpTok"},{"type":"dns-01","url":"https://acme/chal/dns","token":"dnsTok"}]}'
CF_JSON='{"success":true,"errors":[],"result":[{"id":"zone123","name":"example.com","status":"active","meta":{"x":1}}]}'

test_json_str() {
  assert_eq "取 status" "pending" "$(json_str "$ORDER_JSON" status)"
  assert_eq "取 finalize" "https://acme/finalize/1" "$(json_str "$ORDER_JSON" finalize)"
  assert_eq "键不存在时为空" "" "$(json_str "$ORDER_JSON" nonexistent)"
  # 值里含正斜杠和冒号不能被截断
  assert_eq "值含 / 和 :" "https://acme/finalize/1" "$(json_str "$ORDER_JSON" finalize)"
}

test_json_str_takes_first_not_last() {
  # json_str 必须取【第一个】匹配。贪婪 sed 会跳到最后一个，
  # 而这个 bug 只有存在重复键时才暴露 —— 上面 test_json_str 的 fixture
  # 每个键都只出现一次，所以它对这个问题完全免疫。
  #
  # 真机后果：ACME authorization 响应里「authz 自己的 status」与
  # 「每个 challenge 的 status」同名。取最后一个会拿到最后一个 challenge 的状态。
  # DNS-01 通过后 authz 是 valid，而 http-01/tls-alpn-01 仍是 pending，
  # 于是 acme_poll_authz 永远等不到 valid，睡满 180 秒后超时 ——
  # 每一次正式签发都会失败。
  assert_eq "重复键取第一个" "zoneA" \
    "$(json_str '{"result":[{"id":"zoneA"},{"id":"zoneB"}]}' id)"

  local authz='{"identifier":{"type":"dns","value":"example.com"},"status":"valid","expires":"2026-10-08T00:00:00Z","challenges":[{"type":"http-01","status":"pending","token":"a"},{"type":"dns-01","status":"valid","token":"b"},{"type":"tls-alpn-01","status":"pending","token":"c"}]}'
  assert_eq "取 authz 自身的 status 而非 challenge 的" "valid" \
    "$(json_str "$authz" status)"
  # 反向确认 fixture 里确实存在同名干扰键：直接从原始 JSON 里取【最后一个】
  # status，它必须不是 valid。否则一旦 fixture 退化，上面那条断言
  # 在"取最后一个"的实现下也会通过，护栏就失效了。
  assert_eq "fixture 确有同名干扰键（最后一个是 pending）" "pending" \
    "$(printf '%s' "$authz" | grep -o '"status":"[^"]*"' | tail -n1 | sed 's/.*:"//; s/"$//')"
}

test_json_str_after() {
  # AUTHZ_JSON 里 token 出现两次，必须能精确定位到 dns-01 那一个
  assert_eq "dns-01 的 token" "dnsTok" "$(json_str_after "$AUTHZ_JSON" 'dns-01' token)"
  assert_eq "http-01 的 token" "httpTok" "$(json_str_after "$AUTHZ_JSON" 'http-01' token)"
  assert_eq "marker 不存在时为空" "" "$(json_str_after "$AUTHZ_JSON" 'no-such-type' token)"
}

test_json_array_strings() {
  local actual
  actual=$(json_array_strings "$ORDER_JSON" authorizations)
  assert_eq "数组元素个数" "2" "$(printf '%s\n' "$actual" | wc -l | tr -d ' ')"
  assert_eq "第一个元素" "https://acme/authz/1" "$(printf '%s\n' "$actual" | sed -n 1p)"
  assert_eq "第二个元素" "https://acme/authz/2" "$(printf '%s\n' "$actual" | sed -n 2p)"
  assert_eq "空数组" "" "$(json_array_strings '{"a":[]}' a)"
}

test_json_flat_objects() {
  local actual
  actual=$(json_flat_objects "$AUTHZ_JSON" challenges)
  assert_eq "对象个数" "2" "$(printf '%s\n' "$actual" | wc -l | tr -d ' ')"
  assert_eq "第一个是 http-01" "http-01" \
    "$(json_str "$(printf '%s\n' "$actual" | sed -n 1p)" type)"
  assert_eq "第二个是 dns-01" "dns-01" \
    "$(json_str "$(printf '%s\n' "$actual" | sed -n 2p)" type)"
}

test_json_str_after_on_nested() {
  # Cloudflare zone 响应里 result 的对象含嵌套 meta，取 id 不能受影响
  assert_eq "zone id" "zone123" "$(json_str_after "$CF_JSON" '"result":' id)"
}

# 真实 Cloudflare zone 响应里 result[0] 有两个 "id"：
# zone 自己的 id，和 account.id。贪婪匹配会取到后者，那是账号 id 不是 zone id，
# 后果是后续所有 DNS 操作打到不存在的 zone 上。
CF_REAL_JSON='{"success":true,"errors":[],"result":[{"id":"023e105f4ecef8ad9ca31a8372d0c353","name":"example.com","status":"active","account":{"id":"01a7362d577a6c3019a474fd6f485823","name":"user@example.com"},"meta":{"step":2}}]}'

test_json_str_after_picks_first_not_greedy() {
  assert_eq "取 zone id 而非 account id" \
    "023e105f4ecef8ad9ca31a8372d0c353" \
    "$(json_str_after "$CF_REAL_JSON" '"result":' id)"
  assert_eq "取 zone name 而非 account name" \
    "example.com" \
    "$(json_str_after "$CF_REAL_JSON" '"result":' name)"
}

test_json_str_after_nested_error() {
  # 真实 ACME authorization 校验失败时，detail 嵌在 challenges[].error 里：
  #   ..."challenges":[{"type":"dns-01",...,"error":{"type":"urn:...","detail":"...","status":400}}]
  # marker 必须是 '"error":'。
  # 注意不能写成 '"problem"' —— 那是我最初凭印象编的 key，真实响应里不存在，
  # 会导致这里恒返回空，调用方只能靠兜底碰巧拿到值。
  local authz='{"identifier":{"type":"dns","value":"example.com"},"status":"invalid","challenges":[{"type":"dns-01","url":"https://acme/chal/dns/1","status":"invalid","error":{"type":"urn:ietf:params:acme:error:dns","detail":"DNS problem: NXDOMAIN looking up TXT","status":400}}]}'
  assert_eq "取到嵌套的 error.detail" \
    "DNS problem: NXDOMAIN looking up TXT" \
    "$(json_str_after "$authz" '"error":' detail)"
  # 值含逗号不能被截断 —— 提取逻辑不能按逗号切分 JSON
  local authz_comma='{"status":"invalid","challenges":[{"type":"dns-01","error":{"type":"urn:ietf:params:acme:error:dns","detail":"DNS problem: NXDOMAIN, SERVFAIL","status":400}}]}'
  assert_eq "值含逗号不被截断" \
    "DNS problem: NXDOMAIN, SERVFAIL" \
    "$(json_str_after "$authz_comma" '"error":' detail)"
}

test_json_no_match_does_not_abort() {
  # set -e + pipefail 下，grep 无匹配返回 1 会终止整个脚本。
  # 空数组和缺失字段是正常情况，必须返回空而不是崩溃。
  # 这里在子 shell 里开 set -euo pipefail 复现脚本的真实运行环境。
  local out
  out=$(bash -c '
    set -euo pipefail
    . ../le-dns.sh
    json_array_strings "{\"a\":[]}" a
    json_flat_objects "{\"a\":[]}" a
    json_str_after "{\"x\":1}" "nomarker" key
    json_str "{\"x\":1}" missing
    echo survived
  ' 2>&1)
  assert_eq "无匹配时全部函数安全返回" "survived" "$out"
}

test_json_array_strings_skips_empty_entries() {
  # 数组里的空元素不能产生空行，否则调用方会把空字符串当域名
  local actual
  actual=$(json_array_strings '{"a":["x","","y"]}' a)
  assert_eq "过滤掉空元素" "2" "$(printf '%s\n' "$actual" | grep -c . )"
}

# 真机 fixture：Let's Encrypt 复用 30 天内已校验过的授权时返回的 authorization。
# 挑战是 valid，并且带 validationRecord —— 一个【嵌套对象】。
#
# 旧实现 json_flat_objects 用 `grep -o '{[^{}]*}'` 取对象，匹配不了含嵌套的对象，
# 于是把内层的 validationRecord 当成数组元素吐出来，真正的挑战对象被跳过。
# 后果：挑战明明在响应里，却报「授权里没有 dns-01 挑战」，
# 而报错原文里就印着那个 dns-01。实测 --force 重跑必现。
test_json_flat_objects_handles_nested_object() {
  local authz actual
  authz=$(cat "fixtures/authz-valid.json")
  actual=$(json_flat_objects "$authz" challenges)
  assert_eq "嵌套对象仍算作一个" "1" "$(printf '%s\n' "$actual" | wc -l | tr -d ' ')"
  assert_eq "取到的是挑战对象" "dns-01" "$(json_str "$actual" type)"
  # 反向确认：若吐出的是内层 validationRecord，token 就会是空的
  # （不能用 hostname 判别 —— 完整的挑战对象本来就【包含】那个嵌套对象，
  #   所以 hostname 有值是正确的，不是挑错了对象）
  assert_eq "取到的是挑战而非内层对象" \
    "w7N7T2_1ae7-FoZsUSjiW_piWuwgeGtZx7Rf-JzArO0" "$(json_str "$actual" token)"
}

test_json_str
test_json_str_takes_first_not_last
test_json_str_after
test_json_array_strings
test_json_flat_objects
test_json_str_after_on_nested
test_json_str_after_picks_first_not_greedy
test_json_str_after_nested_error
test_json_no_match_does_not_abort
test_json_array_strings_skips_empty_entries
test_json_flat_objects_handles_nested_object
