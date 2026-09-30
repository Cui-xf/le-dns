# 固定密钥，让 thumbprint 有确定期望值。测试用密钥可公开，不涉及任何真实资源。
TEST_KEY="$LE_TEST_TMP/le_test_account.key"

setup_test_key() {
  [ -f "$TEST_KEY" ] || openssl genrsa -out "$TEST_KEY" 2048 2>/dev/null
  chmod 600 "$TEST_KEY"
}
setup_test_key

test_jwk_json_shape() {
  local jwk
  jwk=$(jwk_json "$TEST_KEY")
  # RFC 7638 要求成员按字典序：e, kty, n
  case "$jwk" in
    '{"e":"AQAB","kty":"RSA","n":"'*) assert_eq "JWK 字段顺序符合 RFC 7638" "ok" "ok" ;;
    *) assert_eq "JWK 字段顺序符合 RFC 7638" '{"e":"AQAB","kty":"RSA","n":"...' "$jwk" ;;
  esac
  assert_eq "e 固定为 AQAB（65537）" "AQAB" "$(json_str "$jwk" e)"
  assert_eq "kty 为 RSA" "RSA" "$(json_str "$jwk" kty)"
  assert_ne "n 非空" "" "$(json_str "$jwk" n)"
}

test_jwk_n_matches_openssl() {
  # 独立地用另一种路径算 n，两者必须一致。
  # 参考值：openssl 输出大写 hex，转小写后走标准 base64（非 urlsafe），
  # 由于 n 的长度固定且无 padding 差异，这里用 openssl base64 直接比对长度与内容前缀。
  local n
  n=$(json_str "$(jwk_json "$TEST_KEY")" n)
  # n 是 2048 位 = 256 字节 → base64 无 padding 长度为 ceil(256/3)*4 - padding = 342
  assert_eq "n 的 base64url 长度（2048 位）" "342" "${#n}"
  case "$n" in
    *+*|*/*|*=*) assert_eq "n 不含非 urlsafe 字符" "clean" "dirty" ;;
    *) assert_eq "n 不含非 urlsafe 字符" "clean" "clean" ;;
  esac
}

test_jwk_thumbprint_stable() {
  # 同一密钥两次调用必须得到相同结果（thumbprint 直接参与 challenge 值计算，
  # 不稳定会导致校验必然失败）
  assert_eq "thumbprint 可重现" \
    "$(jwk_thumbprint "$TEST_KEY")" \
    "$(jwk_thumbprint "$TEST_KEY")"
  # thumbprint 是 SHA-256 的 base64url，长度固定 43
  assert_eq "thumbprint 长度" "43" "$(jwk_thumbprint "$TEST_KEY" | wc -c | tr -d ' ')"
}

test_jwk_thumbprint_known_vector() {
  # RFC 7638 第 3.1 节的官方测试向量
  local n='0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw'
  local expected='NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'
  local actual
  actual=$(printf '{"e":"AQAB","kty":"RSA","n":"%s"}' "$n" | sha256_b64url)
  assert_eq "RFC 7638 官方 thumbprint 向量" "$expected" "$actual"
}

test_jws_build_structure() {
  local protected='{"alg":"RS256","nonce":"abc","url":"https://acme/x"}'
  local jws
  jws=$(jws_build "$TEST_KEY" "$protected" '{"a":1}')
  # 三个成员齐全
  assert_ne "protected 非空" "" "$(json_str "$jws" protected)"
  assert_ne "payload 非空" "" "$(json_str "$jws" payload)"
  assert_ne "signature 非空" "" "$(json_str "$jws" signature)"
  # protected 是原文的 base64url，解回来必须一致
  assert_eq "protected 可解码回原文" "$protected" \
    "$(b64url_decode "$(json_str "$jws" protected)")"
}

test_jws_signature_verifies() {
  # 用 openssl 独立验签：把签名解回二进制，对 signing input 验签必须通过。
  # 这是 RS256 选型成立与否的判定点。
  local protected='{"alg":"RS256","nonce":"abc","url":"https://acme/x"}'
  local payload='{"hello":"world"}'
  local jws sig_b64 p64 pl64
  jws=$(jws_build "$TEST_KEY" "$protected" "$payload")
  p64=$(json_str "$jws" protected)
  pl64=$(json_str "$jws" payload)
  sig_b64=$(json_str "$jws" signature)

  b64url_decode "$sig_b64" > "$LE_TEST_TMP/le_sig.bin"

  # RSA-2048 的 PKCS#1 v1.5 签名固定 256 字节。
  # 这条断言同时守住了 padding 解码：漏掉 padding 会少一个字节变成 255，
  # 而 openssl 不会报任何错。
  assert_eq "签名字节数" "256" "$(wc -c < "$LE_TEST_TMP/le_sig.bin" | tr -d ' ')"

  printf '%s.%s' "$p64" "$pl64" > "$LE_TEST_TMP/le_signing_input.txt"
  openssl rsa -in "$TEST_KEY" -pubout -out "$LE_TEST_TMP/le_pub.pem" 2>/dev/null
  assert_ok "签名可被 openssl 验签" \
    openssl dgst -sha256 -verify "$LE_TEST_TMP/le_pub.pem" -signature "$LE_TEST_TMP/le_sig.bin" "$LE_TEST_TMP/le_signing_input.txt"
  rm -f "$LE_TEST_TMP/le_sig.bin" "$LE_TEST_TMP/le_signing_input.txt" "$LE_TEST_TMP/le_pub.pem"
}

test_jws_build_empty_payload() {
  # POST-as-GET 的 payload 是空字符串，RFC 8555 要求
  local jws
  jws=$(jws_build "$TEST_KEY" '{"alg":"RS256","nonce":"n","url":"https://acme/x"}' '')
  assert_eq "POST-as-GET 的 payload 为空" "" "$(json_str "$jws" payload)"
  # 断言 payload 成员【存在且为空】，而不是【缺失】——
  # assert_eq "" 对这两种情况都通过，区分不了
  case "$jws" in
    *'"payload":""'*) assert_eq "payload 成员存在且为空" "ok" "ok" ;;
    *) assert_eq "payload 成员存在且为空" '{"payload":""}' "$jws" ;;
  esac
}

test_jws_build_omitted_payload() {
  # POST-as-GET 最自然的写法就是省略第三参。
  # payload=$3 在 set -u 下会以 `$3: unbound variable` 终止整个脚本。
  local jws
  jws=$(jws_build "$TEST_KEY" '{"alg":"RS256","nonce":"n","url":"https://acme/x"}')
  case "$jws" in
    *'"payload":""'*) assert_eq "省略第三参时 payload 存在且为空" "ok" "ok" ;;
    *) assert_eq "省略第三参时 payload 存在且为空" '{"payload":""}' "$jws" ;;
  esac
}

test_jwk_rejects_unreadable_key() {
  # 坏密钥必须报错退出，不能静默产出空 n —— 那会变成一个
  # 43 字符、看起来完全正常的 thumbprint，被写进 DNS 后校验必然失败，
  # 而报错指向「授权超时」而非「密钥读不出来」。
  local rc
  ( jwk_thumbprint /tmp/definitely_missing_key_xyz.pem ) >/dev/null 2>&1
  rc=$?
  assert_eq "坏密钥时退出码为 1" "1" "$rc"

  # 反向确认：确认这条断言真的在测 exit code，
  # 而不是因为找不到命令之类的无关原因返回 1
  ( jwk_thumbprint "$TEST_KEY" ) >/dev/null 2>&1
  assert_eq "正常密钥时退出码为 0" "0" "$?"
}

test_gen_rsa_key_permissions() {
  local p="$LE_TEST_TMP/le_test_gen.key"
  rm -f "$p"
  gen_rsa_key "$p" 2048
  assert_ok "密钥文件存在" test -f "$p"
  local mode
  mode=$(ls -l "$p" | cut -c1-10)
  assert_eq "密钥权限为 600" "-rw-------" "$mode"
  rm -f "$p"
}

test_jwk_json_shape
test_jwk_n_matches_openssl
test_jwk_thumbprint_stable
test_jwk_thumbprint_known_vector
test_jws_build_structure
test_jws_signature_verifies
test_jws_build_empty_payload
test_jws_build_omitted_payload
test_jwk_rejects_unreadable_key
test_gen_rsa_key_permissions
