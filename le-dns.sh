#!/usr/bin/env bash
# le-dns.sh — 纯 curl + openssl 的 Let's Encrypt DNS-01 证书申请与续期脚本
# 依赖：bash 4+、curl、openssl。不需要 jq / dig / xxd / python / certbot。
set -euo pipefail

# 脚本自身版本。--check 会打印它，便于远程排障时确认对方跑的是哪一版。
LE_DNS_VERSION="1.0.0"

# ============================================================
# 基础层
# ============================================================

# 日志同时写 stderr 和日志文件。日志文件由 derive_paths 设置。
LOG_FILE=""

# 日志的唯一出口：构造时间戳行 → 写 stderr → 有 LOG_FILE 时追加一份。
# 内部函数，必须带一个级别参数调用（log/warn/die 已经保证）。
# 空 LOG_FILE 时最后的 return 0 是承重的：上面的 [ -n ] && 判断为假会返回 1，
# 在 set -e 下会把调用方整个掀掉。
_emit() { # <level> <msg...>
  local line
  line="$(date '+%Y-%m-%d %H:%M:%S') [$1] ${*:2}"
  printf '%s\n' "$line" >&2
  # 追加日志前必须确认目录存在。
  #
  # $LOG_FILE 所在目录可能还不存在：首次运行尚未 --init，
  # 或用 -c 指向一个任意路径时就是这样。
  # 少了这个判断，重定向失败会甩出一条原生
  # "No such file or directory" 盖在真正的错误信息后面 ——
  # 用户看到的是一条路径错误，而不是失败原因。
  # 这恰好发生在"首次运行、还没有配置"这个最容易劝退人的时刻。
  # （用 `2>/dev/null` 包住也能静默，但那是压制错误；
  #   前置检查是根本不产生错误，更干净。）
  if [ -n "$LOG_FILE" ] && [ -d "$(dirname "$LOG_FILE")" ]; then
    printf '%s\n' "$line" >>"$LOG_FILE"
  fi
  return 0
}

log()  { _emit INFO  "$@"; }
warn() { _emit WARN  "$@"; }
die()  { _emit ERROR "$@"; exit 1; }

need_cmd() {
  local c
  for c in "$@"; do
    # 变量后紧跟全角字符时必须写 ${}：UTF-8 locale 下 bash 会把全角字节
    # 当作变量名的一部分，`$c（` 会被解析成变量 `c（`，set -u 下报
    # `c（: unbound variable` —— "缺少命令：curl（请先安装）" 一个字都打不出来。
    # 而这恰恰是依赖缺失时唯一的提示，最需要清晰的路径。
    command -v "$c" >/dev/null 2>&1 || die "缺少命令：${c}（请先安装）"
  done
}

# 取文件权限位，如 "600"。
# GNU 的 stat 用 -c，BSD/macOS 的 stat 用 -f %Lp。
# 顺序不能反：Linux 上 "stat -f" 是合法的但语义是"文件系统状态"，会静默返回错误结果。
file_mode() { # <path>
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

# ---------- 编码 ----------

# hex 字符串 → 原始字节写到 stdout。
# 必须直接写 stdout，不能走 $()：密钥的字节里可能出现 NUL 和换行。
hex2bin() {
  local h=$1 i
  for ((i = 0; i < ${#h}; i += 2)); do
    printf "\\x${h:$i:2}"
  done
}

# 读 stdin，输出无 padding 的 base64url（RFC 7515 要求无 padding）
b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '=\n'
}

b64url_str()  { printf '%s' "$1" | b64url; }
b64url_file() { openssl base64 -A -in "$1" | tr '+/' '-_' | tr -d '=\n'; }

# 读 stdin，输出 SHA-256 的 base64url
sha256_b64url() {
  openssl dgst -sha256 -binary | b64url
}

# ---------- JSON 取值 ----------
#
# ACME 与 Cloudflare 的响应结构固定，只需要针对性的提取函数，
# 不需要通用 JSON 解析器。所有函数都先把换行压平再匹配，
# 因为服务端可能返回格式化过的 JSON。

_flat() { printf '%s' "$1" | tr -d '\n\r' | tr -s ' '; }

# 取第一个 "key":"value" 的 value（仅字符串值）。
#
# 不能用 sed 写：`.*` 贪婪，会跳到【最后】一个匹配，
# 而 `| head -n1` 在这里是空操作 —— _flat 已经把换行压掉了，
# sed -n p 最多只输出一行，head 取到的仍是那一行。
#
# 这个差别的后果是致命的：ACME 的 authorization 响应里
# 「authz 自己的 status」和「每个 challenge 的 status」是同名的，
# 取最后一个会拿到最后一个 challenge 的状态。
# DNS-01 通过后 authz 是 valid、而 http-01/tls-alpn-01 仍是 pending，
# 于是 acme_poll_authz 永远等不到 valid，睡满 180 秒后超时退出 ——
# 每一次正式签发都会失败，且报错是「授权校验超时」，指不到真正原因。
json_str() { # <json> <key>
  local hit
  # grep -o 按出现顺序输出全部匹配，head -n1 取第一个。
  # 无匹配时 grep 返回 1，set -e + pipefail 下会终止脚本，必须吞掉。
  hit=$(_flat "$1" |
    grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" 2>/dev/null | head -n1) || true
  if [ -z "$hit" ]; then
    return 0
  fi
  printf '%s' "$hit" | sed 's/^[^:]*:[[:space:]]*"//; s/"$//'
  return 0
}

# 取 marker 之后第一个 "key":"value"。
#
# 不能写成 sed 's/.*marker.*"key":"\([^"]*\)".*/\1/' —— 两个 .* 都是贪婪的，
# 会跳到最后一个 key 出现的位置。Cloudflare 的 zone 响应里
# {"result":[{"id":"<zone>",...,"account":{"id":"<account>"}}]} 就有两个 "id"，
# 贪婪匹配会返回 account.id，后续所有 DNS 操作都会打到不存在的 zone 上。
#
# 正确做法：先截到 marker 之后，再在剩余内容里取【第一个】匹配。
json_str_after() { # <json> <marker> <key>
  local flat rest hit
  flat=$(_flat "$1")
  # marker 不存在时必须返回空。
  # 不能省掉这一步：sed 的 s/// 在匹配不到时原样返回整行，
  # 于是 grep 会退回在【全文】里找 key，返回一个看似合理但完全错误的答案。
  # 例如 json_str_after "$authz" 'no-such-type' token 会返回第一个挑战的 token，
  # 而不是空 —— 调用方会拿它去算一个错误的 TXT 值，且毫无报错线索。
  case "$flat" in
    *"$2"*) ;;
    *) return 0 ;;
  esac
  rest=$(printf '%s' "$flat" | sed "s/.*$2//")
  # grep -o 按出现顺序输出全部匹配，head -n1 取第一个。
  # 无匹配时 grep 返回 1，在 set -e + pipefail 下会终止脚本，必须吞掉。
  hit=$(printf '%s' "$rest" |
    grep -o "\"$3\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" 2>/dev/null | head -n1) || true
  if [ -z "$hit" ]; then
    return 0
  fi
  printf '%s' "$hit" | sed 's/^[^:]*:[[:space:]]*"//; s/"$//'
  return 0
}

# 取 "key":["a","b"] 的每个字符串元素，每行一个。
# 无匹配时返回空，不能报错 —— 单域名证书里某些数组可能为空。
json_array_strings() { # <json> <key>
  local frag
  frag=$(_flat "$1" | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p') || true
  if [ -z "$frag" ]; then
    return 0
  fi
  # 末尾的 grep -v 在全部过滤掉时返回 1，set -e + pipefail 下会终止脚本
  printf '%s' "$frag" | tr ',' '\n' |
    sed 's/^[[:space:]]*"//; s/"[[:space:]]*$//' | grep -v '^[[:space:]]*$' || true
  return 0
}

# 取 "key":[{...},{...}] 的每个【顶层】对象，每行一个。
#
# 必须按花括号深度取，不能用 `grep -o '{[^{}]*}'`：
# 后者匹配不了内部还有嵌套的对象，会把【内层】对象当成数组元素吐出来，
# 真正的那个元素反而被跳过。
#
# 实测（--force 重跑必现）：Let's Encrypt 会复用 30 天内已校验过的授权，
# 新订单直接返回 status=valid；此时挑战带 validationRecord:[{...}] 嵌套对象，
# 旧实现只吐出内层的 validationRecord，于是 acme_dns01_of 报
# 「授权里没有 dns-01 挑战」—— 而那个 dns-01 就印在同一条报错的原文里。
json_flat_objects() { # <json> <key>
  _flat "$1" |
    sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\[\(.*\)\][^]]*$/\1/p' |
    awk '{
      n = split($0, c, "")
      depth = 0; buf = ""
      for (i = 1; i <= n; i++) {
        ch = c[i]
        if (ch == "{") {
          depth++
          if (depth == 1) buf = "{"; else buf = buf "{"
        } else if (ch == "}") {
          if (depth > 0) {
            buf = buf "}"
            depth--
            if (depth == 0) { print buf; buf = "" }
          }
        } else if (depth > 0) {
          buf = buf ch
        }
      }
    }'
  return 0
}

# ---------- JWK 与 JWS（RS256）----------

gen_rsa_key() { # <path> <bits>
  openssl genrsa -out "$1" "$2" 2>/dev/null
  chmod 600 "$1"
}

# JWK 的 n 成员：RSA 模数的无符号大端表示，base64url。
# openssl -modulus 输出大写 hex 且无符号字节，正好是 JWK 需要的表示。
#
# hex2bin 的入参是【参数】而不是 stdin（见基础层），所以 hex 必须先收进变量。
# hex 是纯 ASCII（无 NUL、无换行），过 $() 安全；
# 承重的是 hex2bin 的【输出】——密钥字节里可能有 NUL 和换行——
# 它必须直接进管道交给 b64url，绝不能先存进变量。
jwk_n_b64() {
  local hex
  hex=$(openssl rsa -in "$1" -noout -modulus 2>/dev/null |
    sed 's/^Modulus=//' | tr 'A-F' 'a-f')
  # 读不到密钥必须报错，不能静默返回空。
  # 少了这一步的后果：2>/dev/null 加 set -e 只终结了 $() 里的子 shell，
  # 而 `printf '...' "$(...)"` 本身仍返回 0 —— 于是 jwk_json 输出
  # {"e":"AQAB","kty":"RSA","n":""} 且 rc=0，jwk_thumbprint 更是返回一个
  # 43 字符、看起来完全正常的哈希（它是那份坏 JWK 的 SHA-256）。
  # 这个值会被写进 DNS TXT 记录，ACME 校验必然失败，
  # 而报错是「授权超时」，指不到「密钥读不出来」。
  # `|| die` 形式在 set -e 下是安全的（成功路径返回 0）。
  [ -n "$hex" ] || die "无法读取 RSA 私钥：$1"
  hex2bin "$hex" | b64url
}

# RFC 7638 要求成员按字典序排列：e < kty < n。
# 顺序错了 thumbprint 就会算错，进而导致所有 DNS 校验失败。
jwk_json() {
  local n
  # jwk_n_b64 的失败必须在这里【接住】：它在 $() 里跑，子 shell 的 exit
  # 传不出去，而 `printf '...' "$(...)"` 本身永远返回 0 ——
  # 单靠 jwk_n_b64 里的 die，jwk_thumbprint 仍会拿空 n 算出一个
  # 43 字符、看起来完全正常的哈希并返回 0。（die 的报错已由内层打印，
  # 这里只需把退出码传出去，不要再打一遍。）
  n=$(jwk_n_b64 "$1") || exit 1
  printf '{"e":"AQAB","kty":"RSA","n":"%s"}' "$n"
}

jwk_thumbprint() {
  jwk_json "$1" | sha256_b64url
}

# 输出 flattened JWS JSON。
# signing input 为 b64url(protected) + "." + b64url(payload)；
# POST-as-GET 时 payload 传空字符串。
jws_build() { # <key-path> <protected-json> [payload]
  # payload 用 ${3:-}：POST-as-GET 时最自然的写法就是省略第三参，
  # 写成 $3 会在 set -u 下以 `$3: unbound variable` 终止脚本。
  local key=$1 protected=$2 payload=${3:-}
  local p64 pl64 sig
  p64=$(b64url_str "$protected")
  pl64=$(b64url_str "$payload")
  sig=$(printf '%s.%s' "$p64" "$pl64" | openssl dgst -sha256 -sign "$key" 2>/dev/null | b64url)
  printf '{"protected":"%s","payload":"%s","signature":"%s"}' "$p64" "$pl64" "$sig"
}

# ---------- HTTP 层 ----------
#
# 所有网络 I/O 都经过 _http()。测试通过替换它注入 fixture，
# 因此协议层可以在无网络条件下被完整覆盖。
HTTP_HEADER_FILE="${HTTP_HEADER_FILE:-}"
HTTP_BODY_FILE="${HTTP_BODY_FILE:-}"

# 惰性确定中转文件路径。
#
# ★ 它们必须落在 TMP_DIR 里，而不是各自 mktemp 一对。
#
# _http 几乎总是跑在 $() 里（`ACME_DIR_JSON=$(_http ...)`），
# 于是函数体在子 shell 中执行。若在这里 mktemp：
#   - 子 shell 里创建的路径回不到父 shell，父 shell 无从登记，
#     on_exit 也就清不掉；
#   - 更要命的是【每次调用都会新建一对】—— 一次签发约 15 次 _http 调用，
#     就是 30 个泄漏的临时文件。
# 而且这不能靠"在 main 里先创建一次"来绕开：任何一次漏掉的直接调用
# 又会退化成同样的问题。
#
# 用 TMP_DIR 则三点全消，且【不需要任何"谁创建的"记账】：
#   - TMP_DIR 由 setup_workdir 用 mktemp -d 创建并 chmod 700，
#     名字不可预测、目录私有 —— CWE-377 从根上不成立；
#   - 路径是【确定性的】，所有子 shell 算出同一对路径，无状态可丢；
#   - 清理就是 on_exit 里已有的 rm -rf "$TMP_DIR"，无需额外标记。
_ensure_http_tmp() {
  [ -n "$HTTP_HEADER_FILE" ] && return 0
  [ -n "${TMP_DIR:-}" ] || die "_ensure_http_tmp: TMP_DIR 未初始化（应先调用 setup_workdir）"
  HTTP_HEADER_FILE="$TMP_DIR/http-headers"
  HTTP_BODY_FILE="$TMP_DIR/http-body"
  return 0
}

# 响应体到 stdout；响应头写入 $HTTP_HEADER_FILE。
# body 传空字符串表示无请求体。
_http() { # <method> <url> <body> [extra curl args...]
  local method=$1 url=$2 body=$3
  shift 3
  _ensure_http_tmp
  local -a args=(-sS -X "$method" -D "$HTTP_HEADER_FILE" -o "$HTTP_BODY_FILE"
    --max-time 30 --retry 2 --retry-delay 2 "$@")
  [ -n "$body" ] && args+=(--data-binary "$body")
  # 必须先存 rc 再判断。写成 `if ! curl ...; then die "...（curl 退出码 $?）"`
  # 时 $? 是【取反后】的值（恒为 0），报错会打印"curl 退出码 0"，
  # 排障时会被这个假数字带偏。
  local rc=0
  curl "${args[@]}" "$url" >/dev/null || rc=$?
  if [ "$rc" -ne 0 ]; then
    # 变量后紧跟全角字符时必须写 ${}：UTF-8 locale 下 bash 会把全角字节
    # 当作变量名的一部分，`$url（` 会被解析成变量 `url（`，
    # set -u 下直接报 `url（: unbound variable` —— 真正的报错一个字都打不出来。
    # 本行三个变量统一用花括号形式。
    die "HTTP 请求失败：${method} ${url}（curl 退出码 ${rc}）"
  fi
  cat "$HTTP_BODY_FILE"
}

# 取响应头字段。无该头时输出空串。
http_header() { # <name>
  # 末尾的 `|| true` 不能省：头不存在时 grep 返回 1，pipefail 下整条管道为 1，
  # 于是 `KID=$(http_header Location)` 这类【赋值式命令替换】返回 1，
  # set -e 当场终止脚本 —— 而紧随其后的
  #   die "账号注册失败，未返回 Location 头"
  # 永远执行不到。同理 acme_nonce 的 die、以及 acme_post 里
  # `[ -n "$new_nonce" ]` 那个"响应没带头也可以容忍"的分支，全部变成死代码。
  # 本函数必须恒返回 0，把"没有这个头"表达成【空串】而不是【失败】。
  grep -i "^$1:" "$HTTP_HEADER_FILE" 2>/dev/null |
    tail -n1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n' || true
}

# ---------- ACME 协议层 ----------

ACME_DIR_JSON=""
ACME_NEW_NONCE=""
ACME_NEW_ACCOUNT=""
ACME_NEW_ORDER=""
NONCE=""
ACCOUNT_KID=""
ACCOUNT_KEY=""
# ACCOUNT_JSON 必须在这里初始化为空串，理由与 Task 5 的 CERT_URL 完全相同：
# 它在 derive_paths 里才被赋值，而 acme_new_account 会把它当作
# 【重定向目标】使用（> "$ACCOUNT_JSON"）—— set -u 下展开未赋值的变量
# 会让 bash 终止整个 shell，而且是在重定向阶段，报错位置极不直观。
# 声明为空串的目的是让 set -u 不报错，把失败留到真正使用处。
ACCOUNT_JSON=""

acme_dir() {
  [ -n "$ACME_DIR_JSON" ] && return 0
  ACME_DIR_JSON=$(_http GET "$ACME_DIRECTORY" "")
  ACME_NEW_NONCE=$(json_str "$ACME_DIR_JSON" newNonce)
  ACME_NEW_ACCOUNT=$(json_str "$ACME_DIR_JSON" newAccount)
  ACME_NEW_ORDER=$(json_str "$ACME_DIR_JSON" newOrder)
  [ -n "$ACME_NEW_ORDER" ] || die "ACME 目录解析失败，原始响应：$ACME_DIR_JSON"
}

acme_nonce() {
  _http HEAD "$ACME_NEW_NONCE" "" >/dev/null
  NONCE=$(http_header Replay-Nonce)
  [ -n "$NONCE" ] || die "未能获取 nonce"
}

# 发一次 JWS 请求，不做重试。响应体到 stdout，并用新的 Replay-Nonce 更新 NONCE。
# use_jwk=1 时用 jwk 字段（仅 new-account），否则用 kid 字段（其余全部请求）。
_acme_post_raw() { # <url> <payload> <use_jwk>
  local url=$1 payload=$2 use_jwk=${3:-0}
  local protected body resp

  if [ "$use_jwk" = 1 ]; then
    protected=$(printf '{"alg":"RS256","nonce":"%s","url":"%s","jwk":%s}' \
      "$NONCE" "$url" "$(jwk_json "$ACCOUNT_KEY")")
  else
    protected=$(printf '{"alg":"RS256","nonce":"%s","url":"%s","kid":"%s"}' \
      "$NONCE" "$url" "$ACCOUNT_KID")
  fi

  body=$(jws_build "$ACCOUNT_KEY" "$protected" "$payload")
  resp=$(_http POST "$url" "$body" -H "Content-Type: application/jose+json")

  local new_nonce
  new_nonce=$(http_header Replay-Nonce)
  [ -n "$new_nonce" ] && NONCE="$new_nonce"

  printf '%s' "$resp"
}

# nonce 只能使用一次，服务端偶尔会因为请求重放等原因判它失效。
# 失效时重取 nonce 并重试一次（RFC 8555 允许），仍失败才报错。
# 注意重试后的响应体必须原样返回，不能走 return —— return 只传退出码，会丢掉响应内容。
acme_post() { # <url> <payload> <use_jwk>
  local url=$1 payload=$2 use_jwk=${3:-0}
  local resp

  resp=$(_acme_post_raw "$url" "$payload" "$use_jwk")

  if printf '%s' "$resp" | grep -q 'badNonce'; then
    warn "nonce 失效，重取后重试一次"
    acme_nonce
    resp=$(_acme_post_raw "$url" "$payload" "$use_jwk")
    if printf '%s' "$resp" | grep -q 'badNonce'; then
      die "nonce 重取后仍然失效。原始响应：$resp"
    fi
  fi

  printf '%s' "$resp"
}

# 注册新账号，或复用已有的 account.json 里的 kid。
acme_new_account() {
  local payload='{"termsOfServiceAgreed":true'
  [ -n "${ACCOUNT_EMAIL:-}" ] && payload="$payload,\"contact\":[\"mailto:$ACCOUNT_EMAIL\"]"
  payload="$payload}"

  local resp
  resp=$(acme_post "$ACME_NEW_ACCOUNT" "$payload" 1)
  ACCOUNT_KID=$(http_header Location)
  [ -n "$ACCOUNT_KID" ] || die "账号注册失败，未返回 Location 头。响应：$resp"
  printf '{"kid":"%s"}' "$ACCOUNT_KID" > "$ACCOUNT_JSON"
  chmod 600 "$ACCOUNT_JSON"
  log "账号已注册：$ACCOUNT_KID"
}

# ---------- 域名与挑战 ----------

# 去掉通配符前缀。zone 探测、记录名计算都必须先做这一步。
normalize_domain() {
  printf '%s' "$1" | sed 's/^\*\.//'
}

# 挑战记录名。用完整 FQDN，Cloudflare API 接受完整名。
# 注意：*.example.com 与 example.com 都映射到 _acme-challenge.example.com，
# 但两者的 TXT 值不同，因此必须同时存在两条记录（边界情况 ①）。
challenge_record_name() {
  printf '_acme-challenge.%s' "$(normalize_domain "$1")"
}

# 从 authorization JSON 里取出 dns-01 挑战，输出 "token<TAB>challenge_url"。
acme_dns01_of() { # <authz-json>
  local authz=$1 obj tok url
  # 逐个顶层对象扫描，挑出 type 为 dns-01 的那个
  while IFS= read -r obj; do
    [ -z "$obj" ] && continue
    if [ "$(json_str "$obj" type)" = "dns-01" ]; then
      tok=$(json_str "$obj" token)
      url=$(json_str "$obj" url)
      printf '%s\t%s\n' "$tok" "$url"
      return 0
    fi
  done < <(json_flat_objects "$authz" challenges)
  return 1
}

# 这个 authorization 该怎么处置：
#   skip      —— 已 valid，不需要再建任何 TXT 记录
#   challenge —— pending，要走 dns-01 流程
#   invalid   —— 其他状态（含 invalid），调用方应报错退出
#
# 为什么需要 skip：Let's Encrypt 会【复用 30 天内已校验过的授权】，
# 新订单直接返回一个 valid 的 authorization，而不是新建 pending 的。
# 少了这个分支，--force 重跑（以及任何在授权有效期内重新下单）都会去挑挑战，
# 而 valid 的挑战带 validationRecord 嵌套对象 —— 越刚签发成功越容易撞上。
#
# status 必须取【顶层】的那个：challenges 里每个挑战也有自己的 status，
# 而 json_str 取的是第一个匹配。顶层 status 出现在 challenges 之前，所以安全；
# 真取错了会把 pending 的授权误判成 skip，挑战被整个跳过、finalize 必然失败。
authz_action() { # <authz-json>
  case "$(json_str "$1" status)" in
    valid)   printf 'skip\n' ;;
    pending) printf 'challenge\n' ;;
    *)       printf 'invalid\n' ;;
  esac
  return 0
}

# TXT 记录值 = b64url(sha256(keyAuthorization))，
# keyAuthorization = token + "." + thumbprint（RFC 8555 第 8.4 节）
acme_key_authz() { # <token>
  printf '%s.%s' "$1" "$(jwk_thumbprint "$ACCOUNT_KEY")" | sha256_b64url
}

# ---------- 订单 ----------

ORDER_URL=""
ORDER_FINALIZE=""
ORDER_AUTHZ_URLS=""
# acme_finalize 里赋值、acme_download_cert 里读取。
# 必须在文件作用域初始化为空：否则在 acme_finalize 之前直接调用
# acme_download_cert 会以 `CERT_URL: unbound variable` 中止。
CERT_URL=""

acme_new_order() {
  local identifiers="" d
  for d in "${DOMAINS[@]}"; do
    identifiers="$identifiers{\"type\":\"dns\",\"value\":\"$d\"},"
  done
  identifiers="${identifiers%,}"

  acme_dir
  acme_nonce
  ACME_NEW_ORDER=$(json_str "$ACME_DIR_JSON" newOrder)
  [ -n "$ACME_NEW_ORDER" ] || die "ACME 目录里没有 newOrder"

  local resp
  resp=$(acme_post "$ACME_NEW_ORDER" "{\"identifiers\":[$identifiers]}" 0)

  ORDER_URL=$(http_header Location)
  ORDER_FINALIZE=$(json_str "$resp" finalize)
  ORDER_AUTHZ_URLS=$(json_array_strings "$resp" authorizations)

  [ -n "$ORDER_URL" ] || die "下单失败，未返回 Location 头。响应：$resp"
  [ -n "$ORDER_FINALIZE" ] || die "下单响应里没有 finalize。响应：$resp"
  [ -n "$ORDER_AUTHZ_URLS" ] || die "下单响应里没有 authorizations。响应：$resp"
  log "订单已创建：$ORDER_URL"
}

acme_authz() { # <authz-url>
  acme_post "$1" "" 0
}

acme_trigger() { # <challenge-url>
  acme_post "$1" "{}" 0 >/dev/null
}

# 轮询 authorization 直到 valid。上限 60 次 × 3 秒 = 180 秒。
acme_poll_authz() { # <authz-url>
  local url=$1 i status resp
  for ((i = 1; i <= 60; i++)); do
    resp=$(acme_authz "$url")
    status=$(json_str "$resp" status)
    case "$status" in
      valid)
        return 0
        ;;
      invalid)
        # 把服务端给的原因完整打出来 —— 这是远程排查的唯一线索。
        # 原因嵌在 challenges[].error.detail 里，marker 必须是 '"error":'。
        # 不要用 '"problem"' —— 那是我最初凭印象编的 key，真实 ACME 响应里不存在，
        # 会让这里恒返回空、只能靠兜底碰巧拿到值。
        local problem
        problem=$(json_str_after "$resp" '"error":' detail)
        if [ -z "$problem" ]; then
          problem=$(json_str "$resp" detail)
        fi
        die "授权校验失败（${url}）：${problem:-无详细信息}。原始响应：$resp"
        ;;
      *)
        sleep 3
        ;;
    esac
  done
  die "授权校验超时（${url}），最后状态：$status"
}

# ---------- CSR 与证书 ----------

# 用临时 openssl.cnf 生成带 SAN 的 CSR。
# 不用 -addext：CentOS 7 自带的 openssl 1.0.2 不支持它，而该版本仍很常见。
make_csr() { # <key-path> <out-der-path> <domain...>
  local key=$1 out=$2
  shift 2
  local cnf san="" d
  cnf=$(mktemp)
  for d in "$@"; do
    san="$san,DNS:$d"
  done
  san="${san#,}"

  cat > "$cnf" <<EOF
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = $(normalize_domain "$1")
[ext]
subjectAltName = $san
EOF

  # openssl 的 stderr 被吞掉了，所以必须显式检查退出码。
  # 少了这一步，在 set -e 下它的失败会直接终止脚本 ——
  # 于是 rm -f "$cnf" 不执行（临时 cnf 泄漏在 TMPDIR 里），
  # 下面那句 die 成为死代码：用户看不到任何解释，只有静默退出。
  local rc=0
  openssl req -new -key "$key" -config "$cnf" -outform DER -out "$out" 2>/dev/null || rc=$?
  rm -f "$cnf"
  if [ "$rc" -ne 0 ]; then
    die "CSR 生成失败（openssl 退出码 ${rc}）。请确认密钥 ${key} 可读、且是 RSA 私钥。"
  fi
  [ -s "$out" ] || die "CSR 生成为空文件：$out"
}

acme_finalize() { # <csr-der-path>
  local csr_b64 resp status i
  csr_b64=$(b64url_file "$1")
  resp=$(acme_post "$ORDER_FINALIZE" "{\"csr\":\"$csr_b64\"}" 0)

  # finalize 后订单进入 processing，需要轮询到 valid 才能取证书。
  #
  # ★ 顺序很关键：每次 fetch 之后【立刻】读 status。
  # 原写法把 status 读在循环顶部、resp 刷新在底部，于是最后一次 fetch
  # 的结果永远不会被检查 —— 若订单恰在那时变成 valid，循环退出后
  # status 仍是上一轮的值，会被误判为"订单未在超时前完成"而 die，
  # 尽管证书其实已经就绪。
  # 窗口只有最后一次 sleep 的 3 秒，概率低，但后果是一次假的致命失败，
  # 且报错（"未在超时前完成"）会把排查方向完全带偏。
  status=$(json_str "$resp" status)
  for ((i = 1; i <= 60; i++)); do
    if [ "$status" = "valid" ]; then
      break
    fi
    if [ "$status" = "invalid" ]; then
      die "订单处理失败。原始响应：$resp"
    fi
    sleep 3
    resp=$(acme_post "$ORDER_URL" "" 0)
    status=$(json_str "$resp" status)
  done
  if [ "$status" != "valid" ]; then
    die "订单未在超时前完成，最后状态：$status"
  fi

  CERT_URL=$(json_str "$resp" certificate)
  # 有些实现把 certificate 放在重新拉取订单后才出现
  if [ -z "$CERT_URL" ]; then
    resp=$(acme_post "$ORDER_URL" "" 0)
    CERT_URL=$(json_str "$resp" certificate)
  fi
  [ -n "$CERT_URL" ] || die "订单已完成但未返回 certificate URL。响应：$resp"
}

acme_download_cert() {
  acme_post "$CERT_URL" "" 0
}

# ---------- Cloudflare DNS ----------

CF_API="https://api.cloudflare.com/client/v4"
CF_ZONE_CACHE=""   # 形如 "sub.example.com=zone_id:zone_name" 的换行分隔列表
# cf_find_zone 的结果。写在全局量里而不是经 stdout 返回 ——
# 原因见该函数的注释（命令替换会让缓存失效）。
CF_ZONE_ID=""
CF_ZONE_NAME=""

cf_api() { # <method> <path-or-url> <body>
  local method=$1 path=$2 body=$3
  local url="$CF_API$path"
  case "$path" in https://*) url="$path" ;; esac

  local args=(-H "Authorization: Bearer $CF_API_TOKEN"
    -H "Content-Type: application/json")
  local resp
  resp=$(_http "$method" "$url" "$body" "${args[@]}")

  # 失败时把 Cloudflare 的完整错误列表打出来，不吞掉服务端信息
  if ! printf '%s' "$resp" | grep -q '"success":true'; then
    local errs
    errs=$(json_str "$resp" message)
    die "Cloudflare API 失败（$method ${path}）：${errs:-无消息}。原始响应：$resp"
  fi
  printf '%s' "$resp"
}

# 由具体到宽泛输出 zone 候选：a.b.example.com → b.example.com → example.com
cf_zone_candidates() { # <domain>
  local d
  d=$(normalize_domain "$1")
  while [ "$(printf '%s' "$d" | tr -cd '.' | wc -c | tr -d ' ')" -ge 1 ]; do
    printf '%s\n' "$d"
    d="${d#*.}"
  done
}

# 逐层回退查找 zone。结果写入 CF_ZONE_ID / CF_ZONE_NAME（全局量），
# 【不通过 stdout 返回】。
#
# ★ 为什么不能用 stdout 返回
#
# 本函数会把探测结果写进 CF_ZONE_CACHE，以便同一次运行内不重复探测。
# 但唯一自然的取用方式 `zone=$(cf_find_zone ...)` 会把函数放进子 shell，
# 于是它对 CF_ZONE_CACHE 的更新在父 shell 里丢失 —— 缓存退化成死优化，
# 每个域名都重新探测一遍（实测：直接调用第二次增量 0 次请求，
# $( ) 调用第二次增量 2 次请求）。
#
# 更麻烦的是这类缺陷会被测试掩盖：测试若用直接调用去验缓存，
# 它会通过，而真实代码里的缓存从未生效过。所以这里改成写全局量，
# 调用方必须【直接调用、不要包 $( )】。
cf_find_zone() { # <domain>
  local d cand cached

  d=$(normalize_domain "$1")

  # 先查缓存（按原始域名匹配）。
  # 末尾的 `|| true` 不能省：缓存为空时 grep 无匹配返回 1，
  # pipefail 下整条管道即为 1，于是赋值语句返回 1 ——
  # 而"缓存为空"正是每次运行的初始状态，set -e 会当场终止脚本。
  cached=$(printf '%s\n' "$CF_ZONE_CACHE" | grep "^$d=" | head -n1) || true
  if [ -n "$cached" ]; then
    CF_ZONE_ID=$(printf '%s' "${cached#*=}" | cut -d: -f1)
    CF_ZONE_NAME=$(printf '%s' "${cached#*=}" | cut -d: -f2)
    return 0
  fi

  while IFS= read -r cand; do
    [ -z "$cand" ] && continue
    local resp zid zname
    # cf_api 失败时会 die（exit）。它跑在 $() 里，所以 exit 只终结那个
    # 子 shell，本函数会若无其事地继续试下一个候选，最后以
    #   "找不到域名 X 对应的 Cloudflare zone"
    # 收尾 —— 把"Token 无效 / 权限不足"误导成"域名不在 Cloudflare 上"，
    # 排查方向整个跑偏。这里显式接住并向上传播，
    # 让 cf_api 打出的真实原因成为用户看到的最后一条消息。
    if ! resp=$(cf_api GET "/zones?name=$cand&status=active" ""); then
      return 1
    fi
    zid=$(json_str_after "$resp" '"result":' id)
    if [ -n "$zid" ]; then
      zname=$(json_str_after "$resp" '"result":' name)
      CF_ZONE_CACHE="$CF_ZONE_CACHE$d=$zid:$zname
"
      CF_ZONE_ID="$zid"
      CF_ZONE_NAME="$zname"
      return 0
    fi
  done < <(cf_zone_candidates "$d")

  die "找不到域名 ${1} 对应的 Cloudflare zone。请确认该域名已托管在 Cloudflare 账号下，且 Token 有 Zone:Zone:Read 权限。"
}

# 创建 TXT 记录，返回记录 id。
# TTL 用 120 秒（Cloudflare 允许的最小值），加快生效与过期。
cf_add_txt() { # <zone-id> <fqdn> <value>
  local zone=$1 name=$2 value=$3
  local payload
  payload=$(printf '{"type":"TXT","name":"%s","content":"%s","ttl":120}' "$name" "$value")
  local resp rid
  resp=$(cf_api POST "/zones/$zone/dns_records" "$payload")
  rid=$(json_str_after "$resp" '"result":' id)
  [ -n "$rid" ] || die "创建 TXT 记录失败，未返回 id。响应：$resp"
  log "已创建 TXT 记录 $name (id=$rid)"
  printf '%s' "$rid"
}

# 按记录 id 精确删除。绝不按名字删 —— 该名字下可能有其他服务商的记录（边界情况 ②）。
# 清理路径上的失败只告警，不中断，否则会掩盖真正的错误原因。
cf_del_txt() { # <zone-id> <record-id>
  local zone=$1 rid=$2
  [ -z "$rid" ] && return 0
  if cf_api DELETE "/zones/$zone/dns_records/$rid" "" >/dev/null 2>&1; then
    log "已删除 TXT 记录 id=$rid"
  else
    warn "删除 TXT 记录 id=$rid 失败，请手动检查 Cloudflare 控制台"
  fi
  return 0
}

# ---------- DNS 传播检测（走 DoH，不需要 dig）----------

# 返回 0 表示该值已在 DNS 中可见。
doh_txt_visible() { # <fqdn> <value>
  local fqdn=$1 value=$2 resp
  resp=$(_http GET \
    "https://cloudflare-dns.com/dns-query?name=$fqdn&type=TXT" "" \
    -H "accept: application/dns-json" 2>/dev/null) || return 1
  # DoH 返回的 TXT 值带引号，直接做子串匹配即可。
  #
  # `--` 不能省：base64url 的字母表含 `-`，challenge 值可能以它开头
  # （SHA-256 摘要的 base64url 首字符在 64 个符号上均匀分布，约 1/64）。
  # 那样 grep 会把值当成【选项】解析，后果取决于 `-` 后面是什么字母：
  #
  #   值以 -V 开头   → 被当成 --version，打印版本号并返回 0
  #                    ★ 最危险：本函数会报告"记录已生效"，而记录其实不在。
  #                      脚本据此提前触发 ACME 校验，必然失败并白烧一次配额。
  #   值以 -X -a -t 等开头 → "invalid option" / "no search PATTERN"，返回 2
  #                    拿不到结果，还把一段 usage 喷进日志。
  #
  # 实测确认：`-VISIBLE` → rc=0（假阳性），`-XYZabc`/`-abc`/`-test` → rc=2。
  # 这是"随机失败"型缺陷：约 3% 的签发撞上，其余时候一切正常，
  # 所以只靠手工试跑几乎不可能发现。
  printf '%s' "$resp" | grep -qF -- "$value"
}

# 轮询直到记录可见。超时则 die —— 绝不"等不及了直接触发校验"，
# 那只会白白消耗一次失败配额，且同样会失败。
wait_dns_visible() { # <fqdn> <value>
  local fqdn=$1 value=$2 i
  local max=$(( ${DNS_WAIT_TIMEOUT:-120} / 2 ))
  log "等待 DNS 生效：$fqdn"
  for ((i = 1; i <= max; i++)); do
    if doh_txt_visible "$fqdn" "$value"; then
      log "DNS 已生效：$fqdn"
      return 0
    fi
    sleep 2
  done
  die "等待 DNS 生效超时（${DNS_WAIT_TIMEOUT:-120} 秒）：${fqdn}。请检查 Cloudflare 记录是否创建成功。"
}

# ---------- 配置与路径 ----------

BASE_DIR="${LE_DNS_BASE:-/etc/le-dns}"
LE_ENV=""
CONF_FILE=""
CONF_OVERRIDE=""
DOMAIN_ARGS=""
CMD=""
FORCE=0
DOMAINS=()
ACCOUNT_EMAIL=""
CF_API_TOKEN=""
RELOAD_CMD=""
RENEW_BEFORE_DAYS=30
DNS_WAIT_TIMEOUT=120
KEY_TYPE="rsa2048"
# CERT_ROOT 是环境级根目录（由 derive_paths 设置）；
# CERT_DIR 是具体的证书目录 = CERT_ROOT/<主域名>（由 set_cert_dir 设置）。
# 分开两步的原因：主域名来自 DOMAINS，而 DOMAINS 来自配置，
# 而 derive_paths 只管环境、不读配置内容。
CERT_ROOT=""
CERT_DIR=""

# 环境由 --staging 一个开关决定，同时推导出全部路径。
# 这样"配置指向 staging 但忘了加 --staging"的错配在结构上不可能发生。
derive_paths() {
  case "$LE_ENV" in
    staging)
      CONF_FILE="$BASE_DIR/le-dns-staging.conf"
      ACCOUNT_KEY="$BASE_DIR/accounts/staging/account.key"
      ACCOUNT_JSON="$BASE_DIR/accounts/staging/account.json"
      CERT_ROOT="$BASE_DIR/certs/staging"
      LOG_FILE="$BASE_DIR/logs/le-dns-staging.log"
      ACME_DIRECTORY="https://acme-staging-v02.api.letsencrypt.org/directory"
      IS_STAGING=1
      ;;
    *)
      LE_ENV="production"
      CONF_FILE="$BASE_DIR/le-dns.conf"
      ACCOUNT_KEY="$BASE_DIR/accounts/production/account.key"
      ACCOUNT_JSON="$BASE_DIR/accounts/production/account.json"
      CERT_ROOT="$BASE_DIR/certs/production"
      LOG_FILE="$BASE_DIR/logs/le-dns.log"
      ACME_DIRECTORY="https://acme-v02.api.letsencrypt.org/directory"
      IS_STAGING=0
      ;;
  esac
  # 命令行的 -c 只覆盖路径，不改变环境归属。
  #
  # 写 if 比 `[ -n "$CONF_OVERRIDE" ] && CONF_FILE=...` 可读，但【真正保证
  # set -e 下不中断的是下面那句 return 0】—— 全局约束禁的是"函数体以 && 结尾"，
  # 而这里的 && 后面还有 return 0，两种写法其实都安全。
  # 别把功劳记在 if 上：照着"if 才是承重的"去顺手删掉那句 return 0，
  # 函数就真的会在没有 -c 时返回 1，调用方当场终止。
  if [ -n "$CONF_OVERRIDE" ]; then
    CONF_FILE="$CONF_OVERRIDE"
  fi
  return 0
}

# 证书目录 = 环境根目录 + 主域名，见设计文档第 4 节：
#   certs/<env>/<主域名>/{fullchain,cert,chain,privkey}.pem
# 主域名取 DOMAINS 的第一个，去掉 *. 前缀。
#
# 必须在 load_config 之后调用 —— 主域名来自 DOMAINS，而 DOMAINS 来自配置文件。
# 这正是它与 derive_paths 分开的原因：derive_paths 只管环境，不读配置。
set_cert_dir() {
  local primary=""
  # 用 ${#DOMAINS[@]} 而不是直接取 [0]：空数组下索引访问在
  # bash 3.2 + set -u 时会以 unbound variable 中止。
  if [ "${#DOMAINS[@]}" -gt 0 ]; then
    primary=$(normalize_domain "${DOMAINS[0]}")
  fi
  [ -n "$primary" ] || die "无法从 DOMAINS 推导主域名（DOMAINS 为空？）"
  CERT_DIR="$CERT_ROOT/$primary"
  return 0
}

parse_args() {
  # 每次调用先把自己的输出量全部复位。
  #
  # 生产里 parse_args 每个进程只调一次，不复位也看不出问题；但这些都是
  # 全局量，同一个 shell 里第二次调用会【继承上一次的结果】：
  #   parse_args --check  然后  parse_args       → CMD 仍是 check
  #   parse_args issue --force  然后  parse_args --check
  #                        → FORCE 残留成 1，撞上下面的 --force 校验而 die
  # 实测踩过（test_functions_survive_set_e 就是这么挂的）。
  # 函数的输出不该取决于"上一次谁调用过它"。
  LE_ENV="production"
  CMD=""
  FORCE=0
  CONF_OVERRIDE=""
  DOMAIN_ARGS=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --staging) LE_ENV="staging" ;;
      --force)   FORCE=1 ;;
      --check)   CMD="check" ;;
      --init)    CMD="init" ;;
      --install-cron) CMD="install-cron" ;;
      --help|-h) CMD="help" ;;
      -d)
        shift
        [ $# -gt 0 ] || die "-d 后面缺少域名"
        DOMAIN_ARGS="$DOMAIN_ARGS${DOMAIN_ARGS:+ }$1"
        ;;
      -c)
        shift
        [ $# -gt 0 ] || die "-c 后面缺少配置文件路径"
        CONF_OVERRIDE=$1
        ;;
      issue) CMD="issue" ;;
      *) die "未知参数：$1（用 --help 查看用法）" ;;
    esac
    shift
  done
  # 同 derive_paths：承重的是下面那句 return 0，不是这个 if。
  # 但要留意这里的后果比 derive_paths 严重得多 ——
  # 若写成 `[ -z "$CMD" ] && CMD="issue"` 并【删掉 return 0】，
  # 只要子命令已给出（如 `renew`）条件就为假、函数返回 1，
  # `le-dns.sh renew` 会在 set -e 下当场终止：而这正是 cron 每天调用的命令。
  if [ -z "$CMD" ]; then
    CMD="issue"
  fi
  # --force 只在 issue 下有意义（--check / --init / --install-cron 都不签发）。
  #
  # 必须显式拒绝，不能静默忽略 —— "开关被悄悄吃掉"是本项目最忌讳的一类缺陷：
  # 用户以为已经强制过了，实际走的是另一条路，且没有任何提示。
  #
  # 注意 ${CMD} 的花括号：后面紧跟全角「」，裸写 $CMD 会让 bash 把全角字节
  # 并进变量名，set -u 下直接 unbound variable，报错一个字都打不出来。
  if [ "$FORCE" = 1 ] && [ "$CMD" != "issue" ]; then
    die "--force 只能配合 issue 使用（当前命令：${CMD}）。例如：le-dns.sh issue --force"
  fi
  return 0
}

check_config_perms() { # <path>
  local f=$1 mode
  [ -f "$f" ] || die "配置文件不存在：$f"
  mode=$(file_mode "$f")
  if [ "$mode" != "600" ]; then
    die "配置文件权限过宽（当前 ${mode}），会泄露 Cloudflare Token。请执行：chmod 600 $f"
  fi
}

load_config() { # <path>
  check_config_perms "$1"

  # 拒绝 CRLF 行尾的配置文件。
  #
  # 在 Windows 上编辑过、或从别处拷贝来的配置文件常常是 CRLF，
  # 而 shell 的赋值会把行尾的 \r 一起留下：
  #   DOMAINS="a.com *.a.com"  →  第二个域名变成 "*.a.com\r"
  # 于是挑战记录名成为 "_acme-challenge.a.com\r" ——
  # Cloudflare 那边会建一条名字带回车符的记录，ACME 永远校验不过，
  # 而玩家看到的是"授权超时"，记录名在终端里看起来还完全正常。
  # 这属于最难排查的一类：不报错、只是结果错。
  #
  # 直接拒绝并给出修复命令，比让它静默跑错好。
  if LC_ALL=C grep -q $'\r' "$1" 2>/dev/null; then
    # ★ 修复建议必须【跨平台可用】，不能写 `sed -i`。
    #
    # BSD sed 的 -i 需要一个 extension 参数，`sed -i 's/\r$//' f` 在 macOS 上
    # 直接报错（实测：sed: 1: "...": command c expects \ followed by text，rc=1），
    # GNU sed 上却正常。而 macOS 恰恰是 CRLF 配置最常见的来源（跨平台拷贝/编辑），
    # 于是唯一给出的指引在它最该起作用的那个平台上恰好是坏的。
    # 用 tr 重定向：GNU 与 BSD 行为一致，不涉及任何 -i 方言。
    die "配置文件含 CRLF 行尾：${1}。请先转换：tr -d '\\r' < ${1} > ${1}.new && mv ${1}.new ${1}"
  fi

  # shellcheck disable=SC1090
  . "$1"

  [ -n "${CF_API_TOKEN:-}" ] || die "配置里 CF_API_TOKEN 为空。请在 Cloudflare 后台创建一个带 Zone:Zone:Read + Zone:DNS:Edit 权限的 Token 并填入 $1"

  case "${KEY_TYPE:-rsa2048}" in
    rsa2048) KEY_BITS=2048 ;;
    rsa4096) KEY_BITS=4096 ;;
    *) die "不支持的 KEY_TYPE：${KEY_TYPE}（只能是 rsa2048 或 rsa4096）" ;;
  esac

  # 命令行 -d 覆盖配置里的 DOMAINS
  local domain_list
  if [ -n "$DOMAIN_ARGS" ]; then
    domain_list="$DOMAIN_ARGS"
  else
    domain_list="${DOMAINS:-}"
  fi
  [ -n "$domain_list" ] || die "没有指定域名。用 -d example.com 指定，或在 $1 里设置 DOMAINS。"

  # 分词前必须关掉 pathname expansion。
  #
  # DOMAINS=($domain_list) 是【不加引号】的分词，所以通配符会被 cwd 下的
  # 同名文件展开：配置里写的是 "example.com *.example.com"，
  # 若当前目录里恰好有个 mail.example.com，DOMAINS 就变成
  #   example.com mail.example.com
  # —— 通配符域名静默消失，订单里多出一个不该有的域名。
  # 已实测复现（cwd 下建一个 mail.example.com 文件即可）。
  #
  # 后果不是报错而是「签错域名」：证书不覆盖 *.example.com，
  # 而失败会以 rejectedIdentifier 的形式出现在 ACME 那边，
  # 指向「这个域名不属于你」，完全指不到真正的原因。
  # cron 的 cwd 是 /，通常没有匹配文件 —— 这正是它靠运气工作的原因，
  # 而手工执行时 cwd 是用户当前目录。
  set -f
  # shellcheck disable=SC2206
  DOMAINS=($domain_list)
  set +f
  RENEW_BEFORE_DAYS="${RENEW_BEFORE_DAYS:-30}"
  DNS_WAIT_TIMEOUT="${DNS_WAIT_TIMEOUT:-120}"
}

# 创建【环境级】目录。
#
# 注意这里建的是 CERT_ROOT 而不是 CERT_DIR：证书目录分两级，
#   CERT_ROOT —— 环境级（certs/production），--init 时就该存在
#   CERT_DIR  —— 含主域名（certs/production/example.com），只有读到
#                DOMAINS 之后才能算出来
# 而 --init 的职责正是【生成】配置文件，那时还没有 DOMAINS，
# 传 CERT_DIR 会得到空字符串，mkdir 报 "mkdir: : No such file or directory"
# 并且 certs 根本不会被创建。
ensure_dirs() {
  mkdir -p "$(dirname "$ACCOUNT_KEY")" "$CERT_ROOT" "$(dirname "$LOG_FILE")"
  # 账号目录里放的是 ACME 账号私钥。mkdir -p 建出来的默认是 755，
  # 所以这一步失败时【目录会停在 755】—— 而 `|| true` 会把这件事
  # 完全咽掉：日志里没有痕迹，日后排查权限问题时只能靠猜。
  # 收紧权限失败不致命（脚本仍能跑），但必须留下可见记录。
  chmod 700 "$(dirname "$ACCOUNT_KEY")" 2>/dev/null ||
    warn "无法把账号目录权限收紧到 700：$(dirname "$ACCOUNT_KEY")"
  return 0
}

# 创建具体证书目录。必须在 set_cert_dir 之后调用。
ensure_cert_dir() {
  [ -n "$CERT_DIR" ] || die "CERT_DIR 为空 —— 是否忘了先调用 set_cert_dir？"
  mkdir -p "$CERT_DIR"
  return 0
}

# ---------- --init 与 --check ----------

cmd_init() {
  derive_paths
  local conf="$CONF_FILE"
  ensure_dirs

  if [ -f "$conf" ]; then
    warn "配置文件已存在，不覆盖：$conf"
  else
    cat > "$conf" <<'EOF'
# le-dns 配置。权限必须是 600。
#
# 要申请证书的域名，空格分隔。第一个作为证书目录名。
# 通配符必须加引号，否则 shell 会展开星号。通配符和裸域建议一起申请，
# 这样 *.example.com 和 example.com 会被合并进同一张证书。
DOMAINS="example.com *.example.com"

# Cloudflare API Token。需要 Zone:Zone:Read 和 Zone:DNS:Edit 权限。
# 在 Cloudflare 后台 My Profile > API Tokens > Create Token 创建。
CF_API_TOKEN=""

# 证书更新成功后执行的命令，留空则不执行。
# 测试环境同样执行这一条 —— 两个环境的配置各写各的，
# 例如测试环境可以写 `systemctl reload nginx-staging`，或留空。
RELOAD_CMD="systemctl reload nginx"

# 提前多少天续期。
RENEW_BEFORE_DAYS=30

# 单条 DNS 记录生效的等待上限（秒）。
DNS_WAIT_TIMEOUT=120

# 证书密钥类型：rsa2048 或 rsa4096。
KEY_TYPE=rsa2048

# 联系邮箱，注册 ACME 账号用，可留空。
ACCOUNT_EMAIL=""
EOF
    chmod 600 "$conf"
    log "已生成配置模板：$conf"
  fi
  log "请编辑 $conf 填入域名与 Cloudflare Token，然后运行 --check 自检。"
}

cmd_check() {
  derive_paths
  local ok=0

  printf '\n===== le-dns 环境自检（%s）=====\n\n' "$LE_ENV"

  printf '依赖命令：\n'
  local c
  for c in curl openssl bash; do
    if command -v "$c" >/dev/null 2>&1; then
      printf '  [ok]   %s\n' "$c"
    else
      printf '  [缺失] %s\n' "$c"
      ok=1
    fi
  done
  printf '  le-dns 版本：%s\n' "$LE_DNS_VERSION"
  printf '  bash 版本：%s\n' "$BASH_VERSION"
  printf '  openssl：%s\n' "$(openssl version 2>/dev/null)"

  printf '\n配置文件：\n'
  if [ -f "$CONF_FILE" ]; then
    printf '  [ok]   %s\n' "$CONF_FILE"
    local mode
    mode=$(file_mode "$CONF_FILE")
    if [ "$mode" = "600" ]; then
      printf '  [ok]   权限 %s\n' "$mode"
    else
      printf '  [错误] 权限为 %s，必须是 600\n' "$mode"
      ok=1
    fi
  else
    printf '  [错误] 不存在：%s（先运行 --init）\n' "$CONF_FILE"
    ok=1
    printf '\n自检未通过。\n\n'
    return 1
  fi

  printf '\nCloudflare API：\n'
  if [ "$ok" -eq 0 ]; then
    # shellcheck disable=SC1090
    . "$CONF_FILE"
    if [ -n "${CF_API_TOKEN:-}" ]; then
      printf '  [ok]   Token 已配置（长度 %s）\n' "${#CF_API_TOKEN}"
      local resp
      if resp=$(cf_api GET "/zones?per_page=1" "" 2>&1); then
        local zname
        zname=$(json_str_after "$resp" '"result":' name)
        printf '  [ok]   Token 可用，可见 zone 示例：%s\n' "${zname:-（无 zone）}"
      else
        printf '  [错误] Token 不可用\n'
        # cf_api 的失败原因被 2>&1 捕在 resp 里，不能就这么丢掉。
        # --check 是远程排查的唯一线索：把 Token 无效 / 缺 Zone:Zone:Read /
        # 被限流 全部归成同一句"Token 不可用"，用户拿不到任何可操作的信息。
        #
        # ★ 必须打【全部】捕获行，不能只取最后一行。
        # curl 失败时捕获到的是两行：第一行是 _http 的
        #   "HTTP 请求失败：GET ...（curl 退出码 7）"  ← 真正的根因
        # 最后一行是 cf_api 的 "Cloudflare API 失败：...原始响应：" ——
        # 而 curl 失败时响应体是空的，那句话没有任何信息量。
        # 只取末行恰好把根因扔掉，等于白修（这个坑是本条修复自身引入的）。
        if [ -n "$resp" ]; then
          printf '         服务端返回：\n'
          printf '%s\n' "$resp" | sed 's/^/           /'
        fi
        ok=1
      fi
    else
      printf '  [错误] CF_API_TOKEN 为空\n'
      ok=1
    fi

    printf '\nDNS over HTTPS（用于检测记录是否生效）：\n'
    # ★ 必须把 _http 包在 () 里。
    #
    # _http 在 curl 失败时会 die（即 exit），而 exit 在 if 条件里
    # 【不会被抑制】—— 直接调用会让脚本当场终止，下面那个"不可达"的
    # else 分支永远执行不到。而"端点不可达"恰恰是本段要报告的情况，
    # 也正是 --check 存在的意义：它在用户网络不通时给出可操作的提示。
    # 结果会变成：打印完标题就没了下文，用户完全无从判断哪里出了问题。
    #
    # 这与 doh_txt_visible 里 `resp=$(_http ...) || return 1` 是同一个道理：
    # $(...) 创建的子 shell 把 exit 关在里面，返回码才能正常传出。
    if ( _http GET "https://cloudflare-dns.com/dns-query?name=example.com&type=A" "" \
        -H "accept: application/dns-json" >/dev/null 2>&1 ); then
      printf '  [ok]   可达\n'
    else
      printf '  [错误] 不可达（检查出网与防火墙）\n'
      ok=1
    fi
  fi

  printf '\n'
  if [ "$ok" -eq 0 ]; then
    printf '自检通过。\n\n'
    if [ "$IS_STAGING" = 1 ]; then
      printf '当前是测试环境。可以用下面的命令试跑：\n'
      printf '  %s --staging -d example.com -d "*.example.com"\n\n' "$0"
      printf '测试环境配额宽松，可反复执行。签出的证书不被浏览器信任，属正常现象。\n\n'
    else
      printf '当前是生产环境。注意：同一组域名每周只有 5 张证书配额。\n'
      printf '首次签发前建议先用 --staging 把流程跑通。\n\n'
    fi
    return 0
  fi
  printf '自检未通过，请先解决上面标为 [错误] 的项目。\n\n'
  return 1
}

# ---------- 业务层 ----------

# 已创建但尚未清理的 DNS 记录，形如 "zone_id:record_id" 的换行分隔列表。
CF_RECORDS=""
# 注：CF_ZONE_ID / CF_ZONE_NAME 已在 Task 6 的 Cloudflare 层声明为空串，
# 这里不再重复声明 —— 同一个全局量有两处初值就是两份真相，
# 日后改一处忘另一处不会被任何测试发现。

# 中间产物目录（CSR、证书链）与域名私钥路径。
# 由 setup_workdir 创建，main 里挂 trap 统一清理。
TMP_DIR=""
CERT_PRIVKEY_NEW=""

setup_workdir() {
  [ -n "$TMP_DIR" ] && { CERT_PRIVKEY_NEW="$TMP_DIR/domain.key"; return 0; }
  TMP_DIR=$(mktemp -d)
  chmod 700 "$TMP_DIR"
  CERT_PRIVKEY_NEW="$TMP_DIR/domain.key"
  return 0
}

# 唯一的退出清理入口。
# trap 是覆盖语义 —— 后设的会顶掉先设的，所以全脚本只能有一个 EXIT trap，
# 需要清理的东西都必须集中在这个函数里。
# 两部分都是幂等的：cleanup_records 清空后重复调用无副作用；
# 脚本正常跑完时中间产物已无用，一并删掉。
on_exit() {
  cleanup_records
  # HTTP 中转文件（$TMP_DIR/http-headers、$TMP_DIR/http-body）随
  # TMP_DIR 一起删掉，不需要单独处理，也不需要"谁创建的"这类标记。
  # 测试把 HTTP_HEADER_FILE 指向自己的中转文件时，它不在 TMP_DIR 里，
  # 这一行也不会碰它。
  [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"
  return 0
}

# 返回 0 表示需要续期。
#
# ★ 必须取反，不能直接返回 openssl 的状态。
#
# openssl -checkend 的语义是"在指定秒数内不会过期"：
#   返回 0 = 还够用（不需要续期）
#   返回 1 = 文件不存在 / 格式损坏 / 即将过期（需要续期）
# 而本函数的契约恰好相反（0 = 需要续期）。
#
# 不取反的后果极其严重：cmd_issue_checked 会把"证书还很新"判成"需要续期"，
# 于是 cron 每天签发一张新证书 —— Let's Encrypt 对同一组域名限制
# 每周 5 张重复证书，一周内即耗尽配额，之后所有续期请求全部失败。
# 而那时证书仍在有效期内，问题不会立刻显现，等到真正需要续期时
# 才发现已经签不出来了。
#
# 顺带一提：-checkend 把"文件不存在""格式损坏""即将过期"三种情况
# 都归为返回 1，所以取反后只需要一个分支，不必分别判断存在性和格式。
renew_needed() { # <cert-path>
  local cert=$1
  if openssl x509 -in "$cert" -checkend $(( ${RENEW_BEFORE_DAYS:-30} * 86400 )) -noout >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

# 把证书链拆成四个文件并原子写入。
# 先写 .tmp 再 mv：避免 nginx 在 reload 时读到写了一半的 fullchain。
write_certs_atomic() { # <dir> <chain-pem-path> <key-path>
  local dir=$1 chain=$2 key=$3
  local tmp
  tmp=$(mktemp -d "$dir/.tmp.XXXXXX")
  local tmpd="$tmp"

  # 预创建两个文件。awk 的 `print > file` 只在真正写入时才创建文件，
  # 若证书链只有叶子（没有中间证书），chain.pem 根本不会存在，
  # 后续的 cat 与 mv 都会以 "No such file or directory" 失败并触发 set -e。
  # 先建空文件既保证存在性，也让"无中间证书"这个语义正确表现为空文件
  # （nginx 的 ssl_trusted_certificate 指向空文件是合法的）。
  # 注：Let's Encrypt 目前总返回叶子+中间两级，所以这是对服务端行为的
  # 防御性处理，而非现存故障 —— 但把它写成对 LE 当前行为的隐性依赖不值得。
  : > "$tmpd/cert.pem"
  : > "$tmpd/chain.pem"

  # 用 awk 按证书块切分：第 1 块是叶子，其余是中间链
  awk -v leaf="$tmpd/cert.pem" -v rest="$tmpd/chain.pem" '
    /-----BEGIN CERTIFICATE-----/ { n++ }
    { if (n <= 1) print > leaf; if (n >= 2) print > rest }
  ' "$chain"

  cat "$tmpd/cert.pem" "$tmpd/chain.pem" > "$tmpd/fullchain.pem"
  cp "$key" "$tmpd/privkey.pem"

  [ -s "$tmpd/fullchain.pem" ] || { rm -rf "$tmpd"; die "证书链为空，拒绝写盘"; }
  [ -s "$tmpd/cert.pem" ] || { rm -rf "$tmpd"; die "未能从证书链中切出叶子证书"; }

  chmod 644 "$tmpd/fullchain.pem" "$tmpd/cert.pem" "$tmpd/chain.pem"
  chmod 600 "$tmpd/privkey.pem"

  local f
  for f in fullchain.pem cert.pem chain.pem privkey.pem; do
    mv -f "$tmpd/$f" "$dir/$f"
  done
  rmdir "$tmpd"
  log "证书已写入 $dir"
}

# 执行 RELOAD_CMD。两个环境都会执行 —— 命令来自各自的配置文件：
# 测试环境做什么由 le-dns-staging.conf 决定（可以是一条空操作，
# 也可以是重启测试用的服务）。
#
# 环境隔离靠的是路径两两不相交（staging 绝不碰生产目录），不是靠跳过 reload。
# 反过来，跳过它还有代价：测试环境里那条 reload 永远不会被执行到，
# 而它恰恰是最容易配错、也最容易在真实续期时炸掉的一步。
run_reload() {
  [ -n "${RELOAD_CMD:-}" ] || { log "未配置 RELOAD_CMD，跳过"; return 0; }
  log "执行 reload 命令：$RELOAD_CMD"
  if ! sh -c "$RELOAD_CMD"; then
    # reload 失败不影响证书已经正确写盘这一事实，只告警
    warn "reload 命令执行失败，请手动检查服务状态"
  fi
  return 0
}

# 清理本次运行创建的全部 TXT 记录。
# 只按记录 id 删，绝不按名字删（边界情况 ②）。
# 幂等：可以重复调用，trap EXIT 与显式调用都走这里。
cleanup_records() {
  [ -z "${CF_RECORDS:-}" ] && return 0
  local line zid rid
  printf '%s\n' "$CF_RECORDS" | while IFS= read -r line; do
    [ -z "$line" ] && continue
    zid="${line%%:*}"
    rid="${line##*:}"
    # ★ 必须用 () 把 cf_del_txt 包起来。
    #
    # cf_del_txt 内部的 cf_api 在响应没有 "success":true 时会 die，
    # 而 die 用的是 exit（不是 return）—— exit 终结的是【整个管道子 shell】，
    # 不是当前这一条命令。所以直接调用时，一条记录删除失败会让
    # 循环体所在的子 shell 立即消失，【后面所有记录都不再清理】。
    #
    # 触发条件很现实：记录已被删过（404）、API 瞬时错误、限流。
    # 而泄漏的正是设计文档警告过的"垃圾 TXT 记录留在线上的 DNS 里"，
    # 且每失败一次就多泄漏几条（下次续期会新建记录，不会复用）。
    #
    # () 让 exit 只终结那个子 shell，循环得以继续。
    ( cf_del_txt "$zid" "$rid" ) ||
      warn "清理 TXT 记录 id=$rid 出错，请手动检查 Cloudflare 控制台"
  done
  CF_RECORDS=""
  return 0
}

# ---------- 签发流程 ----------

cmd_issue() {
  derive_paths
  load_config "$CONF_FILE"
  # set_cert_dir 必须在 load_config 之后：它依赖 DOMAINS 推导主域名
  set_cert_dir
  ensure_dirs
  ensure_cert_dir
  setup_workdir
  need_cmd curl openssl

  log "开始签发（环境：${LE_ENV}，域名：${DOMAINS[*]}）"
  if [ "$IS_STAGING" = 1 ]; then
    log "注意：测试环境签出的证书不被浏览器信任，仅用于验证流程"
  fi

  # 失败路径的清理由 main 里挂的 on_exit trap 负责（边界情况 ③）。
  # 这里不再设 trap —— trap 是覆盖语义，在此设置会顶掉 on_exit。

  # 0. 账号密钥必须在进 ACME 流程之前验证一次。
  #
  #    为什么不能只靠 jwk_n_b64 里的 die：它跑在 jwk_json 的 $() 里，
  #    而 jwk_json 又跑在 acme_post 的 $(printf ...) 里 —— 嵌套命令替换
  #    里没有任何退出码能传出来，子 shell 的 exit 只终结自己。
  #    结果是坏密钥会一路走到「DNS 校验失败」或「授权超时」，
  #    报错指不到根因（实测：acme_key_authz 会算出一个错误但"正常"的 TXT 值）。
  #
  #    在边界上直接调用 jwk_thumbprint，它的退出码能正常传播到这里。
  if [ -s "$ACCOUNT_KEY" ]; then
    jwk_thumbprint "$ACCOUNT_KEY" >/dev/null ||
      die "账号密钥不可用（无法读取 RSA 模数）：$ACCOUNT_KEY"
  fi

  # 1. 账号：已有 account.json 就复用，否则注册
  if [ -f "$ACCOUNT_JSON" ] && [ -s "$ACCOUNT_KEY" ]; then
    ACCOUNT_KID=$(json_str "$(cat "$ACCOUNT_JSON")" kid)
    log "复用已有账号：$ACCOUNT_KID"
  else
    [ -s "$ACCOUNT_KEY" ] || gen_rsa_key "$ACCOUNT_KEY" 2048
    acme_dir
    acme_nonce
    acme_new_account
  fi
  [ -n "$ACCOUNT_KID" ] || die "账号 kid 为空"

  # 2. 域名密钥
  local domain_key="$CERT_PRIVKEY_NEW"
  [ -s "$domain_key" ] || gen_rsa_key "$domain_key" "${KEY_BITS:-2048}"

  # 3. 下单
  acme_new_order

  # 4. 收集全部挑战。边界情况 ①：先把所有 TXT 建好，再统一触发校验。
  #    通配符与裸域的记录名相同但值不同，必须两条共存。
  local authz_url dns01 token ch_url rec_name txt_value
  local -a pending_names=() pending_values=() pending_urls=()

  for authz_url in $ORDER_AUTHZ_URLS; do
    local authz
    authz=$(acme_authz "$authz_url")

    # 授权可能已经是 valid：Let's Encrypt 复用 30 天内校验过的结果，
    # 此时不需要建任何 TXT 记录，直接进 finalize。
    # 真机实测：少了这一步，--force 重跑必失败（授权越新鲜越容易撞上）。
    case "$(authz_action "$authz")" in
      skip)
        log "授权已有效（复用既有校验结果），跳过：$authz_url"
        continue
        ;;
      challenge) ;;
      *)
        die "授权 $authz_url 的状态是「$(json_str "$authz" status)」，无法继续。原始响应：$authz"
        ;;
    esac

    if ! dns01=$(acme_dns01_of "$authz"); then
      die "授权 $authz_url 里没有 dns-01 挑战。原始响应：$authz"
    fi
    token=$(printf '%s' "$dns01" | cut -f1)
    ch_url=$(printf '%s' "$dns01" | cut -f2)
    txt_value=$(acme_key_authz "$token")

    # 从 authorization 里取回它对应的域名，用于算记录名
    local ident
    ident=$(json_str_after "$authz" '"identifier":' value)
    [ -n "$ident" ] || die "无法从 authorization 里取得域名：$authz"
    rec_name=$(challenge_record_name "$ident")

    log "域名 $ident 的挑战记录：$rec_name"

    # 直接调用，不要包 $( )：命令替换会把函数放进子 shell，
    # 于是它对 CF_ZONE_CACHE 的更新在父 shell 里丢失 ——
    # 缓存退化成死优化，每个域名都重新探测一遍。
    # cf_find_zone 把结果写进 CF_ZONE_ID / CF_ZONE_NAME。
    cf_find_zone "$ident"
    local zid="$CF_ZONE_ID"

    local rid
    rid=$(cf_add_txt "$zid" "$rec_name" "$txt_value")
    CF_RECORDS="$CF_RECORDS$zid:$rid
"

    pending_names+=("$rec_name")
    pending_values+=("$txt_value")
    pending_urls+=("$ch_url")
  done

  # 5. 等全部记录生效后再触发校验。
  #    逐个等会让后面的记录在等待期间可能仍未传播，统一等待更稳。
  local i
  for ((i = 0; i < ${#pending_names[@]}; i++)); do
    wait_dns_visible "${pending_names[$i]}" "${pending_values[$i]}"
  done

  # 6. 触发并轮询全部挑战
  for ((i = 0; i < ${#pending_urls[@]}; i++)); do
    acme_trigger "${pending_urls[$i]}"
  done
  for authz_url in $ORDER_AUTHZ_URLS; do
    acme_poll_authz "$authz_url"
  done
  log "全部授权已通过"

  # 7. 提交 CSR 并下载证书
  local csr="$TMP_DIR/domain.csr.der"
  make_csr "$domain_key" "$csr" "${DOMAINS[@]}"
  acme_finalize "$csr"
  local chain="$TMP_DIR/fullchain.pem"
  acme_download_cert > "$chain"
  [ -s "$chain" ] || die "下载到的证书链为空"
  log "证书链已下载（$(grep -c 'BEGIN CERTIFICATE' "$chain") 张）"

  # 8. 清理 DNS 记录，然后才写盘。
  #    先清理再写盘：即使写盘失败，线上也不会留下垃圾 TXT 记录。
  cleanup_records

  # 9. 原子写盘并 reload（边界情况 ⑤）
  #    每次签发都生成全新的域名私钥，不复用旧的。
  #    私钥随中间产物目录一起销毁，只有 CERT_DIR/privkey.pem 这一份留存。
  write_certs_atomic "$CERT_DIR" "$chain" "$domain_key"

  run_reload

  log "完成。证书目录：$CERT_DIR"
}

# issue 的默认路径：先判断证书是否存在、是否临近到期，需要时才真的签发。
# `issue --force` 跳过这里，直接调 cmd_issue。
#
# renew_needed 是纯本地判断（openssl x509 -checkend），证书仍然有效时
# 【一个网络请求都不发】—— cron 每天都跑这条命令，这一点是硬要求。
cmd_issue_checked() {
  derive_paths
  # 必须先读配置：既要 RENEW_BEFORE_DAYS，也要 DOMAINS 才能算出证书目录
  load_config "$CONF_FILE"
  set_cert_dir
  local leaf="$CERT_DIR/cert.pem"

  if renew_needed "$leaf"; then
    log "证书需要续期：$leaf"
    cmd_issue
  else
    local end
    end=$(openssl x509 -in "$leaf" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    log "证书仍然有效（到期时间 ${end}），无需续期"
  fi
}

# ---------- cron 与文档 ----------

# 解析脚本自身的绝对路径，而不是硬编码 /usr/local/bin/le-dns.sh。
# 否则脚本还在 ~/le-dns/ 下调试时会生成一条指向错误路径的 cron。
SCRIPT_PATH=""
resolve_script_path() {
  case "$0" in
    /*) SCRIPT_PATH="$0" ;;
    *) SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")" ;;
  esac
}

# cron 用 17 分而非 0 分：整点是所有人的默认选择，
# 错开可以避免与全球其他任务在同一时刻竞争 Let's Encrypt 的接口。
# cron 的命令字段是【整行剩余部分】交给 /bin/sh -c 执行的，所以引号有效。
#
# 路径必须加引号：脚本可以待在任意目录（resolve_script_path 的全部意义所在），
# 而目录名带空格时，不加引号的 cron 会去执行 "/home/my" 并把
# "app/le-dns/le-dns.sh" 当成参数 —— 而 cron 行末尾是 >/dev/null 2>&1，
# 这个失败连一行日志都不会留下。
render_cron_line() {
  printf '# le-dns 自动续期。每天检查一次，未临近到期时不产生任何网络请求。\n'
  printf '17 3 * * * root "%s" issue >/dev/null 2>&1\n' "${SCRIPT_PATH:-/usr/local/bin/le-dns.sh}"
}

cmd_install_cron() {
  resolve_script_path
  local target=/etc/cron.d/le-dns

  [ "$(id -u)" = "0" ] || die "--install-cron 需要 root 权限"

  render_cron_line > "$target"
  chmod 644 "$target"
  log "已写入 $target"
  cat "$target" >&2
}

usage() {
  cat <<'USAGE'
le-dns — 纯 curl + openssl 的 Let's Encrypt DNS-01 证书申请与续期工具
不使用 certbot / acme.sh / jq / dig / python，只依赖 curl 与 openssl。

================================================================
首次部署（一次性）
================================================================

  1. 放置脚本（二选一）

       install -m 755 le-dns.sh /usr/local/bin/le-dns.sh   # 装进 PATH，随处可调

     或直接在仓库目录里跑（不安装）：

       chmod +x le-dns.sh
       ./le-dns.sh --help

     后者同样可用 --install-cron：它写的是脚本自身的真实路径，
     不依赖脚本是否在 PATH 里。

  2. 生成配置模板与目录结构
       le-dns.sh --init              # 生产配置 /etc/le-dns/le-dns.conf
       le-dns.sh --staging --init    # 测试配置 /etc/le-dns/le-dns-staging.conf

  3. 编辑配置文件，填入域名与 Cloudflare Token
       chmod 600 /etc/le-dns/le-dns*.conf
     Token 需要 Zone:Zone:Read + Zone:DNS:Edit 权限。

  4. 环境自检（不触碰 ACME，不消耗任何配额）
       le-dns.sh --staging --check

================================================================
调试流程（测试环境，可反复执行任意多次）
================================================================

  le-dns.sh --staging -d example.com -d '*.example.com'

  测试环境配额宽松，可以随便跑。
  签出的证书不被浏览器信任，这是正常的 —— 它只用来验证流程能跑通。
  此模式下 RELOAD_CMD 同样会执行 —— 它来自 le-dns-staging.conf，
  与生产配置各写各的。

================================================================
正式签发（每套域名执行一次）
================================================================

  le-dns.sh -d example.com -d '*.example.com'

  参数与测试环境完全相同，只是去掉 --staging。

  证书已存在且未临近到期时会直接跳过，不产生任何网络请求。
  想立刻重新申请、不等续期窗口，就加 --force：

    le-dns.sh issue --force

  --staging 只决定"用哪套环境"，与"是否强制"无关：
  在生产上强制就是去掉 --staging。

  务必先用 --staging 把流程完整跑通再执行这一步。
  生产环境对同一组域名每周只允许 5 张证书。

================================================================
配置定时任务（一次性）
================================================================

  le-dns.sh --install-cron

  写入 /etc/cron.d/le-dns，每天 3:17 检查一次。
  未临近到期时脚本只做本地判断，不产生任何网络请求。

  cron 行写的是脚本自身的绝对路径，不必先装进 PATH。
  但移动脚本后要重跑本命令 —— 否则 cron 还指向旧路径。

================================================================
日常续期（由 cron 自动执行，无需人工干预）
================================================================

  le-dns.sh issue

  与上面"正式签发"是同一条命令：不加 --force 时它先判断有效期，
  证书仍然有效就直接退出，一个 ACME 请求都不发。

================================================================
手动验证续期是否正常（可选，建议每季度一次）
================================================================

  le-dns.sh --staging issue --force

  必须加 --force：不加的话证书没过期就直接跳过了，等于什么都没验证。

================================================================
命令与开关
================================================================

  无子命令            等同 issue
  issue               先判断证书是否存在、是否临近到期，需要时才签发
  --staging           切换到测试环境（配置文件、账号、证书、端点、日志全部切）
  --force             配合 issue 跳过有效期判断，无条件重新申请。
                      它在 --check / --init 等不签发的命令下会被直接拒绝，
                      而不是当作没看见 —— 静默吃掉一个开关只会误导
  -d <域名>           可重复。指定后覆盖配置里的 DOMAINS
  -c <配置文件>       覆盖配置文件路径，不改变环境归属
  --check             环境自检，不连 ACME，不消耗配额
  --init              生成配置模板与目录结构
  --install-cron      写入 /etc/cron.d/le-dns
  --help              显示本帮助

================================================================
环境隔离
================================================================

  --staging 是唯一的开关，它一次性切换以下全部路径：

                        生产                      测试
    配置文件   /etc/le-dns/le-dns.conf    /etc/le-dns/le-dns-staging.conf
    账号       accounts/production/       accounts/staging/
    证书       certs/production/          certs/staging/
    日志       logs/le-dns.log            logs/le-dns-staging.log
    端点       acme-v02.api...            acme-staging-v02.api...

  上述路径两两不相交，测试环境永远不会读写生产目录。

  RELOAD_CMD 不在其列：两个环境都会执行它，执行什么由各自的配置决定。

================================================================
退出码
================================================================

  0  成功（或证书未到期，无需续期）
  1  失败。证书不会被写坏 —— 磁盘上仍是原来那张，服务不受影响。
USAGE
}

# ---------- 入口 ----------

# 注：TMP_DIR / CERT_PRIVKEY_NEW 已在 Task 8 的业务层段落里声明为空串，
# 这里不再重复声明 —— 同一个全局量有两处初值就是两份真相，
# 日后改一处忘另一处不会被任何测试发现。
# （Task 8 的声明在本文件更靠前，main 运行时它已经执行过。）

main() {
  parse_args "$@"
  derive_paths

  # ★ setup_workdir 与 trap 必须在【命令分发之前】。
  #
  # _ensure_http_tmp 要求 TMP_DIR 已初始化（中转文件的路径确定性完全建立在
  # TMP_DIR 之上），而 TMP_DIR 只在 setup_workdir 里建立 —— 所以任何会发起
  # HTTP 请求的命令路径都必须排在 setup_workdir 之后。
  #
  # --check 正是这样一条路径：它要调 cf_api 验 Token、再发一次 DoH 探测。
  # 若 setup_workdir 留在下面那个 case 之后，--check 一进 cf_api 就会
  # 以 "_ensure_http_tmp: TMP_DIR 未初始化" 中止，而那两个错误分支还会把它
  # 分别报成「Token 不可用」和「DoH 不可达」——
  # 两条消息都把矛头指向用户的网络与配置，真正的原因却是脚本自己。
  # 这恰好摧毁了 --check 存在的意义（它是远程排查的唯一线索）。
  # 已实测：TMP_DIR 为空时 _ensure_http_tmp 确定以 rc=1 中止。
  #
  # 放在这里还顺带让 trap 覆盖 --help / --init / --check 三条路径的失败退出。
  # 备选方案「让 _ensure_http_tmp 自己在需要时建 TMP_DIR」是错的：
  # _http 几乎总在 $() 里，子 shell 建的目录回不到父 shell，on_exit 清不掉 ——
  # 那正是本计划已经踩过三次的子 shell 陷阱。
  setup_workdir
  # 全脚本唯一的退出 trap。on_exit 同时负责清理 DNS 记录与中间产物，
  # 覆盖失败退出、Ctrl-C 和正常结束三种情况。
  trap on_exit EXIT INT TERM

  case "$CMD" in
    help) usage; exit 0 ;;
    init) cmd_init; exit 0 ;;
    check) cmd_check; exit $? ;;
    install-cron) cmd_install_cron; exit 0 ;;
  esac

  need_cmd curl openssl

  case "$CMD" in
    issue)
      # 默认先判断有效期：证书不存在或临近过期才真的去签发。
      # --force 跳过这一步，无条件重新申请。
      if [ "${FORCE:-0}" = 1 ]; then
        log "--force 已指定，忽略有效期判断，直接重新申请"
        cmd_issue
      else
        cmd_issue_checked
      fi
      ;;
    *) die "未知命令：$CMD" ;;
  esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
