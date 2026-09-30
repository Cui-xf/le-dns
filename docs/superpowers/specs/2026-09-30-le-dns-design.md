# le-dns — 纯 shell 的 Let's Encrypt DNS-01 证书申请与自动续期脚本

日期：2026-09-30
状态：设计已确认，待实现

## 1. 目标

在 Linux 上申请和续期 Let's Encrypt 证书，使用 DNS-01 挑战，通过 Cloudflare API
自动配置验证记录，由 cron 驱动自动续期。

**硬约束：不依赖任何第三方软件。** 只用目标机器上几乎必然存在的两个命令：

- `curl` — 所有 HTTPS 通信（ACME API、Cloudflare API、DoH 查询）
- `openssl` — 密钥生成、CSR、JWS 签名、证书解析

不使用 `certbot`、`acme.sh`、`jq`、`dig`、`python`、`bash` 之外的解释器。

实现语言为 POSIX sh 兼容的 bash 脚本，单文件。

## 2. 非目标

- 不支持 HTTP-01 / TLS-ALPN-01 挑战。只做 DNS-01（通配符证书的硬性要求）。
- 不支持 Cloudflare 之外的 DNS 服务商。协议层预留函数边界，但本次不实现。
- 不支持证书吊销（revoke）。需要时用 `openssl` 手动操作。
- 不做多机证书分发、不做证书监控面板。

## 3. 环境隔离模型

**`--staging` 是唯一的开关**，它一次性切换五个路径。不存在"部分 staging"的状态。

| | 生产（默认） | 测试（`--staging`） |
|---|---|---|
| 配置文件 | `/etc/le-dns/le-dns.conf` | `/etc/le-dns/le-dns-staging.conf` |
| 账号目录 | `accounts/production/` | `accounts/staging/` |
| 证书目录 | `certs/production/<主域名>/` | `certs/staging/<主域名>/` |
| ACME 端点 | `https://acme-v02.api.letsencrypt.org/directory` | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| 日志 | `logs/le-dns.log` | `logs/le-dns-staging.log` |
| reload 命令 | 执行配置里的 RELOAD_CMD | 同样执行，命令来自 staging 配置 |

设计理由：不让"配置文件是否叫 `-staging`"来推断环境。那样会出现 `-c` 指向 staging 配置
却漏加 `--staging` 的错配，后果是把 staging 证书写进生产目录。
单一开关决定全部路径，使错配在结构上不可能发生。

路径隔离是这里的全部保护手段，reload 不参与其中：两个环境都执行各自配置里的
RELOAD_CMD。跳过 reload 并不能多保护什么，反而让测试环境里那条命令永远得不到
验证 —— 而它是最容易配错、也最容易在真实续期时炸掉的一步。

`-c <file>` 仍然支持，作用**仅**于覆盖配置文件路径，不改变环境归属。

## 4. 磁盘布局

```
/etc/le-dns/
├── le-dns.conf                    # 生产配置，权限 600
├── le-dns-staging.conf            # 测试配置，权限 600
├── accounts/
│   ├── production/
│   │   ├── account.key            # ACME 账号私钥，RSA-2048，600
│   │   └── account.json           # {"kid":"<账号 URL>"}，600
│   └── staging/
│       ├── account.key
│       └── account.json
├── certs/
│   ├── production/
│   │   └── example.com/
│   │       ├── fullchain.pem      # 证书链（叶子 + 中间），nginx ssl_certificate 用这个
│   │       ├── privkey.pem        # 私钥
│   │       ├── chain.pem          # 仅中间证书
│   │       └── cert.pem           # 仅叶子证书
│   └── staging/
│       └── example.com/…
└── logs/
    ├── le-dns.log
    └── le-dns-staging.log
```

证书目录名取**主域名**（第一个 `-d` 参数，去掉 `*.` 前缀）。

## 5. 配置文件格式

`key=value` 的纯文本，`#` 开头为注释。由 `--init` 生成模板。

```sh
# 要申请证书的域名，空格分隔。第一个作为证书目录名。
# 通配符要加引号写，如 "*.example.com"
DOMAINS="example.com *.example.com"

# Cloudflare API Token，需要 Zone:Zone:Read + Zone:DNS:Edit 权限
CF_API_TOKEN=""

# 证书更新成功后执行的命令，可多条，用 ; 分隔。留空则不执行。
# staging 模式下此配置被忽略。
RELOAD_CMD="systemctl reload nginx"

# 提前多少天续期
RENEW_BEFORE_DAYS=30

# 单次 DNS 生效等待的上限秒数
DNS_WAIT_TIMEOUT=120

# 密钥类型：rsa2048 | rsa4096
KEY_TYPE=rsa2048

# 联系邮箱，注册 ACME 账号用，可留空
ACCOUNT_EMAIL=""
```

配置文件权限强制为 600。脚本启动时检查，过宽则拒绝运行并提示
`chmod 600`——避免 Token 被同机其他用户读走。

**域名的来源优先级**：命令行 `-d` 指定的域名覆盖配置里的 `DOMAINS`；
命令行未给 `-d` 时使用配置里的 `DOMAINS`。两者都为空则报错退出。
这样首次签发可以临时指定域名，而 cron 续期只需读配置。

## 6. 分层架构

单文件脚本，内部四层，上层只调用下层：

```
命令层    issue（默认） | renew | --check | --init | --install-cron | --help
   ↓
业务层    续期必要性判断、证书原子写盘、reload 执行、DNS 记录清理
   ↓
协议层    ACME v2 状态机  |  Cloudflare DNS API  |  DoH 传播检测
   ↓
基础层    curl 封装、openssl 封装、b64url、JSON 取值、JWS 签名、日志
```

子命令与开关：

| | 含义 |
|---|---|
| 无子命令（默认） | 等同于 `issue`，走完整签发流程 |
| `renew` | 先判断有效期，需要时才走签发流程 |
| `--check` | 只做环境自检，不连 ACME |
| `--init` | 生成配置模板与目录结构 |
| `--install-cron` | 写入 `/etc/cron.d/le-dns` |
| `--staging` | 开关：切换到测试环境（见第 3 节） |
| `--force` | 开关：`renew` 时忽略有效期判断，强制签发 |
| `-d <域名>` | 可重复，覆盖配置里的 `DOMAINS` |
| `-c <配置文件>` | 覆盖配置文件路径，不改变环境归属 |
| `--help` | 打印第 12 节的完整使用流程 |

### 基础层要点

- `b64url()` — `openssl base64 -A | tr '+/' '-_' | tr -d '='`。所有 base64url
  一律不带 padding（RFC 7515 要求）。
- `json_get()` — 用 `sed` 从扁平 JSON 中取字段。ACME 与 Cloudflare 的响应结构固定，
  只取 `status`、`token`、`type`、`url`、`id`、`name` 这类简单标量字段，不解析嵌套数组。
  需要遍历数组时（authorizations、challenges、DNS 记录列表）另写专用提取函数。
- `jws_sign()` — **RS256**。`openssl dgst -sha256 -sign account.key` 的输出直接就是
  JWS 需要的 PKCS#1 v1.5 字节串，无需任何格式转换。这是选 RS256 而非 ES256 的唯一原因：
  ES256 要求把 openssl 输出的 DER 拆成 R‖S 的 64 字节裸格式，纯 shell 实现约 40 行
  且极易出错，而 ACME 全程只签名十余次，RSA 的性能劣势完全不可感知。

### JWS 构造

受保护头（flattened JSON 序列化）：

```json
{"alg":"RS256","nonce":"<nonce>","url":"<请求 URL>",
 "jwk":{...}}          // 仅 new-account 用 jwk
{"alg":"RS256","nonce":"<nonce>","url":"<请求 URL>",
 "kid":"<账号 URL>"}   // 其余请求用 kid
```

签名输入为 `b64url(protected) + "." + b64url(payload)`，payload 为 POST-as-GET 时是
空字符串。JWK 的 `n` 与 `e` 用 `openssl rsa -noout -modulus` 取出后转 base64url，
`e` 固定为 `AQAB`（65537）。JWK thumbprint 用 RFC 7638 规定的字典序
`{"e":...,"kty":"RSA","n":...}` 做 SHA-256 再 base64url。

## 7. ACME v2 申请流程

```
1  读配置并校验（域名格式、Token 非空、依赖命令存在、配置文件权限）
2  HEAD  new-nonce                              → nonce
3  POST  new-account {termsOfServiceAgreed:true} → Location 头即 kid，存 account.json
4  POST  new-order  {identifiers:[…]}            → Location 头即 order URL，
                                                    响应含 authorizations[] 与 finalize
5  对每个 authorization 做 POST-as-GET           → 取 dns-01 的 token 与 challenge URL
6  对每个 token 生成 TXT 值并调用 Cloudflare API 创建 TXT 记录，记下返回的记录 id
7  DoH 轮询直到所有记录可见
8  对每个 challenge 做 POST {} 触发校验
9  轮询 authorization 直到全部 valid
10 POST  finalize {csr: b64url(DER)}             → 轮询 order 直到 status=valid，
                                                    取 certificate URL 下载 PEM 链
11 按 id 清理全部 TXT 记录
12 原子写盘 → 执行 reload（命令来自当前环境的配置）
```

### challenge 值计算

```
keyAuthorization = token + "." + b64url(sha256(JWK thumbprint 的 JSON))
TXT 值           = b64url(sha256(keyAuthorization))
```

### 依赖签名算法之外的两个协议细节

- **nonce 每次都要更新**。每个响应都带 `Replay-Nonce` 头，必须用它做下一次请求的 nonce。
  收到 `urn:ietf:params:acme:error:badNonce` 时重取并重试一次。
- **所有读操作都是 POST-as-GET**（空 payload 的 POST），不是 GET。RFC 8555 规定。

## 8. 五个必须处理正确的边界情况

这些是本实现的核心风险点，也是测试重点。

### ① 通配符与裸域共用同一个记录名

`*.example.com` 和 `example.com` 的挑战记录名都是 `_acme-challenge.example.com`，
但 TXT 值是两个不同的 token。Cloudflare 允许同名多条 TXT 记录，ACME 校验时按值匹配。

**因此：必须先把全部 TXT 记录建好，再统一触发校验。** 若按域名逐个"先删后建"，
第二条会覆盖第一条，第一个域名永远无法通过校验，且现象是"randomly 失败"，极难排查。

### ② 清理只能按记录 id 精确删除

绝不能按名字删除 `_acme-challenge.example.com` —— 该名字下可能存在其他服务商或
其他服务器管理的记录。每创建一条记录都从 API 响应中提取 `id` 并保存，
清理时逐个 `DELETE /zones/{zone}/dns_records/{id}`。

### ③ 失败路径必须清理

用 `trap 'cleanup' EXIT INT TERM` 兜底。任何一步失败、Ctrl-C、`set -e` 触发退出，
都会执行清理，不留垃圾 TXT 记录在线上 DNS 里。清理函数自身必须幂等且不因失败中断。

### ④ nonce 失效

见第 7 节。另外 nonce 只能使用一次，不能缓存跨请求复用。

### ⑤ 证书原子替换

先写 `<file>.tmp` 再 `mv` 覆盖。避免 nginx 在 reload 时读到写了一半的 fullchain —— 
那会导致 worker 启动失败并拒绝加载配置。四个文件全部写完后才执行 reload。

## 9. Cloudflare 集成

### 鉴权

`Authorization: Bearer <CF_API_TOKEN>`。Token 权限：`Zone:Zone:Read`、`Zone:DNS:Edit`。

不使用 Global API Key + Email 的旧方式，因为 Global Key 权限覆盖整个账号，
一旦泄漏后果远大于范围受限的 Token。

### zone 自动逐层探测

从域名剥掉 `*.` 前缀，先查 `a.b.example.com`，未命中则去掉最左标签重试
（`b.example.com` → `example.com`），直到命中或标签耗尽。

```
GET /client/v4/zones?name=<候选>&status=active
```

命中的 zone 的 `id` 用于后续所有 DNS 记录操作。**探测结果在同一次运行内按域名缓存**，
避免每个域名都重新探测。

记录名一律使用**完整 FQDN**（`_acme-challenge.example.com`），Cloudflare API 同时接受
完整名与相对名，用完整名可以省掉一层拼接逻辑和随之而来的边界 bug。
记录名由域名剥掉 `*.` 前缀后加 `_acme-challenge.` 前缀得到：
`*.example.com` 与 `example.com` 都映射到 `_acme-challenge.example.com`。

### 创建与删除记录

```
POST   /client/v4/zones/{zone_id}/dns_records
       {"type":"TXT","name":"_acme-challenge.example.com","content":"<值>","ttl":120}
DELETE /client/v4/zones/{zone_id}/dns_records/{record_id}
```

TTL 用 120 秒（Cloudflare 允许的最小值），加快验证记录的生效与过期。
每次响应都检查 `success` 字段，失败时把完整的 `errors[]` 打进日志。

### DNS 传播检测走 DoH

```
curl -s -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=_acme-challenge.example.com&type=TXT'
```

这样不需要安装 `dig`（属于 `bind-utils`，最小化系统里常不存在）。
DoH 查询也解析到 Cloudflare 自己的权威服务器，记录可见即权威生效。

轮询间隔 2 秒，上限由 `DNS_WAIT_TIMEOUT` 控制（默认 120 秒）。
**超时则放弃本次申请并清理，绝不"等不及了直接触发校验"** —— 
那只会白白消耗一次失败配额，且同样会失败。

## 10. 续期策略

`renew` 子命令的判断逻辑：

```
证书文件不存在          → 执行完整签发
openssl x509 -checkend $((RENEW_BEFORE_DAYS*86400)) 失败  → 执行完整签发
否则                     → 记录日志并退出，不连接 ACME
```

`-checkend` 返回成功表示证书在指定秒数内不会过期，此时跳过。
这意味着绝大多数 cron 执行都是**零网络请求**的本地判断。

cron 配置由 `--install-cron` 生成 `/etc/cron.d/le-dns`：

```
17 3 * * * root /usr/local/bin/le-dns.sh renew >/dev/null 2>&1
```

刻意用 17 分而非 0 分：整点是所有人的默认选择，错开可以避免与全球其他任务
在同一时刻竞争 Let's Encrypt 的接口。

cron 行内不出现任何密钥，全部从 600 权限的配置文件读取。

`--install-cron` 写入的是**脚本自身的绝对路径**（运行时解析 `$0`），
不是硬编码 `/usr/local/bin/le-dns.sh`。若脚本不在 `/usr/local/bin/`
（例如还在 `~/le-dns/` 下调试），生成的行会指向实际位置并打印提示。
`--install-cron` 只生成生产环境的 cron 行，staging 不应被定时调用。

## 11. 错误处理原则

- **证书不会被半途写坏**。续期失败时磁盘上仍是旧的（可能即将过期的）证书。
  这是刻意的：过期证书比损坏证书好，服务至少还在运行。
- 所有错误以非 0 退出码结束，cron 会通过邮件送达（若配置了 MTA）。
- 每一处 ACME / Cloudflare 调用的失败，都把**原始响应体**写进日志。
  不吞掉服务端信息，因为这是远程排查的唯一线索。
- 日志带时间戳，写到 `logs/le-dns.log`，同时输出到 stderr。
  日志包含域名、订单 URL、步骤名，不包含 Token 和私钥。

## 12. 使用流程（将写入脚本头部与 --help）

脚本头部的 `USAGE` 段必须完整写明以下流程，并明确标注一次性与重复性命令。

### 首次部署（一次性）

```sh
# 1. 放置脚本
install -m 755 le-dns.sh /usr/local/bin/le-dns.sh

# 2. 生成配置模板与目录结构
le-dns.sh --init              # 生成 /etc/le-dns/le-dns.conf
le-dns.sh --staging --init    # 生成 /etc/le-dns/le-dns-staging.conf

# 3. 编辑配置文件，填入域名与 Cloudflare Token
chmod 600 /etc/le-dns/le-dns*.conf
#    Cloudflare Token 需要 Zone:Zone:Read + Zone:DNS:Edit 权限

# 4. 环境自检（不触碰 ACME，不消耗任何配额）
le-dns.sh --staging --check
```

### 调试流程（staging，可反复执行任意多次）

```sh
le-dns.sh --staging -d example.com -d '*.example.com'
```

staging 环境配额宽松，可反复跑。证书不被浏览器信任，属正常现象，
仅用于验证流程。reload 命令照常执行，执行什么由 staging 配置决定。

### 正式签发（每套域名执行一次）

```sh
le-dns.sh -d example.com -d '*.example.com'
```

参数与 staging 完全相同，只去掉 `--staging`。
**必须先确认 staging 已完整跑通再执行此步**，生产环境同一组域名每周仅 5 张配额。

### 配置定时任务（一次性）

```sh
le-dns.sh --install-cron
```

### 日常续期（由 cron 自动执行，无需人工干预）

```sh
le-dns.sh renew           # cron 每天调用，绝大多数时候直接退出
```

### 手动验证续期是否正常（可选，建议每季度一次）

```sh
le-dns.sh --staging --force   # 忽略有效期判断，强制走完整流程
```

## 13. 验证策略

开发机为 macOS，目标运行环境是 **Rocky Linux 8.10**（bash 4.4 + OpenSSL 1.1.1k +
GNU coreutils + systemd），且**目标服务器不可由开发侧直接访问**。因此验证分两层：

### 第 1 层：交付前的静态验证（开发侧）

- `bash -n` 语法检查
- `shellcheck`（若可用）静态分析
- 在 macOS 上跑完整的单元测试与 `--staging` 端到端流程。
  macOS 自带 bash 3.2 + BSD 工具链 + LibreSSL，是比 Rocky 8.10 **更严格的子集**，
  因此本地全绿即意味着目标环境可用；反过来不成立，本地测试不能省略。
- macOS 测不出来的差异只有三处：GNU 工具特有行为、systemd reload 是否真正生效、
  `/etc/cron.d/` 是否被 cron 接受。这三项列入目标环境验收清单。

### 第 2 层：目标环境验证（用户侧）

在 Linux 服务器上按第 12 节流程执行。由于开发侧无法访问该机器，
脚本必须做到：

- `--check` 输出详细的环境诊断（命令版本、配置可读性、Token 能否列出 zone、
  DoH 是否可达），**不触碰 ACME**，不消耗任何配额。
- 所有失败路径把原始响应体打进日志，便于用户直接回贴定位。

### 必须在 staging 覆盖的测试用例

| 用例 | 验证点 |
|---|---|
| 单域名 | 基本流程 |
| 裸域 + 通配符 | 边界情况 ①，两条同名 TXT 共存 |
| 多域名跨 zone | zone 探测逐层回退、每域名独立记录 |
| 中途 Ctrl-C | 边界情况 ③，TXT 记录被清理 |
| 错误的 API Token | Cloudflare 错误信息完整回显 |
| 重复执行 | 边界情况 ⑤，证书被正确覆盖 |
| `renew` 且证书未到期 | 不产生任何网络请求 |
| 无 `dig` 的环境 | DoH 检测路径正常工作 |

## 14. 已知限制

- 单文件脚本，预计 700–900 行。这是"零第三方依赖"的必然代价：
  ACME 协议、JSON 解析、DNS 检测全部要手写。
- `json_get` 只支持平面 JSON。ACME 与 Cloudflare 的响应结构稳定，
  但若服务端在未来改动响应嵌套层级，需要同步调整提取逻辑。
- 只支持 Cloudflare。接入其他 DNS 服务商需要新增一组函数并修改配置格式。
- 证书密钥只支持 RSA（`rsa2048` / `rsa4096`，由 `KEY_TYPE` 配置）。
  签发 ECDSA 证书需要先实现 ES256 签名（见第 6 节），本次不做。
  ACME 账号密钥固定为 RSA-2048。
- 不支持 IPv6-only 或需要 SNI 代理的特殊网络环境。若服务器需要走 HTTP 代理
  访问外网，需自行设置 `https_proxy` 环境变量（`curl` 原生支持，脚本不干预）。
