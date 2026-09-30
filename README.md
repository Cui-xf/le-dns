# le-dns

纯 shell 的 Let's Encrypt 证书申请与自动续期工具，使用 DNS-01 挑战，
通过 Cloudflare API 自动配置验证记录。

## 特点

- **零第三方依赖**：只用系统自带的 `curl` 和 `openssl`。
  不需要 certbot、acme.sh、jq、dig、python。
- **通配符证书**：支持 `*.example.com`，且与裸域合并进同一张证书。
- **自动续期**：cron 驱动，未临近到期时零网络请求。
- **测试环境完全隔离**：`--staging` 一个开关切换全部路径，
  测试环境不可能碰到生产目录。

## 快速开始

完整流程见 `./le-dns.sh --help`。要点：

```sh
chmod +x le-dns.sh                          # 直接在仓库目录里跑，不必安装

./le-dns.sh --staging --init                # 一次性：生成测试配置
vi /etc/le-dns/le-dns-staging.conf          # 一次性：填域名与 CF Token
./le-dns.sh --staging --check               # 一次性：环境自检

./le-dns.sh --staging issue --force         # 调试：强制重签，可反复跑

./le-dns.sh -d example.com -d '*.example.com'   # 正式签发
./le-dns.sh --install-cron                      # 一次性：装定时任务
```

**默认不指定 `--force` 时会先判断有效期**：证书已存在且未临近到期就直接
退出，一个 ACME 请求都不发。要无条件重新申请就加 `--force`。

cron 装的是 `le-dns.sh issue`，靠的就是这个判断——未到期时零网络请求。

## 文档

- 设计文档：`docs/superpowers/specs/2026-09-30-le-dns-design.md`
- 实现计划：`docs/superpowers/plans/2026-09-30-le-dns.md`

## 测试

```sh
bash tests/run-tests.sh
```

测试通过替换内部 `_http()` 函数注入 fixture，不产生任何网络请求。
