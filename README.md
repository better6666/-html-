# HTML Cloud

HTML Cloud 用于把静态网站发布到 Cloudflare R2，并返回可分享链接。用户必须先用激活码注册账号，再登录发布页面。系统支持粘贴 HTML 代码、上传 `.html` / `.htm` 文件，以及上传包含 HTML、CSS、JavaScript、图片与字体资源的 ZIP 静态网站包；不支持后端程序。

## 项目文件

- `index.html`：账号注册、登录、发布和“我的网页”。
- `admin.html`：激活码生成、状态管理、账号与发布记录查询。
- `worker.js`：Cloudflare Worker、两个 Durable Object、KV、R2 与网站资源分发逻辑。
- `zip-utils.js`：ZIP 文件预检、安全路径校验、解压和内容类型识别。
- `wrangler.example.toml`：Worker 配置示例。
- `tests/worker.test.mjs`：核心接口与 ZIP 发布自动化测试。
- `可视化/`：桌面端、手机端及管理端成品截图。

## 账号与激活规则

- 一个激活码只能成功注册一个账号，绑定后不能转给其他账号。
- 一个账号只在注册时绑定一个激活码，已存在的账号不能再次注册。
- 时间卡从账号注册成功时开始计时；次卡只在页面和发布记录都保存成功后扣减。
- 每个账号只保留一个有效会话。再次登录会让此前的会话立即失效。
- 后台记录最近登录的 User-Agent 和加盐 IP 哈希，供异常使用排查，不因更换设备或公网 IP 直接封禁。
- 激活码被管理员作废后，账号已有登录会话仍不能继续发布。

`LicenseGuard` 按激活码串行处理绑定与核销，阻止同一卡密并发注册或超额使用。`AccountRegistry` 串行维护账号、密码摘要、单会话状态和发布记录。密码使用 PBKDF2-SHA-256 与独立随机盐保存，迭代次数为 100,000；服务端不保存明文密码或明文 IP。

## Cloudflare 配置

复制 `wrangler.example.toml` 为 `wrangler.toml`，填写真实 KV namespace ID、R2 bucket 名称、前端来源和公开页面域名。不要把密钥写进配置文件。

设置两个 secret：

```bash
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put SECURITY_HASH_SALT
```

`SECURITY_HASH_SALT` 应使用独立的长随机字符串，用于隐藏后台记录中的原始 IP。修改该值后，新旧 IP 哈希将无法直接比较，但不会影响账号登录或激活码绑定。

首次部署：

```bash
npx wrangler deploy
```

必须同时存在以下绑定：

- `LICENSE_KV`：激活码镜像以及旧数据导入来源。
- `UPLOAD_BUCKET`：用户 HTML 页面及 ZIP 静态网站资源存储。
- `LICENSE_GUARD`：激活码强一致绑定、状态与核销。
- `ACCOUNT_REGISTRY`：账号、单会话和网页发布记录。
- `ALLOWED_ORIGINS`：逗号分隔的前台、后台完整来源，正式环境不要使用 `*`。
- `PUBLIC_PAGE_ORIGIN`：用户页面专用域名，建议与 API 管理域名分离。
- `MAX_HTML_BYTES`：默认 `5242880`，即 5MB，适用于粘贴或上传的单个 HTML 文件。
- `MAX_ZIP_BYTES`：默认 `10485760`，即 10MB，适用于上传的 ZIP 文件。
- `MAX_SITE_BYTES`：默认 `26214400`，即 25MB，限制 ZIP 解压后的所有网站文件总大小及单文件最大值。
- `MAX_SITE_FILES`：默认 `500`，限制每个 ZIP 网站的文件数量。

从旧版升级时，KV 激活码会在首次查询或注册时导入对应的 `LicenseGuard`。旧数据中已有的到期时间会保留；未激活时间卡从账号注册成功时起算。部署迁移前应备份 KV 和 R2 数据。

## 部署页面

`index.html` 和 `admin.html` 应部署到 HTTPS 静态站点。部署前确认两个文件中的 `WORKER_URL` 指向同一个 Worker API：

```text
https://api.better666.dpdns.org
```

将前台和后台站点的完整 Origin 都写入 `ALLOWED_ORIGINS`。管理页地址不要放入公开导航；即使地址被发现，管理接口仍要求 `ADMIN_PASSWORD`，并受 IP 频率限制。

## 安全边界

- 用户页面响应包含 CSP sandbox、`nosniff`、无引用来源和浏览器权限限制；CSS、JavaScript、图片等资源会按其文件类型返回。
- ZIP 上传会拒绝加密包、分卷包、ZIP64、重复路径、路径穿越、绝对路径、超限文件及没有唯一 `index.html` / `index.htm` 入口的包。
- 激活码、账号密码只通过 POST 请求体传输，激活码不会出现在请求 URL。
- 激活码使用 `crypto.getRandomValues` 生成，写入时再次检查冲突。
- 认证接口每个 IP 每分钟最多 20 次，发布接口最多 30 次，管理接口最多 20 次。
- 会话令牌有效期为 30 天，新登录会删除旧会话。
- 单次最多生成 50 个激活码，大批量应分批执行。
- R2 页面不会自动删除，正式运营前应配置生命周期规则或增加页面删除功能。
- User-Agent 和 IP 哈希只能辅助发现共享账号，不能证明真实硬件身份。需要更严格控制时，应增加邮箱验证、风险评分或人工封禁流程。

## 本地检查

```bash
npm test
python3 -m http.server 8877 --bind 127.0.0.1
```

浏览器打开 `http://127.0.0.1:8877/index.html` 和 `http://127.0.0.1:8877/admin.html` 检查页面。完整接口功能需要部署新版 Worker，并配置 `LICENSE_GUARD` 与 `ACCOUNT_REGISTRY`。
