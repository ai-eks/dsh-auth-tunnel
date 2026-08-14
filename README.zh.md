# @deepseek-ai/dsh-auth-tunnel

[English](README.md) | 中文

该插件通过 Cloudflare Tunnel 发布 DeepSeek Harness 已有的 WebServer，并向 Web bundle 的全局访问服务贡献共享密码认证。插件不再创建代理，也不需要枚举应用路由。

```text
公网浏览器
  -> Cloudflare edge（TLS）
  -> 本机 cloudflared
  -> WebServer 全局访问 guard  <- 登录页与 Cookie 认证
  -> 当前及未来插件注册的全部 HTTP、WebSocket 路由

loopback 浏览器
  -> WebServer 全局访问 guard  <- 判定为 local，不要求密码
```

插件注入 `webServer`、`webAccess` 和 `credentials`。不提供全局 `webAccess` 服务的旧版 Harness 会让该插件保持 pending，不会启动一条未受保护的 tunnel。核心 guard 在路由匹配前运行，因此其他插件晚于本插件注册的接口也会自动经过相同认证。放行后的请求保留原始公网 `Host` 和 `Origin`；核心 connection 层使用服务端写入的 authenticated 结论，同时继续执行同源与 DNS rebinding 检查。

同一访问结论会投影到浏览器。已认证公网页面可以使用 Host 配置面，本机桌面操作仍只允许 local 页面。Web bundle 可以同时注册原生和应用内目录 provider：同一进程里，loopback 页面使用 OS 目录选择器，公网页面使用应用内目录浏览器。

## 认证

登录页位于 `/dsh-auth-tunnel/login`。成功提交 URL-encoded POST 后会签发 `dsh_auth_tunnel` Cookie；该 Cookie 使用 `HttpOnly`、`SameSite=Strict`，Cloudflare 报告 HTTPS 时还会使用 `Secure`。Cookie 只包含绝对过期时间和以 `SHA-256(password)` 为密钥的 HMAC，不保存密码本身。

每次请求都会重新解析密码引用。轮换或删除对应凭据会立即使现有会话失效。`GET` 或 `POST /dsh-auth-tunnel/logout` 会清除 Cookie。登录请求体上限为 16 KiB，且必须使用 `application/x-www-form-urlencoded`。

未认证的文档导航会跳转到登录页，其他 HTTP 请求返回 401 JSON，upgrade 请求在关闭 socket 前返回 401。没有公开资源例外：Web App Manifest 通过 `crossorigin="use-credentials"` 携带认证 Cookie。

## Cloudflare 模式

- `quick` 运行 `cloudflared tunnel --url http://127.0.0.1:<webserver-port> --no-autoupdate`，并从进程输出发现生成的 `*.trycloudflare.com` URL。
- `token` 运行 `cloudflared tunnel run --no-autoupdate`，通过 `TUNNEL_TOKEN` 传递 Tunnel Token，并报告 `https://<publicHostname>`。命名 tunnel 的 dashboard ingress 应指向 WebServer，通常是 `http://localhost:3080`，或 `dsh web --port` 指定的端口。

密码缺失、模式配置冲突、token 缺失、cloudflared 无法启动、就绪前退出或启动超时时，插件会在公开 URL 前失败。卸载时只撤销 authenticator 并终止 cloudflared；插件不拥有也不会关闭 WebServer。

## 配置

| 键 | 类型 | 默认值 | 效果 |
|---|---|---|---|
| `passwordRef` | credential reference | `DSH_WEB_PASSWORD` | 共享访问密码；无法解析或为空时激活失败。 |
| `sessionTtlHours` | number >= 0.01 | `720` | Cookie 的绝对有效期（小时）。 |
| `mode` | `quick` \| `token` | `quick` | tunnel 模式。 |
| `tokenRef` | credential reference | - | Tunnel Token 引用；token 模式必填。 |
| `publicHostname` | string | - | dashboard 绑定的主机名；token 模式必填。 |
| `executable` | string | `cloudflared` | PATH 名或 cloudflared 绝对路径。 |
| `startupTimeoutMs` | integer >= 1 | `15000` | 等待 tunnel 就绪的超时时间。 |

## 安装

把该仓库作为 Web profile bundle 安装：

```sh
dsh plugin --profile web add <package>
```

`<package>` 可以是 npm 包名、Git URL 或 `file:` 路径。包内 patch 会按 quick 模式默认值插入 `auth-tunnel` 行。把密码存入 Harness 凭据 provider，例如 `$DSH_HOME/.credentials.yaml`：

```yaml
DSH_WEB_PASSWORD: 'pick-a-long-random-password'
```

命名 tunnel 可在 `~/.dsh/profiles/web/cordis.patch.yml` 覆盖该行：

```yaml
- id: auth-tunnel
  config:
    mode: token
    tokenRef: DSH_TUNNEL_TOKEN
    publicHostname: gui.example.com
```

随后在 Cloudflare dashboard 把 `gui.example.com` 指向当前 Harness WebServer 端口，并保存两项凭据：

```yaml
DSH_WEB_PASSWORD: 'pick-a-long-random-password'
DSH_TUNNEL_TOKEN: 'eyJhIjo...'
```

## 运行时事实

tunnel 就绪后，进程打印 `cloudflare tunnel: <public-url>`。可选服务存在时，插件还会向 shell 环境贡献 `DSH_PUBLIC_URL`，并注册 `app:public-access` system-prompt 段，要求模型只分享 URL、绝不分享密码。

## 限制

- 所有密码持有者共享同一个 authenticated Host 权限；没有多用户身份、速率限制、锁定机制或密码轮换之外的服务端会话吊销。
- cloudflared 意外退出时只记录错误，不自动重启。
- quick tunnel 主机名每次运行都会变化。
- direct-loopback 访问按设计绕过密码；该方案不防御已经运行在 Host 上的恶意进程。
- token 模式依赖 dashboard ingress 与 WebServer 端口一致；修改 `dsh web --port` 后也要更新 ingress。
