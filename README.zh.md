# DSH Auth Tunnel

[English](README.md) | 中文

无需修改 `deepseek-harness`,即可通过带共享密码保护的 Cloudflare Tunnel 公网访问 DeepSeek Harness Web GUI。

## 使用

### 前置条件

- `dsh` CLI 和 pnpm 已加入 `PATH`;Web profile 不存在时,插件命令会自动创建。
- `cloudflared` 已加入 `PATH`,或在插件中配置其绝对 `executable` 路径。
- 一个以 DSH 凭据保存的长随机共享密码。

### 安装

从 Git 安装 bundle:

```sh
dsh plugin --profile web add github:ai-eks/dsh-auth-tunnel
```

当前分支适配 DeepSeek Harness `0.1.0-rc.7` 及以上版本。Harness `0.1.0-rc.6` 必须固定安装对应的不可变 tag:

```sh
dsh plugin --profile web add 'github:ai-eks/dsh-auth-tunnel#v0.1.0-rc.6'
```

Git 安装通过 `prepare` 构建检出的源码。pnpm 10 及以上版本可能先要求允许该构建;按照 `dsh` 打印的 profile `pnpm-workspace.yaml` 路径和准确包名配置后,重新执行命令。

使用本地 checkout 时,先构建再添加路径:

```sh
cd /path/to/dsh-auth-tunnel
pnpm install
dsh plugin --profile web add .
```

该 bundle 会以 quick 模式插入并启用 `auth-tunnel` 行,同时把 Host 原生目录选择器替换为应用内浏览器选择器。不需要修改 `deepseek-harness` 源码,也不需要额外添加 profile 行。

### Quick 模式

Quick 是默认模式。把共享密码写入 `$DSH_HOME/.credentials.yaml`(`$DSH_HOME` 默认为 `~/.dsh`):

```yaml
DSH_WEB_PASSWORD: 'replace-with-a-long-random-password'
```

启动 Web profile:

```sh
dsh web
```

隧道就绪后,终端会打印:

```text
cloudflare tunnel: https://<random>.trycloudflare.com
```

打开这个 URL,在登录页输入 `DSH_WEB_PASSWORD` 对应的密码。只分享 URL,不要分享密码。启用的行也会显示在 Web Settings → Plugins 中。

### Web 设置

保持 Loader 的 `auth-tunnel` 行启用后,打开 **Settings → Plugins → 插件配置 → Auth Tunnel** 即可编辑全部配置。页面中的 **启用公网隧道** 开关保存后会立即启动或停止密码门和 `cloudflared`,并保留这张设置卡片。页面同时显示应用中、运行中、已停止或失败状态以及当前公网 URL。密码和 Tunnel Token 仍只保存在凭据服务中;页面填写的是 `passwordRef` / `tokenRef` 引用名,不会读取或展示凭据明文。

页面保存的配置会自动应用,无需重启 DeepSeek Harness。`passwordRef` 和 `sessionTtlHours` 原地更新;`mode`、`tokenRef`、`gatePort` 或 `executable` 等隧道级变更会只重建插件自己的密码门或 `cloudflared`。新配置启动失败时,页面会显示错误并尽量保留旧隧道。切换回 Quick 模式时会保留 Token 模式字段,方便之后切回;Quick 模式会忽略这些字段。日常启停应使用页面开关;设置 Loader `disabled: true` 会卸载 Host 的 `auth-tunnel` 设置命名空间和卡片本身。

### 命名隧道模式

公网域名需要保持稳定时使用 token 模式。在 Cloudflare 创建命名隧道,绑定 `gui.example.com` 之类的域名,并让 dashboard ingress 指向固定 loopback 密码门,例如 `http://127.0.0.1:7677`。

把两个凭据写入 `$DSH_HOME/.credentials.yaml`:

```yaml
DSH_WEB_PASSWORD: 'replace-with-a-long-random-password'
DSH_TUNNEL_TOKEN: 'eyJhIjo...'
```

在 `$DSH_HOME/profiles/web/cordis.patch.yml` 中覆盖 bundle 行:

```yaml
- id: auth-tunnel
  disabled: false
  config:
    enabled: true
    mode: token
    tokenRef: DSH_TUNNEL_TOKEN
    publicHostname: gui.example.com
    gatePort: 7677
```

`publicHostname` 只能填写 DNS 主机名,不能带 `https://`、端口或路径。也可以在上述 Web 设置卡片中完成同样的配置并立即应用;修改 `gatePort` 后,仍需确保 Cloudflare Dashboard ingress 指向相同端口。

### 配置参考

| 键 | 类型 | 默认值 | 作用 |
|---|---|---|---|
| `enabled` | boolean | `true` | 是否运行密码门和 `cloudflared`;页面保存 `false` 后立即停止公网访问但保留设置页面。 |
| `passwordRef` | string(credential-ref) | `DSH_WEB_PASSWORD` | 解析共享访问密码的凭据引用;未配置会导致启动失败。 |
| `sessionTtlHours` | number ≥ 0.01 | `720` | Cookie 有效期,单位为小时,默认 30 天。 |
| `mode` | `quick` \| `token` | `quick` | 临时 quick 隧道或命名 token 隧道。 |
| `tokenRef` | string(credential-ref) | — | Tunnel Token 凭据引用;仅 token 模式。 |
| `publicHostname` | DNS hostname | — | 不带 scheme、端口或路径的命名隧道主机名;仅 token 模式。 |
| `gatePort` | integer 0…65535 | `0` | loopback 密码门端口;token 模式要求固定的非零值。 |
| `executable` | string | `cloudflared` | `cloudflared` 的 PATH 名称或绝对路径。 |
| `startupTimeoutMs` | integer ≥ 1 | `15000` | 激活等待隧道就绪的最长时间。 |

## 已知限制

- **共享密码、单用户信任**:每个密码持有者都可以访问完整 Web GUI,包括 Host 配置面。当前没有速率限制、锁定、按用户会话或服务端吊销表。轮换密码会使所有会话失效;更严肃的部署应使用 Cloudflare Access 或其他身份感知代理。
- **单隧道、无自动重启**:`cloudflared` 意外退出时会记录并显示错误,但不会自动重启;在页面关闭再开启隧道即可恢复。
- **Quick URL 每次启动都会变化**:需要固定 URL 时应使用 token 模式和自有域名。
- **Loopback 保持未认证**:密码只保护隧道路径;本机浏览器和进程仍可直接访问原始 Web GUI。
- **子进程环境最小化**:只继承 `PATH`、`HOME` 和 `TMPDIR`;公司代理应在插件之外为 `cloudflared` 配置。
- **Loopback HTTP 是明文**:密码门和上游 WebServer 通过同主机 loopback HTTP 通信;TLS 在 Cloudflare 终结。
- **每次启动只有一种目录选择器交互**:启用 bundle 后,本机客户端也使用应用内浏览器选择器,因为 Web 应用不能按连接分别选择原生和浏览器选择器。

## 工作原理

```text
public client
  → Cloudflare edge (TLS)
  → cloudflared (this host)
  → password gate, loopback only
  → existing loopback WebServer
```

### 密码门与代理

插件依赖 `webServer` 和 `credentials` 服务。它启动一个自己的 loopback `node:http` 密码门,解析配置的密码引用,再让 `cloudflared` 指向这道门。原始 WebServer 以及其他插件贡献的所有路由都原样保留在门后。

未认证的浏览器导航会重定向到 `/dsh-auth-tunnel/login`;其他未认证请求返回精简的 401。登录成功后签发 `HttpOnly; SameSite=Strict` 的 `dsh_auth_tunnel` Cookie,使用从密码派生的 HMAC 密钥签名。每次请求都会重新解析凭据,因此轮换密码会立即使已有会话失效。`GET` 或 `POST /dsh-auth-tunnel/logout` 会清除 Cookie。

密码门把登录请求体限制为 16 KiB,并代理已认证的 HTTP 与 WebSocket 流量。它把 `Host` 和匹配当前主机的浏览器 `Origin` 改写为 loopback 上游地址,让 WebServer 的 DNS-rebinding 与同源检查继续看到可信地址;外来或不透明 Origin 保持不变。HTTP 两段代理都会删除逐跳头并按连接重新生成,升级握手则保留协议需要的字段。客户端断开时,对应的上游请求也会取消。

唯一不需要认证的上游应用路由是只读的 `GET`/`HEAD /manifest.webmanifest`。除非页面明确要求带凭据获取 manifest,否则浏览器不会为这类请求携带凭据;该文件只包含公开的应用元数据。

### 目录选择器

bundle 会禁用启动时选择的原生目录选择器,并挂载应用内目录浏览器。公网 `host.pickDirectory` 无法操作 Host 显示器上的系统弹窗,否则会一直等待到 Cloudflare 返回 524。浏览器选择器无需按接口打补丁,即可同时服务本机和公网客户端。

### 隧道生命周期

- **quick** 执行 `cloudflared tunnel --url http://127.0.0.1:<gate>`,并从子进程输出读取生成的 `*.trycloudflare.com` URL。
- **token** 通过子进程环境变量 `TUNNEL_TOKEN` 传递 Tunnel Token,执行 `cloudflared tunnel run`,并等待连接注册标记。token 不会出现在 argv 中。

只有密码门开始监听且隧道报告就绪后,初次插件激活才会完成。凭据或模式字段无效、密码门端口被占用、可执行文件缺失、子进程提前退出或等待超时,都会在公布公网 URL 前让初次加载失败。运行期间的配置变更会串行合并;需要重建时先启动新资源,成功后再替换旧资源,失败则保留旧隧道并通过设置页状态接口报告。拆卸或页面关闭时会关闭密码门,向 `cloudflared` 发送 `SIGTERM`,必要时在 2000 ms 后升级为 `SIGKILL`,并移除 shell 与提示词贡献。

## 模型体验

隧道就绪后,插件通过可选的 shell-env 服务发布 `DSH_PUBLIC_URL`,并通过可选的 system-prompt 服务添加 `app:public-access` 提示段。没有这行插件时,两项贡献都不存在。

提示段渲染为:

```markdown
This instance is also reachable from the public internet at <publicUrl> through a Cloudflare Tunnel, protected by the instance's shared access password. Share that URL — never the password — when the user asks to open this GUI from another device or network. All sessions, tools, and files still run on this host.
```

该提示段在隧道进程存活期间保持静态,不会使跨轮 KV cache 失效。
