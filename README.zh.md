# @deepseek-ai/dsh-auth-tunnel

[English](README.md) | 中文

通过 Cloudflare Tunnel 为 Web GUI 提供带密码的公网访问,打包成单个自包含插件:启动一个只监听 loopback 的**密码门**(完全归插件所有的 `node:http` 代理),把 `cloudflared` 指到这道门上,并把公网 URL 告知操作者、shell 和模型。需要从另一台设备或网络打开 GUI 时挂载这一行;行不存在时一切照旧——loopback webserver 直接响应浏览器。

```
public client
  → Cloudflare edge (TLS)
  → cloudflared (this host)
  → gate, loopback only   ← login page, cookie check, Host rewrite
  → loopback webserver    ← unchanged: routes, fallback, /api fence
```

保护在门上,因此该行只针对服务工作:它要求 `webServer` 与 `credentials`(`inject = ['webServer', 'credentials']`,组合缺少任一服务时该行保持 pending),通过二者解析代理目标与密码,并在可选的 shell-env 和 system-prompt 服务挂载时注入事实。任何面向 Web 的包都不需要改动。门后,被放行的请求会被代理到上游,`Host` 和匹配该主机的浏览器 `Origin` 都改写为 loopback 地址,使 connection 的 DNS-rebinding 与同源信任栅栏(`/api` 防护)看到它为之构建的 loopback 面;外来或不透明 Origin 保持原样,仍会被上游拒绝。直接访问 `127.0.0.1:<webserver 端口>` 是有意的未认证:密码只锁公网路径。

握手是一段共享访问密码加 `/dsh-auth-tunnel/login` 的自包含登录页:组合配置只放密码引用(绝不放密码值);POST 成功即签发 `dsh_auth_tunnel`——一个 `HttpOnly; SameSite=Strict` Cookie,HMAC 密钥是 `SHA-256(password)`;密码错误时携带 `?error=1` 反弹。会话密钥**每次请求**重新解析,所以更换所引用的凭据会使所有已开会话立即失效,无需重启(内联测试组合证明了这一点)。`GET/POST /dsh-auth-tunnel/logout` 清除客户端 Cookie。登录请求体上限 16 KiB(声明长度与流式都算),类型错误返回 415;未认证请求由门回答 302 到登录页(导航请求、`Sec-Fetch-Dest: document` 或 `Accept: text/html`)或极简的 401 JSON(其他一切,包括升级请求)。WebSocket/升级连接同样先过 Cookie 检查,然后双向转发原始字节,任一侧关闭时一并拆掉对端。

## Cloudflare 模式

- **quick** 拉起 `cloudflared tunnel --url http://127.0.0.1:<gate>` 并从子进程输出中抓取 `*.trycloudflare.com` URL。快速隧道的主机名每次运行都会变,边缘立即可达。
- **token** 拉起 `cloudflared tunnel run`,Tunnel Token 通过 `TUNNEL_TOKEN` 环境变量传递(绝不经 argv),并等待 `Registered tunnel connection` 就绪标记。命名隧道的 dashboard ingress 必须指向门地址,因此 token 模式下 `gatePort` 是必填的固定值,`publicHostname` 是你在 dashboard 绑定的主机名。`tokenRef` 同样只命名一个凭据引用(存在 `.credentials.yaml` 或 `$DSH_ENV`),绝不放 token 本身。

激活阶段就把能校验的全部校验掉,并在任何公网 URL 出现之前让启动失败:不可解析的 `passwordRef`;模式键矛盾(quick 模式里出现 `tokenRef`);token 模式缺 `publicHostname`/`gatePort`;不可解析的 `tokenRef`;cloudflared 可执行文件缺失;子进程提前退出(附带限长尾部的诊断);以及超时。隧道就绪之前激活不完成;完成后控制台打印 `cloudflare tunnel: <url>`,shell 得到 `DSH_PUBLIC_URL`(shell-env 行挂载时),模型看到 `app:public-access` 提示段(system-prompt 行挂载时)。拆卸时关闭密码门、终止 cloudflared(先 SIGTERM,2000 ms 后 SIGKILL),并移除两项注册贡献;子进程意外退出会以错误级别记录并点名已死的 URL。

## 配置

| 键 | 类型 | 默认 | 效果 |
|---|---|---|---|
| `passwordRef` | string(credential-ref) | `DSH_WEB_PASSWORD` | 解析共享访问密码的凭据引用;未配置则启动失败。 |
| `sessionTtlHours` | number ≥ 0.01 | `720` | Cookie 有效期(小时,30 天)。 |
| `mode` | `quick` \| `token` | `quick` | 隧道模式;见上。 |
| `tokenRef` | string(credential-ref) | — | Tunnel Token 引用;仅 token 模式。 |
| `publicHostname` | string | — | 命名隧道主机名,用于 URL 行和模型事实;仅 token 模式。 |
| `gatePort` | integer 0…65535 | `0` | 密码门监听的 loopback 端口;0 交给操作系统。token 模式必须显式给出,因为 dashboard ingress 指向它。 |
| `executable` | string | `cloudflared` | cloudflared 可执行文件:PATH 名或绝对路径。 |
| `startupTimeoutMs` | integer ≥ 1 | `15000` | 激活等待隧道就绪的时长。 |

随包的 Web bundle 已自带该行(默认禁用)。通过你自己的 profile patch 层 `~/.dsh/profiles/web/cordis.patch.yml`(`$DSH_HOME` 默认为 `~/.dsh`;你的 patch 应用在所有 bundle 层之后,且启动器会监听该文件,运行中的实例无需重启)启用:

```yaml
- id: auth-tunnel
  disabled: false
```

脱离 monorepo 的安装(独立克隆本仓库)以 bundle 形式一条命令装完——包自带的 patch 层会自动插入该组合行:

```sh
dsh plugin --profile web add <package>
```

`<package>` 是本仓库的 npm 名、git 地址或 `file:` 路径。上面这个 bundle 层足以按默认值启动;只有要覆盖键(token 模式、TTL、端口)时,才把同样的 `auth-tunnel` 行写进你 profile 的 patch 层。

`dsh web` 启动时打印 `cloudflare tunnel: https://<random>.trycloudflare.com`;浏览器首先看到密码页,挂上的行(id `auth-tunnel`)与其他条目一样出现在 Web Settings → Plugins 中。命名隧道模式扩展同一条 patch 行:

```yaml
- id: auth-tunnel
  disabled: false
  config:
    mode: token
    tokenRef: DSH_TUNNEL_TOKEN
    publicHostname: gui.example.com
    gatePort: 7677
```

同时把 `cloudflared` dashboard 中 `gui.example.com` 的 ingress 指向 `http://localhost:7677`,并把 `DSH_TUNNEL_TOKEN`/`DSH_WEB_PASSWORD` 存为凭据,例如在 `$DSH_HOME/.credentials.yaml`:

```yaml
DSH_WEB_PASSWORD: 'pick-a-long-random-password'
DSH_TUNNEL_TOKEN: 'eyJhIjo...'
```

## 模型体验

### 公网访问提示段

#### 模型看到的内容

隧道就绪后,一个提示段(`app:public-access`,order −97)给出公网 URL、共享密码保护、"只分享 URL,绝不分享密码"的规则,以及一切仍在本机运行的保证;`<publicUrl>` 是抓到的快速隧道 URL 或 token 配置里的 `https://<publicHostname>`。通过 bash 工具启动的 shell 还会看到 `auth-tunnel` 贡献者提供的 `DSH_PUBLIC_URL` 托管变量(带描述),每次调用从活跃隧道解析。没有这一行时两者都不存在。精确渲染文本:

##### Rendered prompt section

```markdown
This instance is also reachable from the public internet at <publicUrl> through a Cloudflare Tunnel, protected by the instance's shared access password. Share that URL — never the password — when the user asks to open this GUI from another device or network. All sessions, tools, and files still run on this host.
```

#### Token 影响

每进程一段提示段落加两行托管环境变量;每次隧道挂载期间恒定。

#### KV Cache 影响

该提示段在进程存活期间是静态的(URL 是启动期事实),不会使跨轮缓存失效。

## 已知限制与延后工作

- **共享密码、单用户**:每个密码持有者都获得完整 Web GUI,包括 Host 配置面;无速率限制、无锁定、无按用户会话、无服务端吊销表(密码轮换会全量失效)。更严肃的部署应当换更强的前置认证。
- **单隧道、无自重启**:cloudflared 意外退出会以错误记录,但隧道不会复活;需要重启 dsh。
- **快速隧道 URL 不稳定**:`*.trycloudflare.com` 主机名每次运行都变;token 模式的代价是一条命名隧道加一个域名。
- **本地绕行**:loopback 浏览器按设计保持对 Web GUI 的未认证访问(门只挡隧道入口);如果威胁模型覆盖本机进程,请把整个 GUI 放在私有网络中运行。
- **子进程环境最小化**:只继承 PATH、HOME、TMPDIR;公司代理后的 cloudflared 需要它自己的系统级配置,而不是在这里加环境变量。
- **密码门与上游之间是明文 HTTP**:两者都是同主机上的 loopback 监听者,在当前拓扑下 TLS 没有增加任何东西。
