# @deepseek-ai/dsh-auth-tunnel

English | [中文](README.zh.md)

Password-gated public access for the Web GUI through a Cloudflare Tunnel, packaged as one self-contained plugin: it starts a loopback **password gate** (a `node:http` proxy it owns outright), points `cloudflared` at that gate, and tells the operator, the shell, and the model the public URL. Mount the row when you want to open the GUI from another device or network; with the row absent nothing changes — the loopback webserver keeps answering browsers directly.

```
public client
  → Cloudflare edge (TLS)
  → cloudflared (this host)
  → gate, loopback only   ← login page, cookie check, Host rewrite
  → loopback webserver    ← unchanged: routes, fallback, /api fence
```

The gate is the protection, so the row works purely against services: it requires `webServer` and `credentials` (`inject = ['webServer', 'credentials']`, so a composition missing either service leaves the row pending), resolves the proxy target and password through them, and publishes facts into optional shell-env and system-prompt services when mounted. No web-facing package changes shape. Behind the gate, accepted requests are proxied to the upstream with their `Host` and matching browser `Origin` rewritten to the loopback authority, which keeps the connection's DNS-rebinding and same-origin trust fence (`/api` guards) reading the loopback surface it was built for; foreign or opaque origins remain unchanged and are still rejected upstream. Direct use of `127.0.0.1:<webserver port>` stays unauthenticated on purpose: the password only locks the public path.

The handshake is a shared access password over a self-contained login page at `/dsh-auth-tunnel/login`: the password reference (never the value) lives in composition config; a successful POST mints `dsh_auth_tunnel`, an `HttpOnly; SameSite=Strict` cookie whose HMAC key is `SHA-256(password)`; a wrong password bounces with `?error=1`. Session keys resolve **per request**, so rotating the referenced credential invalidates every open session without a restart (the inline test composition proves this). `GET/POST /dsh-auth-tunnel/logout` clears the client-side cookie. Login posts are capped at 16 KiB (declared and streamed), a wrong content type answers 415, and the gate answers unauthenticated requests with 302 to the login page (navigation, `Sec-Fetch-Dest: document`, or `Accept: text/html`) or a terse 401 JSON (anything else, including upgrades). WebSocket/upgrade connections pass the same cookie check and then pipe raw bytes both ways, taking down their peer when one side closes.

## Cloudflare modes

- **quick** spawns `cloudflared tunnel --url http://127.0.0.1:<gate>` and scrapes the `*.trycloudflare.com` URL from the child output. Quick-tunnel hostnames change every run and are edge-reachable immediately.
- **token** spawns `cloudflared tunnel run` with the Tunnel Token over the `TUNNEL_TOKEN` environment (never argv) and waits for the `Registered tunnel connection` marker. The named tunnel's dashboard ingress must point at the gate's address, so `gatePort` is a mandatory, fixed value in token mode and `publicHostname` the hostname you bound in the dashboard. `tokenRef` likewise names a credential reference held in `.credentials.yaml` or `$DSH_ENV`, never the token.

Activation validates what it can and fails the boot before any public URL exists: an unresolvable `passwordRef`, contradictory mode keys (`tokenRef` in quick mode), a token-mode row missing `publicHostname`/`gatePort`, an unresolvable `tokenRef`, a missing cloudflared executable, an exited child (with a tail-bounded diagnostic), and a timeout. Activation completes only once the tunnel is up; afterwards the console shows `cloudflare tunnel: <url>`, shells get `DSH_PUBLIC_URL` (when the shell-env row is mounted), and the model sees the `app:public-access` prompt section (when the system-prompt row is mounted). Disposal closes the gate, terminates cloudflared (SIGTERM, SIGKILL after 2000 ms), and removes both registry contributions; an unexpected child exit logs an error naming the dead URL.

## Config

| Key | Type | Default | Effect |
|---|---|---|---|
| `passwordRef` | string (credential-ref) | `DSH_WEB_PASSWORD` | Credential reference resolving to the shared access password; unconfigured fails the boot. |
| `sessionTtlHours` | number ≥ 0.01 | `720` | Cookie lifetime in hours (30 days). |
| `mode` | `quick` \| `token` | `quick` | Tunnel flavor; see above. |
| `tokenRef` | string (credential-ref) | — | Tunnel Token reference; `token` mode only. |
| `publicHostname` | string | — | Named-tunnel hostname for the URL line and model facts; `token` mode only. |
| `gatePort` | integer 0…65535 | `0` | Loopback port the gate binds; 0 asks the OS. `token` mode requires an explicit value because the dashboard ingress points at it. |
| `executable` | string | `cloudflared` | cloudflared executable: PATH name or absolute path. |
| `startupTimeoutMs` | integer ≥ 1 | `15000` | How long activation waits for the tunnel to come up. |

The shipped Web bundle already contains the row (disabled). Enable it through your own profile patch layer at `~/.dsh/profiles/web/cordis.patch.yml` (`$DSH_HOME` defaults to `~/.dsh`; your patches apply after every bundle layer, and the launcher watches that file, so no restart is needed on a running instance):

```yaml
- id: auth-tunnel
  disabled: false
```

Out-of-the-monorepo installs (this repository cloned standalone) install it as a bundle with one command — the package's own patch layer inserts the row automatically:

```sh
dsh plugin --profile web add <package>
```

`<package>` is this repository's npm name, git URL, or `file:` path. The bundle layer above is enough to boot with defaults; add the same `auth-tunnel` row to your profile patch only to override keys (token mode, TTL, ports).

`dsh web` prints `cloudflare tunnel: https://<random>.trycloudflare.com` on startup; the browser shows the password page first, and the mounted row (id `auth-tunnel`) appears in Web Settings → Plugins like every other entry. For named-tunnel mode extend the same patch row:

```yaml
- id: auth-tunnel
  disabled: false
  config:
    mode: token
    tokenRef: DSH_TUNNEL_TOKEN
    publicHostname: gui.example.com
    gatePort: 7677
```

…with `cloudflared`'s dashboard ingress for `gui.example.com` pointing at `http://localhost:7677`, and `DSH_TUNNEL_TOKEN`/`DSH_WEB_PASSWORD` stored as credentials, e.g. in `$DSH_HOME/.credentials.yaml`:

```yaml
DSH_WEB_PASSWORD: 'pick-a-long-random-password'
DSH_TUNNEL_TOKEN: 'eyJhIjo...'
```

## Model Experience

### Public-access section

#### What the model sees

Once the tunnel is up, one prompt section (`app:public-access`, order −97) names the public URL, the shared-password protection, the rule to share the URL but never the password, and the assurance that everything still runs on this host; `<publicUrl>` is the discovered quick-tunnel URL or `https://<publicHostname>` from the token config. Shells started through the bash tool additionally see the `DSH_PUBLIC_URL` managed variable (with its description) from the `auth-tunnel` contributor, resolved per invocation from the live tunnel. Without this row neither artifact exists. The exact rendered text:

##### Rendered prompt section

```markdown
This instance is also reachable from the public internet at <publicUrl> through a Cloudflare Tunnel, protected by the instance's shared access password. Share that URL — never the password — when the user asks to open this GUI from another device or network. All sessions, tools, and files still run on this host.
```

#### Token effect

One prompt paragraph per process plus two managed-environment variable lines; constant per tunnel mount.

#### KV Cache effect

The section is static for the life of the process (the URL is a boot fact), so it does not invalidate the cache across turns.

## Known Limitations and Deferred Work

- **Shared-password, one user**: every password holder receives the whole Web GUI, including its Host configuration plane; there is no rate limiting, lockout, per-user session, or server-side revocation list (password rotation invalidates everything). A webmail-grade deployment would front something stronger than this.
- **Single tunnel, no auto-restart**: an unexpected cloudflared exit is logged as an error, but the tunnel does not resurrect; restart dsh.
- **Quick URLs are unstable**: `*.trycloudflare.com` hostnames change every run; token mode costs a named tunnel plus a domain.
- **Local bypass**: loopback browsers keep unauthenticated access to the Web GUI by design (the gate only fronts the tunnel); if your threat model covers local processes, run the whole GUI on a private network instead.
- **Child environment is minimal**: PATH, HOME, and TMPDIR are the only inherited variables; cloudflared running behind a corporate proxy needs its own system-level config, not environment variables added here.
- **Plain HTTP between gate and upstream**: both are loopback listeners on the same host, so TLS adds nothing until multi-host topologies exist.
