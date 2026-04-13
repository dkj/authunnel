# Authunnel: Proposal for Deployment

## The Opportunity

Remote access to internal SSH services is a common need across the institute. The existing solutions serve this need, but have either limitations or significant costs:

- **Teleport** integrates with Okta SSO and works well, but escalating licence fees are a growing concern for what is mostly used as an "SSH to an internal host" use case.
- **VPN** is often effective for staff on Sanger laptops. However, it is not available to those working from non-Sanger machines, and it grants broader network access than some use cases require.
- **The legacy bastion** (ssh-gateway) was decommissioned several years ago due to a lack of resource to maintain it and no integration with SSO. _(Is this correct?)_

Authunnel is a lightweight, purpose-built tool that fills these gaps. It tunnels SSH connections over an Okta-authenticated WebSocket, using infrastructure the institute already operates. Initially, it can complement existing access methods rather than necessarily replacing them.

## What Authunnel Is

Authunnel is an authenticated tunnel for reaching internal SSH services. Users run `ssh` as normal; the Authunnel client, configured as an SSH `ProxyCommand`, transparently handles Okta login via the browser and establishes an encrypted WebSocket tunnel to the server. The server acts as an OAuth2 resource server — it validates the Okta-issued JWT access token (signature, issuer, expiry, audience) and proxies the SSH connection to the requested internal host. The entire system is a single Go binary with no database, no external state, and no licence fees.

## Why Authunnel

1. **Zero licence cost** Authunnel is a single Go binary with no commercial dependencies. There is no per-seat fee, no annual renewal, no vendor lock-in. The total infrastructure cost is one or two small VMs.

2. **Uses existing Okta SSO.** Users authenticate via the same Okta login they already use. When someone is offboarded in Okta, they immediately lose Authunnel access. It requires only an issuer URL and a token audience — no client secrets, no synced user database.

3. **Can run behind Ivanti Traffic Manager (vTM).** Authunnel can run in plaintext mode behind a TLS-terminating reverse proxy, benefiting from the team's existing knowledge and experience of Ivanti as an external interface. Ivanti handles TLS certificates and termination as it already does for other services. No new TLS infrastructure is needed.

4. **Minimal attack surface.** The entire codebase is approximately 2,000 lines of Go (excluding tests). A security reviewer can read it in full in an afternoon. On Linux, the server drops all capabilities and sets `PR_SET_NO_NEW_PRIVS` after binding ports, limiting the impact of any future vulnerability.

5. **Scoped access at multiple levels.** Access can be restricted at several independent layers, each enforced by a different part of the infrastructure:
   - **Application layer:** The `--allow` option restricts which destinations authenticated users can reach, using host glob patterns and CIDR rules (e.g. `*.internal:22`, `10.0.0.0/8:22`).
   - **Network layer:** VMware or OpenStack security groups on the server VM control both inbound access (who can reach the Authunnel server) and outbound access (which internal hosts the server can connect to).

   This is useful for granting access to specific services only, or for limiting exposure to the broader network.

6. **Works from macOS or Linux machines.** The client is a statically compiled binary available for macOS and Linux (amd64 and arm64). It requires no special network configuration and no Sanger-issued hardware. This makes it suitable for staff working from personal machines, university desktops, or cloud development environments where the VPN is not an option. If Windows clients are required this should be a small amount of work to deliver.

7. **Transparent audit trail.** Every tunnel is logged with the authenticated user's identity and destination. Denied connections are logged at warn level. Logs are structured JSON with request and trace correlation IDs, ready for ingestion into ELK or Splunk without custom parsing (see Logging & Observability below).

8. **Familiar user experience.** Users add a `ProxyCommand` entry to their SSH config. On first use, a browser tab opens for Okta login. Subsequent SSH sessions reuse cached or refreshed tokens silently — SSH "just works" without re-authenticating each time.

9. **Maintainable by design.** The codebase is deliberately kept small and simple. Any developer comfortable with Go should be able to understand and patch the code if required.

10. **Horizontally scalable.** Server instances share no state. Multiple instances can run behind Ivanti load balancing for high availability. Scaling is simply adding another VM.

## Deployment Architecture

```
User's machine                    Sanger infrastructure
─────────────                    ──────────────────────
ssh internal-host
  └─ authunnel-client
       └─ HTTPS WebSocket ──→  Ivanti vTM (TLS termination, :443)
                                   └─ HTTP ──→  authunnel-server VM (:8080)
                                                  └─ SOCKS5 CONNECT ──→  internal-host:22
```

**Components:**

- **Ivanti Traffic Manager** — TLS termination at `st.sanger.ac.uk:443`, forwarding to the backend VM on port 8080. Requires WebSocket upgrade pass-through and setting `X-Forwarded-Proto` and `X-Forwarded-Host` headers on forwarded requests.
- **Server VM** (VMware or OpenStack) — a single small Linux VM running the authunnel-server binary, managed by systemd. No database, no disk state beyond the binary and a configuration file. Security groups restrict both inbound access (to the Ivanti VIP) and outbound access (to permitted internal hosts only).
- **Okta** — one public OIDC client registration (for the CLI tool) and one audience/resource entry (for token scoping to `authunnel-server`).
- **DNS** — `st.sanger.ac.uk` pointing at the Ivanti VIP.

**Server configuration** is minimal:

```bash
OIDC_ISSUER='https://<okta-issuer-url>'
TOKEN_AUDIENCE='authunnel-server'
PLAINTEXT_BEHIND_REVERSE_PROXY=true
ALLOW_RULES='*.internal.sanger.ac.uk:22'
```

**Client configuration** is an SSH config entry:

```sshconfig
Host *.internal.sanger.ac.uk
  ProxyCommand authunnel-client \
    --ws-url https://st.sanger.ac.uk/protected/socks \
    --oidc-issuer https://<okta-issuer-url> \
    --oidc-client-id authunnel-cli \
    --oidc-audience authunnel-server \
    --proxycommand %h %p
```

## What's Required

| Item | Owner | Effort |
|------|-------|--------|
| Okta public OIDC client + audience | Identity team | ~30 min config |
| VM (small, any Linux) | Infrastructure | Standard provisioning |
| Ivanti VIP + TLS cert for `st.sanger.ac.uk` | Network / Ivanti team | Standard config |
| WebSocket upgrade pass-through on Ivanti | Network / Ivanti team | Standard config |
| DNS entry for `st.sanger.ac.uk` | Network team | ~5 min |
| Security groups (inbound from Ivanti, outbound to Okta, logging endpoints, and permitted hosts) | Infrastructure / Network team | Standard config |
| Deploy binary + systemd unit | Infrastructure & Authunnel maintainer | ~1 hour |
| Log shipping (Filebeat or Splunk UF) | Logging / observability team | Standard config (see below) |
| Security review of codebase and deployment architecture | Security team | See below |
| Client binary distribution + SSH config docs | Authunnel maintainer | Documentation task |

## Logging & Observability

Authunnel emits structured JSON logs to stderr via Go's `slog.JSONHandler`. Every log line is a self-contained JSON object. Systemd captures stderr by default, so logs are available in the journal immediately.

**What gets logged:**

| Event | Level | Key fields |
|-------|-------|------------|
| HTTP request | info | `method`, `path`, `status`, `bytes`, `duration_ms`, `remote_ip`, `request_id`, `trace_id` |
| Tunnel open | info | `tunnel_id`, `remote_ip`, `user`, `email`, `subject`, `client_id` |
| Tunnel close | info | `tunnel_id`, `duration_ms`, plus all identity fields |
| SOCKS destination | debug | `target_host`, `target_port`, plus tunnel and identity fields |
| Connection denied | warn | `target_host`, `target_port`, plus tunnel and identity fields |
| Auth failure | warn | `remote_ip`, `request_id`, error detail |

**Example log line** (tunnel open):

```json
{
  "time": "2026-04-07T10:15:32.456Z",
  "level": "INFO",
  "msg": "tunnel_open",
  "request_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "trace_id": "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3",
  "tunnel_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
  "remote_ip": "203.0.113.42",
  "user": "dj3",
  "email": "dj3@sanger.ac.uk",
  "subject": "00u1a2b3c4d5e6f7g",
  "client_id": "authunnel-cli"
}
```

**Integration with ELK / Splunk:**

Since the output is already structured JSON, integration with ELK (via Filebeat) or Splunk (via Universal Forwarder) requires only a standard JSON input — no grok patterns or custom parsing.

Setting `--log-level debug` enables per-connection destination logging, providing full audit visibility of which internal hosts each user connects to.

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Ivanti vTM limitations (licensing or implementation) prevent, or have significant negatives if used for Authunnel TLS termination | Consider either Ivanti vTM changes and instead of vTM mediated access, firewall based access to suitably isolated Authunnel instances. |
| WebSocket blocked by network policy | Authunnel uses standard HTTPS on port 443 with a WebSocket upgrade — the same mechanism used by most modern web applications. Ivanti already handles WebSocket traffic. |
| Okta outage prevents new logins | Cached and refresh tokens allow continued access for hours. Only first-time logins or expired refresh tokens require live Okta connectivity. |
| Single server is a single point of failure | Server instances are stateless. Run two or more behind Ivanti load balancing for high availability. |
| Maintainability over time | The codebase is ~2,000 lines of Go with an explicit design goal of auditability. It has significantly lower maintenance burden than a full platform like Teleport. |
| Security of non-Sanger client machines | Authunnel does not trust the client machine. It provides only a tunnel — the SSH host still requires its own authentication (keys, certificates, etc.). Allow rules and VM security groups independently limit which destinations a tunnel can reach. |

## Scope & Limitations

Authunnel's current functionality is SSH tunnelling. It does not provide the additional capabilities that Teleport offers, such as Okta-gated access to internal web applications. Where those capabilities are needed, it may be worth exploring whether existing infrastructure — such as the Ivanti Traffic Manager or other systems — could provide them independently.

## Security Review

We would like the security team to consider reviewing the deployment architecture and the code with the prospect of a production rollout. A non-exhaustive list where their input would be valuable:

- **Authentication model** — the server validates JWT access tokens locally via OIDC discovery and JWKS. Is the token validation (signature, issuer, expiry, audience) sufficient? 
- **Network architecture** — the server runs behind Ivanti with security groups restricting inbound and outbound traffic. Are the proposed security group rules and allow rules appropriate?
- **Capability dropping** — on Linux, the server drops all capabilities and sets `PR_SET_NO_NEW_PRIVS` after binding ports. Is this hardening adequate for the deployment environment?
- **Logging and monitoring** — are the logged fields sufficient for incident response and audit purposes? Are there additional events or fields the security team would want to see?
- **Threat model** — what residual risks does the security team see with an authenticated WebSocket tunnel to internal SSH hosts, how do these compare with the existing Teleport provision, and what additional controls (if any) would they recommend?

The [codebase is open](https://github.com/dkj/authunnel/blob/main/README.md) and so avialable for review now. Given its size (~2,000 lines of Go excluding tests), a full read-through is realistic within a single session.

## Proposed Rollout

1. **Security review** — engage the security team for review of the codebase and proposed deployment architecture. Incorporate their findings before proceeding.
2. **Pilot** — deploy to a small group of willing early adopters, particularly those working from non-Sanger machines or those who would benefit from scoped SSH-only access.
3. **Evaluate** — confirm that token lifecycle (cache, refresh, re-login), allow rules, logging integration, and user experience meet expectations.
4. **Expand** — roll out to the broader user base with documentation and SSH config examples.
5. **Assess Teleport** — once Authunnel is proven in production, evaluate whether Teleport licence renewal is still justified at the next contract cycle.
