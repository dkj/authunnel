# Authunnel: Proposal for Deployment

## The Opportunity

Remote access to internal SSH services is a common need across the institute. The existing solutions serve this need, but have either limitations or significant costs:

- **Teleport** integrates with Okta SSO and works well, but escalating licence fees are a growing concern for what is mostly used as an "SSH to an internal host" use case.
- **VPN** is often effective for staff on Sanger laptops. However, it is not available to those working from non-Sanger machines, and it grants broader network access than some use cases require.
- **The legacy bastion** (ssh-gateway) was decommissioned several years ago due to a lack of resource to maintain it and no integration with SSO. _(Is this correct?)_

Authunnel is a lightweight, purpose-built tool that fills these gaps. It tunnels SSH connections over an Okta-authenticated WebSocket, using infrastructure the institute already operates. Initially, it can complement existing access methods rather than necessarily replacing them.

## What Authunnel Is

Authunnel is an authenticated tunnel for reaching internal SSH services. Users run `ssh` as normal; the Authunnel client, configured as an SSH `ProxyCommand`, transparently handles Okta login via the browser and establishes an encrypted WebSocket tunnel to the server. The server acts as an OAuth2 resource server — it validates the Okta-issued JWT access token (signature, issuer, expiry, audience, subject presence, `iat` sanity, `nbf`) and proxies the SSH connection to the requested internal host. Tunnel lifetime is bound to the access token's expiry by default: when the token expires the tunnel closes, unless the client refreshes the token (typically silently) while the tunnel is still alive. The entire system is a single Go binary with no database, no external state, and no licence fees.

## Why Authunnel

1. **Zero licence cost** Authunnel is a single Go binary with no commercial dependencies. There is no per-seat fee, no annual renewal, no vendor lock-in. The total infrastructure cost is one or two small VMs.

2. **Uses existing Okta SSO, with prompt offboarding.** Users authenticate via the same Okta login they already use. Tunnel lifetime is bound to the access token's expiry, so when someone is offboarded in Okta they lose Authunnel access as soon as their current access token expires (typically minutes, not hours) — refresh attempts fail immediately against Okta. The server requires only an issuer URL and a token audience — no client secrets, no synced user database.

3. **Can run behind Ivanti Traffic Manager (vTM).** Authunnel can run in plaintext mode behind a TLS-terminating reverse proxy, benefiting from the team's existing knowledge and experience of Ivanti as an external interface. Ivanti handles TLS certificates and termination as it already does for other services. No new TLS infrastructure is needed.

4. **Minimal attack surface.** The entire codebase is approximately 3,400 lines of Go source (excluding tests, comments, and blanks). A security reviewer can read it in full over a day or two. On Linux, the server drops all capabilities and sets `PR_SET_NO_NEW_PRIVS` after binding ports, limiting the impact of any future vulnerability. The OIDC issuer and tunnel URLs must use HTTPS (plain HTTP is rejected at startup). The client validates ownership and permissions on its token-cache and unix-socket directories before use — important for shared hosts such as HPC login nodes.

5. **Scoped access at multiple levels.** Access can be restricted at several independent layers, each enforced by a different part of the infrastructure:
   - **Destination allowlist:** The `--allow` option restricts which destinations authenticated users can reach, using host glob patterns and CIDR rules (e.g. `*.internal:22`, `10.0.0.0/8:22`). Starting the server without either `--allow` rules or an explicit `--allow-open-egress` flag is rejected — the egress posture is never silently permissive.
   - **Admission limits:** Per-user and global caps on concurrent tunnels, plus per-user open-rate limits, bound the impact of credential abuse or misbehaving clients.
   - **Network layer:** VMware or OpenStack security groups on the server VM control both inbound access (only from the Ivanti VIP) and outbound access. The outbound allowlist must include the Okta OIDC endpoints (for discovery and JWKS), the centralised logging endpoints (ELK / Splunk), and the permitted internal SSH destinations — and nothing else.

   This is useful for granting access to specific services only, or for limiting exposure to the broader network.

6. **Works from any machine.** The client is a statically compiled binary available for Linux, macOS, and Windows (10 1803 or later). It requires no special network configuration and no Sanger-issued hardware. This makes it suitable for staff working from personal machines, for academic collaborators, or commercial partners where the company VPN is not an option.

7. **Transparent audit trail.** Every tunnel is logged with the authenticated user's identity and destination. Denied connections are logged at warn level. Logs are structured JSON with request and trace correlation IDs, ready for ingestion into ELK or Splunk without custom parsing (see Logging & Observability below).

8. **Familiar user experience.** Users add a `ProxyCommand` entry to their SSH config. On first use, a browser tab opens for Okta login. Subsequent SSH sessions reuse cached or refreshed tokens silently — SSH "just works" without re-authenticating each time.

9. **Maintainable by design.** The codebase is deliberately kept small and simple. Any developer comfortable with Go should be able to understand and patch the code if required.

10. **Horizontally scalable.** Server instances share no state. Multiple instances can run behind Ivanti load balancing for high availability. Scaling is simply adding another VM.

11. **Admission controls against abuse.** The server supports optional global and per-user caps on concurrent tunnels, a per-user tunnel-open rate limit with burst, and a bounded dial timeout for outbound SOCKS CONNECT. Over-limit requests receive `429`/`503` with `Retry-After`. This bounds the blast radius of a compromised credential or a misbehaving client without requiring an external rate-limiting layer.

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

- **Ivanti Traffic Manager** — TLS termination at `st.sanger.ac.uk:443`, forwarding to the backend VM on port 8080. Configured to accept HTTPS only — any plain HTTP listener should either be absent or redirect to HTTPS; it must never accept plaintext client traffic. Requires WebSocket upgrade pass-through and setting `X-Forwarded-Proto` and `X-Forwarded-Host` headers on forwarded requests.
- **Server VM** (VMware or OpenStack) — a single small Linux VM running the authunnel-server binary, managed by systemd. No database, no disk state beyond the binary and a configuration file. Security groups restrict inbound access (only from the Ivanti VIP) and outbound access (only to Okta OIDC endpoints, centralised logging endpoints, and the permitted internal SSH destinations).
- **Okta** — one public OIDC client registration (for the CLI tool) and one audience/resource entry (for token scoping to `authunnel-server`).
- **DNS** — `st.sanger.ac.uk` pointing at the Ivanti VIP.

**Server configuration** is minimal:

```bash
OIDC_ISSUER='https://<okta-issuer-url>'
TOKEN_AUDIENCE='authunnel-server'
PLAINTEXT_BEHIND_REVERSE_PROXY=true
ALLOW_RULES='*.internal.sanger.ac.uk:22'
```

Initial deployment would limit egress to `*.internal.sanger.ac.uk:22`, or a tightly monitored subset. The server refuses to start without either one or more `--allow` rules or an explicit `--allow-open-egress` flag, so the egress posture is always a deliberate operator choice.

**Client configuration** is an SSH config entry:

```sshconfig
Host *.internal.sanger.ac.uk
  ProxyCommand authunnel-client \
    --tunnel-url https://st.sanger.ac.uk/protected/tunnel \
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
| Ivanti VIP + TLS cert for `st.sanger.ac.uk`, configured to accept HTTPS only (no plain HTTP listener, or 80→443 redirect at most) | Network / Ivanti team | Standard config |
| WebSocket upgrade pass-through on Ivanti | Network / Ivanti team | Standard config |
| DNS entry for `st.sanger.ac.uk` | Network team | ~5 min |
| Security groups (inbound from Ivanti, outbound to Okta, logging endpoints, and permitted hosts) | Infrastructure / Network team | Standard config |
| Deploy binary + systemd unit | Infrastructure & Authunnel maintainer | ~1 hour |
| Log shipping from server VM (Filebeat or Splunk UF) | Logging / observability team | Standard config (see below) |
| Ivanti access/TLS log shipping to the same logging system | Network / Ivanti team + Logging team | Standard config; ideally configure Ivanti to emit a `Traceparent` header so server logs and Ivanti logs can be joined by `trace_id` |
| Log receiver configuration (Elasticsearch index + Kibana, or Splunk index + sourcetype) for both Authunnel server and Ivanti logs, plus any required dashboards or alerts | Logging / observability team | Standard config — structured JSON means fields are available without parsing |
| Security review of codebase and deployment architecture | Security team | See below |
| Host vulnerability scanning enrolment (Rapid7 InsightVM or equivalent) for the server VM | Infrastructure / Security team | Standard config — enrol VM in existing scanner |
| SAST/SCA CI jobs (`govulncheck`, `gosec`, `staticcheck`, `go vet`, Dependabot) | Authunnel maintainer | Already in place (daily cron + per-PR); CodeQL can be added if required |
| SBOM generation per release (CycloneDX JSON) | Authunnel maintainer | Already in place — generated and published automatically per release binary |
| Client binary distribution + SSH config docs | Authunnel maintainer | Documentation task |

The repository's [Deployment Hardening Checklist](https://github.com/dkj/authunnel/blob/main/README.md#deployment-hardening-checklist) provides a concrete pre-production checklist (HTTPS enforcement, egress posture, admission limits, dial timeout, socket hygiene, reverse-proxy header handling, etc.) that the infrastructure and security teams can work against directly.

## Logging & Observability

Authunnel emits structured JSON logs to stderr via Go's `slog.JSONHandler`. Every log line is a self-contained JSON object. Systemd captures stderr by default, so logs are available in the journal immediately.

**What gets logged:**

| Event | Level | Key fields |
|-------|-------|------------|
| HTTP request | info | `method`, `path`, `status`, `bytes`, `duration_ms`, `remote_ip`, `request_id`, `trace_id` |
| Tunnel open | info | `tunnel_id`, `remote_ip`, `user`, `email`, `subject`, `client_id` |
| Tunnel close | info | `tunnel_id`, `duration_ms`, plus all identity fields |
| Token expiry warning sent | info | `tunnel_id`, `expires_at`, plus identity fields |
| Token refresh accepted | info | `tunnel_id`, `new_expiry`, plus identity fields |
| Token refresh rejected | warn | `tunnel_id`, reason (signature / subject mismatch / expiry reduced), plus identity fields |
| Tunnel closed on token expiry | info | `tunnel_id`, plus identity fields |
| Admission denied | warn | `reason` (`global`, `per_user`, or `rate`), `remote_ip`, `request_id`, plus identity fields |
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

**End-to-end correlation with Ivanti:** Authunnel's `trace_id` is sourced from an incoming W3C `Traceparent` header when present. If Ivanti is configured to emit a `Traceparent` header on forwarded requests, and Ivanti's own access/TLS logs are shipped to the same index as the Authunnel server logs, a single `trace_id` will join the edge (TLS termination, client IP seen by Ivanti) with the backend (authentication, tunnel lifecycle, SOCKS destinations) for any given request.

Setting `--log-level debug` enables per-connection destination logging, providing full audit visibility of which internal hosts each user connects to.

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Ivanti vTM limitations (licensing or implementation) prevent, or have significant negatives if used for Authunnel TLS termination | Consider either Ivanti vTM changes and instead of vTM mediated access, firewall based access to suitably isolated Authunnel instances. |
| WebSocket blocked by network policy | Authunnel uses standard HTTPS on port 443 with a WebSocket upgrade — the same mechanism used by most modern web applications. Ivanti already handles WebSocket traffic. |
| Okta outage prevents new logins or token refresh | Existing tunnels continue until the current access token expires (typically an hour or less, depending on Okta policy). New logins and token refreshes require live Okta connectivity. This is a deliberate trade-off — tying tunnel lifetime to token expiry is what makes offboarding prompt. |
| Single server is a single point of failure | Server instances are stateless. Run two or more behind Ivanti load balancing for high availability. |
| Maintainability over time | The codebase is ~3,400 lines of Go source (excluding tests, comments, and blanks) with an explicit design goal of auditability. It has significantly lower maintenance burden than a full platform like Teleport. |
| Security of non-Sanger client machines | Authunnel does not trust the client machine. It provides only a tunnel — the SSH host still requires its own authentication (keys, certificates, etc.). Allow rules and VM security groups independently limit which destinations a tunnel can reach. |

## Scope & Limitations

Authunnel's current functionality is SSH tunnelling. It does not provide the additional capabilities that Teleport offers, such as Okta-gated access to internal web applications. Where those capabilities are needed, it may be worth exploring whether existing infrastructure — such as the Ivanti Traffic Manager or other systems — could provide them independently.

## Security Review

We would like the security team to consider reviewing the deployment architecture and the code with the prospect of a production rollout. A non-exhaustive list where their input would be valuable:

- **Authentication model** — the server validates JWT access tokens locally via OIDC discovery and JWKS, checking signature, issuer, expiry, audience, subject presence, `iat` sanity, and `nbf` (with a 30s clock-skew tolerance at admission). Tunnel lifetime is bound to token expiry, with optional client-driven refresh over a control channel. Are these choices appropriate for the deployment environment, and are the refresh rules (pin to original subject, refuse refresh that reduces expiry) the right ones?
- **Egress posture** — the server refuses to start without either one or more `--allow` rules or an explicit `--allow-open-egress` flag. The initial deployment would use `*.internal.sanger.ac.uk:22` (or a tightly monitored subset). Is this adequate as a default policy, and what additional rules or review cadence should apply before widening the allowlist?
- **Admission controls** — the server supports global and per-user concurrent-tunnel caps, a per-user rate limit with burst, and a bounded dial timeout. Are the proposed limits and defaults appropriate for abuse resistance?
- **Network architecture** — the server runs behind Ivanti with security groups restricting inbound and outbound traffic. Are the proposed security group rules appropriate?
- **Capability dropping** — on Linux, the server drops all capabilities and sets `PR_SET_NO_NEW_PRIVS` after binding ports. Is this hardening adequate?
- **Client-side hardening** — the client validates ownership and permissions on its token-cache and unix-socket parent directories. The token cache is plaintext JSON at `0600` inside a `0700` directory with validated ancestry; this defends against co-tenant read access on shared hosts but not against same-uid processes, root, or offline disk access. Is this model adequate, and does the deployment environment warrant additional at-rest protection (full-disk encryption, secrets-manager-sourced tokens)?
- **Logging and monitoring** — are the logged fields sufficient for incident response and audit purposes? Are there additional events or fields the security team would want to see?
- **Threat model** — what residual risks does the security team see with an authenticated WebSocket tunnel to internal SSH hosts, how do these compare with the existing Teleport provision, and what additional controls (if any) would they recommend?

The [codebase is open](https://github.com/dkj/authunnel/blob/main/README.md) and so available for review now. Given its size (~3,400 lines of Go source, excluding tests, comments, and blanks), a full read-through is realistic within a day or two.

## Vulnerability Management

Vulnerability management covers three independent layers:

**Host.** The server VM is enrolled in Sanger's existing host vulnerability management (Rapid7 InsightVM or equivalent) so OS-level CVEs, missing patches, and configuration drift are picked up by routine scans. Rapid7 is a commercial product, but the assumption is that Sanger already operates it under existing licensing — adding the Authunnel VM to the scan scope should be marginal cost at most. Because the VM runs a single static Go binary under `DynamicUser=yes` and no ancillary services, the host surface is deliberately small, but routine scanning still catches drift in the base image.

**Source code (SAST).** A dedicated GitHub Actions workflow (`.github/workflows/security.yml`) runs on every push and pull request, plus a daily 06:00 UTC cron so newly published CVEs are caught even when the codebase has not changed. The workflow runs:

- **`govulncheck`** (from the Go team) — reports vulnerabilities from the Go vulnerability database that are actually reachable from `main`, giving a very low false-positive rate.
- **`gosec`** — Go-specific security linter for patterns like hardcoded credentials and weak crypto.
- **`staticcheck`** — broad correctness and style checks.
- **`go vet`** — standard Go correctness analyser.

CodeQL (GitHub native) can be added if the security team wants an additional layer.

**Supply chain (SCA).** `govulncheck` also scans module dependencies, so the same CI job doubles as SCA. **Dependabot** is configured (`.github/dependabot.yml`) to propose weekly update PRs for both `gomod` dependencies and GitHub Actions versions. The dependency footprint is small and easy to review: eight direct dependencies (`armon/go-socks5`, `coder/websocket`, `go-jose/v4`, `zitadel/oidc/v3`, and four `golang.org/x/*` modules — `crypto`, `oauth2`, `sys`, `time`) and a further ~19 transitive modules declared in `go.mod` (under 50 in total once all tooling-adjacent modules are counted), all from well-known Go ecosystem sources. A CycloneDX JSON SBOM is generated automatically per release (one per OS/architecture per component, via the `make sbom` target wired into the release workflow) and published alongside the release binaries.

All three layers are cheap to add and keep running. The SAST and SCA tools (`govulncheck`, `gosec`, CodeQL for public repositories, Dependabot) are all free and self-service; the CI additions are a few lines of YAML each. Only the host scanner is commercial, and that cost is assumed to fall under existing Sanger licensing.

## Proposed Rollout

1. **Security review** — engage the security team for review of the codebase and proposed deployment architecture. Incorporate their findings before proceeding.
2. **Pilot** — deploy to a small group of willing early adopters, particularly those working from non-Sanger machines or those who would benefit from scoped SSH-only access.
3. **Evaluate** — confirm that token lifecycle (cache, refresh, re-login), allow rules, logging integration, and user experience meet expectations.
4. **Expand** — roll out to the broader user base with documentation and SSH config examples.
5. **Assess Teleport** — once Authunnel is proven in production, evaluate whether Teleport licence renewal is still justified at the next contract cycle.
