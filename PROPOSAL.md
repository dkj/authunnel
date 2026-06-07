# Authunnel: Proposal for Deployment

## The Opportunity

Remote access to internal SSH services is a common need across the institute. The existing solutions serve this need, but have either limitations or significant costs:

- **Teleport** integrates with Okta SSO and works well, but escalating licence fees are a growing concern for what is mostly used as an "SSH to an internal host" use case.
- **VPN** is often effective for staff on Sanger laptops. However, it is not available to those working from non-Sanger machines, and it grants broader network access than some use cases require.
- **The legacy bastion** (ssh-gateway) was decommissioned several years ago due to a lack of resource to maintain it and no integration with SSO.

Authunnel is a lightweight, purpose-built tool that fills these gaps. It tunnels SSH connections over an Okta-authenticated WebSocket, using infrastructure the institute already operates. Initially, it can complement existing access methods rather than necessarily replacing them.

## What Authunnel Is

Authunnel is an authenticated tunnel for reaching internal SSH services. Users run `ssh` as normal; the Authunnel client, configured as an SSH `ProxyCommand`, transparently handles Okta login via the browser and establishes an encrypted WebSocket tunnel to the server. The server acts as an OAuth2 resource server: it validates the Okta-issued JWT access token (signature, issuer, expiry, audience, subject presence, `iat` sanity, `nbf`) and proxies the SSH connection to the requested internal host. Tunnel lifetime is bound to the access token's expiry by default: when the token expires the tunnel closes, unless the client refreshes the token (typically silently) while the tunnel is still alive. The entire system is a single Go binary with no database, no external state, and no licence fees.

## Why Authunnel

1. **Zero licence cost** Authunnel is a single Go binary with no commercial dependencies. There is no per-seat fee, no annual renewal, no vendor lock-in. The total infrastructure cost is one or two small VMs.

2. **Uses existing Okta SSO, with prompt offboarding.** Users authenticate via the same Okta login they already use. Tunnel lifetime is bound to the access token's expiry, so when someone is offboarded in Okta they lose Authunnel access as soon as their current access token expires (typically minutes, not hours); refresh attempts fail immediately against Okta. The server requires only an issuer URL and a token audience: no client secrets, no synced user database.

3. **Can run behind an existing reverse proxy.** Authunnel can run in plaintext mode behind a TLS-terminating reverse proxy, benefiting from the team's existing knowledge and experience of that layer as an external interface. Either of the platforms already operated at Sanger (**Ivanti vTM** or **Kemp LoadMaster**) is suitable: both handle TLS termination, load balancing, and WebSocket upgrade pass-through as they already do for other services. No new TLS infrastructure is needed.

4. **Smaller deployment attack surface.** The entire Authunnel codebase is approximately 3,400 lines of Go source (excluding tests, comments, and blanks). A security reviewer can read it in full over a day or two. On Linux, the server drops all capabilities and sets `PR_SET_NO_NEW_PRIVS` after binding ports, limiting the impact of any future vulnerability. The OIDC issuer and tunnel URLs must use HTTPS (plain HTTP is rejected at startup). Pre-auth resource exposure is bounded: the bearer token (8 KiB) and `Authorization` header (8 KiB + 64 bytes) are length-capped before the JWT verifier runs, and the HTTP request-header memory cap is reduced from Go's 1 MiB default to 16 KiB. Anonymous callers cannot push oversized payloads onto the verifier or onto general header parsing.

   On the **target hosts**, Authunnel adds no daemon, no in-process SSH server, and no outbound persistent tunnel; it simply proxies TCP to the existing OpenSSH `sshd`. Teleport's current deployment adds a Teleport node agent on each target host (its own Go SSH server, plus a persistent outbound TLS reverse-tunnel to the Proxy and node-side cluster credentials), running alongside `sshd`. Authunnel has zero target-host footprint.

   The two designs imply different **network postures**. Authunnel is **firewall-enhanced**: its own `--allow` rules control destinations at the application layer, and outbound TCP connections to `host:22` are further constrained by explicit ingress firewall rules to access each target (in practice tightly scoped: particular internal destination IPs and a single port). These rules are exactly the kind of perimeter control institutional firewall regimes are built to express and audit. Teleport's reverse-tunnel approach is **firewall-evading by design**: each node holds a persistent outbound TLS connection to the Proxy, so target hosts need only permissive egress and no ingress rules. Access decisions then sit inside Teleport's configuration rather than at the firewall, which lets Teleport work through restrictive networks but also moves access policy out of the layer most security teams already monitor. The reverse-tunnel topology also makes the Proxy a high-value central pivot: every node's connection is routed through it, and it holds cluster-level Teleport credentials. Authunnel has no comparable cluster role: it sees only opaque SSH bytes flowing between user and target `sshd` (the SSH session is end-to-end encrypted), and its access decisions are enforced (and visible) at the firewall layer, reinforcing the server's own configured allowlist.

5. **Scoped access at multiple levels.** Access can be restricted at several independent layers, each enforced by a different part of the infrastructure:
   - **Destination allowlist:** The `--allow` option restricts which destinations authenticated users can reach, using host glob patterns and CIDR rules (e.g. `*.internal:22`, `10.0.0.0/8:22`). Starting the server without either `--allow` rules or an explicit `--allow-open-egress` flag is rejected: the egress posture is never silently permissive.
   - **Resolved-IP blocklist:** `--ip-block` denies connections to specified IP addresses or ranges *after* allowlist evaluation, with deny taking precedence. Useful for excluding specific IPs from a broader allowlist (e.g. cloud-metadata addresses, link-local, or known-bad ranges) that an authenticated user should never reach via the tunnel.
   - **Admission limits:** Per-user and global caps on concurrent tunnels, plus per-user open-rate limits, bound the impact of credential abuse or misbehaving clients.
   - **Network layer:** VMware or OpenStack security groups on the server VM control both inbound access (only from the reverse-proxy VIP) and outbound access. The outbound allowlist must include the Okta OIDC endpoints (for discovery and JWKS), the centralised logging endpoints (ELK / Splunk), the permitted internal SSH destinations, DNS resolvers (for hostname resolution), NTP (UDP 123; needed for accurate JWT time-claim validation: `iat`, `nbf`, `exp`), and (depending on how the VM is initialised) DHCP (UDP 67/68) at boot. Nothing else.

   This is useful for granting access to specific services only, or for limiting exposure to the broader network.

6. **Works from any machine.** The client is a statically compiled binary available for Linux, macOS, and Windows (10 1803 or later). It requires no special network configuration and no Sanger-issued hardware. This makes it suitable for staff working from personal machines, academic collaborators, or some commercial partners: settings where the company VPN is not an option.

7. **Transparent audit trail.** Every tunnel is logged with the authenticated user's identity and destination. Denied connections are logged at warn level. Logs are structured JSON with request and trace correlation IDs, ready for ingestion into ELK or Splunk without custom parsing (see Logging & Observability below).

8. **Familiar user experience.** Users add a `ProxyCommand` entry to their SSH config. On first use, a browser tab opens for Okta login. Subsequent SSH sessions reuse cached or refreshed tokens silently. SSH "just works" without re-authenticating each time.

9. **Maintainable by design.** The codebase is deliberately kept small and simple. Any developer comfortable with Go should be able to understand and patch the code if required.

10. **Horizontally scalable.** Server instances share no state. Multiple instances can run behind the chosen reverse proxy's load balancing for high availability. Scaling is simply adding another VM.

11. **Admission controls against abuse.** The server supports optional global and per-user caps on concurrent tunnels, a per-user tunnel-open rate limit with burst, and a bounded dial timeout for outbound SOCKS CONNECT. Over-limit requests receive `429`/`503` with `Retry-After`. This bounds the blast radius of a compromised credential or a misbehaving client without requiring an external rate-limiting layer.

## Deployment Architecture

```
User's machine                    Sanger infrastructure
─────────────                    ──────────────────────
ssh internal-host
  └─ authunnel-client
       └─ HTTPS WebSocket ──[FW]──▶  Reverse proxy (Ivanti vTM / Kemp, TLS termination, :443)
                                          │
                                          └─ HTTP ──[FW]──▶  authunnel-server VM (:8080)
                                                                  │
                                                                  └─ SOCKS5 CONNECT ──[FW]──▶  internal-host:22
```

Each `[FW]` marks a firewall / security-group gate:

1. **Perimeter firewall**: internet to reverse-proxy VIP, port `:443` only.
2. **Internal firewall and/or security group**: reverse-proxy VIP to authunnel-server VM, port `:8080` only.
3. **Internal firewall and/or security group**: authunnel-server VM to permitted internal SSH hosts, port `:22`, narrow destination set.

**Components:**

- **Reverse proxy** (Ivanti vTM *or* Kemp LoadMaster, both already operated at Sanger): TLS termination at `st.sanger.ac.uk:443`, forwarding to the backend VM on port 8080. Configured to accept HTTPS only; any plain HTTP listener should either be absent or redirect to HTTPS, and it must never accept plaintext client traffic. Requires WebSocket upgrade pass-through and setting `X-Forwarded-Proto` and `X-Forwarded-Host` headers on forwarded requests. Because `st.sanger.ac.uk` is internet-facing, the server's pre-auth rate limiter should be enabled to reject anonymous floods before any token validation; it works with the default `X-Forwarded-For` behaviour of both Ivanti vTM and Kemp LoadMaster.
- **Server VM** (VMware or OpenStack): a single small Linux VM running the authunnel-server binary, managed by systemd. No database, no disk state beyond the binary and a configuration file. Security groups restrict inbound access (only from the reverse-proxy VIP) and outbound access (only to Okta OIDC endpoints, centralised logging endpoints, the permitted internal SSH destinations, and the infrastructure services the host needs to function: DNS resolvers, NTP, and DHCP if required at boot).
- **Okta**: one public OIDC client registration (for the CLI tool) and one audience/resource entry (for token scoping to `authunnel-server`).
- **DNS**: `st.sanger.ac.uk` pointing at the reverse-proxy VIP.

**Server configuration** is minimal:

```bash
OIDC_ISSUER='https://<okta-issuer-url>'
TOKEN_AUDIENCE='authunnel-server'
PLAINTEXT_BEHIND_REVERSE_PROXY=true
ALLOW_RULES='*.internal.sanger.ac.uk:22'
PREAUTH_RATE=20                              # rate-limit anonymous requests before token validation
PREAUTH_TRUST_FORWARDED_FOR=rightmost        # client IP from the proxy-appended X-Forwarded-For
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
| Reverse-proxy VIP + TLS cert for `st.sanger.ac.uk` on either Ivanti vTM or Kemp LoadMaster, configured to accept HTTPS only (no plain HTTP listener, or 80→443 redirect at most) | Network team (Ivanti/Kemp operators) | Standard config |
| WebSocket upgrade pass-through on the reverse proxy | Network team (Ivanti/Kemp operators) | Standard config |
| DNS entry for `st.sanger.ac.uk` | Network team | ~5 min |
| Security groups (inbound from the reverse-proxy VIP; outbound to Okta, logging endpoints, permitted SSH hosts, DNS, NTP, and DHCP if needed at boot) | Infrastructure / Network team | Standard config |
| Deploy binary + systemd unit | Infrastructure & Authunnel maintainer | ~1 hour |
| Log shipping from server VM (Filebeat or Splunk UF) | Logging / observability team | Standard config (see below) |
| Reverse-proxy access/TLS log shipping to the same logging system | Network team (Ivanti/Kemp operators) + Logging team | Standard config; ideally configure the reverse proxy to emit a `Traceparent` header so server logs and reverse-proxy logs can be joined by `trace_id` |
| Log receiver configuration (Elasticsearch index + Kibana, or Splunk index + sourcetype) for both Authunnel server and reverse-proxy logs, plus any required dashboards or alerts | Logging / observability team | Standard config: structured JSON means fields are available without parsing |
| Security review of codebase and deployment architecture | Security team | See below |
| Host vulnerability scanning enrolment (Rapid7 InsightVM or equivalent) for the server VM | Infrastructure / Security team | Standard config: enrol VM in existing scanner |
| SAST/SCA CI jobs (`govulncheck`, `gosec`, `staticcheck`, `go vet`, Dependabot) | Authunnel maintainer | Already in place (daily cron + per-PR); CodeQL can be added if required |
| SBOM generation per release (CycloneDX JSON) | Authunnel maintainer | Already in place: generated and published automatically per release binary |
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

Since the output is already structured JSON, integration with ELK (via Filebeat) or Splunk (via Universal Forwarder) requires only a standard JSON input, with no grok patterns or custom parsing.

**End-to-end correlation with the reverse proxy:** Authunnel's `trace_id` is sourced from an incoming W3C `Traceparent` header when present. If the reverse proxy (Ivanti vTM or Kemp LoadMaster) is configured to emit a `Traceparent` header on forwarded requests, and its own access/TLS logs are shipped to the same index as the Authunnel server logs, a single `trace_id` will join the edge (TLS termination, client IP seen by the proxy) with the backend (authentication, tunnel lifecycle, SOCKS destinations) for any given request.

Setting `--log-level debug` enables per-connection destination logging, providing full audit visibility of which internal hosts each user connects to.

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Reverse-proxy limitations (licensing or implementation) prevent, or have significant negatives if used for Authunnel TLS termination | Two existing platforms are available (Ivanti vTM and Kemp LoadMaster); the one that fits best can be chosen, or a fallback to firewall-based access to suitably isolated Authunnel instances is possible. |
| WebSocket blocked by network policy | Authunnel uses standard HTTPS on port 443 with a WebSocket upgrade (the same mechanism used by most modern web applications). Both Ivanti vTM and Kemp LoadMaster already handle WebSocket traffic. |
| Okta outage prevents new logins or token refresh | Existing tunnels continue until the current access token expires (typically an hour or less, depending on Okta policy). New logins and token refreshes require live Okta connectivity. This is a deliberate trade-off: tying tunnel lifetime to token expiry is what makes offboarding prompt. |
| Single server is a single point of failure | Server instances are stateless. Run two or more behind the reverse proxy's load balancing for high availability. |
| Maintainability over time | The codebase is ~3,400 lines of Go source (excluding tests, comments, and blanks) with an explicit design goal of auditability. It has significantly lower maintenance burden than a full platform like Teleport. |
| Security of non-Sanger client machines | Authunnel does not trust the client machine. It provides only a tunnel; the SSH host still requires its own authentication (keys, certificates, etc.). Allow rules and VM security groups independently limit which destinations a tunnel can reach. |

## Scope & Limitations

Authunnel's current functionality is SSH tunnelling. It does not provide the additional capabilities that Teleport offers, such as Okta-gated access to internal web applications. Where those capabilities are needed, it may be worth exploring whether existing infrastructure (such as Ivanti vTM, Kemp LoadMaster, or other systems) could provide them independently.

## Security Review

We would like the security team to consider reviewing the deployment architecture and the code with the prospect of a production rollout. A non-exhaustive list where their input would be valuable:

- **Authentication model**: the server validates JWT access tokens locally via OIDC discovery and JWKS, checking signature, issuer, expiry, audience, subject presence, `iat` sanity, and `nbf` (with a 30s clock-skew tolerance at admission). Tunnel lifetime is bound to token expiry, with optional client-driven refresh over a control channel. Are these choices appropriate for the deployment environment, and are the refresh rules (pin to original subject, refuse refresh that reduces expiry) the right ones?
- **Egress posture**: the server refuses to start without either one or more `--allow` rules or an explicit `--allow-open-egress` flag. The initial deployment would use `*.internal.sanger.ac.uk:22` (or a tightly monitored subset). Is this adequate as a default policy, and what additional rules or review cadence should apply before widening the allowlist?
- **Admission controls**: the server supports global and per-user concurrent-tunnel caps, a per-user rate limit with burst, and a bounded dial timeout. Are the proposed limits and defaults appropriate for abuse resistance?
- **Network architecture**: the server runs behind a reverse proxy (Ivanti vTM or Kemp LoadMaster) with security groups restricting inbound and outbound traffic. Are the proposed security group rules appropriate?
- **Capability dropping**: on Linux, the server drops all capabilities and sets `PR_SET_NO_NEW_PRIVS` after binding ports. Is this hardening adequate?
- **Client-side hardening**: the client validates ownership and permissions on its token-cache and unix-socket parent directories. The token cache is plaintext JSON at `0600` inside a `0700` directory with validated ancestry; this defends against co-tenant read access on shared hosts but not against same-uid processes, root, or offline disk access. Is this model adequate, and does the deployment environment warrant additional at-rest protection (full-disk encryption, secrets-manager-sourced tokens)?
- **Logging and monitoring**: are the logged fields sufficient for incident response and audit purposes? Are there additional events or fields the security team would want to see?
- **Threat model**: what residual risks does the security team see with an authenticated WebSocket tunnel to internal SSH hosts, how do these compare with the existing Teleport provision, and what additional controls (if any) would they recommend?

The [codebase is open](https://github.com/dkj/authunnel/blob/main/README.md) and so available for review now. Given its size (~3,400 lines of Go source, excluding tests, comments, and blanks), a full read-through is realistic within a day or two.

## Vulnerability Management

Vulnerability management covers three independent layers:

**Host.** The server VM is enrolled in Sanger's existing host vulnerability management (Rapid7 InsightVM or equivalent) so OS-level CVEs, missing patches, and configuration drift are picked up by routine scans. Rapid7 is a commercial product, but the assumption is that Sanger already operates it under existing licensing; adding the Authunnel VM to the scan scope should be marginal cost at most. Because the VM runs a single static Go binary under `DynamicUser=yes` and no ancillary services, the host surface is deliberately small, but routine scanning still catches drift in the base image.

**Source code (SAST).** A dedicated GitHub Actions workflow (`.github/workflows/security.yml`) runs on every push and pull request, plus a daily 06:00 UTC cron so newly published CVEs are caught even when the codebase has not changed. The workflow runs:

- **`govulncheck`** (from the Go team): reports vulnerabilities from the Go vulnerability database that are actually reachable from `main`, giving a very low false-positive rate.
- **`gosec`**: Go-specific security linter for patterns like hardcoded credentials and weak crypto.
- **`staticcheck`**: broad correctness and style checks.
- **`go vet`**: standard Go correctness analyser.

CodeQL (GitHub native) can be added if the security team wants an additional layer.

**Supply chain (SCA).** `govulncheck` also scans module dependencies, so the same CI job doubles as SCA. **Dependabot** is configured (`.github/dependabot.yml`) to propose weekly update PRs for both `gomod` dependencies and GitHub Actions versions. The dependency footprint is small and easy to review: eight direct dependencies (`armon/go-socks5`, `coder/websocket`, `go-jose/v4`, `zitadel/oidc/v3`, and four `golang.org/x/*` modules: `crypto`, `oauth2`, `sys`, `time`) and a further ~19 transitive modules declared in `go.mod` (under 50 in total once all tooling-adjacent modules are counted), all from well-known Go ecosystem sources. A CycloneDX JSON SBOM is generated automatically per release (one per OS/architecture per component, via the `make sbom` target wired into the release workflow) and published alongside the release binaries. Each release also carries a SLSA build provenance attestation, providing cryptographic evidence that the binary was built from the published source by the public CI pipeline.

All three layers are cheap to add and keep running. The SAST and SCA tools (`govulncheck`, `gosec`, CodeQL for public repositories, Dependabot) are all free and self-service; the CI additions are a few lines of YAML each. Only the host scanner is commercial, and that cost is assumed to fall under existing Sanger licensing.

## Proposed Rollout

1. **Security review**: engage the security team for review of the codebase and proposed deployment architecture. Incorporate their findings before proceeding.
2. **Pilot**: deploy to a small group of willing early adopters, particularly those working from non-Sanger machines or those who would benefit from scoped SSH-only access.
3. **Evaluate**: confirm that token lifecycle (cache, refresh, re-login), allow rules, logging integration, and user experience meet expectations.
4. **Expand**: roll out to the broader user base with documentation and SSH config examples.
5. **Assess Teleport**: once Authunnel is proven in production, evaluate whether Teleport licence renewal is still justified at the next contract cycle.

## Reviews

### 2026-04-24: Critique

> Just thinking about some of the features of Teleport and comparing them with Authunnel, one of the the key security features of Teleport is to manage SSH keys, providing short lived keys to allow access to the bastion host and along with SSO authentication that provides a more secure remote access solution. We are also able to allow 3rd party access without needing an Okta license.
> Authunnel only provides SAML access to a secure tunnel and none of the other features.
> I'm sure we could find a way to provide those features or find another way to support then, but that would take time to setup and manage.

#### Response

Thanks for the critique. A correction and some framing.

The proposal aims to provide:

- the SSH functionality most Sanger users and academic collaborators actually use;
- security at parity with (and in places ahead of) the current Teleport configuration for *that* functionality.

**Factual note.** Authunnel authenticates with OIDC/OAuth2 (Authorization Code + PKCE, JWT bearer tokens), not SAML. The two have different security properties and implementation paths.

**On short-lived SSH keys.** A real Teleport feature, not replicated by Authunnel. Three points complicate the direct comparison:

1. *Scope of the short-lived keys.* Teleport's short-lived SSH keys are only accepted by Teleport's own SSH servers (node agents via proxy). Onward hops between hosts during normal daily work rely on standard, long-lived SSH keys (to avoid password prompts), so long-lived keys are *also* in use today, in parallel.
2. *Where the strength comes from.* Both the short-lived SSH key and the mTLS cert authenticating the Teleport client to the Proxy are obtained from the same Okta login (with Okta-driven MFA), at the same time. The security strength comes from the Okta authentication, not from the credentials used to wrap the connection. Authunnel uses the same Okta authentication; the user then typically presents their standard SSH key to the target, which adds a second independent factor over the Okta-mediated tunnel (modest extra friction, marginally stronger).
3. *Lifetime coupling to IdP state.* Teleport's temporary credentials have a lifetime decoupled from the IdP token lifetime, so a practical 5–10 hour working session means Okta-side revocation can take up to the same 5–10 hours to propagate (please correct if this is wrong). Authunnel ties tunnel lifetime directly to the OIDC token cycle: with 30-min access tokens and 5-hour refresh tokens, an Okta-side disable propagates within ≤30 min; silent refresh extends to ≤5 hours; a fresh Okta interaction extends from there. A real, if narrow, offboarding improvement, and an end-user experience improvement.

**Session recording and RBAC.** Real Teleport features, not replicated. Open-source alternatives exist (`tlog-rec-session` or `auditd` for recording; OpenSSH + LDAP groups for RBAC), but standing them up would be a separate workstream not part of this proposal.

Note: session recording was, as I recall, switched on during a Teleport trial at Sanger and disabled after user objections, so for normal Sanger users (and, I assume, academic collaborators) this feature is not in active use, and the apparent gap is largely theoretical for that use case and so for this proposal.

For RBAC, equivalent scoping can be achieved at the Okta level (controlling which OIDC clients or audiences a user can obtain) combined with multiple Authunnel server instances each carrying its own allowlist. Different Okta groups would then have access to different sets of internal SSH destinations. I understand the majority use case this proposal is addressing (Sanger and academic-collaborator SSH access) currently fits in one such role, so the minimal deployment of Authunnel proposed here should suffice.

**3rd-party access without an Okta licence.** A genuine Teleport feature; not a goal of this proposal. Beyond this proposal's scope, Authunnel federates via *any* OIDC issuer, so external collaborators can be admitted via a secondary issuer (partner Okta tenant, self-hosted Keycloak or Zitadel) without expanding the main Okta tenancy. The cost shifts rather than vanishes: with Teleport you pay per-seat for externals; with Authunnel you either pay for an extra Okta seat or run an issuer.

**Framing.** The proposal addresses the authenticated-SSH-transport/gateway layer only: the SSO-mediated bastion role Teleport plays today. Cert authority, session recording, and RBAC are orthogonal to that layer and have (open-source) replacements if Teleport were ever retired wholesale, but that's a larger programme, not what's being proposed.

So the proposal stands on its own as a gateway-layer option: zero licence cost, same Okta SSO, smaller deployment surface, explicit and therefore auditable firewall / security-group rules for access to target hosts (rather than access decisions declared in the Teleport configuration on top of permissive egress to the proxy from nodes), prompt offboarding via the OIDC token cycle, and operation from non-Sanger environments. It does not claim to be a drop-in Teleport replacement. Where the broader Teleport feature set is wanted, keeping Teleport remains reasonable; where just the SSH gateway layer is what's needed, Authunnel is a lighter, cheaper option.
