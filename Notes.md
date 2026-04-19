

## Auth model notes

Current auth model:

- The client is a public OIDC client and uses Authorization Code + PKCE.
- The server is an OAuth2 resource server: it uses OIDC discovery only to bootstrap the JWKS endpoint location, then validates JWT access tokens locally.
- The server requires a configured token audience in the access-token `aud` claim.
- No separate resource-server client secret is needed for Authunnel startup.

### server setup

Assumes the localhost server cert `cert.pem` and key `key.pem` were signed by
the local dev CA `dev-ca.pem` described below.

```bash
export OIDC_ISSUER=https://dev-125016.okta.com/oauth2/default
export TOKEN_AUDIENCE=authunnel-server
export TLS_CERT_FILE=$PWD/cert.pem
export TLS_KEY_FILE=$PWD/key.pem

# Startup now requires an egress posture: pass --allow rules, or
# --allow-open-egress for a local-dev flow that tunnels to arbitrary targets.
(cd server; go run . --allow-open-egress)
```

Check the localhost TLS setup working ok. The smoke test should trust the CA
certificate `dev-ca.pem`, not the leaf server certificate `cert.pem`:

```bash
curl --cacert dev-ca.pem https://localhost:8443; echo
```
should give something like:

```text
OK 2024-08-01 11:16:24.39347267 +0000 UTC m=+2361.464048826
```

### client setup for manual token testing


```bash
export ISSUER=https://dev-125016.okta.com/oauth2/default
export CLIENT_ID=<public-client-id>
```

Get an access token:

```bash
oauth2c "$ISSUER" \
  --client-id="$CLIENT_ID" \
  --grant-type=authorization_code \
  --auth-method=none \
  --response-mode=form_post \
  --response-types=code \
  --scopes=openid,email,profile \
  --pkce | tee tmp.json | jq -c .
```

This goes via the browser and a local callback port opened by `oauth2c`.
Then get the access token:

```bash
export ACCESS_TOKEN=$(jq -r .access_token tmp.json)
```

#### check access token access

##### inspect the JWT payload locally

The important field now is `aud`. It must include the Authunnel server audience
configured in `TOKEN_AUDIENCE`.

```bash
jq -R '
  split(".")[1]
  | gsub("-"; "+")
  | gsub("_"; "/")
  | . + (if (length % 4) == 2 then "==" elif (length % 4) == 3 then "=" else "" end)
  | @base64d
  | fromjson
' <<<"$ACCESS_TOKEN"
```

should give something like:
```json
{
  "aud": [
    "authunnel-server"
  ],
  "iss": "https://dev-125016.okta.com/oauth2/default",
  "sub": "user@example.com",
  "exp": 1722514880,
  "iat": 1722511280
}
```

##### to our server

Again, trust `dev-ca.pem` here rather than `cert.pem`:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" --cacert dev-ca.pem https://localhost:8443/protected; echo
```
should return something like:
```text
Protected OK 2024-08-01 11:30:37.729193176 +0000 UTC m=+7.188534380
```

#### so try to run proper client
```bash
SSL_CERT_FILE=dev-ca.pem go run ./client \
  --tunnel-url https://localhost:8443/protected/tunnel \
  --oidc-issuer "$OIDC_ISSUER" \
  --oidc-client-id "$CLIENT_ID" \
  --oidc-audience "$TOKEN_AUDIENCE" \
  --oidc-redirect-port 38081 \
  --unix-socket "$PWD/proxy.sock"
```
and use the unix socket that provides for the proxy:
```bash
all_proxy=socks5h://localhost$PWD/proxy.sock curl https://www.bbc.co.uk
```

For providers that require an exact loopback callback URL, register:

```text
http://127.0.0.1:38081/callback
```

For Auth0-style custom APIs, also make sure the managed client sends the API
audience explicitly with `--oidc-audience`.


## Dev reminders

### local CA and localhost cert creation

For local testing on macOS, prefer a tiny local CA plus a localhost server
cert signed by that CA. A self-signed leaf often still fails macOS/Go
verification with:

```text
x509: "localhost" certificate is not standards compliant
```

#### create a local CA

```bash
rm -f dev-ca.key dev-ca.pem dev-ca.srl cert.pem key.pem localhost.csr localhost.ext

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -days 3650 \
  -subj "/CN=Authunnel Local Dev CA" \
  -keyout dev-ca.key \
  -out dev-ca.pem \
  -addext "basicConstraints = critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage = critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier = hash"
chmod 600 dev-ca.key
```

#### create a localhost server key and CSR

```bash
openssl req \
  -newkey rsa:2048 \
  -new \
  -nodes \
  -subj "/CN=localhost" \
  -keyout key.pem \
  -out localhost.csr \
  -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints = critical,CA:FALSE" \
  -addext "keyUsage = critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage = serverAuth"
chmod 600 key.pem
```

Write the signing extensions:
```bash
cat > localhost.ext <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
EOF
```

#### sign the localhost cert with the local CA

```bash
openssl x509 \
  -req \
  -in localhost.csr \
  -CA dev-ca.pem \
  -CAkey dev-ca.key \
  -CAcreateserial \
  -out cert.pem \
  -days 825 \
  -sha256 \
  -extfile localhost.ext
```

Inspect the server cert:
```bash
openssl x509 -text -noout -in cert.pem | grep -A1 "Issuer:\|Subject:\|Subject Alternative Name\|Basic Constraints\|Key Usage\|Extended Key Usage"
```
gives
```
        Issuer: CN=Authunnel Local Dev CA
        Subject: CN=localhost
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Alternative Name: 
                DNS:localhost, IP Address:127.0.0.1
```

#### trust the local CA on macOS

Either import `dev-ca.pem` into Keychain Access and mark it trusted, or run:

```bash
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db dev-ca.pem
```

If you later want to remove it:

```bash
security find-certificate -c "Authunnel Local Dev CA" -a -Z ~/Library/Keychains/login.keychain-db
security delete-certificate -c "Authunnel Local Dev CA" ~/Library/Keychains/login.keychain-db
```

Then use it with Authunnel:

```bash
export TLS_CERT_FILE=$PWD/cert.pem
export TLS_KEY_FILE=$PWD/key.pem

# --allow-open-egress is the explicit opt-in for running without an allowlist;
# use --allow rules instead when you want to restrict tunnel destinations.
(cd server; go run . --allow-open-egress)
```

From another shell, verify the cert and endpoint:

```bash
curl --cacert dev-ca.pem https://localhost:8443
```

For the client, if Keychain trust is in place, the default Go/macOS verifier
should accept the server certificate. Keeping `SSL_CERT_FILE` pointed at the CA
bundle is still reasonable:

```bash
SSL_CERT_FILE=$PWD/dev-ca.pem go run ./client \
  --tunnel-url https://localhost:8443/protected/tunnel \
  --oidc-issuer "$OIDC_ISSUER" \
  --oidc-client-id "$CLIENT_ID" \
  --oidc-audience "$TOKEN_AUDIENCE" \
  --oidc-redirect-port 38081 \
  --unix-socket "$PWD/proxy.sock"
```

This is only for local development. For anything beyond localhost testing, use
a cert chain the client already trusts instead of shipping a private dev CA.

## OAuth2 CLI client usage

### CLI client example with `oauth2c`

Using
- "authorization_code" flow for client to exchange code for access token
- "auth-method" of "none" as the client can have no secret
  - pkce as recommended/ okta-enforced for such a flow
- response-mode of "query" or "form_post" work
- the IdP must be configured so the resulting access token includes the
  Authunnel audience, for example `authunnel-server`

```bash
export ISSUER=https://dev-125016.okta.com/oauth2/default
export CLIENT_ID=<public-client-id>
oauth2c "$ISSUER" --client-id="$CLIENT_ID" --grant-type=authorization_code --auth-method=none --response-mode=form_post --response-types=code --scopes=openid,email,profile --pkce
```

If the resulting access token is set in `ACCESS_TOKEN`...

### Access-token validation notes

Authunnel no longer depends on token introspection with a separate server-side
client secret. The server startup inputs are:

- `OIDC_ISSUER`
- `TOKEN_AUDIENCE`
- One TLS mode: `TLS_CERT_FILE`+`TLS_KEY_FILE`, or `ACME_DOMAINS`, or `PLAINTEXT_BEHIND_REVERSE_PROXY=true`

At runtime the server validates:

- JWT signature via issuer JWKS
- issuer
- expiry
- audience
- subject (`sub`) is non-empty — the tunnel's refresh identity is pinned to `sub`
- `iat` is not meaningfully in the future (within a 30 s clock-skew allowance)
- `nbf` is not after `exp`
- at admission, `nbf` has been reached (the 30 s skew allowance applies here, since the comparison is against wall-clock `time.Now()`); on refresh, `nbf` must be at or before the current enforced deadline (`exp + --expiry-grace`) — this comparison is strict with no additional skew, so refresh cannot stretch enforcement past the configured grace window

For manual debugging, either decode the JWT locally to inspect `aud`, or hit
`/protected` with the bearer token and expect a `200 OK` only when the token is
valid for the configured audience.

### Managed OIDC client notes

Managed login now has two extra knobs that matter for some IdPs:

- `--oidc-audience` requests a specific API/resource audience during the
  authorization flow.
- `--oidc-redirect-port` binds the loopback callback listener to a fixed local
  port instead of a random ephemeral port.

Those are mainly useful when the IdP:

- will not issue the right API access token unless `audience` is passed on the
  authorize request
- requires an exact callback URL to be pre-registered instead of allowing
  `http://127.0.0.1/*`

## Resilience design note

This project may later want tunnels that survive temporary network loss or a
sleeping client machine for at least a few minutes.

That is not implemented today. Current behavior is still tied closely to a
single live websocket transport. The important constraint for current work is
to avoid making that future harder.

The connection longevity system (text-frame control channel, `MultiplexConn`
adapter) provides a foundation for future session-level state management.
Token refresh over the control channel already demonstrates the pattern of
in-band session renegotiation without disrupting the data path.

Design guardrails:

- Treat tunnel session identity as separate from the current websocket
  connection. Avoid spreading assumptions that `one websocket == one tunnel's
  entire lifetime`.
- Keep short timeouts for HTTP admission and websocket setup, but avoid adding
  aggressive established-tunnel idle/read/write deadlines as a blanket
  "resilience" feature. Those would work against sleep tolerance.
- If connection limits, rate limits, or backpressure are added, prefer to scope
  them in terms of tunnel sessions, detached sessions, and bounded buffers, not
  only raw websocket counts.
- Prefer shutdown logic that can later drain, park, or explicitly expire active
  sessions instead of assuming that process shutdown must immediately destroy
  all live tunnels.
- Avoid burying protocol state only inside one goroutine stack or one live
  transport object. Resumption would need explicit session state, resume
  identifiers/tokens, and bounded buffering.

If resumable tunnels are implemented later, the likely model is:

- A tunnel can move between `attached`, `detached`, and `expired` states.
- Temporary websocket loss moves a session to `detached` instead of immediately
  closing the target TCP connection.
- The server keeps detached sessions for a bounded grace period and under
  bounded memory/session limits.
- The client reconnects and resumes the existing session using an explicit
  resume token rather than implicitly creating a new tunnel every time.

## Multiplexing and control-plane design note

The `1 websocket : 1 tunnel` shape is preserved, but an in-band control channel
now exists alongside the SOCKS5 data path. The `internal/wsconn.MultiplexConn`
adapter uses WebSocket text frames for JSON control messages and binary frames
for SOCKS5 data, giving each tunnel a lightweight control plane without adding
framing overhead to the data path.

A helpful distinction remains:

- `session != websocket`
- `control channel != data multiplexing`

### What is implemented

The control channel currently supports connection longevity management:

- **`expiry_warning`** (server→client): sent before either the token expiry or
  max-duration limit is reached, with a `reason` field (`"token"` or
  `"max_duration"`) so the client knows whether a refresh can help.
- **`token_refresh`** (client→server): the client sends a new access token to
  extend the tunnel when the server signals token expiry.
- **`token_accepted` / `token_rejected`** (server→client): confirmation of
  whether the refresh succeeded. Subject pinning prevents identity swaps.
- **`disconnect`** (server→client): sent immediately before server-initiated
  close, with a reason string.

The server validates refreshed tokens using the same `TokenValidator` and
enforces subject continuity (the new token's `sub` must match the original).

### What remains for future work

Full data multiplexing (many TCP tunnels over one websocket) is not implemented
and the earlier reasoning against premature multiplexing still holds:

- Full data multiplexing adds framing, stream IDs, fairness, per-stream flow
  control, shared-buffer accounting, and more complicated failure handling.
- A single multiplexed websocket creates a larger blast radius: one transport
  failure could drop many active tunnels at once.

Useful future control-plane extensions could include:

- session creation and resume tokens
- attached/detached state transitions
- heartbeat / liveness signals
- server shutdown or drain notifications
- structured logging / user-visible diagnostics

Essential guardrails (unchanged):

- Send new access tokens over the control plane only. Never send refresh tokens
  to the Authunnel server.
- When renewing, validate continuity of identity and audience before extending
  the session lease. (Implemented: subject pinning in `manageTunnelLongevity`.)
- Never log bearer tokens or resume tokens.

Current guardrail:

- Do not spread websocket-specific assumptions deeper into the code than
  necessary. The `MultiplexConn` adapter keeps the control channel isolated
  from the SOCKS5 data path, preserving a simple and auditable per-tunnel
  byte-forwarding layer.
