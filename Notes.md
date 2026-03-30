

## PoC reminders

Current auth model:

- The client is a public OIDC client and uses Authorization Code + PKCE.
- The server validates JWT access tokens locally via issuer discovery + JWKS.
- The server requires a configured token audience in the access-token `aud` claim.
- No separate resource-server client secret is needed for Authunnel startup.

### server setup

```bash
export OIDC_ISSUER=https://dev-125016.okta.com/oauth2/default
export TOKEN_AUDIENCE=authunnel-server
export TLS_CERT_FILE=$PWD/cert.pem
export TLS_KEY_FILE=$PWD/key.pem

(cd server; go run .)
```

Check self signed cert working ok:

```bash
curl --cacert cert.pem https://localhost:8443; echo
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

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" --cacert cert.pem https://localhost:8443/protected; echo
```
should return something like:
```text
Protected OK 2024-08-01 11:30:37.729193176 +0000 UTC m=+7.188534380
```

#### so try to run proper client
```bash
SSL_CERT_FILE=cert.pem go run ./client \
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

### self-signed cert creation

https://github.com/denji/golang-tls ?

```bash
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem -addext "subjectAltName = DNS:localhost"
```
and inspect
```bash
openssl x509 -text -noout -in cert.pem | grep -A1 Alternative
```
gives
```
            X509v3 Subject Alternative Name: 
                DNS:localhost
```

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
- `TLS_CERT_FILE`
- `TLS_KEY_FILE`

At runtime the server validates:

- JWT signature via issuer JWKS
- issuer
- expiry
- audience

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

It may be useful later to break the current practical `1 websocket : 1 tunnel`
shape, but that should be done carefully.

A helpful distinction:

- `session != websocket`
- `control channel != data multiplexing`

The first likely architectural step is an explicit session/control layer, not
immediate multiplexing of many TCP tunnels over one websocket.

Why that ordering is preferable:

- A control plane can support resume/reconnect, lease renewal, shutdown/drain
  notices, diagnostics, and explicit session expiry without immediately making
  the byte-forwarding path much more complex.
- Full data multiplexing adds framing, stream IDs, fairness, per-stream flow
  control, shared-buffer accounting, and more complicated failure handling.
- A single multiplexed websocket also creates a larger blast radius: one
  transport failure could drop many active tunnels at once.

Useful future control-plane functions could include:

- session creation and resume tokens
- attached/detached state transitions
- heartbeat / liveness signals
- lease renewal or explicit session expiry
- reauthentication state for future resumes or live sessions
- server shutdown or drain notifications
- structured logging / user-visible diagnostics

For live tunnels, prefer session-lease renewal over tying the tunnel directly to
the original access token expiry. For example, the server could send a
`renew_soon` control message a few minutes before expiry; the client would try
refresh-token renewal first, then browser reauth if needed, and send only a new
access token over the control plane. The server can then extend the session
lease, or move the session into grace/expiry if renewal never arrives.

Essential guardrails:

- Send new access tokens over the control plane only. Never send refresh tokens
  to the Authunnel server.
- Do not hard-drop a live tunnel exactly at token expiry; use explicit
  grace/expiry policy.
- When renewing, validate continuity of identity and audience before extending
  the session lease.
- Never log bearer tokens or resume tokens.

Current guardrail:

- Do not spread websocket-specific assumptions deeper into the code than
  necessary. Future work should be able to introduce a session/control layer
  while preserving a simple and auditable per-tunnel data path.
