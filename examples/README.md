# Example deployments

This directory contains runnable CloudFormation templates that stand up a
complete Authunnel topology on AWS, so you can see the whole system working
end to end before deploying it on your own infrastructure.

All five stacks are **test/dev learning aids, not production blueprints**.
To make it quick to stand one up and try it, they run the `authunnel-server`
instances with a deliberately permissive posture:

- open egress (`--allow-open-egress`, rather than a scoped `--allow` list)
- the resolved-IP guard disabled (`--no-ip-block`)
- debug-level logging

A real deployment should tighten all three. See
[docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md), and in particular its
[Deployment Hardening Checklist](../docs/DEPLOYMENT.md#deployment-hardening-checklist),
for the settings a production rollout should use instead.

## Common topology

Every stack terminates TLS at a public-facing load balancer or reverse
proxy, then forwards plaintext to two `authunnel-server` instances on
`:8080`. The backend security group accepts `:8080` connections only from
the fronting proxy, so the origin servers are never directly reachable from
the internet. This mirrors how Authunnel is meant to run in production:
plaintext behind a TLS-terminating reverse proxy that the operator already
runs for other services.

Every stack also deploys an **isolated backend host**: a plain EC2 instance
running stock `sshd`, whose security group accepts port 22 only from the
authunnel-server nodes' security group — no public SSH, no other path in.
This is the scenario authunnel is actually for (see the "Managed OIDC client
mode" `ProxyCommand` pattern in the main [README](../README.md)): point
`authunnel-client` at the isolated host's private IP (stack output
`IsolatedHostPrivateIp`) through the tunnel, e.g.

```sshconfig
Host isolated-host
  HostName <IsolatedHostPrivateIp output>
  User ec2-user
  ProxyCommand /path/to/authunnel-client \
    --tunnel-url https://<tunnel endpoint>/protected/tunnel \
    --oidc-issuer <issuer> \
    --oidc-client-id <client-id> \
    --proxycommand %h %p
```

then `ssh isolated-host`. There is no other way to reach it.

The exact flags above depend on which stack you deployed, since each wires
up the token audience differently:

- **generic / vTM / Kemp** — the server runs with
  `--token-audience=<TokenAudience parameter>`. The client must request a
  matching `aud` by adding `--oidc-audience <the same TokenAudience value>`
  (the Auth0-style `audience` request parameter); omit it and the server
  rejects the token.
- **Keycloak** — no extra flag needed. The imported realm's `authunnel-cli`
  client has the audience mapper baked into its default client scope, so
  every token already carries `aud=authunnel-server`.
- **Cognito** — ignores `--oidc-audience` entirely. Use the flags from the
  stack's `ClientInvocationHint` output instead (`--oidc-resource`,
  `--oidc-scopes`, `--oidc-redirect-port`); see the template header for why.

Three of the five stacks are **issuer-agnostic** — you point them at an
OIDC provider you already have (Auth0, Okta, an existing Keycloak, ...) —
and differ only in what sits in front of the servers as the TLS-terminating
reverse proxy:

- [`aws_cf_authunnel_testdev_generic.yaml`](aws_cf_authunnel_testdev_generic.yaml) —
  an AWS Network Load Balancer terminates TLS on `:443` in front of the
  backend pool. The simplest stack to stand up, useful as a baseline or when
  you don't need to evaluate a specific reverse-proxy product.
- [`aws_cf_authunnel_testdev_ivanti_vtm_ce.yaml`](aws_cf_authunnel_testdev_ivanti_vtm_ce.yaml) —
  the same topology, but with **Ivanti vTM** running in its licence-free
  **Community Edition** as the reverse proxy. vTM terminates TLS, load-balances
  the backend pool, and sets the `X-Forwarded-*` headers the server expects
  (the backends run with `--preauth-trust-forwarded-for=rightmost`). Community
  Edition needs no licence key (capped at 10 Mb/s and a 4-node cluster — ample
  for evaluation). The companion script
  [`configure_vtm.sh`](configure_vtm.sh) applies the L7 service configuration
  after boot, starting with a self-signed certificate that you can later swap
  for a real one once DNS points at the vTM.
- [`aws_cf_authunnel_testdev_kemp_free.yaml`](aws_cf_authunnel_testdev_kemp_free.yaml) —
  the same topology again, but with a **Progress Kemp LoadMaster** in its
  **free edition** (20 Mb/s, perpetual licence) as the reverse proxy. The
  companion script [`configure_kemp.sh`](configure_kemp.sh) applies the L7
  service configuration over the LoadMaster's RESTful API. Licensing here is a
  short manual first-boot step (an SSH setup console, then accepting the EULA
  in the web UI) rather than fully automated from user-data, so it's a little
  less hands-off than the vTM stack.

The other two instead **deploy an OIDC authorization server as well**, so
the whole flow can be exercised without needing an external identity
provider at all:

- [`aws_cf_authunnel_testdev_keycloak.yaml`](aws_cf_authunnel_testdev_keycloak.yaml) —
  the NLB topology plus a **Keycloak** instance acting as the OIDC issuer,
  with a working test realm imported inline. A second NLB TLS listener
  fronts Keycloak, so one certificate and DNS name serve both the tunnel and
  the issuer. Works with the `authunnel-client` unmodified.
- [`aws_cf_authunnel_testdev_cognito.yaml`](aws_cf_authunnel_testdev_cognito.yaml) —
  the NLB topology plus **AWS Cognito** (fully managed) as the issuer: user
  pool, resource server, custom scope, managed login, and app client, all
  defined natively in CloudFormation. Cognito only sets an `aud` claim on
  access tokens when the authorization request carries an RFC 8707 `resource`
  parameter, so this stack requires the client's `--oidc-resource` flag and a
  fixed `--oidc-redirect-port`; the template header documents the full set of
  Cognito-specific requirements.

## Getting started

Each template documents its own parameters and any manual post-boot steps
in a comment block at the top of the file — read that first. In brief:

1. Pick a stack based on what you want to evaluate: the plain NLB variant to
   see the core topology, one of the vTM/Kemp variants to evaluate a specific
   reverse-proxy product, or the Keycloak/Cognito variants if you don't have
   an OIDC provider handy.
2. Deploy it with the AWS CLI or console, supplying the parameters the
   template asks for (VPC, subnets, an ACM certificate ARN, and so on).
3. For the vTM and Kemp variants, run the companion `configure_*.sh` script
   against the newly created appliance to apply its L7 service configuration.
   The stack's `ConfigureVtmCommand` / `ConfigureKempCommand` output prints
   the exact invocation, prefixed with `cd examples &&` — run it from the
   repo root, or drop that prefix if you're already inside `examples/`.
4. Point `authunnel-client` at the stack's public DNS name and confirm you
   can open a tunnel end to end.

Tear the stack down when you're done evaluating it — these templates are not
meant to be left running.
