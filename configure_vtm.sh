#!/usr/bin/env bash
#
# Post-boot Layer-7 configuration for the Ivanti vTM stood up by
# aws_cf_authunnel_testdev_ivanti_vtm_ce.yaml.
#
# The vTM appliance configures only its admin password from EC2 user-data; it
# does not run shell scripts. This script applies the rest of the configuration
# over the vTM REST API once the node is up.
#
# WHAT IT DOES
#   1. Installs a self-signed TLS cert on :443 (PHASE 1 placeholder; swap for a
#      Let's Encrypt cert later -- see the template header notes).
#   2. Creates the backend pool over plaintext :8080.
#   3. Adds a TrafficScript request rule setting X-Forwarded-Proto/Host/For
#      (the backends run with --preauth-trust-forwarded-for=rightmost).
#   4. Creates the TLS-decrypting :443 virtual server (WebSockets pass through).
#   5. Creates a :80 virtual server that redirects to HTTPS except the ACME
#      challenge path (so the Let's Encrypt HTTP-01 switch works later).
#
# PREREQUISITES
#   * Run from a host inside AdminCidr (the vTM REST API on :9070 is restricted
#     to that CIDR by the stack's security group).
#   * The REST API is enabled by default -- no need to turn it on in the Admin
#     UI first. But after boot the appliance takes a few minutes to bring up the
#     web (:9090) and REST (:9070) services, so the first connection may be
#     refused; wait and retry. Confirm it is up and list supported API versions:
#       curl -sk -u admin:PW https://VTM_HOST:9070/api/tm/
#   * openssl and python3 must be available locally (used to mint and JSON-encode
#     the self-signed certificate).
#
# VERSION SENSITIVITY
#   The REST API version (path segment) is the API version, NOT the product
#   version. This script defaults to 8.5 (vTM 22.9r4); override with VTM_API_VER
#   if your build differs -- list supported versions with:
#     curl -sk -u admin:PW https://HOST:9070/api/tm/
#   The resource field names should be stable across recent versions, but if a
#   PUT is rejected, perform the equivalent step in the Admin UI (:9090).
#
# USAGE
#   VTM_HOST=<vtm-public-ip>  VTM_ADMIN_PW=<password> \
#   BACKEND1=<backend1-private-ip> BACKEND2=<backend2-private-ip> \
#   DOMAIN=<dns-name> [VTM_API_VER=<x.y>] ./configure_vtm.sh
#
#   (The stack's ConfigureVtmCommand output prints this with values filled in.)
#
set -euo pipefail

: "${VTM_HOST:?set VTM_HOST to the vTM public IP/hostname}"
: "${VTM_ADMIN_PW:?set VTM_ADMIN_PW to the vTM admin password}"
: "${BACKEND1:?set BACKEND1 to backend 1 private IP}"
: "${BACKEND2:?set BACKEND2 to backend 2 private IP}"
: "${DOMAIN:=authunnel.test.example}"

# REST API version (path segment). This is the API version, NOT the product
# version; vTM 22.9r4 tops out at 8.5. Override with VTM_API_VER if your build
# differs (list supported versions with: curl -sk -u admin:PW https://HOST:9070/api/tm/).
API_VER="${VTM_API_VER:-8.5}"
CURL=(curl -sk -u "admin:${VTM_ADMIN_PW}")
REST="https://${VTM_HOST}:9070/api/tm/${API_VER}/config/active"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# vtm_put <url> [extra curl args...]
# PUT to the vTM REST API and fail loudly on any non-2xx response, printing the
# vTM error body (error_id / error_text) so a rejected resource is not silent.
vtm_put() {
  local url="$1"; shift
  local out status body
  if ! out="$("${CURL[@]}" -S -w $'\n%{http_code}' -X PUT "$@" "$url")"; then
    echo "ERROR: curl could not reach ${url}" >&2
    exit 1
  fi
  status="${out##*$'\n'}"   # last line is the HTTP status from -w
  body="${out%$'\n'*}"      # everything before it is the response body
  case "$status" in
    2[0-9][0-9]) ;;
    *)
      echo "ERROR: PUT ${url} returned HTTP ${status}" >&2
      [ -n "$body" ] && echo "       ${body}" >&2
      exit 1
      ;;
  esac
}

echo "==> Using REST API version ${API_VER}: ${REST}"
if ! "${CURL[@]}" "${REST}/" >/dev/null 2>&1; then
  echo "ERROR: cannot reach ${REST}/. If the node booted only a few minutes ago" >&2
  echo "       the REST/web services may still be starting -- wait and retry." >&2
  echo "       Otherwise check you are inside AdminCidr and that API version" >&2
  echo "       ${API_VER} is supported: curl -sk -u admin:PW https://${VTM_HOST}:9070/api/tm/" >&2
  exit 1
fi

echo "==> 1. Self-signed TLS certificate for :443 (PHASE 1 placeholder)"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "${workdir}/vs.key" -out "${workdir}/vs.crt" \
  -subj "/CN=${DOMAIN}" -addext "subjectAltName=DNS:${DOMAIN}" 2>/dev/null

KEY_JSON=$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' "${workdir}/vs.key")
CRT_JSON=$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' "${workdir}/vs.crt")
cat > "${workdir}/serverkey.json" <<EOF
{"properties":{"basic":{"note":"authunnel testdev","private":${KEY_JSON},"public":${CRT_JSON}}}}
EOF
vtm_put "${REST}/ssl/server_keys/authunnel" \
  -H 'Content-Type: application/json' --data @"${workdir}/serverkey.json"

echo "==> 2. Backend pool over plaintext :8080 (${BACKEND1}, ${BACKEND2})"
cat > "${workdir}/pool.json" <<EOF
{"properties":{"basic":{"nodes_table":[
  {"node":"${BACKEND1}:8080","state":"active"},
  {"node":"${BACKEND2}:8080","state":"active"}
],"monitors":["Connect"]}}}
EOF
vtm_put "${REST}/pools/authunnel" \
  -H 'Content-Type: application/json' --data @"${workdir}/pool.json"

echo "==> 3. Request rule: set X-Forwarded-Proto/Host/For"
# X-Forwarded-Proto/Host drive authunnel's WebSocket origin check; X-Forwarded-For
# carries the real client IP for this single trusted hop. Rules are text resources.
vtm_put "${REST}/rules/authunnel-forwarded" -H 'Content-Type: application/octet-stream' \
  --data-binary $'http.setHeader( "X-Forwarded-Proto", "https" );\nhttp.setHeader( "X-Forwarded-Host", http.getHostHeader() );\nhttp.setHeader( "X-Forwarded-For", request.getRemoteIP() );'

echo "==> 4. TLS-decrypting virtual server on :443 -> pool"
# protocol "http" carries WebSocket upgrades transparently.
cat > "${workdir}/vs.json" <<EOF
{"properties":{"basic":{
  "enabled":true,
  "port":443,
  "protocol":"http",
  "pool":"authunnel",
  "ssl_decrypt":true,
  "listen_on_any":true,
  "request_rules":["authunnel-forwarded"]
},"ssl":{
  "server_cert_default":"authunnel"
}}}
EOF
vtm_put "${REST}/virtual_servers/authunnel" \
  -H 'Content-Type: application/json' --data @"${workdir}/vs.json"

echo "==> 5. Plain HTTP virtual server on :80 (redirect, ACME-challenge-aware)"
# Redirects everything to HTTPS EXCEPT /.well-known/acme-challenge/, which is
# left for vTM to serve during a Let's Encrypt HTTP-01 challenge. Uses the
# built-in "discard" pool because the redirect rule short-circuits real requests.
vtm_put "${REST}/rules/authunnel-https-redirect" -H 'Content-Type: application/octet-stream' \
  --data-binary $'$path = http.getPath();\nif( ! string.startsWith( $path, "/.well-known/acme-challenge/" ) ) {\n   http.redirect( "https://" . http.getHostHeader() . $path );\n}'
cat > "${workdir}/vs80.json" <<EOF
{"properties":{"basic":{
  "enabled":true,
  "port":80,
  "protocol":"http",
  "pool":"discard",
  "listen_on_any":true,
  "request_rules":["authunnel-https-redirect"]
}}}
EOF
vtm_put "${REST}/virtual_servers/authunnel-http" \
  -H 'Content-Type: application/json' --data @"${workdir}/vs80.json"

echo "==> Done (PART 1). The vTM is serving https://${DOMAIN}/ with a SELF-SIGNED"
echo "    cert. Set up a real signed cert next (PART 2):"
echo "      1. Point ${DOMAIN}'s public DNS at the vTM's IP and let it resolve."
echo "      2. Admin UI > Catalogs > SSL > Server Certs > LetsEncrypt: create a"
echo "         cert for ${DOMAIN}. NOTE on vTM 22.9r4: the built-in Let's Encrypt"
echo "         works via the DNS-01 challenge with Cloudflare (supply the zone ID"
echo "         and an API token); the HTTP-01 challenge FAILS ('uacme: failed to"
echo "         create new order') on this build, so use DNS-01."
echo "      3. Edit the 'authunnel' (:443) virtual server and set its SSL server"
echo "         certificate to the new Let's Encrypt cert."
