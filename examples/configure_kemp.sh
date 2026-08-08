#!/usr/bin/env bash
#
# Post-boot Layer-7 configuration for the Progress Kemp LoadMaster stood up by
# aws_cf_authunnel_testdev_kemp_free.yaml, applied over the LoadMaster RESTful
# API. This is the Kemp counterpart to configure_vtm.sh.
#
# WHAT IT DOES
#   1. Imports a self-signed TLS cert (PHASE 1 placeholder; switch to a real one
#      via the WUI's built-in ACME/Let's Encrypt once DNS resolves).
#   2. Creates the :443 virtual service: SSL offload, L7 (vstype=http), and adds
#      X-Forwarded-For (addvia=5, "X-Forwarded-For without Via") plus a static
#      X-Forwarded-Proto: https header. The backends run with
#      --preauth-trust-forwarded-for=rightmost.
#   3. Adds the two authunnel backends as real servers on :8080.
#   4. (Best effort) creates a :80 virtual service that 302-redirects to HTTPS.
#
# PREREQUISITES (Kemp Free has manual first-boot; see the template header)
#   * SSH setup console (ssh bal@<public-ip>): accept the pre-filled PRIVATE IP
#     with its subnet mask (e.g. 172.31.16.110/20) -- not the public IP, not /32.
#     At the end it sets the admin password: when prompted for the CURRENT
#     password enter the EC2 instance ID, then your new password.
#   * WUI at https://<public-ip>:8443/ (the WUI/API is on :8443 by default on the
#     AWS Free image, so :443 is already free for the VS -- no port move needed):
#     log in as "bal" with the password you set, accept the EULA. The AMI often
#     arrives already licensed (License Management shows "Unlimited"); if not,
#     apply the free licence with a Progress/Kemp ID.
#   * Enable the RESTful API: tick "Enable API Interface" under Certificates &
#     Security > Remote Access (older builds: System Configuration >
#     Miscellaneous Options > Remote Access).
#   * Run this from inside AdminCidr. openssl is needed locally for the cert.
#   * KEMP_VS_IP is the LoadMaster PRIVATE IP (the VS binds to it); KEMP_HOST is
#     the public IP/EIP used to reach the API and serve clients.
#
# VERSION SENSITIVITY
#   The /access API parameters below match common LoadMaster firmware. If a call
#   is rejected, perform the equivalent step in the WUI. The :80 redirect step is
#   best-effort (param names vary by version) and only warns on failure.
#
# USAGE
#   KEMP_HOST=<lm-public-ip>  KEMP_ADMIN_PW=<bal-password> \
#   KEMP_VS_IP=<lm-private-ip>  BACKEND1=<b1-private-ip> BACKEND2=<b2-private-ip> \
#   DOMAIN=<dns-name> [KEMP_API_PORT=8443] [SKIP_CERT=1] [CERT_NAME=authunnel] \
#   ./configure_kemp.sh
#
#   SKIP_CERT=1 skips the self-signed cert import (use it if you imported a cert
#   by hand in the WUI, or issued one via ACME). CERT_NAME picks which cert
#   identifier the :443 VS uses -- e.g. CERT_NAME=authunnel-acme SKIP_CERT=1 to
#   bind an ACME cert issued under that name (a real cert can't reuse the
#   self-signed "authunnel" identifier, so it needs a distinct name).
#
#   (The stack's ConfigureKempCommand output prints this with values filled in.)
#
set -euo pipefail

: "${KEMP_HOST:?set KEMP_HOST to the LoadMaster public IP/hostname}"
: "${KEMP_ADMIN_PW:?set KEMP_ADMIN_PW to the bal-user password}"
: "${KEMP_VS_IP:?set KEMP_VS_IP to the LoadMaster private IP (the VS binds to it)}"
: "${BACKEND1:?set BACKEND1 to backend 1 private IP}"
: "${BACKEND2:?set BACKEND2 to backend 2 private IP}"
: "${DOMAIN:=authunnel.test.example}"

# Certificate identifier the :443 virtual service uses. Defaults to "authunnel"
# (the self-signed PHASE 1 cert). Set CERT_NAME to bind a different cert -- e.g.
# CERT_NAME=authunnel-acme SKIP_CERT=1 to point the VS at an ACME cert you issued
# under that name in the WUI.
CERT_NAME="${CERT_NAME:-authunnel}"

KEMP_API_PORT="${KEMP_API_PORT:-8443}"
BASE="https://${KEMP_HOST}:${KEMP_API_PORT}/access"
CURL=(curl -sk -u "bal:${KEMP_ADMIN_PW}")

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# kemp_raw <endpoint?query> [extra curl args...]
# Runs the request and prints "<body>\n<http_status>" -- the HTTP status is the
# LAST line (curl -w). Returns curl's own exit status. The status is parsed in
# the CALLER (not via a global, which would be lost across the $() subshell).
kemp_raw() {
  local ep="$1"; shift
  "${CURL[@]}" -S -w $'\n%{http_code}' "$@" "${BASE}/${ep}"
}

# kemp_api <endpoint?query> [extra curl args...]: fail loudly on transport error,
# non-2xx, or a LoadMaster stat="fail" body.
kemp_api() {
  local ep="$1"; shift
  local out status body
  if ! out="$(kemp_raw "$ep" "$@")"; then
    echo "ERROR: could not reach ${BASE}/${ep%%\?*}" >&2
    exit 1
  fi
  status="${out##*$'\n'}"   # last line is the HTTP status from -w
  body="${out%$'\n'*}"      # everything before it is the response body
  # LoadMaster returns HTTP 200 with <Response stat="ok"> or stat="fail"; check both.
  if [ "${status#2}" = "${status}" ] || printf '%s' "$body" | grep -qi 'stat="fail"'; then
    echo "ERROR: '${ep%%\?*}' failed (HTTP ${status})" >&2
    [ -n "$body" ] && printf '       %s\n' "$body" >&2
    exit 1
  fi
}

# kemp_api_idem <add-verb> <mod-verb> <query>: idempotent create-or-update. Tries
# the add verb; if the object "already exists" (a re-run), retries the mod verb
# with the same query so re-running the script -- or changing CERT_NAME -- works.
kemp_api_idem() {
  local add="$1" mod="$2" q="$3"
  local out status
  out="$(kemp_raw "${add}?${q}" || true)"
  status="${out##*$'\n'}"
  if printf '%s' "$out" | grep -qi 'already exists'; then
    kemp_api "${mod}?${q}"
  elif [ "${status#2}" = "${status}" ] || printf '%s' "$out" | grep -qi 'stat="fail"'; then
    echo "ERROR: '${add}' failed (HTTP ${status})" >&2
    [ -n "${out%$'\n'*}" ] && printf '       %s\n' "${out%$'\n'*}" >&2
    exit 1
  fi
}

echo "==> Checking the LoadMaster RESTful API at ${BASE}/"
api_status="$("${CURL[@]}" -S -o /dev/null -w '%{http_code}' "${BASE}/listvs" 2>/dev/null || echo 000)"
if [ "${api_status#2}" = "${api_status}" ]; then
  echo "ERROR: REST API not reachable at ${BASE}/listvs (HTTP ${api_status})." >&2
  echo "       Enable it in the WUI (Certificates & Security > Remote Access >" >&2
  echo "       'Enable RESTful API'; older builds: System Configuration >" >&2
  echo "       Miscellaneous Options > Remote Access). Confirm you are inside" >&2
  echo "       AdminCidr and that the API is on :${KEMP_API_PORT}. Aborting." >&2
  exit 1
fi

# Certificate handling. NOTE (observed on firmware 7.2.63.2): the addcert API
# reliably CREATES a brand-new identifier only sometimes -- a first import often
# returns HTTP 422 "Certificate Identifier has been deleted", yet a REPLACE of an
# already-existing identifier succeeds. The dependable flow is therefore:
#   * import a cert named "authunnel" once via the WUI (Certificates & Security >
#     SSL Certificates > Import Certificate -- separate Certificate/Key fields,
#     far more forgiving), or issue one via ACME Certificates, THEN
#   * run with SKIP_CERT=1 (recommended) so this script leaves that cert alone.
# The API import below is attempted only when SKIP_CERT is not set; if it 422s,
# fall back to the WUI import + SKIP_CERT=1.
if [ "${SKIP_CERT:-0}" = "1" ]; then
  echo "==> 1. SKIP_CERT=1 -- using the existing '${CERT_NAME}' cert (WUI/ACME)"
else
  echo "==> 1. Self-signed TLS certificate '${CERT_NAME}' (PHASE 1 placeholder)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "${workdir}/vs.key.p8" -out "${workdir}/vs.crt" \
    -subj "/CN=${DOMAIN}" -addext "subjectAltName=DNS:${DOMAIN}" 2>/dev/null
  # LoadMaster's importer wants a traditional PKCS#1 "RSA PRIVATE KEY", not the
  # PKCS#8 "PRIVATE KEY" that `openssl req -nodes` emits (OpenSSL 3.x also
  # defaults `rsa` to PKCS#8, so -traditional is required).
  openssl rsa -traditional -in "${workdir}/vs.key.p8" -out "${workdir}/vs.key" 2>/dev/null
  cat "${workdir}/vs.key" "${workdir}/vs.crt" > "${workdir}/vs.pem"
  # Sent as the raw request body (curl --data-binary default Content-Type).
  cert_out="$(kemp_raw "addcert?cert=${CERT_NAME}&replace=1" --data-binary @"${workdir}/vs.pem" || true)"
  cert_status="${cert_out##*$'\n'}"
  if [ "${cert_status#2}" = "${cert_status}" ] || printf '%s' "$cert_out" | grep -qi 'stat="fail"'; then
    # Persist the generated cert/key so the manual WUI import is copy-paste easy.
    cp -f "${workdir}/vs.crt" ./authunnel.crt
    cp -f "${workdir}/vs.key" ./authunnel.key
    echo "ERROR: addcert failed (HTTP ${cert_status})." >&2
    echo "       This firmware's API rejects a fresh combined-PEM import; the" >&2
    echo "       reliable path is a WUI import then SKIP_CERT=1:" >&2
    echo "         1. Wrote ./authunnel.crt and ./authunnel.key in this dir." >&2
    echo "         2. WUI > Certificates & Security > SSL Certificates > Import:" >&2
    echo "            Certificate File = authunnel.crt, Key File = authunnel.key," >&2
    echo "            Certificate Identifier = ${CERT_NAME}." >&2
    echo "         3. Re-run this command with SKIP_CERT=1 prepended." >&2
    echo "       (API response was: ${cert_out%$'\n'*})" >&2
    exit 1
  fi
fi

echo "==> 2. Virtual service on :443 (SSL offload, X-Forwarded-For + Proto)"
# vstype=http (L7); sslacceleration=Y with certfile=${CERT_NAME}; transparent=N so
# the backend sees the LoadMaster and the real client travels in X-Forwarded-For;
# addvia=5 adds "X-Forwarded-For (no Via)"; the extra header carries the scheme.
# add-or-modify so re-runs (and CERT_NAME changes) update the existing VS.
kemp_api_idem addvs modvs "vs=${KEMP_VS_IP}&port=443&prot=tcp&vstype=http&nickname=authunnel&sslacceleration=Y&certfile=${CERT_NAME}&transparent=N&addvia=5&extrahdrkey=X-Forwarded-Proto&extrahdrvalue=https"

echo "==> 3. Real servers on :8080 (${BACKEND1}, ${BACKEND2})"
for rs in "${BACKEND1}" "${BACKEND2}"; do
  kemp_api_idem addrs modrs "vs=${KEMP_VS_IP}&port=443&prot=tcp&rs=${rs}&rsport=8080&forward=nat&weight=1000"
done

echo "==> 4. (best effort) :80 virtual service redirecting to HTTPS"
# Param names for the redirect vary by firmware; this is non-essential, so only
# warn on failure. If it doesn't take, add the :80 redirect in the WUI.
redir_out="$(kemp_raw "addvs?vs=${KEMP_VS_IP}&port=80&prot=tcp&vstype=http&nickname=authunnel-redirect&errorcode=302&errorurl=https://%h%s" 2>/dev/null || true)"
redir_status="${redir_out##*$'\n'}"
if printf '%s' "$redir_out" | grep -qi 'already exists'; then
  echo "    :80 redirect VS already present -- leaving as is."
elif [ "${redir_status#2}" = "${redir_status}" ] || printf '%s' "$redir_out" | grep -qi 'stat="fail"'; then
  echo "    WARN: :80 redirect VS not created (HTTP ${redir_status}). Add it in the WUI:" >&2
  echo "          a port-80 VS with a 302 redirect to https://%h%s." >&2
fi

echo "==> Done (PART 1). The LoadMaster is serving https://${DOMAIN}/ with a"
echo "    SELF-SIGNED cert. For a real cert (PART 2): point ${DOMAIN}'s public DNS"
echo "    at the LoadMaster IP, then use the WUI's built-in ACME / Let's Encrypt"
echo "    (Certificates & Security > SSL Certificates) and assign it to the"
echo "    'authunnel' virtual service."
echo
echo "    NOTE: authunnel's WebSocket origin check also looks at X-Forwarded-Host."
echo "    LoadMaster passes the original Host header to the backend by default; if"
echo "    the origin check rejects, add an X-Forwarded-Host header rule in the WUI."
