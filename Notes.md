

## PoC reminders

using two Okta, https://dev-125016-admin.okta.com, "Apps":
- for real client `CLIENT_ID`
- for token checking on server `CC_CLIENT_ID` (should not be  needed?)

### server server/server.go setup

```bash
export ISSUER=https://dev-125016.okta.com/oauth2/default
export CC_CLIENT_ID=0oaigwf79lMMYlvA64x7
export CC_CLIENT_SECRET=EB-SrGvgMQY8jVQaKJP7JEHImDLWWYZ7YDHO6yyXdCYLlmmVe71rSHxYBl9eA7i_

(cd server; CLIENT_ID=$CC_CLIENT_ID CLIENT_SECRET=$CC_CLIENT_SECRET go run server.go )
```
####

Check self signed cert working ok:

```bash
curl --cacert cert.pem https://localhost:8443; echo
```
should give something like:

```text
OK 2024-08-01 11:16:24.39347267 +0000 UTC m=+2361.464048826
```

### client client/client.go setup


```bash
export ISSUER=https://dev-125016.okta.com/oauth2/default
export CLIENT_ID=0oaig0t59zmBb32vX4x7
```

and get an access token:

```bash
oauth2c $ISSUER --client-id=$CLIENT_ID --grant-type=authorization_code --auth-method=none --response-mode=form_post --response-types=code  --scopes=openid,email,profile --pkce | tee tmp.json | jq -c .
```

will go via web browser and login, which will need to access local port created by `outh2c`. Then get access token:

```bash
export ACCESS_TOKEN=$(jq -r .access_token tmp.json)
```

#### check access token access

##### direct with IdP:
(duplicated below ... )
```bash
curl -s --location --request POST  $ISSUER/v1/introspect --header 'Content-Type: application/x-www-form-urlencoded' --header 'Authorization: Basic '$(echo -n "$CC_CLIENT_ID:$CC_CLIENT_SECRET" | base64 -w0)  --data-urlencode 'token_type_hint=access_token' --data-urlencode token=$ACCESS_TOKEN | jq -c .
```
should give something like:
```json
{"active":true,"scope":"email profile openid","username":"david.jackson+okta@sanger.ac.uk","exp":1722514880,"iat":1722511280,"sub":"david.jackson+okta@sanger.ac.uk","aud":"api://default","iss":"https://dev-125016.okta.com/oauth2/default","jti":"AT.MNy0cnGf9MNx6vvxMPSsje4AF-9saYgtoCd2B_YhPNE","token_type":"Bearer","client_id":"0oaig0t59zmBb32vX4x7","uid":"00uxr08tjdMUabnxA4x6"}
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
SSL_CERT_FILE=cert.pem go run client/client.go
```
and use the unix socket that provides for the proxy:
```bash
all_proxy=socks5h://localhost$PWD/proxy.sock curl https://www.bbc.co.uk
```


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

```bash
export ISSUER=https://dev-125016.okta.com/oauth2/default
export CLIENT_ID=0oaig0t59zmBb32vX4x7
oauth2c $ISSUER --client-id=$CLIENT_ID --grant-type=authorization_code --auth-method=none --response-mode=form_post --response-types=code  --scopes=openid,email,profile --pkce
```

If the resulting access token is set in `ACCESS_TOKEN`...

### Resource Server style validation of Access Token

#### same client ID

```bash
curl -s --location --request POST  $ISSUER/v1/introspect --header 'Content-Type: application/x-www-form-urlencoded'  --data-urlencode 'token_type_hint=access_token' --data-urlencode token=$ACCESS_TOKEN --data-urlencode client_id=$CLIENT_ID | jq .
```
gives
```json
{
  "active": true,
  "scope": "email profile openid",
  "username": "david.jackson+okta@sanger.ac.uk",
  "exp": 1713100341,
  "iat": 1713096741,
  "sub": "david.jackson+okta@sanger.ac.uk",
  "aud": "api://default",
  "iss": "https://dev-125016.okta.com/oauth2/default",
  "jti": "AT.CyrlgVQhwUUGinMZw2qFa_P1HiY4B8lrKybxd8r7EA0",
  "token_type": "Bearer",
  "client_id": "0oaig0t59zmBb32vX4x7",
  "uid": "00uxr08tjdMUabnxA4x6"
}
```

#### separate client credential ID and secret

where separate client ID and secret are set in `CC_CLIENT_ID` and `CC_CLIENT_SECRET`. (This secret is on the resource server so can be kept).

```bash
curl -s --location --request POST  $ISSUER/v1/introspect --header 'Content-Type: application/x-www-form-urlencoded' --header 'Authorization: Basic '$(echo -n "$CC_CLIENT_ID:$CC_CLIENT_SECRET" | base64 -w0)  --data-urlencode 'token_type_hint=access_token' --data-urlencode token=$ACCESS_TOKEN | jq .
```
also gives:
```json
{
  "active": true,
  "scope": "email profile openid",
  "username": "david.jackson+okta@sanger.ac.uk",
  "exp": 1713100341,
  "iat": 1713096741,
  "sub": "david.jackson+okta@sanger.ac.uk",
  "aud": "api://default",
  "iss": "https://dev-125016.okta.com/oauth2/default",
  "jti": "AT.CyrlgVQhwUUGinMZw2qFa_P1HiY4B8lrKybxd8r7EA0",
  "token_type": "Bearer",
  "client_id": "0oaig0t59zmBb32vX4x7",
  "uid": "00uxr08tjdMUabnxA4x6"
}
```


