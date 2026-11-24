# IAM Hands-On Labs Guide

Practical exercises for building, testing, and securing identity systems.

**Estimated duration:** 6 to 8 weeks at part-time pace (rough estimate; adjust to your schedule)
**Prerequisites:** Linux, Docker with the Compose plugin, basic networking, basic Python

> **Scope and safety.** Run every lab only on systems you own or are authorized to test. The passwords, keys, and secrets in these labs are for local practice only. Generate new ones for any shared environment. Do not expose lab services to a network you do not control. Bind them to `127.0.0.1` as shown.

---

## Table of Contents

- [Environment Setup](#environment-setup)
- [Lab 1: LDAP Directory Services](#lab-1-ldap-directory-services)
- [Lab 2: OAuth 2.0 and OpenID Connect](#lab-2-oauth-20-and-openid-connect)
- [Lab 3: RBAC and Separation of Duties](#lab-3-rbac-and-separation-of-duties)
- [Lab 4: Detection and Defensive Testing](#lab-4-detection-and-defensive-testing)
- [Lab 5: Capstone Project](#lab-5-capstone-project)
- [Self-Assessment Rubric](#self-assessment-rubric)

---

## Environment Setup

Ubuntu 24.04 and recent Debian releases block system-wide `pip install`. Use a virtual environment.

```bash
# System packages
sudo apt-get update
sudo apt-get install -y \
  ldap-utils jq curl git openssl tcpdump \
  build-essential python3-dev python3-venv \
  libsasl2-dev libldap2-dev libssl-dev

# Docker Engine and the Compose plugin: follow https://docs.docker.com/engine/install/
docker compose version

# Python environment for the labs
mkdir -p ~/iam-labs/{ldap,oauth,rbac,detection,capstone}
python3 -m venv ~/iam-labs/.venv
source ~/iam-labs/.venv/bin/activate
pip install --upgrade pip
pip install python-ldap flask requests cryptography pyjwt argon2-cffi

# Isolated Docker network for the LDAP lab
docker network create --subnet=172.20.0.0/16 iam-ldap
```

Pin image tags and library versions in your own copies. Tags such as `latest` change without notice and can break these labs.

---

## Lab 1: LDAP Directory Services

### Lab 1.1: Deploy and Secure an LDAP Directory

**Objective:** Deploy OpenLDAP, design a directory tree, configure access controls, and verify them.

#### Step 1: Deploy OpenLDAP

Create a `.env` file with lab-only passwords. Do not commit it to version control.

```bash
cd ~/iam-labs/ldap
cat > .env << 'EOF'
LDAP_ADMIN_PASSWORD=change-me-admin
LDAP_CONFIG_PASSWORD=change-me-config
EOF
chmod 600 .env
```

Replace the placeholder values with your own before starting the container.

```yaml
# ~/iam-labs/ldap/docker-compose.yml
services:
  openldap:
    image: osixia/openldap:1.5.0   # confirm the current tag on Docker Hub before use
    container_name: iam-openldap
    env_file: .env
    environment:
      LDAP_ORGANISATION: "IAM Labs Inc"
      LDAP_DOMAIN: "iamlabs.local"
    ports:
      - "127.0.0.1:389:389"
      - "127.0.0.1:636:636"
    volumes:
      - ./data:/var/lib/ldap
      - ./config:/etc/ldap/slapd.d
    networks:
      - iam-ldap

networks:
  iam-ldap:
    external: true
```

```bash
docker compose up -d
sleep 10
docker compose logs openldap | tail -n 20
```

The admin DN for this image is `cn=admin,dc=iamlabs,dc=local`. Confirm it in the container logs, since image defaults can change between versions.

#### Step 2: Design the Directory Information Tree

```ldif
# ~/iam-labs/ldap/base-structure.ldif
dn: ou=People,dc=iamlabs,dc=local
objectClass: organizationalUnit
ou: People

dn: ou=Groups,dc=iamlabs,dc=local
objectClass: organizationalUnit
ou: Groups

dn: ou=Services,dc=iamlabs,dc=local
objectClass: organizationalUnit
ou: Services

dn: ou=Policies,dc=iamlabs,dc=local
objectClass: organizationalUnit
ou: Policies

dn: cn=admins,ou=Groups,dc=iamlabs,dc=local
objectClass: groupOfNames
cn: admins
member: cn=admin,dc=iamlabs,dc=local

dn: cn=developers,ou=Groups,dc=iamlabs,dc=local
objectClass: groupOfNames
cn: developers
member: cn=admin,dc=iamlabs,dc=local

dn: cn=finance,ou=Groups,dc=iamlabs,dc=local
objectClass: groupOfNames
cn: finance
member: cn=admin,dc=iamlabs,dc=local
```

`groupOfNames` requires at least one member, which is why the admin DN appears in each group. Remove it once real members exist.

```bash
ldapadd -x -H ldap://localhost \
  -D "cn=admin,dc=iamlabs,dc=local" -W \
  -f base-structure.ldif
```

#### Step 3: Configure Password Policy and Access Controls

Password policy in OpenLDAP depends on the `ppolicy` overlay. The entry below has no effect until that overlay is loaded and configured. Check whether your image has it enabled:

```bash
ldapsearch -x -H ldap://localhost \
  -D "cn=admin,cn=config" -W \
  -b "cn=config" "(objectClass=olcOverlayConfig)" dn olcOverlay
```

If `ppolicy` is missing, load it through your image's documentation or the overlay LDIF in the OpenLDAP distribution before continuing. Then add the policy entry:

```ldif
# ~/iam-labs/ldap/password-policy.ldif
dn: cn=default,ou=Policies,dc=iamlabs,dc=local
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: userPassword
pwdMinLength: 12
pwdMaxAge: 7776000
pwdInHistory: 5
pwdCheckQuality: 2
pwdLockout: TRUE
pwdMaxFailure: 5
pwdFailureCountInterval: 900
pwdLockoutDuration: 900
pwdAllowUserChange: TRUE
pwdSafeModify: TRUE
```

```bash
ldapadd -x -H ldap://localhost -D "cn=admin,dc=iamlabs,dc=local" -W \
  -f password-policy.ldif
```

Access controls live in the `cn=config` tree. First find the database entry name, which depends on the backend (`mdb` or `hdb`):

```bash
ldapsearch -x -H ldap://localhost \
  -D "cn=admin,cn=config" -W \
  -b "cn=config" "(olcDatabase={1}*)" dn
```

Use the DN you find in place of `olcDatabase={1}mdb` below.

```ldif
# ~/iam-labs/ldap/acls.ldif
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword
  by self write
  by anonymous auth
  by dn="cn=admin,dc=iamlabs,dc=local" write
  by * none
olcAccess: {1}to dn.subtree="ou=People,dc=iamlabs,dc=local"
  by dn="cn=admin,dc=iamlabs,dc=local" write
  by self read
  by * none
olcAccess: {2}to *
  by dn="cn=admin,dc=iamlabs,dc=local" write
  by * read
```

```bash
ldapmodify -x -H ldap://localhost \
  -D "cn=admin,cn=config" -W \
  -f acls.ldif
```

Back up the existing ACLs before applying changes, and test with a lab user before you rely on them.

#### Step 4: Create Test Users

This script generates a random password for each user and stores them in a file readable only by you. Passwords are never hardcoded.

```python
#!/usr/bin/env python3
# ~/iam-labs/ldap/create_test_users.py
import base64
import hashlib
import json
import os
import secrets

import ldap
import ldap.modlist as modlist

LDAP_URI = "ldap://localhost"
BASE = "dc=iamlabs,dc=local"
ADMIN_DN = f"cn=admin,{BASE}"
ADMIN_PW = os.environ["LDAP_ADMIN_PASSWORD"]
CREDS_FILE = os.path.expanduser("~/iam-labs/ldap/lab-users.json")

USERS = [
    {"uid": "john.admin",   "cn": "John Administrator", "sn": "Administrator", "groups": ["admins", "developers"]},
    {"uid": "jane.dev",     "cn": "Jane Developer",     "sn": "Developer",     "groups": ["developers"]},
    {"uid": "bob.finance",  "cn": "Bob Finance",        "sn": "Finance",       "groups": ["finance"]},
    {"uid": "alice.audit",  "cn": "Alice Auditor",      "sn": "Auditor",       "groups": []},
]


def ssha(password: str) -> str:
    """Salted SHA-1 password hash in LDAP {SSHA} format (lab compatibility only)."""
    salt = secrets.token_bytes(8)
    digest = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(digest + salt).decode()


conn = ldap.initialize(LDAP_URI)
conn.simple_bind_s(ADMIN_DN, ADMIN_PW)

creds = {}
for index, user in enumerate(USERS):
    dn = f"uid={user['uid']},ou=People,{BASE}"
    password = secrets.token_urlsafe(16)

    attrs = {
        "objectClass": [b"inetOrgPerson", b"posixAccount", b"shadowAccount"],
        "uid": [user["uid"].encode()],
        "cn": [user["cn"].encode()],
        "sn": [user["sn"].encode()],
        "mail": [f"{user['uid']}@iamlabs.local".encode()],
        "userPassword": [ssha(password).encode()],
        "uidNumber": [str(10000 + index).encode()],
        "gidNumber": [b"10000"],
        "homeDirectory": [f"/home/{user['uid']}".encode()],
        "loginShell": [b"/usr/sbin/nologin"],
    }

    try:
        conn.add_s(dn, modlist.addModlist(attrs))
        creds[user["uid"]] = password
        print(f"Created {user['uid']}")
    except ldap.ALREADY_EXISTS:
        print(f"{user['uid']} already exists; delete the entry to regenerate its password")
        continue

    for group in user["groups"]:
        group_dn = f"cn={group},ou=Groups,{BASE}"
        try:
            conn.modify_s(group_dn, [(ldap.MOD_ADD, "member", [dn.encode()])])
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass

conn.unbind_s()

with open(CREDS_FILE, "w") as f:
    json.dump(creds, f, indent=2)
os.chmod(CREDS_FILE, 0o600)
print(f"Passwords written to {CREDS_FILE} (mode 600)")
```

```bash
export LDAP_ADMIN_PASSWORD="$(grep ^LDAP_ADMIN_PASSWORD ~/iam-labs/ldap/.env | cut -d= -f2)"
python create_test_users.py
```

#### Step 5: Test Authentication

```bash
CREDS=~/iam-labs/ldap/lab-users.json
for user in john.admin jane.dev bob.finance alice.audit; do
  pw=$(jq -r --arg u "$user" '.[$u]' "$CREDS")
  if ldapwhoami -x -H ldap://localhost \
       -D "uid=$user,ou=People,dc=iamlabs,dc=local" -w "$pw" >/dev/null 2>&1; then
    echo "$user: bind OK"
  else
    echo "$user: bind FAILED"
  fi
done
```

Also confirm that an empty password is rejected. Some servers accept an empty-password simple bind as an unauthenticated (anonymous) bind, and applications must guard against it:

```bash
ldapwhoami -x -H ldap://localhost \
  -D "uid=john.admin,ou=People,dc=iamlabs,dc=local" -w "" && echo "UNEXPECTED" || echo "Empty password rejected"
```

#### Step 6: Security Check

```bash
#!/usr/bin/env bash
# ~/iam-labs/ldap/security_check.sh
set -u
BASE="dc=iamlabs,dc=local"
CREDS=~/iam-labs/ldap/lab-users.json
ALICE_PW=$(jq -r '."alice.audit"' "$CREDS")

echo "=== LDAP lab security check ==="

echo "[1] Anonymous bind"
if ldapwhoami -x -H ldap://localhost 2>/dev/null | grep -qi anonymous; then
  echo "    FINDING: anonymous bind succeeds"
else
  echo "    OK: anonymous bind refused"
fi

echo "[2] LDAPS on port 636"
if timeout 3 openssl s_client -connect localhost:636 </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
  echo "    OK: LDAPS presents a certificate"
else
  echo "    FINDING: LDAPS not reachable"
fi

echo "[3] Non-admin user enumerating other users (expected: no results)"
count=$(ldapsearch -x -H ldap://localhost \
  -D "uid=alice.audit,ou=People,$BASE" -w "$ALICE_PW" \
  -b "ou=People,$BASE" "(objectClass=inetOrgPerson)" uid 2>/dev/null | grep -c "^uid:")
if [ "$count" -le 1 ]; then
  echo "    OK: low-privilege user sees only own entry ($count result)"
else
  echo "    FINDING: low-privilege user sees $count entries"
fi

echo "[4] Password policy entry"
if ldapsearch -x -H ldap://localhost \
     -D "cn=admin,$BASE" -W -b "cn=default,ou=Policies,$BASE" pwdMinLength 2>/dev/null | grep -q pwdMinLength; then
  echo "    OK: policy entry present (confirm ppolicy overlay is active)"
else
  echo "    FINDING: policy entry not found"
fi

echo "=== Check complete ==="
```

```bash
chmod +x ~/iam-labs/ldap/security_check.sh
~/iam-labs/ldap/security_check.sh
```

Each check is a starting point. A real audit covers much more, including ACLs on every subtree, logging, and replication security.

### Lab 1.2: Integrate LDAP with a Web Application

**Objective:** Authenticate users against LDAP in a web app, and avoid the common injection and anonymous-bind mistakes.

```python
#!/usr/bin/env python3
# ~/iam-labs/ldap/ldap_web_app.py
import os
import secrets

import ldap
from ldap.filter import escape_filter_chars
from flask import Flask, redirect, render_template_string, request, session, url_for

LDAP_URI = "ldap://localhost"
BASE = "dc=iamlabs,dc=local"
# A service account for searches. In production, use a dedicated read-only account.
SEARCH_DN = f"cn=admin,{BASE}"
SEARCH_PW = os.environ["LDAP_ADMIN_PASSWORD"]

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

LOGIN_HTML = """
<!DOCTYPE html>
<html><head><title>LDAP Login</title></head>
<body>
  <h1>LDAP Authentication Lab</h1>
  {% if error %}<p style="color:darkred">{{ error }}</p>{% endif %}
  <form method="post" action="/login">
    <label>Username <input name="username" required></label><br>
    <label>Password <input type="password" name="password" required></label><br>
    <button type="submit">Log in</button>
  </form>
</body></html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html><head><title>Dashboard</title></head>
<body>
  <h1>Welcome {{ user }}</h1>
  <ul>
    <li>DN: {{ dn }}</li>
    <li>Email: {{ email }}</li>
    <li>Groups: {{ groups }}</li>
  </ul>
  <h2>Permissions</h2>
  <ul>{% for p in permissions %}<li>{{ p }}</li>{% endfor %}</ul>
  <a href="/logout">Log out</a>
</body></html>
"""


def authenticate_user(username: str, password: str):
    # Reject empty passwords. Many directories treat an empty-password simple bind as anonymous and succeed.
    if not username or not password:
        return None, "Username and password are required"

    service = ldap.initialize(LDAP_URI)
    service.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
    try:
        service.simple_bind_s(SEARCH_DN, SEARCH_PW)

        # Escape user input before placing it in a filter (prevents LDAP injection)
        results = service.search_s(
            f"ou=People,{BASE}",
            ldap.SCOPE_SUBTREE,
            f"(uid={escape_filter_chars(username)})",
            ["cn", "mail"],
        )
        results = [(dn, attrs) for dn, attrs in results if dn]
        if len(results) != 1:
            return None, "Invalid username or password"

        user_dn, attrs = results[0]

        # Verify the password by binding as the user, on a separate connection
        user_conn = ldap.initialize(LDAP_URI)
        user_conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
        try:
            user_conn.simple_bind_s(user_dn, password)
        except ldap.INVALID_CREDENTIALS:
            return None, "Invalid username or password"
        finally:
            user_conn.unbind_s()

        group_results = service.search_s(
            f"ou=Groups,{BASE}",
            ldap.SCOPE_SUBTREE,
            f"(member={escape_filter_chars(user_dn)})",
            ["cn"],
        )
        groups = [a["cn"][0].decode() for dn, a in group_results if dn and "cn" in a]

        return {
            "username": username,
            "dn": user_dn,
            "email": attrs.get("mail", [b""])[0].decode(),
            "groups": groups,
        }, None

    except ldap.LDAPError:
        return None, "Directory service unavailable"
    finally:
        service.unbind_s()


def permissions_for(groups):
    mapping = {
        "admins": ["users:manage", "audit:view", "settings:modify"],
        "developers": ["code:read", "code:write", "logs:read"],
        "finance": ["invoices:approve", "reports:generate"],
    }
    perms = set()
    for group in groups:
        perms.update(mapping.get(group, []))
    return sorted(perms)


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        info, error = authenticate_user(
            request.form.get("username", ""),
            request.form.get("password", ""),
        )
        if info:
            session["user"] = info
            return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    u = session["user"]
    return render_template_string(
        DASHBOARD_HTML,
        user=u["username"],
        dn=u["dn"],
        email=u["email"],
        groups=", ".join(u["groups"]),
        permissions=permissions_for(u["groups"]),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # Debug mode exposes an interactive debugger, so it stays off. Bind to localhost only.
    app.run(host="127.0.0.1", port=5002, debug=False)
```

Run it with `python ldap_web_app.py` and log in as one of the lab users. Port 5002 avoids collisions with the OAuth labs.

### Lab 1 Assessment Questions

1. What changes if you disable TLS on the LDAP server, and which credentials and data are exposed?
2. How would you enforce password history in OpenLDAP, and what does the `ppolicy` overlay provide?
3. What is the security impact of allowing anonymous bind?
4. Why does `escape_filter_chars` matter, and what would `(uid=*)` return from an unescaped login form?
5. Design a DIT for a multi-tenant application where each tenant administers its own users.

---

## Lab 2: OAuth 2.0 and OpenID Connect

### Lab 2.1: Build a Minimal Authorization Server

**Objective:** Implement an authorization code flow with OIDC ID tokens, signed with RS256, and publish keys through JWKS.

**Lab limitations:** plaintext passwords, in-memory storage, no CSRF protection on the login form, and no PKCE. These are deliberate simplifications. Lab 2.2 adds PKCE as an extension exercise.

```python
#!/usr/bin/env python3
# ~/iam-labs/oauth/oauth2_server.py
"""Lab-only OAuth 2.0 / OIDC authorization server. Not for production use."""
import base64
import hmac
import secrets
import time
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, redirect, render_template_string, request, session

ISSUER = "http://127.0.0.1:5000"
KID = "lab-key-1"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Generate the signing key at startup. Restarting the server invalidates previously issued ID tokens.
_signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = _signing_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)

CLIENTS = {
    "demo-client": {
        "client_secret": "demo-secret-123",  # lab only
        "redirect_uris": ["http://127.0.0.1:5001/callback"],
        "allowed_scopes": {"openid", "profile", "email", "api:read"},
    }
}

USERS = {  # lab only: real systems store salted password hashes
    "alice": {"password": "alice123", "email": "alice@example.com", "name": "Alice Admin"},
    "bob": {"password": "bob123", "email": "bob@example.com", "name": "Bob User"},
}

AUTH_CODES = {}       # code -> grant data, single use, 10 minute lifetime
ACCESS_TOKENS = {}
REFRESH_TOKENS = {}

LOGIN_HTML = """
<!DOCTYPE html>
<html><head><title>Authorize</title></head>
<body>
  <h1>Authorize {{ client_id }}</h1>
  <p>Requested scopes: {{ scope }}</p>
  {% if error %}<p style="color:darkred">{{ error }}</p>{% endif %}
  <form method="post">
    <label>Username <input name="username" required></label><br>
    <label>Password <input type="password" name="password" required></label><br>
    <button name="action" value="approve">Approve</button>
    <button name="action" value="deny">Deny</button>
  </form>
</body></html>
"""


def _b64url_int(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@app.route("/.well-known/openid-configuration")
def discovery():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks",
        "scopes_supported": ["openid", "profile", "email", "api:read"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    })


@app.route("/jwks")
def jwks():
    pub = _signing_key.public_key().public_numbers()
    return jsonify({"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
        "n": _b64url_int(pub.n), "e": _b64url_int(pub.e),
    }]})


@app.route("/authorize", methods=["GET", "POST"])
def authorize():
    if request.method == "GET":
        client_id = request.args.get("client_id", "")
        redirect_uri = request.args.get("redirect_uri", "")
        scope = request.args.get("scope", "")

        client = CLIENTS.get(client_id)
        if not client or redirect_uri not in client["redirect_uris"]:
            return "Unknown client or redirect URI", 400
        if request.args.get("response_type") != "code":
            return "Unsupported response_type", 400
        requested = set(scope.split())
        if not requested <= client["allowed_scopes"]:
            return "Requested scope not allowed for this client", 400

        session["auth_request"] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": request.args.get("state", ""),
            "nonce": request.args.get("nonce", ""),
        }
        return render_template_string(LOGIN_HTML, client_id=client_id, scope=scope)

    auth_req = session.get("auth_request")
    if not auth_req:
        return "No pending authorization request", 400

    params = {"state": auth_req["state"]}
    if request.form.get("action") == "deny":
        params["error"] = "access_denied"
        return redirect(f"{auth_req['redirect_uri']}?{urlencode(params)}")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = USERS.get(username)
    if not user or not hmac.compare_digest(user["password"], password):
        return render_template_string(
            LOGIN_HTML, client_id=auth_req["client_id"],
            scope=auth_req["scope"], error="Invalid credentials",
        )

    code = secrets.token_urlsafe(32)
    AUTH_CODES[code] = {
        "client_id": auth_req["client_id"],
        "redirect_uri": auth_req["redirect_uri"],
        "username": username,
        "scope": auth_req["scope"],
        "nonce": auth_req["nonce"],
        "expires": time.time() + 600,
    }
    session.pop("auth_request", None)
    params["code"] = code
    return redirect(f"{auth_req['redirect_uri']}?{urlencode(params)}")


@app.route("/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type")
    client_id = request.form.get("client_id", "")
    client_secret = request.form.get("client_secret", "")

    client = CLIENTS.get(client_id)
    if not client or not hmac.compare_digest(client["client_secret"], client_secret):
        return jsonify({"error": "invalid_client"}), 401

    if grant_type == "authorization_code":
        # Pop removes the code, so each code works exactly once
        grant = AUTH_CODES.pop(request.form.get("code", ""), None)
        if (not grant or grant["expires"] < time.time()
                or grant["client_id"] != client_id
                or grant["redirect_uri"] != request.form.get("redirect_uri")):
            return jsonify({"error": "invalid_grant"}), 400

        now = int(time.time())
        id_token_claims = {
            "iss": ISSUER,
            "sub": grant["username"],
            "aud": client_id,
            "iat": now,
            "exp": now + 3600,
            "auth_time": now,
            "nonce": grant["nonce"],
        }
        id_token = jwt.encode(id_token_claims, PRIVATE_PEM, algorithm="RS256",
                              headers={"kid": KID})

        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        ACCESS_TOKENS[access] = {
            "username": grant["username"], "client_id": client_id,
            "scope": grant["scope"], "expires": time.time() + 3600,
        }
        REFRESH_TOKENS[refresh] = {
            "username": grant["username"], "client_id": client_id, "scope": grant["scope"],
        }
        return jsonify({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh,
            "id_token": id_token,
            "scope": grant["scope"],
        })

    if grant_type == "refresh_token":
        data = REFRESH_TOKENS.get(request.form.get("refresh_token", ""))
        if not data or data["client_id"] != client_id:
            return jsonify({"error": "invalid_grant"}), 400
        access = secrets.token_urlsafe(32)
        ACCESS_TOKENS[access] = {
            "username": data["username"], "client_id": client_id,
            "scope": data["scope"], "expires": time.time() + 3600,
        }
        return jsonify({
            "access_token": access, "token_type": "Bearer",
            "expires_in": 3600, "scope": data["scope"],
        })

    return jsonify({"error": "unsupported_grant_type"}), 400


@app.route("/userinfo")
def userinfo():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return jsonify({"error": "invalid_request"}), 400

    data = ACCESS_TOKENS.get(header[7:])
    if not data or data["expires"] < time.time():
        return jsonify({"error": "invalid_token"}), 401

    user = USERS[data["username"]]
    return jsonify({
        "sub": data["username"],
        "name": user["name"],
        "email": user["email"],
        "email_verified": True,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
```

### Lab 2.2: Build an OIDC Client

**Objective:** Run the authorization code flow end to end, and validate the ID token instead of trusting it.

```python
#!/usr/bin/env python3
# ~/iam-labs/oauth/oauth2_client.py
import secrets
from urllib.parse import urlencode

import jwt
import requests
from flask import Flask, jsonify, redirect, request, session

ISSUER = "http://127.0.0.1:5000"
AUTHORIZE_URL = f"{ISSUER}/authorize"
TOKEN_URL = f"{ISSUER}/token"
USERINFO_URL = f"{ISSUER}/userinfo"
JWKS_URL = f"{ISSUER}/jwks"

CLIENT_ID = "demo-client"
CLIENT_SECRET = "demo-secret-123"   # lab only; load from a secret store in real systems
REDIRECT_URI = "http://127.0.0.1:5001/callback"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
jwks_client = jwt.PyJWKClient(JWKS_URL)


@app.route("/")
def index():
    if "access_token" in session:
        return jsonify({"logged_in": True, "user": session.get("user")})
    return '<a href="/login">Log in with the lab OIDC provider</a>'


@app.route("/login")
def login():
    session["oauth_state"] = secrets.token_urlsafe(32)
    session["oauth_nonce"] = secrets.token_urlsafe(32)
    query = urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email api:read",
        "state": session["oauth_state"],
        "nonce": session["oauth_nonce"],
    })
    return redirect(f"{AUTHORIZE_URL}?{query}")


@app.route("/callback")
def callback():
    if request.args.get("error"):
        return f"Authorization failed: {request.args['error']}", 400

    expected_state = session.pop("oauth_state", None)
    if not expected_state or not secrets.compare_digest(
            request.args.get("state", ""), expected_state):
        return "State mismatch", 400

    resp = requests.post(TOKEN_URL, data={
        "grant_type": "authorization_code",
        "code": request.args.get("code", ""),
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }, timeout=5)
    if resp.status_code != 200:
        return "Token exchange failed", 400
    tokens = resp.json()

    # Validate the ID token: signature, issuer, audience, expiry, and nonce
    signing_key = jwks_client.get_signing_key_from_jwt(tokens["id_token"])
    claims = jwt.decode(
        tokens["id_token"],
        signing_key.key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=ISSUER,
    )
    expected_nonce = session.pop("oauth_nonce", "")
    if not secrets.compare_digest(claims.get("nonce", ""), expected_nonce):
        return "Nonce mismatch", 400

    ui = requests.get(USERINFO_URL,
                      headers={"Authorization": f"Bearer {tokens['access_token']}"},
                      timeout=5)
    session["access_token"] = tokens["access_token"]
    session["refresh_token"] = tokens.get("refresh_token")
    session["user"] = ui.json() if ui.status_code == 200 else {"sub": claims["sub"]}
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
```

Start both servers in separate terminals, then open `http://127.0.0.1:5001/login`. Log in as `alice` or `bob`.

### Lab 2 Exercises

1. **PKCE.** Add a code verifier and S256 code challenge to the client, store the verifier in the session, and require the server to verify it at the token endpoint. Explain what attack this blocks.
2. **Token revocation.** Add a `/revoke` endpoint that removes access and refresh tokens, and confirm that `/userinfo` rejects the revoked token.
3. **Break the client.** Remove the nonce check and describe a scenario where the missing check matters.
4. **Scope enforcement.** Make `/userinfo` return fewer claims when `email` is not in the granted scope.

### Lab 2 Assessment Questions

1. What attack does the `state` parameter prevent, and what happens if the client skips the check?
2. How does PKCE protect a public client that cannot keep a secret?
3. What is the difference between an ID token and an access token, and who should read each one?
4. How would you detect a refresh token being replayed after rotation?
5. Design a revocation mechanism that works across multiple API servers.

---

## Lab 3: RBAC and Separation of Duties

### Lab 3.1: Build an RBAC System with Static SoD

**Objective:** Implement roles, permissions, role hierarchy, time-limited assignments, and SoD checks backed by an audit log.

**Known limitations to study:** SoD rules are checked against directly assigned roles only, not inherited ones. Rules are hardcoded in Python rather than stored in the database. Both are good extension exercises.

```python
#!/usr/bin/env python3
# ~/iam-labs/rbac/rbac_system.py
import json
import sqlite3
from datetime import datetime, timedelta


class SoDViolation(Exception):
    """Raised when an assignment would break a separation-of-duties rule."""


class RBACSystem:
    # Symmetric: each role lists the roles it must not coexist with
    SOD_RULES = {
        "payment_creator": {"payment_approver"},
        "payment_approver": {"payment_creator"},
        "code_author": {"code_reviewer"},
        "code_reviewer": {"code_author"},
        "audit_viewer": {"system_admin", "data_owner"},
        "system_admin": {"audit_viewer"},
        "data_owner": {"audit_viewer", "data_processor"},
        "data_processor": {"data_owner"},
    }

    def __init__(self, db_path="rbac.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS roles (
                role_id TEXT PRIMARY KEY,
                role_name TEXT UNIQUE NOT NULL,
                description TEXT,
                parent_role TEXT REFERENCES roles(role_id)
            );
            CREATE TABLE IF NOT EXISTS permissions (
                permission_id TEXT PRIMARY KEY,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                description TEXT,
                UNIQUE(resource, action)
            );
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id TEXT REFERENCES roles(role_id),
                permission_id TEXT REFERENCES permissions(permission_id),
                PRIMARY KEY (role_id, permission_id)
            );
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id TEXT REFERENCES users(user_id),
                role_id TEXT REFERENCES roles(role_id),
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                assigned_by TEXT,
                PRIMARY KEY (user_id, role_id)
            );
            CREATE TABLE IF NOT EXISTS sod_violations (
                violation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                conflicting_roles TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                actor TEXT,
                action TEXT,
                resource TEXT,
                result TEXT,
                details TEXT
            );
        """)
        self.conn.commit()

    def _audit(self, actor, action, resource, result, details=None):
        self.conn.execute(
            "INSERT INTO audit_log (actor, action, resource, result, details) VALUES (?, ?, ?, ?, ?)",
            (actor, action, resource, result, details),
        )
        self.conn.commit()

    def create_user(self, user_id, name, email):
        try:
            self.conn.execute("INSERT INTO users (user_id, name, email) VALUES (?, ?, ?)",
                              (user_id, name, email))
            self.conn.commit()
            self._audit("system", "user_created", user_id, "success")
            return True
        except sqlite3.IntegrityError:
            self._audit("system", "user_created", user_id, "failed", "already exists")
            return False

    def create_role(self, role_id, role_name, description=None, parent_role=None):
        try:
            self.conn.execute(
                "INSERT INTO roles (role_id, role_name, description, parent_role) VALUES (?, ?, ?, ?)",
                (role_id, role_name, description, parent_role))
            self.conn.commit()
            self._audit("system", "role_created", role_id, "success")
            return True
        except sqlite3.IntegrityError:
            self._audit("system", "role_created", role_id, "failed", "already exists")
            return False

    def create_permission(self, permission_id, resource, action, description=None):
        try:
            self.conn.execute(
                "INSERT INTO permissions (permission_id, resource, action, description) VALUES (?, ?, ?, ?)",
                (permission_id, resource, action, description))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def grant_permission(self, role_id, permission_id):
        try:
            self.conn.execute(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
                (role_id, permission_id))
            self.conn.commit()
            self._audit("system", "permission_granted", f"{role_id}:{permission_id}", "success")
            return True
        except sqlite3.IntegrityError:
            return False

    def _current_roles(self, user_id):
        rows = self.conn.execute(
            "SELECT role_id FROM user_roles WHERE user_id = ? "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (user_id, datetime.utcnow().isoformat(sep=" ")),
        ).fetchall()
        return {r["role_id"] for r in rows}

    def assign_role(self, user_id, role_id, assigned_by, expires_in_days=None):
        current = self._current_roles(user_id)
        conflicts = self.SOD_RULES.get(role_id, set()) & current
        if conflicts:
            self.conn.execute(
                "INSERT INTO sod_violations (user_id, conflicting_roles) VALUES (?, ?)",
                (user_id, json.dumps(sorted([role_id, *conflicts]))))
            self.conn.commit()
            self._audit(assigned_by, "role_assignment", f"{user_id}:{role_id}",
                        "denied", "SoD conflict")
            raise SoDViolation(f"{user_id} cannot receive {role_id}; conflicts with {sorted(conflicts)}")

        expires_at = None
        if expires_in_days:
            expires_at = (datetime.utcnow() + timedelta(days=expires_in_days)).isoformat(sep=" ")
        try:
            self.conn.execute(
                "INSERT INTO user_roles (user_id, role_id, assigned_by, expires_at) VALUES (?, ?, ?, ?)",
                (user_id, role_id, assigned_by, expires_at))
            self.conn.commit()
            self._audit(assigned_by, "role_assignment", f"{user_id}:{role_id}", "success")
            return True
        except sqlite3.IntegrityError:
            self._audit(assigned_by, "role_assignment", f"{user_id}:{role_id}",
                        "failed", "already assigned")
            return False

    def check_permission(self, user_id, resource, action):
        query = """
            WITH RECURSIVE role_tree(role_id, parent_role) AS (
                SELECT r.role_id, r.parent_role
                FROM user_roles ur JOIN roles r ON ur.role_id = r.role_id
                WHERE ur.user_id = ?
                  AND (ur.expires_at IS NULL OR ur.expires_at > ?)
                UNION
                SELECT r.role_id, r.parent_role
                FROM roles r JOIN role_tree t ON r.role_id = t.parent_role
            )
            SELECT 1
            FROM role_tree t
            JOIN role_permissions rp ON t.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.permission_id
            WHERE p.resource = ? AND p.action = ?
            LIMIT 1
        """
        now = datetime.utcnow().isoformat(sep=" ")
        allowed = self.conn.execute(query, (user_id, now, resource, action)).fetchone() is not None
        self._audit(user_id, "permission_check", f"{resource}:{action}",
                    "granted" if allowed else "denied")
        return allowed

    def effective_permissions(self, user_id):
        query = """
            WITH RECURSIVE role_tree(role_id, parent_role, role_name) AS (
                SELECT r.role_id, r.parent_role, r.role_name
                FROM user_roles ur JOIN roles r ON ur.role_id = r.role_id
                WHERE ur.user_id = ?
                  AND (ur.expires_at IS NULL OR ur.expires_at > ?)
                UNION
                SELECT r.role_id, r.parent_role, r.role_name
                FROM roles r JOIN role_tree t ON r.role_id = t.parent_role
            )
            SELECT p.resource, p.action,
                   GROUP_CONCAT(DISTINCT t.role_name) AS via_roles
            FROM role_tree t
            JOIN role_permissions rp ON t.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.permission_id
            GROUP BY p.resource, p.action
            ORDER BY p.resource, p.action
        """
        now = datetime.utcnow().isoformat(sep=" ")
        return [dict(r) for r in self.conn.execute(query, (user_id, now)).fetchall()]


if __name__ == "__main__":
    rbac = RBACSystem("rbac-lab.db")

    rbac.create_user("alice", "Alice Admin", "alice@example.com")
    rbac.create_user("charlie", "Charlie Finance", "charlie@example.com")

    rbac.create_role("payment_creator", "Payment Creator", "Creates payments")
    rbac.create_role("payment_approver", "Payment Approver", "Approves payments")
    rbac.create_role("system_admin", "System Administrator", "Full system access")

    rbac.create_permission("payment:create", "payment", "create")
    rbac.create_permission("payment:approve", "payment", "approve")
    rbac.create_permission("system:all", "system", "*")

    rbac.grant_permission("payment_creator", "payment:create")
    rbac.grant_permission("payment_approver", "payment:approve")
    rbac.grant_permission("system_admin", "system:all")

    rbac.assign_role("alice", "system_admin", assigned_by="setup")
    rbac.assign_role("charlie", "payment_creator", assigned_by="setup")

    try:
        rbac.assign_role("charlie", "payment_approver", assigned_by="setup")
    except SoDViolation as exc:
        print(f"SoD enforced: {exc}")

    print("alice can system:*  ->", rbac.check_permission("alice", "system", "*"))
    print("charlie can approve ->", rbac.check_permission("charlie", "payment", "approve"))

    for row in rbac.effective_permissions("charlie"):
        print(f"charlie: {row['resource']}:{row['action']} via {row['via_roles']}")
```

The code raises `SoDViolation` instead of returning `False`, so callers cannot ignore a denied assignment. This is a deliberate design choice you should be able to justify.

### Lab 3 Exercises

1. **Inherited SoD.** Extend `assign_role` to check the role hierarchy so that a parent role cannot bypass a rule through a child role.
2. **Stored rules.** Move `SOD_RULES` into a database table, and write a migration that loads the current rules.
3. **Time-based activation.** Add a `valid_from` column and a check so assignments take effect only at a scheduled time.
4. **Break-glass access.** Design an emergency role that requires two approvers, expires after a fixed period, and produces an alert on every use.

### Lab 3 Assessment Questions

1. How would you implement dynamic SoD, where conflicting roles can be held but not used together in one transaction?
2. Design a role hierarchy for a bank with payment, audit, and administration functions.
3. How would you detect SoD violations that already exist in production data?
4. What evidence would an auditor need to confirm that a time-limited role expired?
5. Design an emergency access process that keeps a complete audit trail.

---

## Lab 4: Detection and Defensive Testing

This lab focuses on detecting and blocking identity attacks. It does not include attack tooling for live systems. Use existing tools only in environments you own, under a written test plan.

### Lab 4.1: Detect Password Spraying and Brute Force

**Objective:** Write a detector for authentication failure patterns, and test it against synthetic logs.

Attackers spray one or two passwords across many accounts, which keeps per-account failure counts low. Brute force concentrates many failures on one account. Your detector needs to recognize both.

```python
#!/usr/bin/env python3
# ~/iam-labs/detection/detect_auth_patterns.py
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

LINE = re.compile(
    r"^(?P<ts>\S+) (?P<result>BIND_OK|BIND_FAIL) user=(?P<user>\S+) src=(?P<src>\S+)$"
)


def parse(lines):
    events = []
    for line in lines:
        m = LINE.match(line.strip())
        if m:
            events.append({
                "ts": datetime.fromisoformat(m["ts"]),
                "result": m["result"],
                "user": m["user"],
                "src": m["src"],
            })
    return sorted(events, key=lambda e: e["ts"])


def detect(events, window=timedelta(minutes=10),
           spray_min_accounts=10, brute_min_failures=10):
    alerts = []
    fails = [e for e in events if e["result"] == "BIND_FAIL"]

    # Password spray: one source hits many accounts, with few failures on each
    by_src = defaultdict(list)
    for e in fails:
        by_src[e["src"]].append(e)
    for src, evs in by_src.items():
        for i, start in enumerate(evs):
            in_window = [e for e in evs[i:] if e["ts"] - start["ts"] <= window]
            per_user = Counter(e["user"] for e in in_window)
            if len(per_user) >= spray_min_accounts and max(per_user.values()) <= 3:
                alerts.append(f"possible password spray from {src}: "
                              f"{len(per_user)} accounts in {window}")
                break

    # Brute force: many failures against one account
    by_user = defaultdict(list)
    for e in fails:
        by_user[e["user"]].append(e)
    for user, evs in by_user.items():
        for i, start in enumerate(evs):
            in_window = [e for e in evs[i:] if e["ts"] - start["ts"] <= window]
            if len(in_window) >= brute_min_failures:
                alerts.append(f"possible brute force against {user}: "
                              f"{len(in_window)} failures in {window}")
                break

    return alerts


def synthetic_log(seed=1):
    """Generate sample log lines (normal traffic plus one spray and one brute force)."""
    rng = random.Random(seed)
    start = datetime(2026, 11, 24, 9, 0, 0)
    users = [f"user{i:02d}" for i in range(40)]
    lines = []
    t = start
    for _ in range(200):
        t += timedelta(seconds=rng.randint(5, 60))
        u = rng.choice(users)
        result = "BIND_OK" if rng.random() > 0.05 else "BIND_FAIL"
        lines.append(f"{t.isoformat()} {result} user={u} src=10.0.0.{rng.randint(2, 50)}")

    t = start + timedelta(hours=1)
    for u in users[:15]:  # spray from one source, one attempt per account
        t += timedelta(seconds=20)
        lines.append(f"{t.isoformat()} BIND_FAIL user={u} src=192.0.2.44")

    t = start + timedelta(hours=2)
    for _ in range(15):  # brute force against one account
        t += timedelta(seconds=10)
        lines.append(f"{t.isoformat()} BIND_FAIL user=user07 src=198.51.100.9")

    return lines


if __name__ == "__main__":
    events = parse(synthetic_log())
    for alert in detect(events):
        print("ALERT:", alert)
```

Expected output: one spray alert for `192.0.2.44` and one brute-force alert for `user07`. Then:

1. Lower `spray_min_accounts` to 5 and observe the false positives in normal traffic.
2. Replace the synthetic generator with a real log export from your lab directory, and adapt the regex.
3. Add a rule that alerts when a successful bind follows a run of failures for the same account.

### Lab 4.2: Test LDAP Filter Escaping

**Objective:** Confirm that user input cannot change the structure of an LDAP filter in the Lab 1.2 application.

```python
#!/usr/bin/env python3
# ~/iam-labs/detection/test_filter_escaping.py
from ldap.filter import escape_filter_chars

def user_filter(username: str) -> str:
    return f"(uid={escape_filter_chars(username)})"

PAYLOADS = [
    "admin",
    "*",
    "*)(uid=*))(|(uid=*",
    "admin)(|(password=*",
    "a\\b",
    "x\x00y",
]

for payload in PAYLOADS:
    f = user_filter(payload)
    # The filter must still have exactly one opening and one closing parenthesis
    assert f.count("(") == 1 and f.count(")") == 1, f"Filter structure changed: {f}"
    print(f"OK  {payload!r:30} -> {f}")

print("All payloads escaped.")
```

This test checks the filter string the application builds. It does not test the live server. For a complete test, run the Lab 1.2 app and submit the same payloads through its login form.

### Lab 4.3: Recognize Kerberos Ticket Abuse

Kerberoasting requests service tickets for accounts with service principal names, then cracks them offline. Any domain user can make these requests, so the defensive focus is detection, not reproduction.

Indicators to monitor in a Windows domain lab:

- Event ID 4769 (Kerberos service ticket requested), filtered for `TicketEncryptionType 0x17` (RC4-HMAC). Modern environments should see little RC4 use for service tickets.
- Bursts of 4769 events from one account requesting tickets for many different service accounts.
- Requests for service accounts that are not normally accessed by that user or host.

Mitigations are covered in `ADVANCED_TOPICS.md` section 4.2: gMSA, long random service account passwords, and AES-only service tickets.

### Lab 4 Assessment Questions

1. How does a password spray differ from a brute force in logs, and what threshold would you set for each?
2. Why is blocklisting characters such as `*` and `(` weaker than escaping for LDAP input?
3. Which log fields would you need to attribute a spray to a specific source when the attacker uses many IP addresses?
4. Design a CAPTCHA or step-up control that triggers after repeated failures without locking out legitimate users.
5. Where would you place honey accounts, and how would you alert on their use without revealing the trap?

---

## Lab 5: Capstone Project

### Lab 5.1: Integrated IAM Platform

**Objective:** Combine directory, federation, RBAC, audit, and monitoring into one platform.

```yaml
# ~/iam-labs/capstone/docker-compose.yml
# Lab only: passwords come from .env. Pin every image tag before use.
services:
  openldap:
    image: osixia/openldap:1.5.0
    env_file: .env
    environment:
      LDAP_ORGANISATION: "Capstone Corp"
      LDAP_DOMAIN: "capstone.local"
    ports:
      - "127.0.0.1:389:389"
    networks: [iam]

  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: iam
      POSTGRES_USER: iam
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set in .env}
    ports:
      - "127.0.0.1:5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks: [iam]

  redis:
    image: redis:7-alpine
    ports:
      - "127.0.0.1:6379:6379"
    networks: [iam]

  keycloak:
    image: quay.io/keycloak/keycloak:26.0   # confirm the current release
    command: start-dev
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD:?set in .env}
    ports:
      - "127.0.0.1:8080:8080"
    networks: [iam]

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.22
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false   # lab only; enable security in any shared environment
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports:
      - "127.0.0.1:9200:9200"
    networks: [iam]

  kibana:
    image: docker.elastic.co/kibana/kibana:7.17.22
    environment:
      ELASTICSEARCH_HOSTS: http://elasticsearch:9200
    ports:
      - "127.0.0.1:5601:5601"
    depends_on: [elasticsearch]
    networks: [iam]

volumes:
  pgdata:

networks:
  iam:
    driver: bridge
```

Keycloak 26 and later use the `KC_BOOTSTRAP_ADMIN_*` variables shown above. Older releases use `KEYCLOAK_ADMIN` and `KEYCLOAK_ADMIN_PASSWORD`. Check the release notes for the version you pin.

### Project Requirements

1. **Directory:** LDAP with a documented DIT, ACLs, and a read-only service account for applications.
2. **Authentication:** Password policy plus a second factor. FIDO2 is the target for privileged accounts.
3. **Authorization:** RBAC with static SoD enforced at assignment time and dynamic SoD enforced at approval time.
4. **Federation:** OIDC for applications you build, and SAML for at least one legacy-style integration.
5. **Audit:** Centralized logs from the directory, the identity provider, and the RBAC service, with protection against modification by administrators.
6. **Security:** TLS on every service, rate limiting on login endpoints, and detection rules from Lab 4.
7. **Compliance mapping:** Each control mapped to a SOC 2 or ISO 27001 requirement, with the evidence it produces.
8. **Monitoring:** Dashboards and alerts for the thresholds in `ADVANCED_TOPICS.md` section 13.

### Deliverables

- Architecture diagram and design decisions, with the reasons for each
- Configuration files, with secrets removed and replaced by references
- Test evidence for each requirement
- Threat model for the platform, using STRIDE
- Disaster recovery plan for the directory and the identity provider
- A short presentation to a non-technical audience explaining the risks and the controls

---

## Self-Assessment Rubric

These criteria help you judge your own work. They are not an accredited certification.

| Component | Points | What to demonstrate |
|-----------|--------|---------------------|
| Lab 1: LDAP | 20 | DIT design, access controls, safe filter construction, verified checks |
| Lab 2: OAuth 2.0 and OIDC | 20 | Working code flow, ID token validation, state and nonce handling |
| Lab 3: RBAC and SoD | 20 | SoD enforced at assignment, expiry handled, audit trail complete |
| Lab 4: Detection | 20 | Detector tested on synthetic data, filter escaping verified, reasoning written up |
| Lab 5: Capstone | 20 | Integrated system, documented decisions, test evidence, recovery plan |

**Interpreting your score (self-assessment only):**

- **90 to 100:** Strong grasp of the material. Ready to apply it under supervision in a real environment.
- **75 to 89:** Solid foundation. Revisit the components where the test evidence was weakest.
- **60 to 74:** Concepts understood, but implementation or verification needs more practice.
- **Below 60:** Work through the earlier labs again before starting the capstone.

---

## Additional Resources

- **LDAP:** Apache Directory Studio (client and schema browser)
- **OAuth 2.0 and OIDC:** RFC 6749, RFC 7636 (PKCE), OpenID Connect Core 1.0, jwt.io for inspecting tokens (decode only; never paste production tokens)
- **Password storage:** OWASP Password Storage Cheat Sheet, RFC 9106 (Argon2)
- **Testing your own applications:** OWASP ZAP and Burp Suite Community Edition, against systems you are authorized to test
- **Cloud IAM:** AWS IAM Policy Simulator, Microsoft Entra documentation and a free developer tenant
- **Monitoring:** the Elastic Stack or Grafana, using the lab compose file above

---

*Lab guide revised for accuracy and safety. Commands target Ubuntu 24.04 with Docker Compose v2. Re-verify image tags and product options before use.*
