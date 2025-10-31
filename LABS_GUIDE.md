# 🧪 IAM Hands-On Labs Guide
## Complete Practical Exercises for Deep Understanding

**Duration**: 6-8 weeks of hands-on practice  
**Prerequisites**: Linux environment, Docker, basic networking knowledge  
**Goal**: Build, break, and secure real IAM systems  

---

## 📋 Lab Environment Setup

### Base Requirements
```bash
# Install required packages (Ubuntu/Debian/Mint)
sudo apt-get update
sudo apt-get install -y \
  docker.io docker-compose \
  openldap-clients ldap-utils \
  krb5-user krb5-admin-server \
  postgresql-client mysql-client \
  python3-pip python3-venv \
  curl jq git openssl \
  wireshark tcpdump nmap \
  build-essential libsasl2-dev \
  python3-dev libldap2-dev libssl-dev

# Python packages for labs
pip3 install --user \
  python-ldap flask requests \
  cryptography argon2-cffi \
  pyjwt python-jose \
  boto3 azure-identity \
  kubernetes

# Create lab workspace
mkdir -p ~/iam-labs/{ldap,ad,oauth,rbac,forensics,attacks}
cd ~/iam-labs
```

### Docker Networks for Isolation
```bash
# Create isolated networks for each lab
docker network create --subnet=172.20.0.0/16 iam-ldap
docker network create --subnet=172.21.0.0/16 iam-oauth
docker network create --subnet=172.22.0.0/16 iam-attack
```

---

## 🔬 Lab 1: LDAP Directory Services

### Lab 1.1: Build Your Own LDAP Directory

**Objective**: Design, deploy, and secure an LDAP directory from scratch.

#### Step 1: Deploy OpenLDAP Server
```bash
# Create docker-compose.yml
cat > ~/iam-labs/ldap/docker-compose.yml << 'EOF'
version: '3.7'
services:
  openldap:
    image: osixia/openldap:latest
    container_name: iam-openldap
    environment:
      LDAP_ORGANISATION: "IAM Labs Inc"
      LDAP_DOMAIN: "iamlabs.local"
      LDAP_BASE_DN: "dc=iamlabs,dc=local"
      LDAP_ADMIN_PASSWORD: "AdminPass123!"
      LDAP_CONFIG_PASSWORD: "ConfigPass123!"
      LDAP_TLS: "true"
      LDAP_TLS_ENFORCE: "true"
    ports:
      - "389:389"
      - "636:636"
    volumes:
      - ./data:/var/lib/ldap
      - ./config:/etc/ldap/slapd.d
      - ./certs:/container/service/slapd/assets/certs
    networks:
      - iam-net

  phpldapadmin:
    image: osixia/phpldapadmin:latest
    container_name: iam-phpldapadmin
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: "openldap"
      PHPLDAPADMIN_HTTPS: "false"
    ports:
      - "8080:80"
    networks:
      - iam-net

networks:
  iam-net:
    external:
      name: iam-ldap
EOF

# Start the services
cd ~/iam-labs/ldap
docker-compose up -d

# Wait for services
sleep 10
```

#### Step 2: Design Directory Information Tree (DIT)
```bash
# Create organizational structure
cat > ~/iam-labs/ldap/base-structure.ldif << 'EOF'
# Organizational Units
dn: ou=People,dc=iamlabs,dc=local
objectClass: organizationalUnit
ou: People
description: User accounts

dn: ou=Groups,dc=iamlabs,dc=local
objectClass: organizationalUnit
ou: Groups
description: Security groups

dn: ou=Services,dc=iamlabs,dc=local
objectClass: organizationalUnit
ou: Services
description: Service accounts

dn: ou=Policies,dc=iamlabs,dc=local
objectClass: organizationalUnit
ou: Policies
description: Password and access policies

# Create base groups
dn: cn=admins,ou=Groups,dc=iamlabs,dc=local
objectClass: groupOfNames
cn: admins
member: cn=admin,dc=iamlabs,dc=local
description: System administrators

dn: cn=developers,ou=Groups,dc=iamlabs,dc=local
objectClass: groupOfNames
cn: developers
member: cn=admin,dc=iamlabs,dc=local
description: Development team

dn: cn=finance,ou=Groups,dc=iamlabs,dc=local
objectClass: groupOfNames
cn: finance
member: cn=admin,dc=iamlabs,dc=local
description: Finance department
EOF

# Import structure
ldapadd -x -H ldap://localhost \
  -D "cn=admin,dc=iamlabs,dc=local" \
  -w "AdminPass123!" \
  -f base-structure.ldif
```

#### Step 3: Implement Security Controls
```bash
# Create password policy
cat > ~/iam-labs/ldap/password-policy.ldif << 'EOF'
dn: cn=default,ou=Policies,dc=iamlabs,dc=local
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: userPassword
pwdMaxAge: 7776000
pwdMinAge: 0
pwdInHistory: 5
pwdCheckQuality: 2
pwdMinLength: 12
pwdExpireWarning: 604800
pwdGraceAuthNLimit: 3
pwdLockout: TRUE
pwdLockoutDuration: 900
pwdMaxFailure: 5
pwdFailureCountInterval: 900
pwdMustChange: TRUE
pwdAllowUserChange: TRUE
pwdSafeModify: TRUE
EOF

# Create ACL configuration
cat > ~/iam-labs/ldap/acls.ldif << 'EOF'
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword
  by self write
  by anonymous auth
  by dn="cn=admin,dc=iamlabs,dc=local" write
  by * none
olcAccess: {1}to attrs=shadowLastChange
  by self write
  by dn="cn=admin,dc=iamlabs,dc=local" write
  by * read
olcAccess: {2}to dn.subtree="ou=People,dc=iamlabs,dc=local"
  by dn="cn=admin,dc=iamlabs,dc=local" write
  by self read
  by * none
olcAccess: {3}to *
  by dn="cn=admin,dc=iamlabs,dc=local" write
  by * read
EOF
```

#### Step 4: Create Test Users with Different Privileges
```python
#!/usr/bin/env python3
# save as: create_test_users.py
import ldap
import ldap.modlist as modlist
import hashlib
import base64
import os

def create_ssha_password(password):
    """Create SSHA hash for LDAP password"""
    salt = os.urandom(16)
    sha = hashlib.sha1()
    sha.update(password.encode('utf-8'))
    sha.update(salt)
    return "{SSHA}" + base64.b64encode(sha.digest() + salt).decode('ascii')

# Connect to LDAP
l = ldap.initialize("ldap://localhost")
l.simple_bind_s("cn=admin,dc=iamlabs,dc=local", "AdminPass123!")

# Test users with different roles
users = [
    {
        'uid': 'john.admin',
        'cn': 'John Administrator',
        'sn': 'Administrator',
        'mail': 'john.admin@iamlabs.local',
        'password': 'Admin123!@#',
        'groups': ['admins', 'developers']
    },
    {
        'uid': 'jane.dev',
        'cn': 'Jane Developer',
        'sn': 'Developer',
        'mail': 'jane.dev@iamlabs.local',
        'password': 'Dev123!@#',
        'groups': ['developers']
    },
    {
        'uid': 'bob.finance',
        'cn': 'Bob Finance',
        'sn': 'Finance',
        'mail': 'bob.finance@iamlabs.local',
        'password': 'Fin123!@#',
        'groups': ['finance']
    },
    {
        'uid': 'alice.audit',
        'cn': 'Alice Auditor',
        'sn': 'Auditor',
        'mail': 'alice.audit@iamlabs.local',
        'password': 'Audit123!@#',
        'groups': []  # No groups - read only
    }
]

for user in users:
    dn = f"uid={user['uid']},ou=People,dc=iamlabs,dc=local"
    
    # Create user entry
    attrs = {
        'objectClass': [b'inetOrgPerson', b'posixAccount', b'shadowAccount'],
        'uid': [user['uid'].encode()],
        'cn': [user['cn'].encode()],
        'sn': [user['sn'].encode()],
        'mail': [user['mail'].encode()],
        'userPassword': [create_ssha_password(user['password']).encode()],
        'uidNumber': [str(1000 + users.index(user)).encode()],
        'gidNumber': [b'1000'],
        'homeDirectory': [f"/home/{user['uid']}".encode()],
        'loginShell': [b'/bin/bash']
    }
    
    ldif = modlist.addModlist(attrs)
    try:
        l.add_s(dn, ldif)
        print(f"Created user: {user['uid']}")
    except ldap.ALREADY_EXISTS:
        print(f"User exists: {user['uid']}")
    
    # Add to groups
    for group in user['groups']:
        group_dn = f"cn={group},ou=Groups,dc=iamlabs,dc=local"
        mod_attrs = [(ldap.MOD_ADD, 'member', [dn.encode()])]
        try:
            l.modify_s(group_dn, mod_attrs)
            print(f"  Added to group: {group}")
        except ldap.TYPE_OR_VALUE_EXISTS:
            print(f"  Already in group: {group}")

l.unbind()
```

#### Step 5: Test Authentication & Authorization
```bash
# Test user authentication
for user in john.admin jane.dev bob.finance alice.audit; do
    echo "Testing $user:"
    ldapwhoami -x -H ldap://localhost \
      -D "uid=$user,ou=People,dc=iamlabs,dc=local" \
      -w "${user##*.}123!@#" 2>/dev/null && echo "✓ Auth success" || echo "✗ Auth failed"
done

# Test group membership queries
echo -e "\nGroup memberships:"
ldapsearch -x -H ldap://localhost \
  -D "cn=admin,dc=iamlabs,dc=local" -w "AdminPass123!" \
  -b "ou=Groups,dc=iamlabs,dc=local" \
  "(objectClass=groupOfNames)" cn member
```

#### Step 6: Security Audit
```bash
# Create audit script
cat > ~/iam-labs/ldap/security_audit.sh << 'EOF'
#!/bin/bash
echo "=== LDAP Security Audit ==="
echo

# 1. Check anonymous bind
echo "[1] Testing anonymous bind..."
if ldapwhoami -x -H ldap://localhost 2>/dev/null | grep -q "anonymous"; then
    echo "⚠️  CRITICAL: Anonymous bind is enabled!"
else
    echo "✓ Anonymous bind disabled"
fi

# 2. Check TLS/SSL
echo -e "\n[2] Testing TLS encryption..."
if timeout 2 openssl s_client -connect localhost:636 -showcerts </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
    echo "✓ LDAPS (port 636) is enabled"
else
    echo "⚠️  WARNING: LDAPS not available"
fi

# 3. Check password policy
echo -e "\n[3] Checking password policies..."
ldapsearch -x -H ldap://localhost \
  -D "cn=admin,dc=iamlabs,dc=local" -w "AdminPass123!" \
  -b "ou=Policies,dc=iamlabs,dc=local" \
  "(objectClass=pwdPolicy)" pwdMinLength pwdMaxAge 2>/dev/null | grep -E "pwdMinLength|pwdMaxAge"

# 4. Enumerate users (should fail for non-admin)
echo -e "\n[4] Testing user enumeration..."
if ldapsearch -x -H ldap://localhost \
  -D "uid=alice.audit,ou=People,dc=iamlabs,dc=local" -w "Audit123!@#" \
  -b "ou=People,dc=iamlabs,dc=local" \
  "(objectClass=inetOrgPerson)" uid 2>/dev/null | grep -q "uid:"; then
    echo "⚠️  WARNING: Non-admin can enumerate users"
else
    echo "✓ User enumeration protected"
fi

# 5. Check for weak passwords
echo -e "\n[5] Checking for common passwords..."
for password in "password" "123456" "admin" "Password1"; do
    if ldapwhoami -x -H ldap://localhost \
      -D "cn=admin,dc=iamlabs,dc=local" \
      -w "$password" 2>/dev/null | grep -q "admin"; then
        echo "⚠️  CRITICAL: Admin using weak password: $password"
        break
    fi
done
echo "✓ Admin not using common passwords"

echo -e "\n=== Audit Complete ==="
EOF

chmod +x ~/iam-labs/ldap/security_audit.sh
~/iam-labs/ldap/security_audit.sh
```

### Lab 1.2: LDAP Integration with Applications

**Objective**: Integrate LDAP with real applications for authentication.

```python
#!/usr/bin/env python3
# save as: ldap_web_app.py
from flask import Flask, request, render_template_string, session, redirect, url_for
import ldap
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

LDAP_HOST = 'ldap://localhost'
LDAP_BASE_DN = 'dc=iamlabs,dc=local'

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>LDAP Login Demo</title></head>
<body>
    <h1>LDAP Authentication Demo</h1>
    {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
    <form method="post" action="/login">
        <label>Username: <input name="username" required></label><br>
        <label>Password: <input type="password" name="password" required></label><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
    <h1>Welcome {{ user }}!</h1>
    <h2>Your Information:</h2>
    <ul>
        <li>DN: {{ dn }}</li>
        <li>Email: {{ email }}</li>
        <li>Groups: {{ groups }}</li>
    </ul>
    <h2>Your Permissions:</h2>
    <ul>
        {% for perm in permissions %}
        <li>{{ perm }}</li>
        {% endfor %}
    </ul>
    <a href="/logout">Logout</a>
</body>
</html>
'''

def authenticate_user(username, password):
    """Authenticate user against LDAP"""
    try:
        # Connect to LDAP
        l = ldap.initialize(LDAP_HOST)
        
        # Search for user DN
        search_filter = f"(uid={username})"
        result = l.search_s(
            f"ou=People,{LDAP_BASE_DN}",
            ldap.SCOPE_SUBTREE,
            search_filter,
            ['cn', 'mail', 'memberOf']
        )
        
        if not result:
            return None, "User not found"
        
        user_dn = result[0][0]
        user_attrs = result[0][1]
        
        # Try to bind as user
        try:
            l.simple_bind_s(user_dn, password)
        except ldap.INVALID_CREDENTIALS:
            return None, "Invalid password"
        
        # Get user's groups
        groups = []
        group_filter = f"(member={user_dn})"
        group_result = l.search_s(
            f"ou=Groups,{LDAP_BASE_DN}",
            ldap.SCOPE_SUBTREE,
            group_filter,
            ['cn']
        )
        
        for group_dn, group_attrs in group_result:
            if group_attrs.get('cn'):
                groups.append(group_attrs['cn'][0].decode())
        
        return {
            'username': username,
            'dn': user_dn,
            'email': user_attrs.get('mail', [b''])[0].decode(),
            'groups': groups
        }, None
        
    except Exception as e:
        return None, str(e)
    finally:
        l.unbind()

def get_permissions(groups):
    """Map groups to permissions (RBAC)"""
    permissions = []
    
    if 'admins' in groups:
        permissions.extend([
            'users:create', 'users:read', 'users:update', 'users:delete',
            'systems:manage', 'audit:view', 'settings:modify'
        ])
    
    if 'developers' in groups:
        permissions.extend([
            'code:read', 'code:write', 'deployments:view',
            'logs:read', 'metrics:view'
        ])
    
    if 'finance' in groups:
        permissions.extend([
            'invoices:create', 'invoices:approve', 'reports:generate',
            'budgets:view', 'expenses:manage'
        ])
    
    # Remove duplicates
    return list(set(permissions))

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_info, error = authenticate_user(username, password)
        
        if user_info:
            session['user'] = user_info
            return redirect(url_for('dashboard'))
    
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_info = session['user']
    permissions = get_permissions(user_info['groups'])
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        user=user_info['username'],
        dn=user_info['dn'],
        email=user_info['email'],
        groups=', '.join(user_info['groups']),
        permissions=permissions
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    print("Starting LDAP Web Application on http://localhost:5000")
    print("Try logging in with: john.admin / Admin123!@#")
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### 🏆 Lab 1 Assessment Questions
1. What happens if you disable TLS on the LDAP server?
2. How would you implement password history to prevent reuse?
3. What's the security impact of enabling anonymous bind?
4. How can you detect and prevent LDAP injection attacks?
5. Design a DIT structure for a multi-tenant application

---

## 🔐 Lab 2: OAuth2 & OIDC Implementation

### Lab 2.1: Build Your Own OAuth2 Server

**Objective**: Implement a complete OAuth2/OIDC provider from scratch.

```python
#!/usr/bin/env python3
# save as: oauth2_server.py
from flask import Flask, request, jsonify, render_template_string, redirect
import jwt
import secrets
import time
import hashlib
import base64
from datetime import datetime, timedelta
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# In-memory stores (use Redis/DB in production)
CLIENTS = {
    'demo-client': {
        'client_secret': 'demo-secret-123',
        'redirect_uris': ['http://localhost:5001/callback'],
        'allowed_scopes': ['openid', 'profile', 'email', 'api:read', 'api:write']
    }
}

AUTHORIZATION_CODES = {}
ACCESS_TOKENS = {}
REFRESH_TOKENS = {}
USERS = {
    'alice': {'password': 'alice123', 'email': 'alice@example.com', 'name': 'Alice Admin'},
    'bob': {'password': 'bob123', 'email': 'bob@example.com', 'name': 'Bob User'}
}

# JWT keys (use proper key management in production)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS0JJcds3xfn/ygWyF/tIBBnOJlw3TjI4g0bY8xmsjQxm
6lcWPPqFMXlPRxKNb/SJMRxTBlD5FnTxP0kM6Kt9JRoA6BQOB0qrHBsbI8CAb9kL
LBuPuyBRbYGH43BVnOQA3pFr8XcPKS5ZaZEiNKtAqGoNhEz6KEuUOPxzWrL+nJxF
7p5v2+3wEjkMFvfGTzfnWGBZBbsKsuuphECF/FRmJ+UBdAJEy1D5xA1PVmTTKhD8
p7tDGTdgGCWVZNvUbhNRKxlrAU2KSuqzStZKDpCwC5zYJqNu3JRFLdaVXCvFNqFT
MKKraIcEYB3x7s6JJXE0yJXXrLnmkDAMggCkawIDAQABAoIBAGKyT2t5v/UE7sLO
i8KxPvMlgqC/ZYbJPHqsKNA1vbR/hSCVz1zMG7/iqAkXlL2Md63sUPLykH7Nzq7n
YvCRRfR8FNHgexCpge8x5LOC/IReBvHTYD9Phh8LN5HUhVQQEMHFgJtx5sXjdcHA
uH8KjBGaWXbeMXLBcvKtzCb6ORTqhg3envy9cm5XwDJNJfHmw3qCLwLxYJmH0x1B
bIKkVkBzRFPSyKPsHPAFT8m9Q5h8mmUIdogLxBDqT6qLJWvWTC+ynRPE5m+vD4lt
MUTvgSKwbEKQxLy4X0IGWMD+R0+cVDKJPiGEqVDu6q8Q8F/zH7vLCOOikzPmxYQe
/+lKK0ECgYEA7STxH1CQ9wPYVWDe42m2czTNNzp6BhV5t5JrpVPJvcyE8FAqvdMV
g8TC39iHzH6/h8uI9VBl19yF4HMBJIIGgoqV1mL0E7NHPN2V3NafE4tMHgR0s1Nb
7XHBzgaVzJXNinXCJCH3xYNrLbGqR3pBQKVMvFTdUMXKQc1gLrC5lBsCgYEA4mdT
JmJ6I8WL9YL6h3QI5ephQVlFQ41d70JAbr3JtdHmM9h8hF2lIcNKJMEy8mwl33q1
YmJCH9WlD2MNVMdIhJuxVLvWLJvEQGbQl9mVrUd7lqE9bGTn4QLdDpzB1+9zBig9
h9OjOsSRIHTBR+YJlAVFNzOcBje8H8MImlCWD5ECgYEA2J/PqElHaH6cRfXsweTd
2x9yzJvdDZmg8B6OmekWpT5zgTg6XJY9h9C8gcrC7fEwdkPp0OTfGg1BRD3YasH1
eFZH3Ni4v0cLFvPGNGgOwMH8KxmLVSVcsR+kIgnWLR4V6XQPHN8iAaSt4sOkY9qA
kpv6p2cb+woBohc2OT6WA2UCgYEAvK6JdPFo1e+9qp3aDVLUz0aJ0k8xAClGBVeW
LslCXEL1aENgzmxMJfZzo8tLHizRRx/mLvMdlgZYTGUkNmkwufIXPL5lIB+rKVLx
pYLj7/A7tnVKQxfKqhBgHCvxilT5aGPLxLb5XOobWOVCWLJJb+xViNPh5vBWUsZD
ww9hCsECgYBxDDemKXfaQKJOQmJgLIUeA1HRiNUO1zQ3z/gQxVCJFHUmQv7Jnh8M
xp3qlZy0MHQnfBhXPG3WJLEd9QQVFzxhqt8eIvoTqpEEF6VSKNswlkuFxK8mpI+1
BoqPR7L3Qao6YiSTT5ksNFlj6pv2DutxPvYPzrTW7HxCCPhYjmPqMg==
-----END RSA PRIVATE KEY-----"""

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS0JJcds3xfn/ygWy
F/tIBBnOJlw3TjI4g0bY8xmsjQxm6lcWPPqFMXlPRxKNb/SJMRxTBlD5FnTxP0kM
6Kt9JRoA6BQOB0qrHBsbI8CAb9kLLBuPuyBRbYGH43BVnOQA3pFr8XcPKS5ZaZEi
NKtAqGoNhEz6KEuUOPxzWrL+nJxF7p5v2+3wEjkMFvfGTzfnWGBZBbsKsuuphECF
/FRmJ+UBdAJEy1D5xA1PVmTTKhD8p7tDGTdgGCWVZNvUbhNRKxlrAU2KSuqzStZK
DpCwC5zYJqNu3JRFLdaVXCvFNqFTMKKraIcEYB3x7s6JJXE0yJXXrLnmkDAMggCk
awIDAQAB
-----END PUBLIC KEY-----"""

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>OAuth2 Login</title></head>
<body>
    <h1>OAuth2 Authorization Server</h1>
    <h2>Application "{{ client_id }}" is requesting access</h2>
    <p>Scopes requested: {{ scopes }}</p>
    {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
    <form method="post">
        <label>Username: <input name="username" required></label><br>
        <label>Password: <input type="password" name="password" required></label><br>
        <button type="submit" name="action" value="approve">Approve</button>
        <button type="submit" name="action" value="deny">Deny</button>
    </form>
</body>
</html>
'''

@app.route('/.well-known/openid-configuration')
def discovery():
    """OIDC Discovery endpoint"""
    return jsonify({
        'issuer': 'http://localhost:5000',
        'authorization_endpoint': 'http://localhost:5000/authorize',
        'token_endpoint': 'http://localhost:5000/token',
        'userinfo_endpoint': 'http://localhost:5000/userinfo',
        'jwks_uri': 'http://localhost:5000/jwks',
        'scopes_supported': ['openid', 'profile', 'email', 'api:read', 'api:write'],
        'response_types_supported': ['code', 'token', 'id_token'],
        'grant_types_supported': ['authorization_code', 'refresh_token', 'client_credentials'],
        'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post']
    })

@app.route('/jwks')
def jwks():
    """JSON Web Key Set endpoint"""
    # Extract public key components (simplified)
    return jsonify({
        'keys': [{
            'kty': 'RSA',
            'use': 'sig',
            'kid': 'key-1',
            'n': base64.urlsafe_b64encode(PUBLIC_KEY.encode()).decode().rstrip('='),
            'e': 'AQAB'
        }]
    })

@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """OAuth2 Authorization endpoint"""
    if request.method == 'GET':
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        response_type = request.args.get('response_type')
        scope = request.args.get('scope', '')
        state = request.args.get('state', '')
        
        # Validate client
        if client_id not in CLIENTS:
            return 'Invalid client', 400
        
        if redirect_uri not in CLIENTS[client_id]['redirect_uris']:
            return 'Invalid redirect URI', 400
        
        # Store request in session for POST
        session['auth_request'] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': response_type,
            'scope': scope,
            'state': state
        }
        
        return render_template_string(
            LOGIN_TEMPLATE,
            client_id=client_id,
            scopes=scope
        )
    
    else:  # POST
        auth_request = session.get('auth_request', {})
        action = request.form.get('action')
        
        if action == 'deny':
            redirect_uri = auth_request['redirect_uri']
            state = auth_request.get('state', '')
            return redirect(f"{redirect_uri}?error=access_denied&state={state}")
        
        # Authenticate user
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username not in USERS or USERS[username]['password'] != password:
            return render_template_string(
                LOGIN_TEMPLATE,
                client_id=auth_request['client_id'],
                scopes=auth_request['scope'],
                error='Invalid credentials'
            )
        
        # Generate authorization code
        code = secrets.token_urlsafe(32)
        AUTHORIZATION_CODES[code] = {
            'client_id': auth_request['client_id'],
            'redirect_uri': auth_request['redirect_uri'],
            'username': username,
            'scope': auth_request['scope'],
            'expires': time.time() + 600  # 10 minutes
        }
        
        redirect_uri = auth_request['redirect_uri']
        state = auth_request.get('state', '')
        return redirect(f"{redirect_uri}?code={code}&state={state}")

@app.route('/token', methods=['POST'])
def token():
    """OAuth2 Token endpoint"""
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'authorization_code':
        code = request.form.get('code')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        redirect_uri = request.form.get('redirect_uri')
        
        # Validate client credentials
        if client_id not in CLIENTS or CLIENTS[client_id]['client_secret'] != client_secret:
            return jsonify({'error': 'invalid_client'}), 401
        
        # Validate authorization code
        if code not in AUTHORIZATION_CODES:
            return jsonify({'error': 'invalid_grant'}), 400
        
        code_data = AUTHORIZATION_CODES[code]
        
        if code_data['expires'] < time.time():
            del AUTHORIZATION_CODES[code]
            return jsonify({'error': 'invalid_grant'}), 400
        
        if code_data['client_id'] != client_id or code_data['redirect_uri'] != redirect_uri:
            return jsonify({'error': 'invalid_grant'}), 400
        
        # Generate tokens
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        
        # Create ID token (for OIDC)
        id_token_payload = {
            'iss': 'http://localhost:5000',
            'sub': code_data['username'],
            'aud': client_id,
            'exp': int(time.time() + 3600),
            'iat': int(time.time()),
            'nonce': request.form.get('nonce', '')
        }
        
        id_token = jwt.encode(id_token_payload, PRIVATE_KEY, algorithm='RS256')
        
        # Store tokens
        ACCESS_TOKENS[access_token] = {
            'username': code_data['username'],
            'client_id': client_id,
            'scope': code_data['scope'],
            'expires': time.time() + 3600
        }
        
        REFRESH_TOKENS[refresh_token] = {
            'username': code_data['username'],
            'client_id': client_id,
            'scope': code_data['scope']
        }
        
        # Clean up used code
        del AUTHORIZATION_CODES[code]
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': refresh_token,
            'id_token': id_token,
            'scope': code_data['scope']
        })
    
    elif grant_type == 'refresh_token':
        refresh_token = request.form.get('refresh_token')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        
        # Validate client
        if client_id not in CLIENTS or CLIENTS[client_id]['client_secret'] != client_secret:
            return jsonify({'error': 'invalid_client'}), 401
        
        # Validate refresh token
        if refresh_token not in REFRESH_TOKENS:
            return jsonify({'error': 'invalid_grant'}), 400
        
        token_data = REFRESH_TOKENS[refresh_token]
        
        # Generate new access token
        new_access_token = secrets.token_urlsafe(32)
        ACCESS_TOKENS[new_access_token] = {
            'username': token_data['username'],
            'client_id': token_data['client_id'],
            'scope': token_data['scope'],
            'expires': time.time() + 3600
        }
        
        return jsonify({
            'access_token': new_access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': token_data['scope']
        })
    
    return jsonify({'error': 'unsupported_grant_type'}), 400

@app.route('/userinfo')
def userinfo():
    """OIDC UserInfo endpoint"""
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'invalid_request'}), 400
    
    access_token = auth_header[7:]
    
    if access_token not in ACCESS_TOKENS:
        return jsonify({'error': 'invalid_token'}), 401
    
    token_data = ACCESS_TOKENS[access_token]
    
    if token_data['expires'] < time.time():
        del ACCESS_TOKENS[access_token]
        return jsonify({'error': 'invalid_token'}), 401
    
    user_data = USERS[token_data['username']]
    
    return jsonify({
        'sub': token_data['username'],
        'name': user_data['name'],
        'email': user_data['email'],
        'email_verified': True
    })

if __name__ == '__main__':
    print("OAuth2/OIDC Server running on http://localhost:5000")
    print("Discovery: http://localhost:5000/.well-known/openid-configuration")
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### Lab 2.2: OAuth2 Client Implementation

```python
#!/usr/bin/env python3
# save as: oauth2_client.py
from flask import Flask, request, redirect, session, jsonify
import requests
import secrets
import jwt

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# OAuth2 Configuration
CLIENT_ID = 'demo-client'
CLIENT_SECRET = 'demo-secret-123'
AUTHORIZATION_URL = 'http://localhost:5000/authorize'
TOKEN_URL = 'http://localhost:5000/token'
USERINFO_URL = 'http://localhost:5000/userinfo'
REDIRECT_URI = 'http://localhost:5001/callback'

@app.route('/')
def index():
    if 'access_token' in session:
        return f'''
        <h1>Logged In!</h1>
        <p>Access Token: {session['access_token'][:20]}...</p>
        <p>User Info: {session.get('user_info', {})}</p>
        <a href="/api">Test API Call</a><br>
        <a href="/logout">Logout</a>
        '''
    
    return '''
    <h1>OAuth2 Client Demo</h1>
    <a href="/login">Login with OAuth2</a>
    '''

@app.route('/login')
def login():
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Build authorization URL
    auth_url = (
        f"{AUTHORIZATION_URL}?"
        f"response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"scope=openid profile email api:read&"
        f"state={state}"
    )
    
    return redirect(auth_url)

@app.route('/callback')
def callback():
    # Verify state (CSRF protection)
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        return 'Invalid state', 400
    
    # Check for errors
    error = request.args.get('error')
    if error:
        return f'Authorization failed: {error}', 400
    
    # Exchange authorization code for tokens
    code = request.args.get('code')
    
    token_response = requests.post(TOKEN_URL, data={
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI
    })
    
    if token_response.status_code != 200:
        return f'Token exchange failed: {token_response.text}', 400
    
    tokens = token_response.json()
    
    # Store tokens
    session['access_token'] = tokens['access_token']
    session['refresh_token'] = tokens.get('refresh_token')
    session['id_token'] = tokens.get('id_token')
    
    # Get user info
    userinfo_response = requests.get(
        USERINFO_URL,
        headers={'Authorization': f"Bearer {tokens['access_token']}"}
    )
    
    if userinfo_response.status_code == 200:
        session['user_info'] = userinfo_response.json()
    
    return redirect('/')

@app.route('/api')
def api():
    if 'access_token' not in session:
        return redirect('/login')
    
    # Simulate API call with access token
    return jsonify({
        'message': 'API call successful',
        'token_used': session['access_token'][:20] + '...',
        'user': session.get('user_info', {})
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    print("OAuth2 Client running on http://localhost:5001")
    app.run(debug=True, host='0.0.0.0', port=5001)
```

### 🏆 Lab 2 Assessment Questions
1. What security issue occurs if you don't validate the `state` parameter?
2. How would you implement PKCE for public clients?
3. What's the difference between ID tokens and access tokens?
4. How can you detect token replay attacks?
5. Design a token revocation mechanism

---

## 🛡️ Lab 3: RBAC & Separation of Duties

### Lab 3.1: Build Complete RBAC System

**Objective**: Design and implement a role-based access control system with SoD.

```python
#!/usr/bin/env python3
# save as: rbac_system.py
import json
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional
import sqlite3
import hashlib

class RBACSystem:
    """Complete RBAC implementation with SoD"""
    
    def __init__(self, db_path='rbac.db'):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_database()
        self._init_sod_rules()
    
    def _init_database(self):
        """Initialize RBAC database schema"""
        cursor = self.conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Roles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS roles (
                role_id TEXT PRIMARY KEY,
                role_name TEXT UNIQUE NOT NULL,
                description TEXT,
                parent_role TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (parent_role) REFERENCES roles(role_id)
            )
        ''')
        
        # Permissions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS permissions (
                permission_id TEXT PRIMARY KEY,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(resource, action)
            )
        ''')
        
        # Role-Permission mappings
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id TEXT,
                permission_id TEXT,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (role_id, permission_id),
                FOREIGN KEY (role_id) REFERENCES roles(role_id),
                FOREIGN KEY (permission_id) REFERENCES permissions(permission_id)
            )
        ''')
        
        # User-Role assignments
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id TEXT,
                role_id TEXT,
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                assigned_by TEXT,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (role_id) REFERENCES roles(role_id)
            )
        ''')
        
        # SoD violations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sod_violations (
                violation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                conflicting_roles TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        
        # Audit log
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                action TEXT,
                resource TEXT,
                result TEXT,
                details TEXT
            )
        ''')
        
        self.conn.commit()
    
    def _init_sod_rules(self):
        """Initialize Separation of Duties rules"""
        self.sod_rules = {
            'payment_creator': {'conflicting': ['payment_approver']},
            'payment_approver': {'conflicting': ['payment_creator']},
            'code_author': {'conflicting': ['code_reviewer']},
            'code_reviewer': {'conflicting': ['code_author']},
            'audit_viewer': {'conflicting': ['system_admin', 'data_owner']},
            'system_admin': {'conflicting': ['audit_viewer']},
            'data_owner': {'conflicting': ['audit_viewer', 'data_processor']},
            'data_processor': {'conflicting': ['data_owner']}
        }
    
    def create_user(self, user_id: str, name: str, email: str) -> bool:
        """Create a new user"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO users (user_id, name, email) VALUES (?, ?, ?)",
                (user_id, name, email)
            )
            self.conn.commit()
            self._audit_log(user_id, 'user_created', user_id, 'success')
            return True
        except sqlite3.IntegrityError:
            self._audit_log(user_id, 'user_created', user_id, 'failed', 'User already exists')
            return False
    
    def create_role(self, role_id: str, role_name: str, 
                   description: str = None, parent_role: str = None) -> bool:
        """Create a new role with optional hierarchy"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO roles (role_id, role_name, description, parent_role) VALUES (?, ?, ?, ?)",
                (role_id, role_name, description, parent_role)
            )
            self.conn.commit()
            self._audit_log('system', 'role_created', role_id, 'success')
            return True
        except sqlite3.IntegrityError:
            self._audit_log('system', 'role_created', role_id, 'failed', 'Role already exists')
            return False
    
    def create_permission(self, permission_id: str, resource: str, action: str, description: str = None) -> bool:
        """Create a new permission"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO permissions (permission_id, resource, action, description) VALUES (?, ?, ?, ?)",
                (permission_id, resource, action, description)
            )
            self.conn.commit()
            self._audit_log('system', 'permission_created', permission_id, 'success')
            return True
        except sqlite3.IntegrityError:
            return False
    
    def assign_permission_to_role(self, role_id: str, permission_id: str) -> bool:
        """Grant permission to role"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
                (role_id, permission_id)
            )
            self.conn.commit()
            self._audit_log('system', 'permission_assigned', f"{role_id}:{permission_id}", 'success')
            return True
        except sqlite3.IntegrityError:
            return False
    
    def assign_role_to_user(self, user_id: str, role_id: str, 
                           assigned_by: str, expires_in_days: int = None) -> bool:
        """Assign role to user with SoD check"""
        
        # Check SoD violations
        if self._check_sod_violation(user_id, role_id):
            self._audit_log(
                assigned_by, 
                'role_assignment', 
                f"{user_id}:{role_id}", 
                'failed', 
                'SoD violation detected'
            )
            return False
        
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now() + timedelta(days=expires_in_days)
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO user_roles (user_id, role_id, assigned_by, expires_at) VALUES (?, ?, ?, ?)",
                (user_id, role_id, assigned_by, expires_at)
            )
            self.conn.commit()
            self._audit_log(assigned_by, 'role_assignment', f"{user_id}:{role_id}", 'success')
            return True
        except sqlite3.IntegrityError:
            self._audit_log(assigned_by, 'role_assignment', f"{user_id}:{role_id}", 'failed', 'Already assigned')
            return False
    
    def _check_sod_violation(self, user_id: str, new_role_id: str) -> bool:
        """Check if assigning role would violate SoD"""
        # Get user's current roles
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT role_id FROM user_roles WHERE user_id = ?",
            (user_id,)
        )
        current_roles = [row['role_id'] for row in cursor.fetchall()]
        
        # Check if new role conflicts with existing roles
        if new_role_id in self.sod_rules:
            conflicting_roles = self.sod_rules[new_role_id].get('conflicting', [])
            for current_role in current_roles:
                if current_role in conflicting_roles:
                    # Log violation
                    cursor.execute(
                        "INSERT INTO sod_violations (user_id, conflicting_roles) VALUES (?, ?)",
                        (user_id, json.dumps([current_role, new_role_id]))
                    )
                    self.conn.commit()
                    return True
        
        return False
    
    def check_permission(self, user_id: str, resource: str, action: str) -> bool:
        """Check if user has permission to perform action on resource"""
        cursor = self.conn.cursor()
        
        # Get all user's active roles (including inherited)
        query = '''
            WITH RECURSIVE role_hierarchy AS (
                -- Base case: direct roles
                SELECT r.role_id, r.parent_role
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.role_id
                WHERE ur.user_id = ?
                  AND (ur.expires_at IS NULL OR ur.expires_at > datetime('now'))
                
                UNION ALL
                
                -- Recursive case: parent roles
                SELECT r.role_id, r.parent_role
                FROM roles r
                JOIN role_hierarchy rh ON r.role_id = rh.parent_role
            )
            SELECT DISTINCT p.resource, p.action
            FROM role_hierarchy rh
            JOIN role_permissions rp ON rh.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.permission_id
            WHERE p.resource = ? AND p.action = ?
        '''
        
        cursor.execute(query, (user_id, resource, action))
        result = cursor.fetchone()
        
        has_permission = result is not None
        self._audit_log(
            user_id, 
            'permission_check', 
            f"{resource}:{action}", 
            'granted' if has_permission else 'denied'
        )
        
        return has_permission
    
    def get_user_permissions(self, user_id: str) -> List[Dict]:
        """Get all permissions for a user"""
        cursor = self.conn.cursor()
        
        query = '''
            WITH RECURSIVE role_hierarchy AS (
                SELECT r.role_id, r.parent_role, r.role_name
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.role_id
                WHERE ur.user_id = ?
                  AND (ur.expires_at IS NULL OR ur.expires_at > datetime('now'))
                
                UNION ALL
                
                SELECT r.role_id, r.parent_role, r.role_name
                FROM roles r
                JOIN role_hierarchy rh ON r.role_id = rh.parent_role
            )
            SELECT DISTINCT 
                p.resource, 
                p.action, 
                p.description,
                GROUP_CONCAT(DISTINCT rh.role_name) as via_roles
            FROM role_hierarchy rh
            JOIN role_permissions rp ON rh.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.permission_id
            GROUP BY p.resource, p.action
            ORDER BY p.resource, p.action
        '''
        
        cursor.execute(query, (user_id,))
        return [dict(row) for row in cursor.fetchall()]
    
    def _audit_log(self, user_id: str, action: str, resource: str, 
                  result: str, details: str = None):
        """Log audit event"""
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO audit_log (user_id, action, resource, result, details) VALUES (?, ?, ?, ?, ?)",
            (user_id, action, resource, result, details)
        )
        self.conn.commit()
    
    def get_audit_log(self, user_id: str = None, limit: int = 100) -> List[Dict]:
        """Retrieve audit log"""
        cursor = self.conn.cursor()
        
        if user_id:
            cursor.execute(
                "SELECT * FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?",
                (user_id, limit)
            )
        else:
            cursor.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
        
        return [dict(row) for row in cursor.fetchall()]

# Test the RBAC system
if __name__ == "__main__":
    rbac = RBACSystem()
    
    # Create users
    rbac.create_user('alice', 'Alice Admin', 'alice@example.com')
    rbac.create_user('bob', 'Bob Developer', 'bob@example.com')
    rbac.create_user('charlie', 'Charlie Finance', 'charlie@example.com')
    rbac.create_user('david', 'David Auditor', 'david@example.com')
    
    # Create roles
    rbac.create_role('system_admin', 'System Administrator', 'Full system access')
    rbac.create_role('developer', 'Developer', 'Development access')
    rbac.create_role('payment_creator', 'Payment Creator', 'Can create payments')
    rbac.create_role('payment_approver', 'Payment Approver', 'Can approve payments')
    rbac.create_role('audit_viewer', 'Audit Viewer', 'Can view audit logs')
    
    # Create permissions
    rbac.create_permission('sys:all', 'system', '*', 'All system permissions')
    rbac.create_permission('code:write', 'code', 'write', 'Write code')
    rbac.create_permission('code:deploy', 'code', 'deploy', 'Deploy code')
    rbac.create_permission('payment:create', 'payment', 'create', 'Create payment')
    rbac.create_permission('payment:approve', 'payment', 'approve', 'Approve payment')
    rbac.create_permission('audit:view', 'audit', 'view', 'View audit logs')
    
    # Assign permissions to roles
    rbac.assign_permission_to_role('system_admin', 'sys:all')
    rbac.assign_permission_to_role('developer', 'code:write')
    rbac.assign_permission_to_role('developer', 'code:deploy')
    rbac.assign_permission_to_role('payment_creator', 'payment:create')
    rbac.assign_permission_to_role('payment_approver', 'payment:approve')
    rbac.assign_permission_to_role('audit_viewer', 'audit:view')
    
    # Test role assignments
    print("=== Testing Role Assignments ===")
    
    # Valid assignment
    if rbac.assign_role_to_user('alice', 'system_admin', 'system'):
        print("✓ Alice assigned as system_admin")
    
    # SoD violation test
    rbac.assign_role_to_user('charlie', 'payment_creator', 'system')
    if not rbac.assign_role_to_user('charlie', 'payment_approver', 'system'):
        print("✓ SoD violation prevented: Charlie cannot be both creator and approver")
    
    # Check permissions
    print("\n=== Testing Permission Checks ===")
    
    if rbac.check_permission('alice', 'system', '*'):
        print("✓ Alice can perform system operations")
    
    if not rbac.check_permission('bob', 'payment', 'approve'):
        print("✓ Bob cannot approve payments")
    
    # View user permissions
    print("\n=== Charlie's Permissions ===")
    for perm in rbac.get_user_permissions('charlie'):
        print(f"  {perm['resource']}:{perm['action']} (via {perm['via_roles']})")
    
    # View audit log
    print("\n=== Recent Audit Log ===")
    for log in rbac.get_audit_log(limit=10):
        print(f"  [{log['timestamp']}] {log['user_id']} - {log['action']} on {log['resource']}: {log['result']}")
```

### 🏆 Lab 3 Assessment Questions
1. How would you implement dynamic SoD (runtime checks)?
2. Design a role hierarchy for a bank with proper SoD
3. How can you detect and remediate SoD violations?
4. Implement time-based role activation
5. Create an emergency access mechanism that maintains audit trail

---

## 🔍 Lab 4: Security Attacks & Defense

### Lab 4.1: Attack Simulation Lab

**Objective**: Understand common IAM attacks and defenses.

```python
#!/usr/bin/env python3
# save as: attack_simulator.py
import time
import random
import hashlib
import requests
from typing import List, Dict
import threading

class AttackSimulator:
    """Simulate various IAM attacks for learning purposes"""
    
    def __init__(self, target_url: str = "http://localhost"):
        self.target = target_url
        self.results = []
    
    def credential_stuffing_attack(self, usernames: List[str], passwords: List[str]):
        """Simulate credential stuffing attack"""
        print("=== Credential Stuffing Attack ===")
        attempts = 0
        successful = []
        
        for username in usernames:
            for password in passwords:
                attempts += 1
                # Simulate authentication attempt
                try:
                    response = requests.post(
                        f"{self.target}/login",
                        json={'username': username, 'password': password},
                        timeout=1
                    )
                    
                    if response.status_code == 200:
                        successful.append((username, password))
                        print(f"✓ Found: {username}:{password}")
                    
                    # Add delay to avoid rate limiting
                    time.sleep(random.uniform(0.1, 0.5))
                    
                except:
                    pass
        
        print(f"Attempts: {attempts}, Successful: {len(successful)}")
        return successful
    
    def password_spray_attack(self, usernames: List[str], common_password: str):
        """Simulate password spray attack"""
        print("=== Password Spray Attack ===")
        print(f"Testing password '{common_password}' across all users...")
        
        successful = []
        for username in usernames:
            try:
                response = requests.post(
                    f"{self.target}/login",
                    json={'username': username, 'password': common_password},
                    timeout=1
                )
                
                if response.status_code == 200:
                    successful.append(username)
                    print(f"✓ User '{username}' uses common password!")
                
                # Delay to avoid detection
                time.sleep(random.uniform(5, 10))
                
            except:
                pass
        
        return successful
    
    def ldap_injection_test(self, base_input: str):
        """Test for LDAP injection vulnerabilities"""
        print("=== LDAP Injection Test ===")
        
        payloads = [
            "*)(&",                          # Break out of filter
            "*)(uid=*))(|(uid=*",           # Enumerate users
            "admin*",                        # Wildcard bypass
            "admin)(|(password=*",          # Extract passwords
            "*)(objectClass=*",             # Dump all objects
            "\\00",                         # Null byte injection
            "*|",                           # Command injection attempt
        ]
        
        vulnerable = []
        for payload in payloads:
            test_input = base_input + payload
            print(f"Testing: {test_input}")
            
            # Simulate LDAP query
            if self._is_vulnerable_to_injection(test_input):
                vulnerable.append(payload)
                print(f"⚠️  Vulnerable to: {payload}")
        
        return vulnerable
    
    def _is_vulnerable_to_injection(self, user_input: str) -> bool:
        """Check if input would cause LDAP injection"""
        # Simulate vulnerable LDAP filter construction
        filter_string = f"(uid={user_input})"
        
        # Check for filter manipulation
        dangerous_chars = ['*', ')', '(', '|', '&', '=', '\\']
        return any(char in user_input for char in dangerous_chars)
    
    def token_replay_attack(self, captured_token: str):
        """Simulate token replay attack"""
        print("=== Token Replay Attack ===")
        
        # Try using captured token
        headers = {'Authorization': f'Bearer {captured_token}'}
        
        try:
            response = requests.get(
                f"{self.target}/api/user",
                headers=headers,
                timeout=1
            )
            
            if response.status_code == 200:
                print("⚠️  Token replay successful! Token not properly validated")
                return True
            else:
                print("✓ Token replay blocked")
                return False
        except:
            return False
    
    def kerberoasting_simulation(self):
        """Simulate Kerberoasting attack"""
        print("=== Kerberoasting Attack Simulation ===")
        
        # Simulate requesting service tickets
        service_accounts = [
            'svc_backup',
            'svc_sql',
            'svc_web',
            'svc_api'
        ]
        
        vulnerable_accounts = []
        
        for account in service_accounts:
            # Simulate requesting TGS ticket
            print(f"Requesting ticket for {account}...")
            
            # Simulate offline password cracking
            # (In reality, this would involve cracking the service ticket)
            weak_password = self._simulate_password_crack(account)
            
            if weak_password:
                vulnerable_accounts.append((account, weak_password))
                print(f"⚠️  Cracked {account}: {weak_password}")
        
        return vulnerable_accounts
    
    def _simulate_password_crack(self, account: str) -> str:
        """Simulate offline password cracking"""
        # Simulate weak passwords that could be cracked
        weak_passwords = {
            'svc_backup': 'Backup123!',
            'svc_sql': 'SqlServer2019',
            'svc_web': 'Password1',
            'svc_api': None  # Strong password
        }
        
        return weak_passwords.get(account)
    
    def privilege_escalation_path(self):
        """Find privilege escalation paths"""
        print("=== Privilege Escalation Path Discovery ===")
        
        paths = []
        
        # Simulate discovering escalation paths
        print("Checking group memberships...")
        if self._check_nested_groups():
            paths.append("Nested group membership → Admin access")
            print("⚠️  Found: Nested group privilege escalation")
        
        print("Checking service account permissions...")
        if self._check_service_permissions():
            paths.append("Service account → Database → OS command")
            print("⚠️  Found: Service account escalation path")
        
        print("Checking delegation settings...")
        if self._check_delegation():
            paths.append("Unconstrained delegation → Impersonation")
            print("⚠️  Found: Delegation-based escalation")
        
        return paths
    
    def _check_nested_groups(self) -> bool:
        # Simulate finding nested group vulnerability
        return random.choice([True, False])
    
    def _check_service_permissions(self) -> bool:
        # Simulate finding over-privileged service account
        return random.choice([True, False])
    
    def _check_delegation(self) -> bool:
        # Simulate finding delegation misconfiguration
        return random.choice([True, False])

class DefenseSimulator:
    """Simulate defense mechanisms"""
    
    def __init__(self):
        self.failed_attempts = {}
        self.blocked_ips = set()
    
    def rate_limiting(self, ip: str, max_requests: int = 10, window: int = 60) -> bool:
        """Implement rate limiting"""
        current_time = time.time()
        
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
        
        # Remove old attempts outside window
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip]
            if current_time - t < window
        ]
        
        # Check if limit exceeded
        if len(self.failed_attempts[ip]) >= max_requests:
            self.blocked_ips.add(ip)
            print(f"🛡️ Rate limit: Blocked {ip}")
            return False
        
        self.failed_attempts[ip].append(current_time)
        return True
    
    def detect_password_spray(self, attempts: List[Dict]) -> bool:
        """Detect password spray patterns"""
        # Look for same password across multiple accounts
        password_counts = {}
        
        for attempt in attempts:
            pwd = attempt.get('password')
            if pwd in password_counts:
                password_counts[pwd] += 1
            else:
                password_counts[pwd] = 1
        
        # Alert if same password tried on many accounts
        for pwd, count in password_counts.items():
            if count > 5:
                print(f"🚨 Password spray detected: '{pwd}' tried {count} times")
                return True
        
        return False
    
    def validate_input(self, user_input: str) -> str:
        """Sanitize input to prevent injection"""
        # Remove dangerous LDAP characters
        dangerous_chars = ['*', ')', '(', '|', '&', '=', '\\', '\x00']
        
        sanitized = user_input
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        if sanitized != user_input:
            print(f"🛡️ Sanitized input: '{user_input}' → '{sanitized}'")
        
        return sanitized

# Run attack simulations
if __name__ == "__main__":
    print("="*60)
    print("IAM ATTACK SIMULATION LAB")
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY")
    print("="*60)
    
    attacker = AttackSimulator()
    defender = DefenseSimulator()
    
    # Test credential stuffing
    print("\n1. CREDENTIAL STUFFING")
    usernames = ['admin', 'user', 'test', 'alice', 'bob']
    passwords = ['password', '123456', 'admin', 'Password1']
    # attacker.credential_stuffing_attack(usernames, passwords)
    
    # Test password spray
    print("\n2. PASSWORD SPRAY")
    # attacker.password_spray_attack(usernames, 'Winter2024!')
    
    # Test LDAP injection
    print("\n3. LDAP INJECTION")
    attacker.ldap_injection_test("admin")
    
    # Test defense mechanisms
    print("\n4. DEFENSE MECHANISMS")
    
    # Test rate limiting
    test_ip = "192.168.1.100"
    for i in range(15):
        if not defender.rate_limiting(test_ip, max_requests=10):
            break
    
    # Test input sanitization
    malicious_input = "admin*)(&(password=*)"
    safe_input = defender.validate_input(malicious_input)
    
    print("\n=== Lab Complete ===")
```

### 🏆 Lab 4 Assessment Questions
1. How would you detect credential stuffing vs brute force?
2. Implement a CAPTCHA system after N failed attempts
3. Design an anomaly detection system for authentication
4. How can you prevent Kerberoasting attacks?
5. Implement honey tokens for breach detection

---

## 🎯 Lab 5: Capstone Project - Complete IAM System

### Lab 5.1: Build Production-Ready IAM Platform

**Objective**: Combine all concepts into a complete IAM system.

```yaml
# docker-compose-complete.yml
version: '3.8'

services:
  # LDAP Directory
  openldap:
    image: osixia/openldap:latest
    environment:
      LDAP_ORGANISATION: "Capstone Corp"
      LDAP_DOMAIN: "capstone.local"
    ports:
      - "389:389"
      - "636:636"
    networks:
      - iam-network

  # PostgreSQL for RBAC
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: iam_db
      POSTGRES_USER: iam_user
      POSTGRES_PASSWORD: iam_pass
    ports:
      - "5432:5432"
    networks:
      - iam-network

  # Redis for sessions/tokens
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
    networks:
      - iam-network

  # Keycloak for OAuth2/OIDC
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports:
      - "8080:8080"
    command: start-dev
    networks:
      - iam-network

  # Elasticsearch for audit logs
  elasticsearch:
    image: elasticsearch:7.17.0
    environment:
      - discovery.type=single-node
    ports:
      - "9200:9200"
    networks:
      - iam-network

  # Kibana for log visualization
  kibana:
    image: kibana:7.17.0
    ports:
      - "5601:5601"
    environment:
      ELASTICSEARCH_HOSTS: http://elasticsearch:9200
    networks:
      - iam-network

networks:
  iam-network:
    driver: bridge
```

### Project Requirements:
1. **Directory Service**: LDAP with proper DIT structure
2. **Authentication**: Multi-factor with FIDO2 support
3. **Authorization**: RBAC with dynamic SoD
4. **Federation**: SAML and OIDC support
5. **Audit**: Complete audit trail with tamper protection
6. **Security**: Encryption, rate limiting, anomaly detection
7. **Compliance**: SOC2 and ISO 27001 controls
8. **Monitoring**: Real-time alerts and dashboards

### 🏆 Capstone Assessment
- Build complete IAM system
- Document all design decisions
- Implement security controls
- Perform penetration testing
- Create disaster recovery plan
- Present to "stakeholders"

---

## 📊 Lab Assessment Rubric

### Scoring Criteria

| Component | Points | Requirements |
|-----------|--------|--------------|
| **LDAP Lab** | 20 | DIT design, security, integration |
| **OAuth2 Lab** | 20 | Server implementation, PKCE, tokens |
| **RBAC Lab** | 20 | SoD enforcement, audit, permissions |
| **Security Lab** | 20 | Attack detection, defense mechanisms |
| **Capstone** | 20 | Complete system, documentation |

### Proficiency Levels

- **90-100**: Expert - Ready for production IAM role
- **80-89**: Proficient - Solid understanding, minor gaps
- **70-79**: Competent - Good foundation, needs practice
- **60-69**: Developing - Understands concepts, implementation weak
- **<60**: Beginner - Review fundamentals before proceeding

---

## 🎓 Certificate of Completion

Upon completing all labs with 80%+ score:
```
====================================================
        IAM ENGINEERING CERTIFICATION
====================================================
This certifies that

        [YOUR NAME]

has successfully completed the comprehensive
IAM Hands-On Laboratory Course, demonstrating
proficiency in:

✓ LDAP Directory Services
✓ OAuth2/OIDC Implementation  
✓ RBAC Design with SoD
✓ Security Attack & Defense
✓ Enterprise IAM Architecture

Date: _______________
Score: _____/100

====================================================
Ready for: IAM Engineering & Security Roles
====================================================
```

---

## 📚 Additional Resources

### Tools for Practice
- **LDAP**: Apache Directory Studio
- **OAuth2**: Postman, OAuth2 Debugger
- **Security**: Burp Suite, OWASP ZAP
- **Monitoring**: ELK Stack, Grafana
- **Cloud**: AWS IAM Simulator, Azure AD Sandbox

### Next Steps
1. Deploy labs in cloud environment
2. Add Kubernetes RBAC integration
3. Implement Zero Trust architecture
4. Build compliance automation
5. Create incident response runbooks

---

*Lab Guide Version 1.0 - Comprehensive IAM Training*