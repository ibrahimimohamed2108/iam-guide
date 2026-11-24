# Advanced IAM and Security Topics: Enterprise Depth

Advanced companion to the main IAM guide. It covers enterprise-critical topics that the main guide does not.

**Audience:** IAM and security professionals, interns, and architects
**Scope:** Cryptography, advanced authentication, threat modeling, Kerberos, incident response, cloud IAM, SoD, federation, forensics, compliance, misconfigurations, and operations
**Estimated study time:** 6 to 10 hours

> **Note on examples:** Commands and code are illustrative. Test them in a lab before running them against production systems. Adapt DNs, paths, and product versions to your environment.

---

## Table of Contents

1. [Cryptography for IAM](#1-cryptography-for-iam)
2. [Advanced Authentication Methods](#2-advanced-authentication-methods)
3. [Threat Modeling and Attack Surfaces](#3-threat-modeling-and-attack-surfaces)
4. [Kerberos Deep Dive](#4-kerberos-deep-dive)
5. [Compromise Assessment and Incident Response](#5-compromise-assessment-and-incident-response)
6. [IAM in Cloud Platforms](#6-iam-in-cloud-platforms)
7. [Advanced RBAC: Constraints and SoD (Static and Dynamic)](#7-advanced-rbac-constraints-and-sod-static-and-dynamic)
8. [Privilege Escalation Paths](#8-privilege-escalation-paths)
9. [Identity Federation and Trust](#9-identity-federation-and-trust)
10. [Forensics and Audit Analysis](#10-forensics-and-audit-analysis)
11. [Compliance Frameworks](#11-compliance-frameworks)
12. [Common Misconfigurations and Vulnerabilities](#12-common-misconfigurations-and-vulnerabilities)
13. [Identity Security Operations](#13-identity-security-operations)
14. [Emerging Threats and Zero Trust Evolution](#14-emerging-threats-and-zero-trust-evolution)
15. [Preparation Checklist](#15-preparation-checklist)

---

## 1. Cryptography for IAM

### 1.1 Password Hashing

#### Legacy and broken schemes

| Scheme | Status | Reason |
|--------|--------|--------|
| `crypt()` (traditional DES-based) | **Avoid** | 56-bit effective key, no modern work factor |
| MD5, SHA-1 (unsalted or fast) | **Avoid** | Designed for speed, so trivially brute-forced on GPUs |
| bcrypt | **Legacy** | Sound, but limited to 72 bytes of input and not memory-hard |

#### Modern schemes

| Algorithm | Use case | Notes |
|-----------|----------|-------|
| **Argon2id** | All new implementations | Memory-hard, resistant to GPU and ASIC attacks. Per RFC 9106 and OWASP guidance. |
| **scrypt** | Systems where Argon2 is unavailable | Memory-hard. Tune N, r, p. |
| **PBKDF2-HMAC-SHA256** | Compliance regimes that mandate it (e.g., FIPS) | Not memory-hard. OWASP recommends at least 600,000 iterations for SHA-256. |
| **bcrypt** (cost 12 or higher) | Existing systems you cannot migrate yet | Plan migration to Argon2id. |

#### Why Argon2id

- **Memory-hard:** an attacker needs the same memory per guess as the defender, which makes parallel cracking expensive.
- **Tunable:** time, memory, and parallelism are independent knobs.
- **Salted:** a unique salt per password defeats precomputed tables.
- **Standardized:** RFC 9106.

#### Example parameters

OWASP's current minimum for Argon2id is 19 MiB of memory, 2 iterations, and 1 degree of parallelism. Benchmark on your hardware and target a verification time of roughly 50 to 500 ms.

```text
Memory:      64 MiB (65536 KiB)
Iterations:  3
Parallelism: 4
Hash length: 32 bytes
Salt length: 16 bytes (random, per password)
```

#### Go implementation

```go
import (
    "crypto/rand"
    "encoding/base64"
    "fmt"

    "golang.org/x/crypto/argon2"
)

const (
    argonTime    uint32 = 3
    argonMemory  uint32 = 64 * 1024 // KiB
    argonThreads uint8  = 4
    argonKeyLen  uint32 = 32
    saltLen             = 16
)

func HashPassword(password string) (string, error) {
    salt := make([]byte, saltLen)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }

    hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

    return fmt.Sprintf("%s$%s",
        base64.RawStdEncoding.EncodeToString(salt),
        base64.RawStdEncoding.EncodeToString(hash),
    ), nil
}
```

Store the parameters alongside the hash (for example, in PHC string format `$argon2id$v=19$m=65536,t=3,p=4$...`) so you can raise the cost later without breaking existing hashes.

### 1.2 Encryption of Secrets at Rest

Use a key-encryption approach: a random data-encryption key (DEK) encrypts the secret, and a key-management service or hardware security module protects the DEK. Deriving the encryption key directly from a master password works, but it ties security to password strength and makes rotation harder.

If you do derive a key from a passphrase, the salt must be **stored and reused**. A fresh random salt on each instantiation produces a different key every time, and the secret becomes unrecoverable.

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=64 * 1024,  # KiB
    )
    return kdf.derive(passphrase.encode())

def encrypt_secret(passphrase: str, plaintext: str) -> bytes:
    salt = os.urandom(16)          # store alongside ciphertext
    key = derive_key(passphrase, salt)
    nonce = os.urandom(12)         # 96-bit nonce, unique per encryption
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return salt + nonce + ciphertext  # AES-GCM tag is appended by the library

def decrypt_secret(passphrase: str, blob: bytes) -> str:
    salt, nonce, ciphertext = blob[:16], blob[16:28], blob[28:]
    key = derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()
```

For LDAP bind passwords and similar service credentials, prefer a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) over application-level encryption.

### 1.3 Certificate Chains and Validation

```text
Root CA certificate         (self-signed, in the trust store)
    ^ signed by
Intermediate CA certificate
    ^ signed by
Leaf certificate            (e.g., ldap.example.com)
```

Validation steps:

1. Verify the leaf signature with the intermediate public key.
2. Verify the intermediate signature with the root public key.
3. Confirm the root is in the trust store.
4. Check validity dates.
5. Check that the hostname matches the SAN (not the CN alone).
6. Check revocation (CRL or OCSP).
7. Check key usage and extended key usage extensions.

#### Common mistakes

```bash
# WRONG: TLS without verification (vulnerable to man-in-the-middle)
# Many clients accept this silently if the CA is not configured.
ldapsearch -x -H ldaps://ldap.example.com -b "dc=example,dc=com" "(uid=jdoe)"

# RIGHT: Explicit CA trust and certificate verification
LDAPTLS_CACERT=/etc/ssl/certs/corp-root-ca.pem \
ldapsearch -x -H ldaps://ldap.example.com \
  -D "cn=svc-reader,ou=Services,dc=example,dc=com" \
  -y /etc/ldap/bind.pw \
  -b "dc=example,dc=com" "(uid=jdoe)"
```

In OpenLDAP clients, `TLS_REQCERT demand` (the default) enforces verification. Setting `never` disables it and should never reach production.

#### Certificate pinning

Pinning a leaf or intermediate certificate hash reduces the trust surface but makes rotation operationally expensive. Pin only where the risk justifies it, and pin the public key (SPKI) rather than the full certificate so renewals with the same key do not break clients.

### 1.4 Symmetric vs. Asymmetric Cryptography in IAM

| Property | Symmetric (AES) | Asymmetric (RSA, ECDSA, Ed25519) |
|----------|-----------------|----------------------------------|
| Typical IAM use | Encrypting secrets at rest, session encryption | Signatures, certificates, SSH keys, token signing |
| Key distribution | Hard (shared secret) | Easy (public key can be published) |
| Performance | Orders of magnitude faster | Orders of magnitude slower |

**Hybrid model (TLS and LDAPS):** asymmetric cryptography authenticates the server and negotiates a session key during the handshake. Symmetric cryptography (AES-GCM or ChaCha20-Poly1305) then encrypts the bulk traffic.

---

## 2. Advanced Authentication Methods

### 2.1 Certificate-Based Authentication

**Use cases:** machine-to-machine authentication, privileged administrative access, IoT device identity, and API authentication alongside OAuth 2.0.

#### Setup

Client certificates should be issued by your internal CA, not self-signed.

```bash
# 1. Create a CSR for the client (ldap-admin) and key
openssl req -new -newkey rsa:3072 -nodes \
  -keyout ldap-admin.key \
  -out ldap-admin.csr \
  -subj "/CN=ldap-admin/O=Example Corp"

# 2. Sign with the internal CA (example using an internal CA config)
openssl x509 -req -in ldap-admin.csr \
  -CA corp-ca.crt -CAkey corp-ca.key -CAcreateserial \
  -out ldap-admin.crt -days 365 -sha256 \
  -extfile client-ext.cnf   # includes extendedKeyUsage = clientAuth

# 3. Server side (slapd.d configuration in cn=config, or slapd.conf)
#    olcTLSCACertificateFile: /etc/ldap/certs/corp-ca.crt
#    olcTLSVerifyClient: demand

# 4. Client test
ldapsearch -x -H ldaps://ldap.example.com \
  -Z \
  -E ca_cert_file=/etc/ssl/certs/corp-ca.crt \
  -E cert_file=ldap-admin.crt \
  -E key_file=ldap-admin.key \
  -b "dc=example,dc=com" "(uid=jdoe)"
```

Note that `-E cert_file` and `-E key_file` are passed through SASL/EXTERNAL and require the server to map the certificate subject to an identity (`olcAuthzRegexp`).

#### Trade-offs

- Strong, phishing-resistant authentication when the key is hardware-protected.
- Works without a real-time network dependency for the credential itself.
- Key lifecycle is complex: issuance, rotation, and revocation all need automation.
- Revocation checking (OCSP or CRL) adds latency and a failure mode. Define whether you fail open or closed.

### 2.2 Hardware Tokens (FIDO2 and WebAuthn)

```text
Browser / Authenticator                     Relying Party (IdP)
        |                                          |
        |<------------- challenge -----------------|
        |                                          |
   user verifies (PIN / touch / biometric)         |
        |                                          |
        |-------- signed assertion + counter ----->|
        |                                          | verify signature
        |                                          | verify origin and RP ID
        |                                          | check signature counter (clone detection)
        |                                          |
        |<--------- session / OAuth token ---------|
```

The key property is origin binding: the authenticator signs over the origin and RP ID, so a credential captured on a phishing domain is useless on the real one.

#### Comparison

| Factor | SMS OTP | TOTP | FIDO2 / WebAuthn |
|--------|---------|------|------------------|
| Phishing resistant | No | No | Yes |
| Works offline | No | Yes | Yes |
| SIM-swap resistant | No | Yes | Yes |
| Typical cost per user | Low | Free | About 15 to 50 USD for a hardware key |

#### Server-side sketch (Python, `fido2` library)

```python
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

class MFAManager:
    def __init__(self, rp_id: str = "example.com", rp_name: str = "Example"):
        rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
        self.server = Fido2Server(rp)

    def register_begin(self, user_id: bytes, username: str, existing_credentials):
        options, state = self.server.register_begin(
            {"id": user_id, "name": username, "displayName": username},
            existing_credentials,
        )
        # Store `state` server-side with a short TTL (about 5 minutes)
        return options, state

    def register_complete(self, state, response):
        auth_data = self.server.register_complete(state, response)
        # Persist auth_data.credential_data (credential ID, public key, sign count)
        return auth_data.credential_data
```

Check the library documentation for the exact signatures in your installed version. The core idea is the same across implementations: store the challenge state briefly, verify the origin and RP ID, and persist the public key and signature counter.

### 2.3 Passwordless Authentication Factors

| Factor category | Examples | Notes |
|-----------------|----------|-------|
| Something you have | FIDO2 keys, smart cards, device-bound passkeys | Strongest when hardware-bound |
| Something you are | Fingerprint, face, iris | Usually a local unlock for a device-bound key, not a remote credential |
| Somewhere you are | Corporate network, device posture, IP reputation | Context signal; never a sole factor |
| Something you know | Passwords, PINs | Weakest; security questions should be avoided entirely |

**Recommended combination:** a device-bound FIDO2 credential (possession), protected by local biometric or PIN (inherence or knowledge), evaluated against device posture and risk signals (context).

---

## 3. Threat Modeling and Attack Surfaces

### 3.1 STRIDE Applied to IAM

```text
S - Spoofing identity
    - Credential theft (phishing, keylogging)
    - Replay of authentication tokens
    - Session hijacking (stolen session cookie)
    - Compromise of an issuing CA or signing key

T - Tampering with data
    - Unauthorized modification of directory entries
    - Alteration of audit logs
    - Interception of bind credentials (no TLS)
    - Unauthorized changes to role assignments

R - Repudiation
    - Administrator denies an access change
    - Missing audit trail for privilege elevation
    - Logs stored where administrators can edit them
    - Sensitive operations without strong attribution

I - Information disclosure
    - Anonymous directory enumeration
    - Password hashes readable by unprivileged accounts
    - Credentials in memory, configuration, or source control
    - Tokens transmitted or logged in plaintext
    - Personal data in audit logs

D - Denial of service
    - Unbounded directory queries exhausting the server
    - Account lockout abuse for user enumeration or disruption
    - Token revocation infrastructure overloaded
    - Replication failure without failover
    - MFA service unavailable, blocking all logins

E - Elevation of privilege
    - Broken authorization checks (RBAC bypass)
    - Inherited permissions granting unintended access
    - Service account compromise leading to lateral movement
    - SoD violations (one user both creates and approves)
    - Misconfigured ACLs on directory objects
```

#### Example: escalation chain

```text
1. Start:       Standard user, read access to own files.
2. Discover:    User is a member of a "Developers" group.
3. Inspect:     The group can read web application source code.
4. Find:        Database credentials hardcoded in a configuration file.
5. Compromise:  Database account with broad privileges.
6. Escalate:    Database engine allows OS command execution
                (for example, xp_cmdshell on SQL Server, if enabled).
7. Pivot:       The database service account runs with domain privileges
                because it was misconfigured.
8. Impact:      Domain-wide compromise.
```

Each link is a control you can break: restrict group membership, remove hardcoded secrets, apply least privilege to database accounts, disable dangerous features, and run services under dedicated low-privilege identities.

### 3.2 Common Attack Patterns

#### Credential spraying

One or a few passwords tried against many accounts, which evades per-account lockout.

```bash
# Defensive detection idea: many distinct accounts failing with the same source IP
grep 'err=49' /var/log/slapd.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head
```

#### Directory enumeration

Anonymous or low-privilege reads reveal users and groups for targeting.

```bash
# Check whether anonymous bind is permitted (should return anonymous or fail)
ldapwhoami -x -H ldap://ldap.example.com

# If enumeration succeeds, this is a finding. Restrict with ACLs and disable anonymous access.
```

Use this in authorized assessments only, and document results.

---

## 4. Kerberos Deep Dive

### 4.1 Protocol Flow

```text
Client                         KDC (Domain Controller)            Service
  |                                  |                              |
1 |-- AS-REQ (user, pre-auth) ------>|                              |
  |<---- AS-REP (TGT) --------------|                              |
  |                                  |                              |
2 |-- TGS-REQ (TGT, service SPN) --->|                              |
  |<---- TGS-REP (service ticket) ---|                              |
  |                                  |                              |
3 |-- AP-REQ (ticket, authenticator) ----------------------------->|
  |<-------------- AP-REP (mutual auth, optional) ----------------|
  |                                  |                              |
4 |<============ session encrypted with session key ==============>|
```

Properties:

- No password crosses the network.
- Tickets expire, which limits the window of misuse.
- Mutual authentication is optional for many services; enforce it where possible.

### 4.2 Kerberos Attack Techniques

#### Pass-the-Ticket

An attacker who obtains a valid TGT or service ticket from memory or disk can reuse it to access services until the ticket expires. This is a Kerberos technique.

*Mitigations:* short ticket lifetimes, credential guard or equivalent protections on endpoints, monitoring for tickets used from unexpected hosts, and restricting delegation.

#### Pass-the-Hash

An attacker reuses an NTLM hash to authenticate. This is an NTLM technique, not a Kerberos one, though both appear in the same attack chains.

*Mitigations:* disable NTLM where feasible, enable LSA protection and credential guard, restrict local administrator reuse (LAPS), and tier administrative accounts.

#### Kerberoasting

Any authenticated domain user can request a service ticket for an account with a service principal name. The ticket is encrypted with that account's password hash, so it can be cracked offline.

```text
1. Attacker has any domain user credentials.
2. Requests service tickets for SPN-bearing accounts.
3. Exports the tickets (RC4 or AES encrypted).
4. Cracks offline. Weak service-account passwords fall quickly.
```

*Mitigations:*

- Use group managed service accounts (gMSA), which rotate 120-character passwords automatically.
- Where gMSA is impossible, use long random passwords (25 or more characters) and rotate them.
- Enforce AES and disable RC4 for service tickets where compatible.
- Alert on bursts of TGS requests for SPN accounts, especially RC4 requests.

#### AS-REP roasting

Accounts with Kerberos pre-authentication disabled return an AS-REP that can be cracked offline without any domain credentials. See section 12.2 for detection and remediation.

#### Golden Ticket

An attacker who obtains the KRBTGT account's key can forge TGTs for any user, with any group membership, for as long as the forged ticket's lifetime allows. Recovery requires rotating KRBTGT twice, once for each of the two previous keys, with time between rotations for replication.

*Mitigations:* protect domain controllers as the highest tier, monitor for unusual TGT lifetimes and PACs, rotate KRBTGT on a schedule and after any suspected domain compromise, and monitor for changes to KRBTGT password metadata.

---

## 5. Compromise Assessment and Incident Response

### 5.1 Indicators of Compromise

#### Directory server (LDAP or AD)

| Indicator | Possible meaning | Check |
|-----------|------------------|-------|
| Sudden surge in search volume | Enumeration or exfiltration | Query rate by bind DN and source IP |
| Unexpected modifications to group membership | Privilege escalation | memberOf and group changes in audit logs |
| Repeated bind failures on one account | Brute force | Failures per account per hour |
| Replication lag or failures | Possible attempt to hide changes | Replication status and connectivity |
| ACL changes, especially to anonymous or everyone | Backdoor or exposure | ACL audit history |

#### Token and federation infrastructure

| Indicator | Possible meaning | Check |
|-----------|------------------|-------|
| Tokens with unusual audiences or lifetimes | Issuance abuse | Token claims and issuer logs |
| Same token used from geographically distant IPs in a short window | Token theft ("impossible travel") | Session and IP correlation |
| Token used after password change or session revocation | Persistence through stolen token | Revocation timestamps vs. token use |
| Successful logins without MFA for privileged accounts | MFA policy bypass | Authentication method claims (`amr`) |
| Applications requesting administrative scopes | Malicious or compromised app | Consent grants and scope audit |
| Signature validation failures suddenly accepted | Signing key or validation logic compromise | Validation logs and config changes |

**Response priority for signing-key compromise:** rotate the key, revoke issued tokens where possible, and invalidate sessions. Treat this as an incident, not a configuration task.

### 5.2 Forensic Procedure

#### Step 1: Preserve evidence

```bash
# Do not restart affected servers before capturing volatile data.

# Export the directory configuration and data (run as an authorized admin)
slapcat -n 0 > /forensics/ldap-config-$(date +%F).ldif
slapcat -n 1 > /forensics/ldap-data-$(date +%F).ldif

# Copy audit or access logs before rotation can overwrite them
cp -p /var/log/slapd.log /forensics/

# Capture memory with an approved tool (for example, LiME or AVML) on Linux hosts
# Capture network traffic on the directory segment (LDAPS hides content but not metadata)
sudo tcpdump -i any -w /forensics/ldap-traffic.pcap 'port 389 or port 636 or port 88'
```

Record hashes of every artifact (`sha256sum`) and chain-of-custody details.

#### Step 2: Analyze directory changes

If the directory uses the `accesslog` overlay (OpenLDAP), query its database for write operations:

```bash
ldapsearch -x -H ldap://localhost -D "cn=admin,dc=example,dc=com" -W \
  -b "cn=accesslog" "(&(reqType=modify)(reqStart>=20241001000000.000001Z))" \
  reqDN reqMod reqAuthzID reqStart
```

In Active Directory, use the event log (for example, event IDs 4728, 4732, 4756 for group membership changes, and 5136 for directory object changes, when auditing is enabled).

#### Step 3: Identify affected accounts

```bash
# Accounts whose passwords changed in the window (OpenLDAP ppolicy overlay)
ldapsearch -x -H ldap://localhost -D "cn=admin,dc=example,dc=com" -W \
  -b "ou=People,dc=example,dc=com" \
  "(pwdChangedTime>=20241001000000Z)" uid pwdChangedTime
```

Password hashes are not retrievable for comparison by design. Investigate reused-password patterns through breach-detection tooling, not by reading `userPassword`.

---

## 6. IAM in Cloud Platforms

### 6.1 AWS IAM

| Concept | Definition | Example |
|---------|------------|---------|
| Principal | Entity making API calls | IAM user, role session, AWS service |
| ARN | Globally unique resource identifier | `arn:aws:iam::123456789012:role/app-reader` |
| Trust policy | Who may assume a role | A specific account or service principal |
| Permissions boundary | Maximum permissions a role or user can receive | Caps delegated administrators |
| Session tags | Attributes attached to an assumed session | Used for attribute-based access control |

#### Dangerous policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:*",
      "Resource": "*"
    }
  ]
}
```

This grants full control of IAM, which allows the holder to create users, attach admin policies, and grant themselves any permission. Scope actions to specific resources and prohibit privilege-escalation actions (`iam:PassRole` with broad resources, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`) except for tightly controlled administrative roles.

#### Recommended structure

```text
Root account
    - MFA enabled, no access keys, used only for break-glass

Administrative role
    - Assumed through MFA, with session duration limits
    - Used for emergency and change work only

Security audit role
    - Read-only access to logs and configuration
    - Cannot modify IAM policies or roles

Developer role
    - Deploy to non-production accounts
    - No production access, no IAM modification
    - Permissions boundary applied

Workload roles (EC2, Lambda, ECS)
    - Least-privilege permissions for the specific workload
    - Cannot assume other roles
    - Short session duration
```

Permissions boundaries limit what a role can grant, not what it can spend. Cost controls belong in AWS Budgets and service quotas.

### 6.2 Microsoft Entra ID (formerly Azure AD)

| Concept | Comparable AWS concept | Purpose |
|---------|------------------------|---------|
| Tenant | Organization or account boundary | Isolated directory |
| App registration | OIDC or OAuth client | Defines an application's identity and permissions |
| Service principal | IAM role or workload identity | Runtime identity of an application |
| Managed identity | Instance profile or workload identity | Platform-managed credentials for Azure resources |
| Conditional Access | Policy conditions and SCPs | Context-based access decisions |
| Privileged Identity Management (PIM) | Just-in-time elevation (for example, IAM Identity Center with time-limited assignments) | Time-bound privileged roles |

#### Auditing over-permissioned service principals

```powershell
# Requires the Microsoft.Graph PowerShell SDK
Connect-MgGraph -Scopes "Application.Read.All", "AppRoleAssignment.ReadWrite.All"

# List service principals whose names suggest administrative use
Get-MgServicePrincipal -All |
    Where-Object { $_.DisplayName -like "*admin*" } |
    Select-Object DisplayName, AppId, Id

# Inspect application permissions granted to one service principal
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <id> -All
```

Look for high-impact application permissions such as `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, or `Application.ReadWrite.All`. Read-only directory permissions still expose the full tenant structure to anyone who obtains the credential.

---

## 7. Advanced RBAC: Constraints and SoD (Static and Dynamic)

### 7.1 Static SoD

Static SoD prevents conflicting role assignments at grant time.

```python
from datetime import datetime

class SoDViolation(Exception):
    """Raised when a role assignment would violate a separation-of-duties rule."""

class RoleManager:
    # Mapping of role -> roles it must not coexist with
    SOD_RULES = {
        "PaymentCreator": {"PaymentApprover"},
        "DataOwner": {"DataAuditor"},
        "BackupAdmin": {"RestoreAdmin"},
        "CodeAuthor": {"CodeReviewer"},
    }

    def __init__(self, db, audit):
        self.db = db
        self.audit = audit

    def _conflicts(self, current_roles: set[str], new_role: str) -> set[str]:
        # Check both directions: the new role against existing roles, and vice versa
        blocked = set(self.SOD_RULES.get(new_role, set()))
        for existing in current_roles:
            if new_role in self.SOD_RULES.get(existing, set()):
                blocked.add(existing)
        return blocked & current_roles

    def assign_role(self, user_id: str, role: str) -> None:
        current = set(self.db.get_user_roles(user_id))
        conflicts = self._conflicts(current, role)
        if conflicts:
            raise SoDViolation(f"Cannot assign {role} to {user_id}: conflicts with {sorted(conflicts)}")

        self.db.insert_role_assignment(user_id, role)
        self.audit.record(
            action="role_assignment",
            user=user_id,
            role=role,
            timestamp=datetime.utcnow(),
        )
```

The bidirectional check matters. A rule defined only on `PaymentCreator` would miss the case where `PaymentApprover` is granted first and `PaymentCreator` second.

#### Controlled exceptions

Some business processes need temporary exceptions. Treat them as governed risk:

- Require documented justification and a named approver who is not the requester.
- Set a fixed expiration (for example, 30 days maximum).
- Require compensating controls (dual review, additional logging).
- Schedule an automatic revocation and a review before expiry.
- Report all active exceptions to compliance.

### 7.2 Dynamic SoD

Dynamic SoD allows conflicting roles but enforces separation at the moment of each action.

```python
from datetime import datetime, timedelta

class DynamicSoD:
    HIGH_VALUE_THRESHOLD = 100_000
    MIN_REVIEW_DELAY = timedelta(hours=24)

    def can_approve_payment(self, user_id: str, payment: dict, context: dict) -> bool:
        # Rule 1: no self-approval, regardless of role
        if payment["creator_id"] == user_id:
            return False

        # Rule 2: high-value payments need a second, independent approver
        if payment["amount"] > self.HIGH_VALUE_THRESHOLD and not context.get("secondary_approver_id"):
            return False

        # Rule 3: enforce a minimum delay between creation and approval
        if datetime.utcnow() - payment["created_at"] < self.MIN_REVIEW_DELAY:
            return False

        return self.check_rbac(user_id, "payment:approve")
```

Dynamic checks should run in the authorization layer on every relevant action, not only on page load. See the chain 3 example in section 8 for why this matters.

---

## 8. Privilege Escalation Paths

### 8.1 Chain 1: Directory to database to operating system

```text
1. Normal user with group membership grants read access to a
   configuration subtree in the directory.
2. That subtree stores database connection strings with passwords.
3. The database service account has read and write on application tables.
4. Application code contains an injection flaw reachable with that account.
5. The database engine's features allow operating system commands
   (for example, xp_cmdshell on SQL Server, when enabled).
6. Commands run as the database service account.
7. That account is over-privileged on the host, leading to full compromise.
```

**Controls that break this chain:**

- Never store credentials in directory attributes readable by general users. Use a secrets manager.
- Give database accounts only the permissions the application needs.
- Disable dangerous database features (xp_cmdshell, CLR, external procedures) unless required.
- Run services under dedicated low-privilege identities, not domain or local admin.

### 8.2 Chain 2: Service account to SSH to administrative host

```text
1. Service account credentials found in an application .env file.
2. An SSH private key stored in the service account's home directory,
   without a passphrase.
3. The key is authorized on an administrative jump host.
4. The jump host allows unrestricted shell access for that key.
5. Full administrative compromise of the jump host.
```

**Controls:** store keys in an agent or secrets manager, require passphrases and hardware-backed keys for administrative access, use `command=` restrictions and `from=` options in `authorized_keys` where possible, and use short-lived SSH certificates instead of static keys.

### 8.3 Chain 3: Authorization flaw to separation-of-duties violation

```text
1. User holds the Invoice_Creator role.
2. The application checks role on page load but not on the server-side
   action for approval.
3. The user submits an approval request directly to the API, bypassing
   the UI.
4. The server accepts the approval because it validates the session,
   not the specific operation.
5. The same user created and approved the invoice (SoD violation).
6. Funds transfer proceeds.
```

**Controls:** enforce authorization on every server-side action, verify the operation against the specific resource (not just the role), apply dynamic SoD rules (section 7.2), and reconcile creator and approver identities in the approval workflow itself.

---

## 9. Identity Federation and Trust

### 9.1 Protocol Comparison

| Aspect | SAML 2.0 | OAuth 2.0 | OpenID Connect |
|--------|----------|-----------|----------------|
| Primary purpose | Enterprise web SSO | Delegated API authorization | Authentication on top of OAuth 2.0 |
| Message format | XML (signed, optionally encrypted) | JSON, opaque or JWT tokens | JSON, signed ID tokens (JWT) |
| User identity data | Attributes in assertion | Via API or token claims | ID token claims and UserInfo endpoint |
| Typical transport | Browser POST or redirect bindings | Redirects and back-channel token requests | Redirects and back-channel token requests |
| Strengths | Mature enterprise support | Broad API ecosystem | Modern, JSON-native, flexible |
| Weaknesses | XML parsing risks, complex signing | Authorization only, not authentication | Depends on correct client and issuer validation |

### 9.2 SAML Assertion Structure

```xml
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                Version="2.0"
                ID="_a1b2c3"
                IssueInstant="2024-01-15T12:00:00Z">

  <saml:Issuer>https://idp.example.com/sso</saml:Issuer>

  <!-- Signature element omitted for brevity; required in production -->

  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      john.doe@example.com
    </saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="2024-01-15T12:05:00Z"
                                    Recipient="https://app.example.com/acs"/>
    </saml:SubjectConfirmation>
  </saml:Subject>

  <saml:Conditions NotBefore="2024-01-15T11:55:00Z"
                   NotOnOrAfter="2024-01-15T12:05:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://app.example.com/metadata</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>

  <saml:AuthnStatement AuthnInstant="2024-01-15T11:59:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>
        urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor
      </saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>

  <saml:AttributeStatement>
    <saml:Attribute Name="mail">
      <saml:AttributeValue>john.doe@example.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="role">
      <saml:AttributeValue>developer</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

Note that the `Conditions` element carries `NotOnOrAfter` and `AudienceRestriction`. Service providers must validate both, not only the subject confirmation timestamp.

### 9.3 Common SAML Vulnerabilities

**1. XML external entity (XXE) injection.** If the SP's XML parser resolves external entities, an attacker who can supply or modify XML can read local files or trigger server-side requests. Disable DTDs and external entity resolution in the parser.

**2. XML signature wrapping.** The signature validates one element, but the application reads a different, attacker-inserted assertion. Validate the signature covers the exact element you consume, and reference assertions by ID explicitly.

**3. Signature validation skipped or weakened.** Applications that accept unsigned assertions, or that do not verify the signature against the configured IdP certificate, accept forged logins. Pin the expected IdP signing certificate and reject assertions that do not match.

**4. Assertion replay.** An intercepted assertion can be replayed within its validity window if the SP does not track consumed assertion IDs. Store the ID of each accepted assertion until its `NotOnOrAfter` passes, and reject duplicates.

### 9.4 OAuth 2.0 and OIDC Validation Checklist

- Validate the `iss` claim against the expected issuer.
- Validate the `aud` claim contains your client ID.
- Validate the `exp` and `iat` claims and allow only a small clock skew.
- Verify the `nonce` for OIDC authorization code flows.
- Verify the signature using keys from the issuer's JWKS endpoint, and restrict accepted algorithms (reject `none`, and do not let the token header choose an arbitrary key type).
- Use PKCE for public clients and, as recommended in current OAuth security guidance, for confidential clients too.

---

## 10. Forensics and Audit Analysis

### 10.1 OpenLDAP Logging

Log verbosity is a bitmask set through `olcLogLevel` in `cn=config` (or the legacy `loglevel` directive in `slapd.conf`). Common values:

| Value | Category |
|-------|----------|
| 1 | Trace |
| 2 | Packet handling |
| 4 | Argument parsing |
| 8 | Connection management |
| 16 | BER encoding and decoding |
| 32 | Search filters |
| 64 | Configuration processing |
| 128 | Access control evaluation |
| 256 | Statistics (connections, operations) |

Combine values by adding them. For example, `olcLogLevel: 8 128 256` logs connections, ACL decisions, and statistics. Avoid `-1` (everything) in production, since it can log sensitive data and overwhelm disk.

Enable the **accesslog** overlay for a structured record of writes and bind activity, which is more reliable for forensics than the text log.

### 10.2 Parsing Authentication Failures

OpenLDAP and most directory products report invalid credentials as LDAP result code **49** (`invalidCredentials`). Result code 1 is `operationsError`, not a bind failure, so do not filter on it.

```bash
# Count failed binds per source IP (text log; adjust pattern to your log format)
grep -E 'RESULT tag=97.*err=49' /var/log/slapd.log \
  | grep -oE 'IP=[0-9.]+' \
  | sort | uniq -c | sort -rn | head -20

# Accounts with more than five failures in the sample
grep -E 'BIND dn=.*err=49' /var/log/slapd.log \
  | grep -oE 'dn="[^"]+"' \
  | sort | uniq -c | awk '$1 > 5'
```

Log formats differ between versions and products. Validate the patterns against sample entries before relying on them.

---

## 11. Compliance Frameworks

### 11.1 SOC 2 Trust Services Criteria Mapped to IAM

| Criteria | IAM implementation |
|----------|--------------------|
| CC6.1 Logical access | RBAC with documented roles and SoD |
| CC6.2 Registration and authorization | Provisioning workflow with approval records |
| CC6.3 Role changes | Access reviews and timely deprovisioning |
| CC6.6 Boundary protection | Network segmentation for directory and IdP |
| CC6.7 Data transmission | TLS for all directory and federation traffic |
| CC7.2 Monitoring | Alerts on privileged changes and authentication anomalies |
| CC7.3 Logging | Centralized, tamper-resistant audit logs |
| CC8.1 Change management | Controlled changes to directory schema and policies |

### 11.2 Evidence Checklist for Auditors

**Policies:** password and authentication standard, MFA requirements for privileged and remote access, access review standard, SoD matrix, joiner-mover-leaver procedure.

**Design and configuration:** role-to-permission matrix, directory hardening baseline, TLS and cipher standards, backup and restore procedure for the directory.

**Operating evidence:** completed access reviews with approver sign-off, privileged account review records, configuration baseline scans, alert samples and their triage tickets.

**Incident records:** incident log, root cause analysis, remediation actions, and lessons learned.

---

## 12. Common Misconfigurations and Vulnerabilities

### 12.1 LDAP

**Critical: anonymous bind enabled**

```bash
# Test
ldapwhoami -x -H ldap://ldap.example.com
# Output "anonymous" indicates anonymous access is permitted
```

```text
# Fix (slapd.d / cn=config): disallow anonymous binds
olcDisallows: bind_anon

# Restrict reads of user entries to authenticated users
olcAccess: to dn.subtree="ou=People,dc=example,dc=com"
  by dn.exact="cn=admin,dc=example,dc=com" write
  by users read
  by * none
```

**Critical: plain LDAP without TLS**

```bash
# Insecure: credentials and data cross the network in cleartext
ldapsearch -x -H ldap://ldap.example.com ...

# Secure: LDAPS on port 636, or StartTLS on port 389 with enforced verification
ldapsearch -x -H ldaps://ldap.example.com ...
ldapsearch -x -H ldap://ldap.example.com -ZZ ...   # -ZZ requires StartTLS to succeed
```

**High: password attributes readable by general users**

```text
# Insecure
olcAccess: to attrs=userPassword by * read

# Secure: users change their own password, nobody reads hashes
olcAccess: to attrs=userPassword
  by self write
  by anonymous auth
  by * none
```

**Medium: no audit trail**

Enable the accesslog overlay and forward directory logs to your central logging platform. Verify with a test write that the record appears in the central system, not only on the local host.

### 12.2 Active Directory

**Critical: Kerberos pre-authentication disabled (AS-REP roasting)**

```powershell
# Find accounts that do not require pre-authentication
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
    Select-Object SamAccountName

# Remediate (update account control flag, then verify)
Set-ADAccountControl -Identity <samAccountName> -DoesNotRequirePreAuth $false
```

**High: passwords that never expire**

```powershell
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires |
    Select-Object SamAccountName
```

Exceptions for service accounts should be replaced with gMSA where possible, not left as static never-expiring passwords. Review each exception with its owner.

**High: service accounts in privileged groups**

```powershell
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Where-Object { $_.SamAccountName -like "svc*" }
```

Use tiered administration: dedicated administrative accounts for privileged tasks, separate from daily-use accounts, and no service accounts in Domain Admins.

### 12.3 OAuth 2.0 and OIDC

**Critical: HTTP instead of HTTPS**

Tokens and authorization codes sent over HTTP are readable by any network observer. All authorization, token, and redirect endpoints must use TLS.

**Critical: no PKCE for public clients**

```text
# Without PKCE, an intercepted authorization code can be exchanged by an attacker
GET /authorize?client_id=mobile-app&response_type=code&redirect_uri=...

# With PKCE, the code is useless without the original code_verifier
GET /authorize?client_id=mobile-app&response_type=code&redirect_uri=...
    &code_challenge=<S256 hash of verifier>&code_challenge_method=S256
```

**High: wildcard or overly broad redirect URIs**

```text
# Insecure: any subdomain can receive codes if an attacker controls one
https://*.example.com/callback

# Secure: exact, pre-registered URIs
https://app.example.com/callback
https://app.example.com/mobile/callback
```

Also check for open redirects on your own redirect endpoints, which attackers can chain to exfiltrate codes.

---

## 13. Identity Security Operations

### 13.1 Metrics and Thresholds

These thresholds are starting points. Calibrate them against your baseline for at least two weeks before paging on them.

```yaml
directory_health:
  replication_lag_seconds:
    alert: "> 60 for 5 minutes"
  search_latency_p95_ms:
    alert: "> 100 for 15 minutes"
  anonymous_bind_attempts:
    alert: "> 0 (any occurrence)"

authentication:
  failed_binds_per_account_per_hour:
    alert: "> 5"
  failed_binds_per_source_ip_per_hour:
    alert: "> 50 across more than 10 accounts"
  token_issuance_rate:
    alert: "> 3x 7-day baseline"
  mfa_bypass_or_disabled_privileged_login:
    alert: "> 0"
  impossible_travel:
    alert: "same user, two countries, under 1 hour apart"

authorization:
  privileged_group_changes:
    alert: "any change, outside an approved change window"
  sod_violation_attempts:
    alert: "> 0"
  disabled_account_login:
    alert: "> 0"
```

### 13.2 Playbook: Failed Bind Spike

```text
1. Classify the pattern.
   - One account, many failures: targeted guessing or lockout.
   - Many accounts, few failures each: password spray.
   - Sequential or leaked-list usernames: credential stuffing.

2. Spray or stuffing suspected:
   - Identify accounts with a successful login during or after the spike.
   - Force reset for those accounts, and revoke their sessions and tokens.
   - Block or rate-limit the source IPs at the edge.
   - Notify account owners through a verified out-of-band channel.

3. Targeted attack on one account:
   - Apply temporary lockout per your policy.
   - Verify the account owner's identity before reset.
   - Review all actions performed by the account in the 30 days before the spike.

4. Normal background failures:
   - Document the baseline and confirm no change in trend.
```

---

## 14. Emerging Threats and Zero Trust Evolution

### 14.1 Compromised MFA

Traditional risk: a stolen password. Mitigation: enable MFA.

Emerging risk: MFA itself is the target.

```text
How it happens:
1. Attacker obtains the password (phishing, breach reuse).
2. Attacker defeats the second factor:
   - SIM swap, when SMS or voice is the factor
   - Real-time phishing proxy that relays OTP codes and session cookies
   - Malware on the phone or workstation
   - Social engineering of the help desk to reset MFA enrollment
3. Attacker establishes a session and persists through refresh tokens.

Mitigations:
- Phishing-resistant MFA (FIDO2 and device-bound passkeys) for privileged roles
- Conditional access blocking impossible travel and unmanaged devices
- Token binding or sender-constrained tokens where supported
- Strict help-desk identity verification before any MFA reset
- Step-up authentication for sensitive operations
```

### 14.2 Directory Supply Chain

Traditional risk: a weak directory server. Mitigation: firewalls, LDAPS, ACLs.

Emerging risk: a third-party integration writes to the directory.

```text
How it happens:
1. Attacker compromises a provisioning connector or sync tool that
   writes to the directory.
2. The connector creates privileged accounts or adds members to
   sensitive groups.
3. Downstream systems trust directory group membership and grant access
   to SaaS applications, VPN, and file shares.

Mitigations:
- Scope connector permissions to the specific OUs and attributes it needs
- Use certificate-based or workload identity authentication for connectors
- Alert on privileged group changes made by connector identities
- Review connector scope and credentials on the same schedule as admin accounts
- Segment the connector from the domain controllers' management network
```

---

## 15. Preparation Checklist

**Concepts to explain without notes:**

- How an LDAP search works: base DN, scope, filter, and attributes returned
- The AS-REQ, AS-REP, TGS-REQ, and AP-REQ exchanges in Kerberos
- The difference between OAuth 2.0 (authorization) and OIDC (authentication)
- Why password hashes need a memory-hard function, a unique salt, and a work factor
- Static versus dynamic SoD, with an example of each
- How certificate chain validation establishes trust

**Hands-on skills:**

- Deploy an OpenLDAP server with TLS in a lab, and verify client certificate authentication
- Query and modify directory entries with `ldapsearch`, `ldapmodify`, and `ldapdelete`
- Create, modify, and disable AD users and groups with PowerShell
- Read security logs and identify a credential spray pattern
- Decode a JWT, validate its claims, and explain each one
- Review an OAuth 2.0 client configuration for PKCE and redirect URI issues

**Security mindset:**

- Model privilege escalation paths before testing them, and document each step
- Identify misconfigurations and rank them by exploitability and impact
- Map each technical control to the compliance requirement it satisfies
- Design for least privilege, and assume any single credential will eventually be stolen
- Layer defenses so that no single failure grants access

---

*This guide complements the main Zero-to-Hero IAM guide. Read both for full coverage.*

## Changelog

- **Corrected:** Argon2 parameters and API usage, including a salt that must be stored rather than regenerated on each call.
- **Corrected:** Log level mapping, bind failure result code (49), and Kerberos vs. NTLM attack attribution.
- **Corrected:** Non-existent or incorrect commands and options (`slapd.conf allow none`, `Set-ADUser -KerberosPreAuthRequired`, `ldapcat`, fictional audit-log setup scripts).
- **Corrected:** Python syntax error in the SoD example (`SoD Exception`), and the bidirectional SoD check.
- **Corrected:** FIDO2 server initialization and the typo "FIIDO2".
- **Corrected:** Permissions boundaries described as spending limits, and the fictional SAML "algorithm none" bypass, replaced with documented XML signature wrapping.
- **Corrected:** Broken anchor link for section 7.
- **Removed:** Decorative emojis and status symbols. Status is now expressed in plain text.
- **Restructured:** Consistent code fence languages, tables for comparisons, and a section 15 checklist replacing the informal preparation section.
