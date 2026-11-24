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

# 3. Server side (slapd.d configuration
