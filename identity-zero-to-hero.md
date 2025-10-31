# Identity, Directory, and Access Management — Zero to Hero
## Complete Guide to AD, LDAP, IAM, and RBAC

A comprehensive, hands-on guide from fundamentals to production-ready implementations. Designed for security engineers, system administrators, and developers who need to master identity and access management from the ground up.

### 📋 What You'll Learn
- Master the fundamentals of identity, authentication, and authorization
- Design and implement LDAP directories and Active Directory infrastructures
- Build modern IAM systems with OAuth2, OIDC, and SAML
- Engineer robust RBAC systems with proper governance
- Secure enterprise environments with best practices
- Troubleshoot complex identity and access issues

### 🎯 Target Audience
- **Beginners**: Start with Section 1 (Foundations) and work through linearly
- **Practitioners**: Jump to specific sections based on your needs
- **Architects**: Focus on Sections 6-8 for design patterns and governance

### 📖 Table of Contents
1. **[Foundations](#1-foundations)** - Core concepts and principles
2. **[LDAP Mastery](#2-ldap--zero-to-hero)** - OpenLDAP implementation and operations
3. **[Active Directory](#3-active-directory-ad--zero-to-hero)** - Windows AD design and management
4. **[Modern IAM](#4-iam--zero-to-hero)** - OAuth2, OIDC, SAML, and token-based auth
5. **[RBAC Engineering](#5-rbac--zero-to-hero)** - Role-based access control design
6. **[Integration Patterns](#6-crosswalk-mapping-ad-ldap-iam-rbac)** - Connecting different systems
7. **[Reference Architectures](#7-blueprints-reference-architectures)** - Production-ready designs
8. **[Security & Compliance](#8-security-compliance-and-governance)** - Hardening and governance
9. **[Troubleshooting](#9-troubleshooting-playbooks)** - Common issues and solutions
10. **[Operations](#10-checklists-and-runbooks)** - Checklists and procedures
11. **[Glossary](#11-glossary)** - Terms and definitions
12. **[Resources](#12-further-reading)** - Additional learning materials

--------------------------------------------------------------------------------

## 0) How to use this guide

- Read “Foundations,” then pick a track (LDAP or AD) to build a directory quickly.
- Add IAM for SSO and token-based auth to apps and APIs.
- Implement RBAC to standardize authorization across systems.
- Complete the “Exercises” in each section to reach “Hero” level.

Learning outcomes
- Distinguish identity, directory, and IAM roles and where RBAC fits.
- Design directory structures (DIT/OUs), groups, and policies.
- Implement secure authentication (Kerberos, LDAP bind, OIDC/OAuth2).
- Engineer roles and permissions for least privilege and auditability.

--------------------------------------------------------------------------------

## 1. Foundations: Identity, AuthN, AuthZ, Directory, and Policy

### 1.1 Core Concepts Explained

#### 1.1.1 Identity
**Definition**: A digital representation of an actor (user, service, device, or application) within a system.

**Key Points**:
- Every identity must be **unique** and **identifiable** within an organization
- Identities have **attributes** (email, department, role, clearance level)
- Identities can be **human** (users) or **non-human** (service accounts, workload identities)
- Examples:
  - User: `john.doe@example.com` (employee identity)
  - Service: `api-processor@corp` (API service account)
  - Device: `LAPTOP-ABC123` (workstation identity)
  - Workload: `kubernetes-deployer` (CI/CD pipeline identity)

**Why it matters**: Identity is the foundation of all security decisions. Without accurate identity, you cannot properly authenticate or authorize access.

#### 1.1.2 Authentication (AuthN) — Proving Who You Are
**Definition**: The process of verifying that an identity is genuine through **proof of knowledge, possession, or inherence**.

**Authentication Factors**:
- **Knowledge**: Something you know (password, PIN, security questions)
- **Possession**: Something you have (hardware token, phone, cryptographic key)
- **Inherence**: Something you are (biometric: fingerprint, face recognition)
- **Location/Context**: Where you are, what time, from what network

**Authentication Methods**:
| Method | Strength | Use Case |
|--------|----------|----------|
| Password | Low | Legacy systems, convenience |
| Multi-Factor (MFA) | Medium | Standard security baseline |
| Passwordless (FIDO2) | High | Admin access, sensitive systems |
| Certificate | High | System-to-system authentication |
| OAuth2/OIDC | Medium | Third-party integrations |
| Kerberos | High | Enterprise directory-based |

**Modern Best Practice**: Passwordless authentication (FIDO2/WebAuthn) is preferred for high-security scenarios; MFA is the minimum baseline for sensitive systems.

#### 1.1.3 Authorization (AuthZ) — Deciding What You Can Do
**Definition**: The process of determining **what authenticated identities are allowed to do** after their identity has been verified.

**Authorization is NOT Authentication**:
- Authentication: "Are you John Doe?" → Yes/No
- Authorization: "Can John Doe read file X and delete resource Y?" → Yes/No for each action

**Authorization Models**:
- **Access Control List (ACL)**: Explicit list of who can access what (traditional)
- **Role-Based (RBAC)**: User has role(s) → Role has permission(s)
- **Attribute-Based (ABAC)**: Complex rules based on user, resource, and environmental attributes
- **Relationship-Based (ReBAC)**: Permissions based on graph relationships ("who is related to whom")

**Example Flow**:
```
User: john.doe@example.com
Seeking: Read access to /data/financials/budget-2024.xlsx

Authorization Check:
1. Is john.doe authenticated? ✓ Yes
2. Does john.doe have role "Finance_Analyst"? ✓ Yes
3. Does role "Finance_Analyst" have permission "read:budget_data"? ✓ Yes
4. Is the request from 9-5 AM on business day? ✓ Yes
5. Decision: ALLOW
```

#### 1.1.4 Directory Services
**Definition**: A centralized, hierarchical database that stores **identities, attributes, and group memberships** in a standardized format.

**Directory Types**:
| Type | Primary Use | Protocol | Hierarchy |
|------|-----------|----------|----------|
| **Active Directory (AD)** | Windows enterprise | Kerberos, LDAP, NTLM | Forest/Domain/OU |
| **OpenLDAP** | Linux/Unix, open-source | LDAP, LDAPS | DIT (Directory Information Tree) |
| **FreeIPA** | Linux infrastructure | LDAP, Kerberos, HTTP | Realm/Domains |
| **Okta/Azure AD** | Cloud-native, SaaS | OAuth2, OIDC, SAML | Tenant/Directories |

**Core Functions**:
1. **Identity Storage**: Centralized database of users and devices
2. **Group Management**: Organize identities for permission delegation
3. **Authentication**: Provide login services (passwords, Kerberos)
4. **Authorization**: Store group memberships and entitlements
5. **Schema**: Define what attributes can be stored (email, phone, role)

**Directory as Source of Truth**:
- Single source of truth for identity across the organization
- Changes replicate to all connected systems
- Enables centralized auditing and compliance

#### 1.1.5 Policy
**Definition**: **Machine-evaluable rules** that determine what is allowed or denied for authentication and authorization.

**Types of Policies**:
- **Authentication Policies**: Require MFA at 3 AM, block legacy protocols
- **Authorization Policies**: Allow read access on "public" resources, deny write
- **Compliance Policies**: Enforce encryption, password complexity, data retention
- **Access Policies**: Conditional rules (e.g., "Only from corporate network")

**Policy Example**:
```json
{
  "policy_id": "corporate_api_access",
  "description": "Grant API access to developers",
  "conditions": {
    "user_role": "developer",
    "mfa_verified": true,
    "device_compliant": true,
    "network_location": ["office", "vpn"],
    "time_window": "09:00-17:00 business days"
  },
  "effect": "allow",
  "resources": ["api.example.com/*"],
  "actions": ["read", "write"]
}
```

#### 1.1.6 Governance
**Definition**: The **lifecycle management and oversight** of identities, access, and compliance throughout an organization.

**Key Governance Processes**:
1. **Joiners**: New employee onboarding → Create identity, assign roles, provision access
2. **Movers**: Role change or transfer → Update attributes, revoke old roles, grant new roles
3. **Leavers**: Employee departure → Disable account, revoke all access, archive data
4. **Access Reviews**: Quarterly/annual verification that access is still appropriate
5. **Compliance**: Audit trails, SoD enforcement, policy violations
6. **Exception Handling**: Emergency access, temporary elevated privileges

**Governance Metrics**:
- Onboarding time from hire to productive access
- Offboarding completion time and verification
- Stale account detection and removal
- Access review completion rate and findings
- SoD conflict detection and remediation time

### 1.2 Core Principles

#### 1.2.1 Least Privilege (PoLP — Principle of Least Privilege)
**Definition**: Grant users the **minimum access required** to perform their job function, nothing more.

**Implementation**:
```
Wrong:  "John is finance, give him all finance group access"
Right:  "John needs to approve invoices in system X, grant: approver role on invoice queue only"
```

**Benefits**:
- Limits blast radius of credential compromise
- Reduces attack surface
- Improves auditability
- Easier compliance demonstration

#### 1.2.2 Separation of Duties (SoD)
**Definition**: Distribute critical tasks so that **no single person can approve and execute** a sensitive action.

**Examples**:
- Payment Requester ≠ Payment Approver
- Code Author ≠ Code Reviewer (in CI/CD)
- Access Granter ≠ Access Recipient (for sensitive roles)
- Auditor cannot modify audit logs

**Implementation**:
- Preventive: Automatically block conflicting role assignments
- Detective: Alert when SoD violations are detected
- Corrective: Policies requiring manual review for exceptions

#### 1.2.3 Zero Trust
**Definition**: **Never trust, always verify**. Every request is treated as untrusted regardless of source.

**Zero Trust Pillars**:
1. **Continuous Verification**: Re-authenticate and re-authorize on every request
2. **Device Posture**: Ensure device is compliant (patched, encrypted, MDM-enrolled)
3. **Network Context**: Evaluate network location, IP reputation, VPN status
4. **Behavioral Analytics**: Detect anomalies (impossible travel, unusual resource access)
5. **Microsegmentation**: Network isolation between systems

**Zero Trust IAM Implementation**:
- Passwordless or MFA-enforced authentication
- Token-based (short-lived) rather than session-based
- Conditional access policies based on risk signals
- Continuous monitoring and revocation of compromised tokens

#### 1.2.4 Auditability
**Definition**: **All identity and access decisions must be logged, traceable, and reviewable**.

**What to Log**:
```
✓ Authentication events (success, failure, method)
✓ Authorization decisions (allow/deny, policy evaluated)
✓ Group membership changes (who added, when, why)
✓ Privilege elevation (who elevated, duration, action taken)
✓ Configuration changes (policy updates, role definitions)
✓ Data access (who accessed what, when, what actions)
```

**Audit Trail Requirements**:
- **Immutable**: Cannot be modified after creation
- **Complete**: All relevant details captured
- **Linked**: Connected to ticket systems and change requests
- **Accessible**: Searchable and analyzable
- **Retained**: Per compliance requirements (often 1-7 years)

#### 1.2.5 Automation
**Definition**: Use **rules and workflows** to enforce identity and access policies without manual intervention.

**Automation Opportunities**:
- **Provisioning**: HR system → Directory entry creation
- **Deprovisioning**: Termination date → Automatic access revocation
- **Recertification**: Scheduled role review campaigns
- **Policy Enforcement**: SoD conflict detection → Alert/block
- **Token Management**: Automatic rotation and expiration

**Benefits**:
- Reduces human error
- Enforces consistency
- Enables audit trails
- Frees teams for strategic work

### 1.3 Mental Model: How It All Connects

#### 1.3.1 The Identity Architecture Layer Cake

```
┌─────────────────────────────────────────┐
│  Application Layer                      │
│  (What the user can do)                 │
├─────────────────────────────────────────┤
│  Authorization Layer (RBAC/ABAC)        │
│  Roles → Permissions → Resources        │
├─────────────────────────────────────────┤
│  Token Layer (OIDC/OAuth2/SAML)         │
│  Issues and validates security tokens   │
├─────────────────────────────────────────┤
│  IAM Layer                              │
│  MFA, Conditional Access, Governance    │
├─────────────────────────────────────────┤
│  Authentication Layer                   │
│  Verifies identity (Password/Cert/etc)  │
├─────────────────────────────────────────┤
│  Directory Layer (AD/LDAP)              │
│  Stores identities and groups           │
├─────────────────────────────────────────┤
│  Infrastructure Layer                   │
│  Network, encryption, hardware security │
└─────────────────────────────────────────┘
```

#### 1.3.2 Data Flow Example: Employee Accessing Sensitive Resource

```
┌─────────────────────────────────────────────────────────────────┐
│ SCENARIO: John Doe requests access to /data/financials         │
└─────────────────────────────────────────────────────────────────┘

1. IDENTITY
   ├─ Directory contains: john.doe with attributes:
   │  └─ uid: john.doe
   │  └─ email: john.doe@example.com
   │  └─ department: Finance
   │  └─ memberOf: [Finance_Team, Finance_Approvers]

2. AUTHENTICATION (Proving who you are)
   ├─ John enters password + FIDO2 key
   ├─ Directory validates credentials
   ├─ MFA verified ✓
   └─ Session/Token created

3. AUTHORIZATION (Deciding what you can do)
   ├─ John requests: read /data/financials/budget.xlsx
   ├─ RBAC system checks:
   │  ├─ User john.doe in group Finance_Team? ✓ Yes
   │  ├─ Group Finance_Team has role Finance_Analyst? ✓ Yes
   │  ├─ Role Finance_Analyst has permission read:financial_data? ✓ Yes
   │  └─ Time-of-day policy: 09-17, business day? ✓ Yes
   ├─ ABAC conditions:
   │  ├─ Device compliant/encrypted? ✓ Yes
   │  ├─ Network from corporate VPN? ✓ Yes
   │  └─ No anomalous behavior? ✓ Yes
   └─ DECISION: ALLOW ✓

4. GOVERNANCE & AUDIT
   ├─ Log event: john.doe accessed budget.xlsx
   ├─ Link to quarterly access review
   ├─ Check SoD: Finance_Analyst can create AND approve? ✓ No conflict
   └─ Store in audit system (7-year retention)
```

### 1.4 Quick Diagnosis Matrix

Use this to identify which layer is the problem:

| Symptom | Likely Cause | Solution |
|---------|-------------|----------|
| "I can't log in at all" | Authentication Layer | Check credentials, MFA device, account status |
| "I logged in but don't see my data" | Authorization Layer | Check group memberships, role assignments |
| "I see an error about LDAP" | Directory Layer | Check LDAP connection, DN format, TLS |
| "My token was rejected" | Token Layer | Check token expiry, signature, audience claim |
| "Access was okay yesterday, not today" | Policy Layer | Check time-based policies, SoD rules |
| "Other people can do this but I can't" | RBAC Design | Check role assignments, group hierarchy |

### 1.5 Learning Path Recommendations

**For Beginners (0-3 months)**:
1. Understand concepts in 1.1-1.2
2. Choose ONE technology: LDAP **OR** AD (start with LDAP if Linux-focused, AD if Windows-focused)
3. Build lab environment with basic users and groups
4. Practice authentication and basic authorization
5. Move to Section 5 (RBAC) to understand role concepts

**For Intermediate (3-12 months)**:
1. Implement hierarchical roles and groups
2. Add multi-factor authentication
3. Explore Section 4 (IAM) for SSO integration
4. Implement governance processes (provisioning, deprovisioning)
5. Build monitoring and audit logging

**For Advanced (12+ months)**:
1. Design complex RBAC and SoD models
2. Implement conditional access and zero trust
3. Integrate multiple identity providers
4. Build self-service portals and automation
5. Achieve SOC 2/ISO 27001 compliance

---

## 2. LDAP Mastery — Zero to Hero
### Complete Guide to LDAP Directory Services

### 2.1 Core LDAP Concepts & Architecture
- LDAP v3 (RFC 4510+): operations bind, search, add, modify, delete, compare.
- Directory Information Tree (DIT): hierarchical entries under Base DN.
- DN/RDN: Distinguished Name uniquely identifies an entry; RDN is the leaf.
- ObjectClass/Schema: Defines allowed attributes (inetOrgPerson, posixAccount, groupOfNames).
- Filters: Boolean search expressions, e.g., (&(objectClass=inetOrgPerson)(mail=*@example.com)).

### 2.2 Directory Information Tree (DIT) Design
- Base DN: `dc=example,dc=com`
- Organizational Units: `ou=People`, `ou=Groups`, `ou=Services`, `ou=Systems`
- Users: `inetOrgPerson` (+ `posixAccount` for POSIX login)
- Groups: `groupOfNames` (or `groupOfUniqueNames`)

Example tree
```
dc=example,dc=com
├── ou=People
├── ou=Groups
├── ou=Services
└── ou=Systems
```

### 2.3 Practical Operations: LDAP Commands & Workflows

Add a user (LDIF)
```ldif
dn: uid=jdoe,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
uid: jdoe
cn: John Doe
sn: Doe
mail: jdoe@example.com
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/jdoe
loginShell: /bin/bash
```

Add a group (LDIF)
```ldif
dn: cn=developers,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: developers
member: uid=jdoe,ou=People,dc=example,dc=com
```

CLI basics
```bash
# Search (simple bind)
ldapsearch -x -H ldap://ldap.example.com -b "dc=example,dc=com" "(uid=jdoe)"

# Add/modify/delete
ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f user.ldif
ldapmodify -x -D "cn=admin,dc=example,dc=com" -W -f modify.ldif
ldapdelete -x -D "cn=admin,dc=example,dc=com" -W "uid=jdoe,ou=People,dc=example,dc=com"

# Bind test
ldapwhoami -x -H ldap://ldap.example.com \
  -D "uid=jdoe,ou=People,dc=example,dc=com" -W
```

### 2.4 LDAP Security Hardening
- Use LDAPS (636) or StartTLS; enforce TLS 1.2+; pin CA; disable anonymous binds.
- Store passwords with strong hashes; prevent broad read of `userPassword` and sensitive attributes via ACLs.
- Implement rate limits and lockout policies (directory-dependent); audit failures.

### 2.5 Performance: Indexing & Query Optimization
- Index frequently searched attributes: `uid`, `cn`, `mail`, `member`, `memberOf`.
- Scope searches to the correct base; request only needed attributes.
- Set time/size limits to avoid unbounded scans.

### 2.6 High Availability & Replication Strategies
- Provider/consumer or multi-master; design for at least two replicas per site.
- Monitor replication lag; understand last-writer-wins at attribute level.

### 2.7 Integration: Linux System Authentication with SSSD
- NSS/PAM via SSSD resolves users and authenticates against LDAP/LDAPS.
- Cache credentials, disable enumeration, secure `sssd.conf` (0600 permissions).

Minimal sssd.conf example
```ini
[sssd]
services = nss, pam
domains = LDAP

[domain/LDAP]
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
ldap_uri = ldaps://ldap.example.com
ldap_search_base = dc=example,dc=com
ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt
enumerate = false
cache_credentials = true
```

### 2.8 Application Integration Pattern
1) App binds with a read-only service account.
2) Search for user DN by `uid`/`mail`.
3) Bind as the user DN with provided password to verify.
4) Fetch attributes and groups (`memberOf`) to build an auth context.

### 2.9 LDAP Troubleshooting & Diagnostics
```bash
# Test LDAPS and certificate chain
openssl s_client -connect ldap.example.com:636 -showcerts

# Who am I?
ldapwhoami -x -H ldaps://ldap.example.com -D "cn=admin,dc=example,dc=com" -W

# Groups referencing a member
ldapsearch -x -b "ou=Groups,dc=example,dc=com" \
  "(member=uid=jdoe,ou=People,dc=example,dc=com)" cn
```

### 2.10 Hands-On Exercises: LDAP Zero to Hero
- Create People/Groups OUs, add two users and a group, enable memberOf overlay, validate membership from the user entry.
- Enforce StartTLS/LDAPS only; verify with `openssl s_client`.
- Add indexes for `uid`, `mail`, `member` and measure search latency before/after.
- Integrate a Linux host with SSSD; log in with an LDAP user; restrict sudo via LDAP.
- Implement an app login: service bind → search → user bind → group claims.

---

## 3. Active Directory (AD) Mastery — Zero to Hero
### Complete Guide to Enterprise Windows Directory Services

### 3.1 AD Architecture & Core Concepts
- Domain: Security boundary (e.g., corp.example.com). Contains users, groups, computers.
- Forest: One or more domains with shared schema and global catalog.
- OU: Delegation and policy scope (GPOs, admin rights) — not for org charts.
- DC: Domain Controller hosting AD DS, KDC (Kerberos), Global Catalog; multi-master replication.
- Sites/Subnets: Physical topology for logon/DC selection and replication schedules.
- DNS: AD-integrated zones; SRV records enable service discovery.
- GPO: Group Policy Objects; central configuration for users/computers.
- Auth: Kerberos (preferred), NTLM (legacy; restrict/audit).

### 3.2 AD Design Principles & Best Practices
- Prefer a single domain per forest; keep structure simple.
- OU design for delegation and GPO scoping (e.g., Workstations, Servers, Users, Service Accounts).
- Group strategy: AGDLP — Accounts → Global Groups → Domain Local → Permissions.
- Tiered admin model: Tier 0 (DCs), Tier 1 (Servers), Tier 2 (Workstations); separate admin identities per tier.

### 3.3 Practical Operations: PowerShell Administration
Create OUs
```powershell
New-ADOrganizationalUnit -Name "Workstations" -Path "DC=corp,DC=example,DC=com"
New-ADOrganizationalUnit -Name "Servers" -Path "DC=corp,DC=example,DC=com"
New-ADOrganizationalUnit -Name "Users" -Path "DC=corp,DC=example,DC=com"
New-ADOrganizationalUnit -Name "Groups" -Path "DC=corp,DC=example,DC=com"
```

Create user and groups (AGDLP)
```powershell
New-ADUser -Name "John Doe" -SamAccountName jdoe \
  -UserPrincipalName jdoe@corp.example.com \
  -AccountPassword (Read-Host -AsSecureString "Password") -Enabled $true \
  -Path "OU=Users,DC=corp,DC=example,DC=com"

New-ADGroup -Name "GG_Dev" -GroupScope Global -Path "OU=Groups,DC=corp,DC=example,DC=com"
New-ADGroup -Name "DL_AppX_RW" -GroupScope DomainLocal -Path "OU=Groups,DC=corp,DC=example,DC=com"
Add-ADGroupMember -Identity "GG_Dev" -Members jdoe
Add-ADGroupMember -Identity "DL_AppX_RW" -Members "GG_Dev"
```

Kerberos SPN and constrained delegation
```powershell
# Register SPN for a service account
setspn -S HTTP/app.corp.example.com CORP\svcApp

# Enable constrained delegation to specific SPNs
Set-ADAccountControl -Identity CORP\svcApp -TrustedToAuthForDelegation $true
Set-ADObject -Identity (Get-ADUser svcApp).DistinguishedName \
  -Add @{"msDS-AllowedToDelegateTo"="HTTP/api.corp.example.com"}
```

GPO essentials
- Test OU, link GPOs, avoid blocking inheritance unless necessary.
- Use security baselines; drive mappings; printers; Windows Update; scripts.

### 3.4 AD Security Hardening & Privileged Access
- LAPS/Windows LAPS for local admin password rotation.
- gMSA for services; avoid static passwords and interactive logon.
- Restrict Domain Admins; use Just-In-Time elevation (PIM/PAM) and privileged access workstations.
- Advanced Audit Policy; forward Windows Event Logs to SIEM; monitor DC health.

### 3.5 AD Operations: Health Monitoring & Replication
```powershell
# DC and replication health
dcdiag /v
repadmin /replsummary
repadmin /showrepl

# SYSVOL replication (DFSR vs FRS)
dfsrmig /getglobalstate
```

### 3.6 Hybrid Identity: On-Premises AD + Cloud
- Sync identities with a cloud IdP; filter by OU; handle UPN suffixes.
- Conditional access (MFA, device compliance) for cloud apps; use group-based assignments.
- Understand differences: AD roles (on-prem), cloud directory roles, and resource IAM (e.g., cloud provider RBAC).

### 3.7 Hands-On Exercises: AD Zero to Hero
- Create OU structure and group model (AGDLP); apply NTFS ACLs via Domain Local groups.
- Implement LAPS; verify randomized local admin passwords accessible to the right admins only.
- Configure gMSA for an app service; register SPN; test Kerberos constrained delegation.
- Build a test GPO for security baseline; pilot in a staging OU; measure impact.

---

## 4. Modern IAM — Zero to Hero
### Building Identity & Access Management Systems with OAuth2, OIDC, and SAML

### 4.1 IAM Scope & Building Blocks
- Subjects: users, service principals, workloads.
- Credentials: passwords, keys, certificates, tokens.
- Tokens: SAML Assertions, OIDC ID Tokens, OAuth2 Access Tokens (often JWTs).
- Policies: Allow/Deny on actions and resources with conditions.
- Governance: JML lifecycle, approvals, reviews, SoD, and audit trails.

### 4.2 Modern Protocols: OAuth2, OIDC, SAML
- SAML 2.0: Browser SSO, XML assertions; common for enterprise SaaS.
- OIDC: Identity layer on OAuth2; provides ID Token; modern web/mobile.
- OAuth2: Delegated authorization. Flows: Authorization Code (PKCE), Client Credentials, Device Code.
- SCIM: Provisioning standard to create/update/deprovision users and groups in apps.

### 4.3 Token Anatomy: Understanding JWTs
```json
{
  "iss": "https://idp.example.com",
  "sub": "00u1abcdXYZ",
  "aud": "api://backend",
  "exp": 1735689600,
  "iat": 1735686000,
  "nonce": "random",
  "amr": ["mfa"],
  "groups": ["dev", "finance"],
  "scp": ["read:orders", "write:orders"]
}
```

### 4.4 IAM Architecture Patterns
- Central IdP (Identity Provider) issues tokens; apps verify tokens and enforce authorization locally or via a gateway.
- Federation with enterprise directories (AD/LDAP) for passwordless SSO to apps.
- Gateway/API layer enforces OAuth scopes/claims centrally; services trust gateway.

### 4.5 Building OIDC-Protected Applications
1) Register an app in the IdP with redirect URIs and PKCE enabled.
2) Client starts Authorization Code + PKCE flow.
3) IdP authenticates user (MFA) and returns code to redirect URI.
4) Client exchanges code + verifier at token endpoint; receives ID/Access/Refresh tokens.
5) Client calls API with Bearer access_token; API validates signature, audience, expiry, and claims.

Authorize URL example
```text
GET /authorize?response_type=code&client_id=CLIENT&redirect_uri=URL&scope=openid%20profile%20email&code_challenge=...&code_challenge_method=S256&state=...
```

### 4.6 User Provisioning with SCIM
- IdP pushes user objects and group memberships to SaaS via SCIM.
- Map attributes and groups to application roles; deprovision on termination.

### 4.7 Authorization Policy Models
- RBAC: Roles grant permissions; simple audits; stable environments.
- ABAC: Attributes (user, resource, context) gate access; dynamic and fine-grained.
- ReBAC: Relationship graphs define who can access what (common in collaboration apps).
- Hybrid: RBAC baseline + ABAC conditions + emergency access.

### 4.8 Cloud Platform IAM Examples

AWS IAM policy (API allow)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadOrders",
      "Effect": "Allow",
      "Action": ["orders:Get*", "orders:List*"],
      "Resource": "arn:aws:execute-api:region:acct:api-id/*"
    }
  ]
}
```

Kubernetes RBAC (namespace role)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app
  name: read-orders
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: read-orders-binding
  namespace: app
subjects:
- kind: Group
  name: dev
roleRef:
  kind: Role
  name: read-orders
  apiGroup: rbac.authorization.k8s.io
```

### 4.9 Authentication Hardening & MFA
- MFA by default; prefer phishing-resistant methods (FIDO2/WebAuthn).
- Conditional Access: device posture, network, geo, risk signals; continuous access evaluation.
- Secrets: no hardcoded secrets; rotate keys; use KMS/HSM; minimize token lifetimes.

### 4.10 IAM Governance & Lifecycle Management
- Joiner/Mover/Leaver automation; role-based entitlements; exception workflow with approvals.
- Access reviews and recertification; SoD checks and detective controls.
- Logs and analytics: centralized audit and anomaly detection.

### 4.11 Hands-On Exercises: IAM Zero to Hero
- Register an OIDC app with Authorization Code + PKCE; obtain tokens; introspect ID token.
- Protect an API with JWT validation; enforce scope and group claims.
- Build SCIM mappings to provision users to a SaaS app and test deprovisioning.
- Add conditional access requiring MFA and compliant device for an admin app.

---

## 5. RBAC Engineering — Zero to Hero
### Designing & Implementing Role-Based Access Control

### 5.1 RBAC Concepts & Models
- Subject → Role → Permission → Resource.
- NIST RBAC: Core (users, roles, permissions, sessions), Hierarchical (role inheritance), Constrained (SoD and cardinality).
- Administrative RBAC (ARBAC): Who can create/assign roles and manage entitlements.

### 5.2 Role Engineering Process & Methodology
1) Inventory resources and permissions (systems, APIs, data).
2) Discover access patterns (log mining, interviews, role mining tools).
3) Define role taxonomy:
   - Business roles (Sales Rep, Support Agent)
   - IT roles (DBA, SysAdmin)
   - Application roles (Jira Admin, Warehouse Reader)
   - Platform roles (K8s Namespace Admin)
4) Map roles → entitlements; enforce least privilege.
5) SoD constraints (e.g., Requester vs Approver cannot be the same person).
6) Governance: role owners, approval flows, review cadence, change management.

### 5.3 RBAC Implementation Patterns
- Directory-centric (AD/LDAP): Users → Global Groups (roles) → Domain Local Groups (permissions) → ACLs.
- App-native RBAC: Map IdP groups/claims to app roles; manage in app config.
- Cloud RBAC: Bind IdP groups to cloud roles; use infra-as-code (Terraform) for repeatability.
- Policy as code: Represent roles and grants in Git; CI validates SoD and drift.

AGDLP example
```
Users -> GG_Role_Dev -> DL_AppX_RW -> NTFS/ACL on resource
```

SQL RBAC example (SQL Server)
```sql
CREATE ROLE reporting_reader;
GRANT SELECT ON SCHEMA::reporting TO reporting_reader;
-- Map directory group to DB role via login/user
CREATE LOGIN [CORP\GG_Reporting] FROM WINDOWS;
CREATE USER [CORP\GG_Reporting] FOR LOGIN [CORP\GG_Reporting];
EXEC sp_addrolemember 'reporting_reader', 'CORP\GG_Reporting';
```

Kubernetes namespace RBAC
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: team-a
  name: maintainer
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get","list","watch","create","update","patch","delete"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: team-a
  name: bind-maintainer
subjects:
- kind: Group
  name: GG_TeamA_Maintainer
roleRef:
  kind: Role
  name: maintainer
  apiGroup: rbac.authorization.k8s.io
```

### 5.4 Separation of Duties & Risk Controls
- Static SoD: Prevent conflicting assignments concurrently.
- Dynamic SoD: Allow roles but restrict usage in the same session or require dual control.
- Emergency access (break-glass) with time-bound elevation and detailed auditing.

### 5.5 RBAC Operations & Maintenance
- Avoid role explosion: prefer composable roles and attributes for edge cases.
- Quarterly access reviews; remove stale memberships; automate recertification.
- Test authorization paths; unit-test permissions and policy evaluation.

### 5.6 Hands-On Exercises: RBAC Zero to Hero
- Define a role hierarchy for an e-commerce app (viewer → editor → admin) and implement in app and IdP.
- Implement SoD between Payment Creator and Payment Approver; enforce via policy and review.
- Migrate direct user permissions to group-based roles; validate using access logs.

---

## 6. Integration Patterns: Mapping AD, LDAP, IAM, and RBAC
### How Identity Systems Work Together

- Identity
  - LDAP/AD: entries (user, group, computer) with DN and attributes
  - IAM: user, service principal, workload identity
  - RBAC: subject (user/group/service)

- Group/Role
  - LDAP/AD: security groups; dynamic groups possible; AGDLP nesting
  - IAM: roles/policies/entitlements; groups map to app roles or claims
  - RBAC: roles bind to permissions; inheritance possible

- Policy/Permission
  - LDAP/AD: ACLs on directory entries, NTFS/share ACLs, GPO rights
  - IAM: JSON/YAML policies (allow/deny, actions, resources, conditions)
  - RBAC: permission sets per resource type

- AuthN/AuthZ
  - LDAP/AD: Bind, Kerberos/NTLM; LDAPS for apps
  - IAM: Tokens (SAML/OIDC/OAuth2), Conditional Access, MFA
  - RBAC: Authorization evaluates role/attribute memberships

- Provisioning
  - LDAP/AD: ldapadd/modify; AD cmdlets; sync connectors
  - IAM: SCIM, APIs, workflows
  - RBAC: Assign roles by groups or attributes; track approvals

---

## 7. Reference Architectures: Production-Ready Blueprints
### Complete End-to-End Identity System Designs

### 7.1 Windows-Centric Enterprise Architecture (On-Premises + Cloud)
- AD forest (single domain), Sites/Subnets; OU design for Workstations/Servers/Users/Service Accounts.
- AGDLP for permissions; GPO baselines; LAPS; gMSA; Kerberos constrained delegation.
- Cloud IdP federation; Conditional Access; MFA; group-based app assignments; SCIM to SaaS.

### 7.2 Linux-First Architecture with OpenLDAP
- DIT: People/Groups/Systems/Services; LDAPS; indexes; memberOf overlay.
- SSSD for NSS/PAM; sudo via LDAP; SSH keys managed in directory (restricted read).
- Replication and monitoring; logs to SIEM.

### 7.3 Kubernetes Platform with Centralized Identity
- OIDC between cluster API server and IdP; groups as claims.
- Namespaces per team; K8s RBAC; admission policies; Secret management via KMS.
- CI/CD integrates with IdP (workload identity) for short-lived credentials.

### 7.4 Data Warehouse & Analytics Identity Architecture
- Directory groups bound to DB roles; row-level security with attributes.
- SoD between ETL writers and Finance approvers; periodic reviews.
- Centralized query auditing and lineage tracking.

---

## 8. Security, Compliance, and Governance
### Hardening Identity Infrastructure for Enterprise

### 8.1 Security Controls
- MFA everywhere; phishing-resistant factors for admins.
- TLS/LDAPS; cert lifecycle management; pin trusted CAs.
- PAM/PIM for privileged access; just-in-time elevation; PAWs for admins.
- Rotate secrets and keys; hardware-backed storage where possible.

### 8.2 Compliance & Governance Anchors
- Policy-as-code for IAM; change reviews; traceability to tickets.
- Access recertification; SoD attestation; strong deprovisioning SLAs.
- Data protection: PII minimization in directories; encrypt at rest and in transit.

### 8.3 Monitoring, Detection & Alerting
- Centralized logs (binds, token issuances, auth failures, policy denials).
- Alert on risky sign-ins, impossible travel, unusual consent, token replay.

---

## 9. Troubleshooting Playbooks
### Common Issues & Solutions Across All IAM Systems

### 9.1 LDAP Troubleshooting
- Empty search results: check Base DN, filter, and indexes; verify ACLs.
- TLS errors: CA trust, hostname mismatch, protocol/cipher suites.
- Bind failures: DN resolution, account lockout, password policy.

### 9.2 Active Directory Troubleshooting
- Logon issues: time sync (NTP), DNS SRV records, site placement.
- Kerberos failures: SPN duplication, clock skew, constrained delegation scope.
- GPO problems: link order, WMI filter scope, security filtering, RSOP.

### 9.3 IAM Troubleshooting
- Token validation errors: clock skew, audience/issuer mismatch, key rotation.
- SAML/OIDC misconfig: redirect URIs, NameID/subject mapping, group claim mapping.
- SCIM issues: attribute mappings, pagination, conflict resolution.

### 9.4 RBAC Troubleshooting
- Over/under-permissioned roles: analyze logs, tighten permissions, add ABAC guards.
- SoD conflicts: enforce at request time, monitor drift, and remediate.

---

## 10. Operations: Checklists and Runbooks
### Deployment, Hardening, and Operational Procedures

### 10.1 LDAP Hardening Checklist
- [ ] LDAPS/StartTLS enforced; no anonymous bind
- [ ] Indexes for uid, mail, cn, member, memberOf
- [ ] ACLs restrict sensitive attributes; logs shipped centrally
- [ ] Replication with monitoring; regular backups and tested restores

### 10.2 Active Directory Hardening Checklist
- [ ] Tiered admin model; separate admin accounts; PAWs
- [ ] LAPS/Windows LAPS deployed; gMSA for services
- [ ] Kerberos constrained delegation only; SPNs unique
- [ ] GPO baselines; Advanced Audit Policy; SIEM integration

### 10.3 IAM Deployment & Hardening Checklist
- [ ] MFA and Conditional Access; phishing-resistant for admins
- [ ] Short-lived tokens; key rotation; secrets in KMS/HSM
- [ ] SCIM provisioning; JML automation; deprovision SLAs
- [ ] Access reviews; SoD checks; policy-as-code

### 10.4 RBAC Implementation Checklist
- [ ] Role taxonomy documented; owners assigned
- [ ] SoD constraints defined and enforced
- [ ] Infra-as-code for roles and grants; CI validation
- [ ] Quarterly recertification; drift detection

### 10.5 Critical Runbooks
- Compromised account: disable, revoke sessions, reset creds, rotate secrets, review logs, re-enable post-review.
- Token signing key rotation: publish new JWKS, support dual keys, cutover, revoke old, verify clients.
- Directory restore: determine authoritative vs non-authoritative; follow tested procedures; validate replication.

---

## 11. Glossary
### Key Terminology & Abbreviations

- ABAC: Attribute-Based Access Control
- ACL: Access Control List
- AD DS: Active Directory Domain Services
- AGDLP: Accounts→Global→Domain Local→Permissions group nesting model
- ARBAC: Administrative RBAC
- DN/RDN: Distinguished/Relative Distinguished Name
- DIT: Directory Information Tree
- gMSA: Group Managed Service Account
- GPO: Group Policy Object
- IdP: Identity Provider
- JML: Joiners/Movers/Leavers
- JWT: JSON Web Token
- KDC: Key Distribution Center (Kerberos)
- LAPS/Windows LAPS: Local Administrator Password Solution
- LDAPS: LDAP over TLS
- OIDC: OpenID Connect
- PAM/PIM: Privileged Access/Identity Management
- PKCE: Proof Key for Code Exchange
- RBAC: Role-Based Access Control
- ReBAC: Relationship-Based Access Control
- SCIM: System for Cross-domain Identity Management
- SPN: Service Principal Name
- UPN: User Principal Name

---

## 12. Further Reading & Resources
### Standards, Guides, and Advanced Topics

Standards and specs
- LDAP: RFC 4510–4519
- Kerberos: RFC 4120
- SAML 2.0 Core
- OAuth 2.0 (RFC 6749) and OIDC Core
- SCIM 2.0 (RFC 7643, RFC 7644)

Guides and references
- Microsoft AD DS and Group Policy documentation
- OpenLDAP Administrator’s Guide
- NIST RBAC model and standards
- CNCF: Kubernetes RBAC docs
- Cloud provider IAM docs (AWS, Azure, GCP)

Exercises to master
- Build a small LDAP directory, secure with TLS, integrate SSSD.
- Stand up a test AD domain; implement AGDLP and LAPS; test Kerberos SPN and KCD.
- Configure an OIDC app (Authorization Code + PKCE); protect an API; add Conditional Access.
- Engineer a role taxonomy; implement in directory groups and app RBAC; run an access review.
