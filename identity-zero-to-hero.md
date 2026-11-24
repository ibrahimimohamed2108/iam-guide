# Identity, Directory, and Access Management: Foundations to Operations

A guide to Active Directory, LDAP, IAM, and RBAC, from core concepts to operational practice. It is written for security engineers, system administrators, and developers who work with identity systems.

## What You Will Learn

- Identity, authentication, and authorization, and how they differ
- Designing LDAP directories and Active Directory (AD) environments
- Modern authentication with OAuth 2.0, OpenID Connect (OIDC), and SAML
- Engineering RBAC with separation of duties (SoD) and governance
- Hardening identity infrastructure
- Troubleshooting identity and access problems

## Target Audience

- **Beginners:** start with Section 1 and read in order.
- **Practitioners:** jump to the section that matches your task.
- **Architects:** focus on Sections 6 to 8 for design patterns and governance.

## Table of Contents

1. [Foundations](#1-foundations)
2. [LDAP](#2-ldap)
3. [Active Directory](#3-active-directory)
4. [Modern IAM](#4-modern-iam)
5. [RBAC Engineering](#5-rbac-engineering)
6. [Integration Patterns](#6-integration-patterns)
7. [Reference Architectures](#7-reference-architectures)
8. [Security, Compliance, and Governance](#8-security-compliance-and-governance)
9. [Troubleshooting Playbooks](#9-troubleshooting-playbooks)
10. [Operations: Checklists and Runbooks](#10-operations-checklists-and-runbooks)
11. [Glossary](#11-glossary)
12. [Further Reading](#12-further-reading)

---

## 0. How to Use This Guide

- Read Section 1, then choose a track: LDAP (Linux-focused environments) or AD (Windows-focused environments).
- Add IAM for single sign-on and token-based access to applications and APIs.
- Implement RBAC to standardize authorization across systems.
- Complete the exercises at the end of each section.

Examples in this guide are illustrative. Policy documents, JSON, and tokens show structure and are not complete product configurations. Test every command in a lab before you run it against a production system.

**Learning outcomes**

- Distinguish identity, directory, and IAM, and place RBAC within them.
- Design directory structures (DIT and OUs), groups, and policies.
- Implement secure authentication with Kerberos, LDAP bind, and OIDC/OAuth 2.0.
- Engineer roles and permissions for least privilege and auditability.

---

## 1. Foundations

### 1.1 Core Concepts

#### 1.1.1 Identity

**Definition:** a digital representation of an actor (user, service, device, or application) within a system.

- Each identity must be unique and identifiable within the organization.
- Identities carry attributes such as email, department, role, and clearance level.
- Identities can be human (users) or non-human (service accounts, workload identities).

Examples:

- User: `john.doe@example.com`
- Service: `api-processor@corp`
- Device: `LAPTOP-ABC123`
- Workload: a CI/CD pipeline identity

Identity is the basis of every security decision. Without accurate identity, authentication and authorization cannot be trusted.

#### 1.1.2 Authentication (AuthN): Proving Who You Are

**Definition:** verifying that an identity is genuine, using proof of knowledge, possession, or inherence.

Authentication factors:

- **Knowledge:** something you know (password, PIN)
- **Possession:** something you have (hardware token, phone, cryptographic key)
- **Inherence:** something you are (fingerprint, face)
- **Context:** where you are, when, and from what network (used as a risk signal, never as a sole factor)

| Method | Strength | Typical use |
|--------|----------|-------------|
| Password | Low | Legacy systems |
| Multi-factor (MFA) | Medium | Standard baseline |
| Passwordless (FIDO2/WebAuthn) | High | Administrative and sensitive access |
| Certificate | High | System-to-system authentication |
| OAuth 2.0 / OIDC | Medium | Third-party integrations |
| Kerberos | High | Enterprise directory-based login |

MFA is the minimum baseline for sensitive systems. Phishing-resistant methods such as FIDO2 are preferred for administrative access.

#### 1.1.3 Authorization (AuthZ): Deciding What You Can Do

**Definition:** determining what an authenticated identity may do.

Authentication answers "Are you John Doe?" Authorization answers "May John Doe read file X and delete resource Y?"

Authorization models:

- **Access control list (ACL):** an explicit list of who can access what.
- **Role-based (RBAC):** a user holds roles, and roles hold permissions.
- **Attribute-based (ABAC):** rules evaluate user, resource, and environment attributes.
- **Relationship-based (ReBAC):** permissions follow relationships in a graph, such as "member of a team that owns this document."

Example evaluation:

```text
User:    john.doe@example.com
Request: read /data/financials/budget-2024.xlsx

1. Is john.doe authenticated?                 Yes
2. Does john.doe hold role Finance_Analyst?   Yes
3. Does that role grant read:budget_data?     Yes
4. Does the request meet time and device policy? Yes
Decision: ALLOW
```

#### 1.1.4 Directory Services

**Definition:** a hierarchical store of identities, attributes, and group memberships in a standardized format.

| Type | Primary use | Protocols | Hierarchy |
|------|-------------|-----------|-----------|
| Active Directory (AD) | Windows enterprise | Kerberos, LDAP, NTLM | Forest, domain, OU |
| OpenLDAP | Linux and Unix, open source | LDAP, LDAPS | Directory Information Tree (DIT) |
| FreeIPA | Linux infrastructure | LDAP, Kerberos, HTTP | Realm and domains |
| Okta, Microsoft Entra ID | Cloud and SaaS | OAuth 2.0, OIDC, SAML | Tenant and directories |

Core functions:

1. Store identities and devices.
2. Manage groups for permission delegation.
3. Provide authentication services (passwords, Kerberos).
4. Store group memberships and entitlements.
5. Define the schema for stored attributes.

The directory should act as the source of truth for identity. Changes replicate to connected systems, which makes centralized auditing possible.

#### 1.1.5 Policy

**Definition:** machine-evaluable rules that allow or deny authentication and authorization decisions.

Policy types:

- **Authentication:** require MFA for administrators, block legacy protocols.
- **Authorization:** allow read on public resources, deny write.
- **Compliance:** enforce encryption, password complexity, and retention.
- **Access:** conditional rules such as "only from the corporate network."

Illustrative policy (pseudo-format, not a product schema):

```json
{
  "policy_id": "developer_api_access",
  "description": "Developers may call the internal API",
  "conditions": {
    "role": "developer",
    "mfa_verified": true,
    "device_compliant": true,
    "network": ["office", "vpn"]
  },
  "effect": "allow",
  "resources": ["api.example.com/*"],
  "actions": ["read", "write"]
}
```

#### 1.1.6 Governance

**Definition:** lifecycle management and oversight of identities, access, and compliance.

Key processes:

1. **Joiners:** create the identity, assign roles, provision access.
2. **Movers:** on a role change, update attributes, revoke old roles, grant new ones.
3. **Leavers:** disable the account, revoke access, archive data.
4. **Access reviews:** periodically confirm that access remains appropriate.
5. **Compliance:** keep audit trails, enforce SoD, track policy violations.
6. **Exceptions:** handle emergency access and temporary elevation with approval and expiry.

Useful governance metrics:

- Time from hire to productive access
- Time to complete offboarding, and verification that it happened
- Number of stale accounts detected and removed
- Access review completion rate and findings
- Time to detect and remediate SoD conflicts

### 1.2 Core Principles

#### 1.2.1 Least Privilege

Grant the minimum access needed for the job.

```text
Weak:   "John is in Finance, so give him the whole Finance group."
Better: "John approves invoices in system X, so grant the approver role on the invoice queue only."
```

Benefits: smaller blast radius for a stolen credential, smaller attack surface, simpler audits.

#### 1.2.2 Separation of Duties (SoD)

No single person should be able to both initiate and approve a sensitive action.

Examples:

- Payment requester and payment approver must be different people.
- Code author and code reviewer must be different people.
- Access granter and access recipient must be different people for sensitive roles.
- Auditors must not be able to modify the audit logs they review.

Controls:

- **Preventive:** block conflicting role assignments automatically.
- **Detective:** alert when a conflict exists.
- **Corrective:** require manual review for approved exceptions.

#### 1.2.3 Zero Trust

Never trust, always verify. Treat every request as untrusted until it is verified, regardless of where it originates.

Pillars:

1. **Continuous verification:** re-check identity and authorization on each sensitive request.
2. **Device posture:** confirm the device is patched, encrypted, and managed.
3. **Network context:** evaluate location and VPN status as signals.
4. **Behavioral analytics:** detect anomalies such as impossible travel.
5. **Microsegmentation:** isolate systems from one another.

Zero trust IAM uses MFA or passwordless authentication, short-lived tokens, conditional access driven by risk signals, and prompt revocation of compromised sessions.

#### 1.2.4 Auditability

Every identity and access decision should be logged, traceable, and reviewable.

Log at minimum:

- Authentication events (success, failure, method used)
- Authorization decisions (allow or deny, and the policy applied)
- Group membership changes (who, when, and the approving ticket)
- Privilege elevation (who, how long, what was done)
- Configuration changes to policies and roles
- Access to sensitive data (who, what, when, which actions)

Audit trail requirements:

- **Immutable:** protected against modification after creation, including by administrators.
- **Complete:** every relevant detail captured.
- **Linked:** tied to tickets and change requests.
- **Searchable:** usable for investigation.
- **Retained:** kept for the period required by applicable regulation, which varies by jurisdiction and sector.

#### 1.2.5 Automation

Enforce identity policy through rules and workflows instead of manual steps.

- **Provisioning:** HR system creates directory entries.
- **Deprovisioning:** termination date triggers access revocation.
- **Recertification:** scheduled access review campaigns.
- **Policy enforcement:** SoD conflict detection triggers an alert or blocks the change.
- **Token management:** automatic rotation and expiry.

Automation reduces human error, enforces consistency, and produces audit evidence.

### 1.3 How the Pieces Connect

#### 1.3.1 Layered View

```text
+-----------------------------------------+
| Application layer                       |
| (what the user can do in the app)       |
+-----------------------------------------+
| Authorization layer (RBAC / ABAC)       |
| Roles -> permissions -> resources       |
+-----------------------------------------+
| Token layer (OIDC / OAuth 2.0 / SAML)   |
| Issues and validates tokens             |
+-----------------------------------------+
| IAM layer                               |
| MFA, conditional access, governance     |
+-----------------------------------------+
| Authentication layer                    |
| Verifies identity (password, cert, ...) |
+-----------------------------------------+
| Directory layer (AD / LDAP)             |
| Stores identities and groups            |
+-----------------------------------------+
| Infrastructure layer                    |
| Network, encryption, hardware security  |
+-----------------------------------------+
```

#### 1.3.2 Example: Employee Accesses a Sensitive Resource

```text
Scenario: John Doe requests read access to /data/financials

1. IDENTITY
   Directory entry for john.doe:
     uid: john.doe
     mail: john.doe@example.com
     department: Finance
     memberOf: Finance_Team, Finance_Approvers

2. AUTHENTICATION
   John enters his password and confirms with a FIDO2 key.
   The directory validates the password; the IdP validates the key.
   MFA result: satisfied. A short-lived session token is issued.

3. AUTHORIZATION
   The RBAC service checks:
     - john.doe is in Finance_Team: yes
     - Finance_Team maps to role Finance_Analyst: yes
     - Finance_Analyst grants read:financial_data: yes
     - Request falls within the access time window: yes
   The ABAC layer checks:
     - Device is compliant and encrypted: yes
     - Request comes from the corporate VPN: yes
     - No anomalous behavior detected: yes
   Decision: ALLOW

4. GOVERNANCE AND AUDIT
   The access is logged with the user, resource, and time.
   The access is linked to the quarterly access review.
   SoD check: Finance_Analyst cannot both create and approve: no conflict.
   Log is retained for the required period.
```

### 1.4 Quick Diagnosis

| Symptom | Likely layer | Where to look |
|---------|--------------|---------------|
| Cannot log in at all | Authentication | Credentials, MFA device, account status |
| Logged in but cannot see data | Authorization | Group membership, role assignment |
| LDAP error | Directory | Connection, DN format, TLS |
| Token rejected | Token | Expiry, signature, audience claim |
| Access worked yesterday, not today | Policy | Time-based rules, recent SoD changes |
| Peers have access, you do not | RBAC design | Role assignments, group nesting |

### 1.5 Learning Path

**Beginners (0 to 3 months)**

1. Read Sections 1.1 and 1.2.
2. Choose one technology: LDAP or AD.
3. Build a lab with basic users and groups.
4. Practice authentication and basic authorization.
5. Read Section 5 for role concepts.

**Intermediate (3 to 12 months)**

1. Implement nested roles and groups.
2. Add MFA.
3. Read Section 4 and integrate single sign-on.
4. Implement joiner, mover, and leaver processes.
5. Build monitoring and audit logging.

**Advanced (12+ months)**

1. Design complex RBAC and SoD models.
2. Implement conditional access and zero trust controls.
3. Integrate multiple identity providers.
4. Build self-service workflows and automation.
5. Support your organization through SOC 2 or ISO 27001 audits.

---

## 2. LDAP

### 2.1 Core Concepts

- **LDAP v3** (RFC 4510 and related): operations include bind, search, add, modify, delete, and compare.
- **Directory Information Tree (DIT):** a hierarchy of entries under a base DN.
- **DN and RDN:** a Distinguished Name uniquely identifies an entry; the Relative DN is its leaf component.
- **Object classes and schema:** define allowed attributes, for example `inetOrgPerson`, `posixAccount`, `groupOfNames`.
- **Filters:** boolean search expressions, for example `(&(objectClass=inetOrgPerson)(mail=*@example.com))`.

### 2.2 DIT Design

- Base DN: `dc=example,dc=com`
- Organizational units: `ou=People`, `ou=Groups`, `ou=Services`, `ou=Systems`
- Users: `inetOrgPerson`, with `posixAccount` for Linux login
- Groups: `groupOfNames` (or `groupOfUniqueNames`)

```text
dc=example,dc=com
├── ou=People
├── ou=Groups
├── ou=Services
└── ou=Systems
```

### 2.3 Common Operations

Add a user (LDIF):

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

Add a group (LDIF):

```ldif
dn: cn=developers,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: developers
member: uid=jdoe,ou=People,dc=example,dc=com
```

Command-line basics:

```bash
# Search with a simple bind
ldapsearch -x -H ldap://ldap.example.com -b "dc=example,dc=com" "(uid=jdoe)"

# Add, modify, delete (-W prompts for the password)
ldapadd    -x -D "cn=admin,dc=example,dc=com" -W -f user.ldif
ldapmodify -x -D "cn=admin,dc=example,dc=com" -W -f modify.ldif
ldapdelete -x -D "cn=admin,dc=example,dc=com" -W "uid=jdoe,ou=People,dc=example,dc=com"

# Verify that a user can bind
ldapwhoami -x -H ldap://ldap.example.com \
  -D "uid=jdoe,ou=People,dc=example,dc=com" -W
```

### 2.4 Security Hardening

- Use LDAPS (port 636) or StartTLS. Require TLS 1.2 or later and trust only the intended CA.
- Disable anonymous binds.
- Store passwords as salted hashes. Use ACLs to prevent broad reads of `userPassword` and other sensitive attributes.
- Apply lockout and rate limits where the directory supports them, and audit authentication failures.

### 2.5 Indexing and Query Performance

- Index frequently searched attributes: `uid`, `cn`, `mail`, `member`, `memberOf`.
- Scope searches to the narrowest base DN that works.
- Request only the attributes you need.
- Set size and time limits to prevent unbounded scans.

### 2.6 High Availability and Replication

- Use provider and consumer replication, or multi-master where the directory supports it. Plan for at least two replicas per site.
- Monitor replication lag. Understand conflict resolution. Many directories resolve conflicts per attribute, with the last writer winning.

### 2.7 Linux Integration with SSSD

SSSD provides NSS and PAM integration with LDAP, including credential caching.

```ini
# /etc/sssd/sssd.conf  (must be mode 0600, owned by root)
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

1. The application binds with a read-only service account.
2. It searches for the user's DN by `uid` or `mail`, using escaped input.
3. It binds as the user DN with the supplied password to verify it.
4. It reads attributes and group memberships to build the session's authorization context.

### 2.9 Troubleshooting Commands

```bash
# Inspect the TLS certificate chain
openssl s_client -connect ldap.example.com:636 -showcerts

# Confirm the identity the server sees
ldapwhoami -x -H ldaps://ldap.example.com -D "cn=admin,dc=example,dc=com" -W

# Find groups that reference a user
ldapsearch -x -b "ou=Groups,dc=example,dc=com" \
  "(member=uid=jdoe,ou=People,dc=example,dc=com)" cn
```

### 2.10 Exercises

1. Create People and Groups OUs, add two users and one group, enable the `memberOf` overlay, and confirm that membership appears on the user entry.
2. Enforce LDAPS or StartTLS only, and verify the certificate with `openssl s_client`.
3. Add indexes for `uid`, `mail`, and `member`, and measure search latency before and after.
4. Join a Linux host to LDAP with SSSD, log in as an LDAP user, and restrict sudo through an LDAP group.
5. Build an application login that performs a service bind, a user search, a user bind, and a group lookup.

---

## 3. Active Directory

### 3.1 Architecture

- **Domain:** a security and policy boundary, for example `corp.example.com`. Holds users, groups, and computers.
- **Forest:** one or more domains sharing a schema and a global catalog. The forest root is the true security boundary.
- **Organizational unit (OU):** used for delegation and Group Policy scope. OUs can reflect organization structure, but their main purpose is administration and policy.
- **Domain controller (DC):** hosts AD DS, the Kerberos KDC, and the global catalog. Replicates with multi-master replication.
- **Sites and subnets:** map physical topology to logon and DC selection, and to replication schedules.
- **DNS:** AD-integrated zones. SRV records enable service discovery.
- **Group Policy Objects (GPOs):** central configuration for users and computers.
- **Authentication:** Kerberos is preferred. NTLM is legacy; restrict and audit it.

### 3.2 Design Principles

- Keep the forest and domain structure as simple as the business allows. Prefer one domain per forest unless there is a clear reason for more.
- Design OUs for delegation and GPO scope, for example Workstations, Servers, Users, Groups, Service Accounts.
- Use AGDLP group nesting: accounts go into global groups, global groups go into domain local groups, and domain local groups hold permissions on resources.
- Use a tiered administration model:
  - Tier 0: domain controllers and identity infrastructure
  - Tier 1: servers
  - Tier 2: workstations
  - Separate administrative accounts for each tier.

### 3.3 PowerShell Administration

Create OUs:

```powershell
New-ADOrganizationalUnit -Name "Workstations" -Path "DC=corp,DC=example,DC=com"
New-ADOrganizationalUnit -Name "Servers"      -Path "DC=corp,DC=example,DC=com"
New-ADOrganizationalUnit -Name "Users"        -Path "DC=corp,DC=example,DC=com"
New-ADOrganizationalUnit -Name "Groups"       -Path "DC=corp,DC=example,DC=com"
```

Create a user and apply AGDLP:

```powershell
New-ADUser -Name "John Doe" -SamAccountName jdoe `
  -UserPrincipalName jdoe@corp.example.com `
  -AccountPassword (Read-Host -AsSecureString "Initial password") `
  -Enabled $true `
  -Path "OU=Users,DC=corp,DC=example,DC=com"

New-ADGroup -Name "GG_Dev"    -GroupScope Global      -Path "OU=Groups,DC=corp,DC=example,DC=com"
New-ADGroup -Name "DL_AppX_RW" -GroupScope DomainLocal -Path "OU=Groups,DC=corp,DC=example,DC=com"

Add-ADGroupMember -Identity "GG_Dev"     -Members jdoe
Add-ADGroupMember -Identity "DL_AppX_RW" -Members "GG_Dev"
```

Service principal names and constrained delegation:

```powershell
# Register an SPN for a service account (setspn takes the DOMAIN\account form)
setspn -S HTTP/app.corp.example.com CORP\svcApp

# Allow the service account to delegate to one specific SPN.
# Set-ADAccountControl and Set-ADObject take the sAMAccountName or DN, not DOMAIN\name.
Set-ADAccountControl -Identity svcApp -TrustedToAuthForDelegation $true
Set-ADObject -Identity (Get-ADUser svcApp).DistinguishedName `
  -Add @{ "msDS-AllowedToDelegateTo" = "HTTP/api.corp.example.com" }
```

GPO practice:

- Test in a pilot OU before linking widely.
- Avoid blocking inheritance unless there is a specific reason.
- Use security baselines for hardening settings. Use GPOs for drive mappings, printers, Windows Update settings, and logon scripts.

### 3.4 Security Hardening and Privileged Access

- Deploy Windows LAPS to rotate local administrator passwords automatically.
- Use group managed service accounts (gMSA) for services. Avoid static service passwords and interactive logon for service accounts.
- Restrict Domain Admins. Use just-in-time elevation (PIM or PAM) and privileged access workstations.
- Enable Advanced Audit Policy. Forward Windows event logs to a SIEM. Monitor domain controller health.

### 3.5 Health and Replication

```powershell
dcdiag /v                  # domain controller health
repadmin /replsummary      # replication summary across DCs
repadmin /showrepl         # replication detail per partner
dfsrmig /getglobalstate    # SYSVOL replication migration state
```

### 3.6 Hybrid Identity

- Synchronize on-premises identities to a cloud identity provider. Filter by OU to limit what syncs.
- Plan UPN suffixes so that sign-in names match the cloud tenant.
- Enforce conditional access (MFA, device compliance) for cloud applications. Assign access through groups.
- Keep three things separate: on-premises AD roles, cloud directory roles, and cloud resource IAM (for example, the cloud provider's RBAC).

### 3.7 Exercises

1. Build the OU structure and an AGDLP group model. Apply NTFS permissions through domain local groups.
2. Deploy Windows LAPS. Confirm that only the right administrators can read the rotated passwords.
3. Configure a gMSA for an application service. Register an SPN and test Kerberos constrained delegation.
4. Build a security baseline GPO, pilot it in a staging OU, and measure its effect before wider rollout.

---

## 4. Modern IAM

### 4.1 Scope and Building Blocks

- **Subjects:** users, service principals, workloads.
- **Credentials:** passwords, keys, certificates, tokens.
- **Tokens:** SAML assertions, OIDC ID tokens, OAuth 2.0 access tokens (often JWTs).
- **Policies:** allow or deny actions on resources, with conditions.
- **Governance:** joiner, mover, and leaver processes, approvals, reviews, SoD, audit trails.

### 4.2 Protocols

- **SAML 2.0:** browser-based single sign-on with XML assertions. Common in enterprise SaaS.
- **OIDC:** an identity layer on top of OAuth 2.0. Issues an ID token that states who the user is. Used by modern web and mobile applications.
- **OAuth 2.0:** delegated authorization. Common flows:
  - Authorization code with PKCE (users, web and mobile)
  - Client credentials (services)
  - Device code (input-constrained devices)
- **SCIM:** a standard for creating, updating, and deprovisioning users and groups in applications.

### 4.3 Token Structure

The example below shows an access token payload. Claim names vary by identity provider.

```json
{
  "iss": "https://idp.example.com",
  "sub": "00u1abcdXYZ",
  "aud": "api://backend",
  "exp": 1735689600,
  "iat": 1735686000,
  "amr": ["mfa"],
  "groups": ["dev", "finance"],
  "scp": ["read:orders", "write:orders"]
}
```

Notes:

- `nonce` belongs in the ID token, to bind it to an authentication request. It does not belong in an access token.
- Access tokens are for APIs. ID tokens are for the client application. Do not send an ID token to an API as an access token.
- Validate `iss`, `aud`, `exp`, the signature, and the expected algorithm on every token you accept.

### 4.4 Architecture Patterns

- A central identity provider (IdP) issues tokens. Applications and APIs verify the tokens and enforce authorization locally, or through a gateway.
- Federate enterprise directories (AD or LDAP) to the IdP so users sign in once.
- An API gateway can enforce OAuth scopes and claims centrally, so backend services trust the gateway.

### 4.5 Building an OIDC-Protected Application

1. Register the application with the IdP. Set exact redirect URIs and enable PKCE.
2. The client starts the authorization code flow with PKCE, including `state` and `nonce`.
3. The IdP authenticates the user, enforcing MFA where policy requires it, and returns a code to the redirect URI.
4. The client exchanges the code and the PKCE verifier at the token endpoint and receives an ID token, an access token, and optionally a refresh token.
5. The client validates the ID token. The client calls the API with the access token as a bearer credential. The API validates the signature, audience, expiry, and required claims or scopes.

Authorization request example:

```text
GET /authorize?response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
  &scope=openid%20profile%20email
  &state=RANDOM_STATE
  &nonce=RANDOM_NONCE
  &code_challenge=CHALLENGE
  &code_challenge_method=S256
```

### 4.6 Provisioning with SCIM

- The IdP pushes user objects and group memberships to SaaS applications through SCIM.
- Map attributes and groups to application roles.
- Deprovision accounts when the user leaves or the group membership ends. Measure the time it takes.

### 4.7 Authorization Models

- **RBAC:** roles grant permissions. Simple to audit. Works well in stable environments.
- **ABAC:** attributes of the user, resource, and context gate access. Flexible and fine-grained, but harder to reason about.
- **ReBAC:** relationship graphs define access. Common in collaboration tools.
- **Hybrid:** an RBAC baseline, ABAC conditions for sensitive cases, and a controlled emergency access path.

### 4.8 Cloud Examples

AWS API Gateway invocation policy (grants invoke rights on specific routes):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadOrders",
      "Effect": "Allow",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-east-1:123456789012:abc123/prod/GET/orders/*"
    }
  ]
}
```

Replace the region, account ID, API ID, and stage with your own values.

Kubernetes namespace RBAC:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app
  name: read-pods
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods-binding
  namespace: app
subjects:
- kind: Group
  name: dev
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: read-pods
  apiGroup: rbac.authorization.k8s.io
```

The `dev` group name must match the group claim your cluster receives from the identity provider.

### 4.9 Authentication Hardening

- Require MFA by default. Use phishing-resistant methods (FIDO2 and WebAuthn) for administrators.
- Use conditional access based on device posture, network, location, and risk signals. Evaluate access continuously, not only at sign-in.
- Do not hardcode secrets. Rotate keys. Store them in a KMS or HSM. Keep token lifetimes short.

### 4.10 Governance and Lifecycle

- Automate joiner, mover, and leaver processes. Base entitlements on roles.
- Route exceptions through approval workflows with expiry.
- Run access reviews and recertification campaigns. Detect and remediate SoD conflicts.
- Centralize audit logs and detect anomalies.

### 4.11 Exercises

1. Register an OIDC application using authorization code with PKCE. Obtain tokens, and validate the ID token.
2. Protect an API with JWT validation. Enforce a required scope and a group claim.
3. Build SCIM mappings that provision users to a test SaaS application, then test deprovisioning.
4. Add conditional access that requires MFA and a compliant device for an administrative application.

---

## 5. RBAC Engineering

### 5.1 Concepts and Models

- Subject to role to permission to resource.
- NIST RBAC has three levels:
  - Core: users, roles, permissions, sessions.
  - Hierarchical: role inheritance.
  - Constrained: separation of duties and cardinality limits.
- Administrative RBAC (ARBAC): defines who may create, assign, and change roles.

### 5.2 Role Engineering Process

1. Inventory resources and the permissions they expose: systems, APIs, data.
2. Discover actual access patterns through log analysis and interviews. Role mining tools can help.
3. Define the role taxonomy:
   - Business roles (sales representative, support agent)
   - IT roles (database administrator, system administrator)
   - Application roles (Jira administrator, warehouse reader)
   - Platform roles (Kubernetes namespace administrator)
4. Map roles to entitlements. Apply least privilege.
5. Define SoD constraints. For example, a requester cannot approve their own request.
6. Assign owners to each role. Set approval flows, review cadence, and change management.

### 5.3 Implementation Patterns

- **Directory-centric (AD or LDAP):** users are members of global groups that act as roles. Those groups are nested into domain local groups that hold permissions on resources and ACLs (AGDLP).
- **Application-native RBAC:** map IdP groups or claims to application roles. Manage the mapping in application configuration.
- **Cloud RBAC:** bind IdP groups to cloud roles. Manage with infrastructure as code for repeatability.
- **Policy as code:** store roles and grants in version control. Run CI checks for SoD violations and drift.

AGDLP chain:

```text
Users -> GG_Role_Dev -> DL_AppX_RW -> NTFS or ACL on the resource
```

SQL Server example (maps a Windows group to a database role):

```sql
CREATE ROLE reporting_reader;
GRANT SELECT ON SCHEMA::reporting TO reporting_reader;

CREATE LOGIN [CORP\GG_Reporting] FROM WINDOWS;
CREATE USER  [CORP\GG_Reporting] FOR LOGIN [CORP\GG_Reporting];
EXEC sp_addrolemember 'reporting_reader', 'CORP\GG_Reporting';
```

Kubernetes namespace maintainer role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: team-a
  name: maintainer
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: bind-maintainer
  namespace: team-a
subjects:
- kind: Group
  name: GG_TeamA_Maintainer
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: maintainer
  apiGroup: rbac.authorization.k8s.io
```

### 5.4 SoD and Risk Controls

- **Static SoD:** prevent conflicting role assignments at the time of grant.
- **Dynamic SoD:** allow both roles but prevent their use together in one workflow or session. Require a second approver for high-impact actions.
- **Break-glass access:** provide time-bound elevation with strong authentication, alerting, and detailed audit records.

### 5.5 Operations

- Avoid role explosion. Prefer composable roles, and use attributes for edge cases.
- Run access reviews quarterly. Remove stale memberships. Automate recertification where possible.
- Write tests for permission logic. Test authorization paths, including denial paths.

### 5.6 Exercises

1. Define a role hierarchy for an e-commerce application (viewer, editor, administrator). Implement it in the application and in the IdP.
2. Enforce SoD between payment creator and payment approver, first through policy, then through a review process.
3. Move direct user permissions to group-based roles. Verify the change with access logs.

---

## 6. Integration Patterns

How identity systems map to one another:

**Identity**

- LDAP and AD: entries (user, group, computer) with DNs and attributes.
- IAM: users, service principals, workload identities.
- RBAC: subjects are users, groups, or services.

**Groups and roles**

- LDAP and AD: security groups, dynamic groups where supported, AGDLP nesting.
- IAM: roles, policies, and entitlements. Groups map to application roles or token claims.
- RBAC: roles bind to permissions, with optional inheritance.

**Policy and permission**

- LDAP and AD: ACLs on directory entries, NTFS and share permissions, GPO user rights.
- IAM: policy documents (allow or deny, actions, resources, conditions).
- RBAC: permission sets per resource type.

**Authentication and authorization**

- LDAP and AD: LDAP bind, Kerberos, NTLM. Use LDAPS for application binds.
- IAM: SAML, OIDC, and OAuth 2.0 tokens; conditional access; MFA.
- RBAC: decisions based on role and attribute membership.

**Provisioning**

- LDAP and AD: `ldapadd` and `ldapmodify`, AD PowerShell cmdlets, synchronization connectors.
- IAM: SCIM, APIs, workflows.
- RBAC: role assignment through groups or attributes, with approval records.

---

## 7. Reference Architectures

### 7.1 Windows-Centric Enterprise

- Single AD forest and domain. Sites and subnets match physical topology.
- OU design for workstations, servers, users, and service accounts.
- AGDLP for permissions. GPO baselines. Windows LAPS. gMSA for services. Kerberos constrained delegation where required.
- Cloud identity provider federated to AD. Conditional access and MFA. Group-based application assignment. SCIM to SaaS applications.

### 7.2 Linux-First with OpenLDAP

- DIT with People, Groups, Systems, and Services. LDAPS. Indexes. `memberOf` overlay.
- SSSD for NSS and PAM. Sudo rules delivered through LDAP. SSH public keys managed in the directory with restricted read access.
- Replication with monitoring. Logs forwarded to a SIEM.

### 7.3 Kubernetes Platform

- OIDC between the cluster API server and the identity provider. Groups delivered as token claims.
- A namespace per team. Kubernetes RBAC. Admission policies. Secrets managed through a KMS.
- CI/CD authenticates to the IdP with workload identity, using short-lived credentials.

### 7.4 Data Warehouse and Analytics

- Directory groups mapped to database roles. Row-level security driven by attributes.
- SoD between ETL writers and finance approvers. Periodic access reviews.
- Centralized query auditing and data lineage tracking.

---

## 8. Security, Compliance, and Governance

### 8.1 Security Controls

- MFA for all users. Phishing-resistant factors for administrators.
- TLS everywhere, including LDAPS. Certificate lifecycle management. Pin trusted CAs where the risk justifies it.
- Privileged access management with just-in-time elevation. Privileged access workstations for administrators.
- Rotate secrets and keys. Use hardware-backed storage where available.

### 8.2 Compliance and Governance

- Policy as code. Change reviews. Traceability from each change to a ticket.
- Access recertification. SoD attestation. Deprovisioning service levels.
- Data protection: minimize personal data in directories. Encrypt data at rest and in transit.

### 8.3 Monitoring and Detection

- Centralize logs for binds, token issuance, authentication failures, and policy denials.
- Alert on risky sign-ins, impossible travel, unusual consent grants, and possible token replay.

---

## 9. Troubleshooting Playbooks

### 9.1 LDAP

- **Empty search results:** check the base DN, the filter, indexes, and ACLs.
- **TLS errors:** check CA trust, hostname mismatch, and protocol or cipher configuration.
- **Bind failures:** check DN resolution, account lockout, and password policy.

### 9.2 Active Directory

- **Logon problems:** check time synchronization (NTP), DNS SRV records, and site placement.
- **Kerberos failures:** check for duplicate SPNs, clock skew, and the scope of constrained delegation.
- **GPO problems:** check link order, WMI filter scope, security filtering, and Resultant Set of Policy (RSOP).

### 9.3 IAM

- **Token validation errors:** check clock skew, audience and issuer mismatch, and signing key rotation.
- **SAML and OIDC misconfiguration:** check redirect URIs, NameID or subject mapping, and group claim mapping.
- **SCIM issues:** check attribute mappings, pagination, and conflict resolution.

### 9.4 RBAC

- **Over-permissioned or under-permissioned roles:** analyze access logs, tighten permissions, add ABAC guards where needed.
- **SoD conflicts:** enforce at request time, monitor for drift, remediate promptly.

---

## 10. Operations: Checklists and Runbooks

### 10.1 LDAP Hardening Checklist

- [ ] LDAPS or StartTLS enforced; anonymous bind disabled
- [ ] Indexes on `uid`, `mail`, `cn`, `member`, `memberOf`
- [ ] ACLs restrict sensitive attributes; logs shipped to a central system
- [ ] Replication monitored; backups taken and restores tested

### 10.2 Active Directory Hardening Checklist

- [ ] Tiered administration; separate administrative accounts; privileged access workstations
- [ ] Windows LAPS deployed; gMSA used for services
- [ ] Constrained delegation only where required; SPNs unique
- [ ] GPO baselines; Advanced Audit Policy; SIEM integration

### 10.3 IAM Deployment Checklist

- [ ] MFA and conditional access; phishing-resistant methods for administrators
- [ ] Short-lived tokens; signing key rotation; secrets in a KMS or HSM
- [ ] SCIM provisioning; joiner, mover, and leaver automation; deprovisioning service levels
- [ ] Access reviews; SoD checks; policy as code

### 10.4 RBAC Implementation Checklist

- [ ] Role taxonomy documented; owners assigned
- [ ] SoD constraints defined and enforced
- [ ] Roles and grants managed as infrastructure code; CI validation in place
- [ ] Quarterly recertification; drift detection

### 10.5 Critical Runbooks

**Compromised account**

1. Disable the account.
2. Revoke sessions and tokens.
3. Reset credentials.
4. Rotate any secrets the account could read.
5. Review logs for the period of compromise.
6. Re-enable only after review and sign-off.

**Token signing key rotation**

1. Publish the new key in the JWKS endpoint alongside the old key.
2. Switch signing to the new key.
3. Verify that relying parties accept tokens signed with the new key.
4. Retire the old key after the longest token lifetime has passed.

**Directory restore**

1. Determine whether the restore is authoritative or non-authoritative.
2. Follow the tested restore procedure.
3. Validate replication and application authentication after the restore.

---

## 11. Glossary

- **ABAC:** Attribute-Based Access Control
- **ACL:** Access Control List
- **AD DS:** Active Directory Domain Services
- **AGDLP:** Accounts, Global groups, Domain Local groups, Permissions (group nesting model)
- **ARBAC:** Administrative RBAC
- **DIT:** Directory Information Tree
- **DN, RDN:** Distinguished Name, Relative Distinguished Name
- **gMSA:** Group Managed Service Account
- **GPO:** Group Policy Object
- **IdP:** Identity Provider
- **JML:** Joiner, Mover, Leaver
- **JWT:** JSON Web Token
- **KDC:** Key Distribution Center (Kerberos)
- **LAPS:** Local Administrator Password Solution
- **LDAPS:** LDAP over TLS
- **NTLM:** NT LAN Manager (legacy Windows authentication)
- **OIDC:** OpenID Connect
- **PAM, PIM:** Privileged Access Management, Privileged Identity Management
- **PKCE:** Proof Key for Code Exchange
- **RBAC:** Role-Based Access Control
- **ReBAC:** Relationship-Based Access Control
- **SCIM:** System for Cross-domain Identity Management
- **SPN:** Service Principal Name
- **UPN:** User Principal Name

---

## 12. Further Reading

**Standards and specifications**

- LDAP: RFC 4510 to RFC 4519
- Kerberos: RFC 4120
- SAML 2.0 Core (OASIS)
- OAuth 2.0: RFC 6749. PKCE: RFC 7636
- OpenID Connect Core 1.0
- SCIM 2.0: RFC 7643 and RFC 7644
- NIST SP 800-63B (digital identity guidelines)
- NIST RBAC model (INCITS 359)

**Vendor documentation**

- Microsoft AD DS and Group Policy documentation
- OpenLDAP Administrator's Guide
- Kubernetes RBAC documentation
- AWS, Microsoft Entra ID, and Google Cloud IAM documentation

**Exercises to master the material**

- Build a small LDAP directory, secure it with TLS, and integrate it with SSSD.
- Set up a test AD domain. Implement AGDLP, Windows LAPS, and Kerberos constrained delegation.
- Configure an OIDC application with authorization code and PKCE. Protect an API. Add conditional access.
- Design a role taxonomy. Implement it in directory groups and application RBAC. Run an access review.
