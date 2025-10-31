# Identity, Directory, and Access — AD, LDAP, IAM, RBAC (Zero to Hero)

A comprehensive, hands-on guide from fundamentals to production-ready implementations. Use linearly or jump to sections. All examples are templates—replace domains, DNs, and names to fit your environment.

Table of Contents
- 0. How to use this guide
- 1. Foundations: Identity, AuthN, AuthZ, Directory, Policy
- 2. LDAP — Zero to Hero
- 3. Active Directory (AD) — Zero to Hero
- 4. IAM — Zero to Hero
- 5. RBAC — Zero to Hero
- 6. Crosswalk: Mapping AD, LDAP, IAM, RBAC
- 7. Blueprints (Reference Architectures)
- 8. Security, Compliance, and Governance
- 9. Troubleshooting Playbooks
- 10. Checklists and Runbooks
- 11. Glossary
- 12. Further Reading

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

## 1) Foundations: Identity, AuthN, AuthZ, Directory, Policy

Key terms
- Identity: Digital representation of an actor (user/service/device).
- Authentication (AuthN): Prove identity (passwords, certs, tokens, MFA).
- Authorization (AuthZ): Decide what an authenticated identity can do.
- Directory: Authoritative, hierarchical identity store (AD/OpenLDAP).
- Policy: Machine-evaluable rules controlling authentication and authorization.
- Governance: Lifecycle (joiner/mover/leaver), approval, review, and audit.

Principles
- Least privilege; Separation of Duties (SoD); Zero Trust; Auditability; Automation.
- Identities are central; tokens and secrets must be short-lived and rotated.

Mental model
- Directory (AD/LDAP) stores identities and groups.
- IAM federates identities to apps using standards (SAML/OIDC/OAuth2), issues tokens, orchestrates MFA and conditional access.
- RBAC structures authorization as Roles → Permissions → Resources, often powered by directory groups or IAM claims.

--------------------------------------------------------------------------------

## 2) LDAP — Zero to Hero

### 2.1 Concepts
- LDAP v3 (RFC 4510+): operations bind, search, add, modify, delete, compare.
- Directory Information Tree (DIT): hierarchical entries under Base DN.
- DN/RDN: Distinguished Name uniquely identifies an entry; RDN is the leaf.
- ObjectClass/Schema: Defines allowed attributes (inetOrgPerson, posixAccount, groupOfNames).
- Filters: Boolean search expressions, e.g., (&(objectClass=inetOrgPerson)(mail=*@example.com)).

### 2.2 Design a simple DIT
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

### 2.3 Quick-start operations (OpenLDAP-style)

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

### 2.4 Security
- Use LDAPS (636) or StartTLS; enforce TLS 1.2+; pin CA; disable anonymous binds.
- Store passwords with strong hashes; prevent broad read of `userPassword` and sensitive attributes via ACLs.
- Implement rate limits and lockout policies (directory-dependent); audit failures.

### 2.5 Indexing and performance
- Index frequently searched attributes: `uid`, `cn`, `mail`, `member`, `memberOf`.
- Scope searches to the correct base; request only needed attributes.
- Set time/size limits to avoid unbounded scans.

### 2.6 Replication and HA
- Provider/consumer or multi-master; design for at least two replicas per site.
- Monitor replication lag; understand last-writer-wins at attribute level.

### 2.7 Integration: Linux logins with SSSD (conceptual)
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

### 2.8 App integration pattern (bind then verify)
1) App binds with a read-only service account.
2) Search for user DN by `uid`/`mail`.
3) Bind as the user DN with provided password to verify.
4) Fetch attributes and groups (`memberOf`) to build an auth context.

### 2.9 Troubleshooting
```bash
# Test LDAPS and certificate chain
openssl s_client -connect ldap.example.com:636 -showcerts

# Who am I?
ldapwhoami -x -H ldaps://ldap.example.com -D "cn=admin,dc=example,dc=com" -W

# Groups referencing a member
ldapsearch -x -b "ou=Groups,dc=example,dc=com" \
  "(member=uid=jdoe,ou=People,dc=example,dc=com)" cn
```

### 2.10 Exercises (Zero → Hero)
- Create People/Groups OUs, add two users and a group, enable memberOf overlay, validate membership from the user entry.
- Enforce StartTLS/LDAPS only; verify with `openssl s_client`.
- Add indexes for `uid`, `mail`, `member` and measure search latency before/after.
- Integrate a Linux host with SSSD; log in with an LDAP user; restrict sudo via LDAP.
- Implement an app login: service bind → search → user bind → group claims.

--------------------------------------------------------------------------------

## 3) Active Directory (AD) — Zero to Hero

### 3.1 Concepts
- Domain: Security boundary (e.g., corp.example.com). Contains users, groups, computers.
- Forest: One or more domains with shared schema and global catalog.
- OU: Delegation and policy scope (GPOs, admin rights) — not for org charts.
- DC: Domain Controller hosting AD DS, KDC (Kerberos), Global Catalog; multi-master replication.
- Sites/Subnets: Physical topology for logon/DC selection and replication schedules.
- DNS: AD-integrated zones; SRV records enable service discovery.
- GPO: Group Policy Objects; central configuration for users/computers.
- Auth: Kerberos (preferred), NTLM (legacy; restrict/audit).

### 3.2 Design principles
- Prefer a single domain per forest; keep structure simple.
- OU design for delegation and GPO scoping (e.g., Workstations, Servers, Users, Service Accounts).
- Group strategy: AGDLP — Accounts → Global Groups → Domain Local → Permissions.
- Tiered admin model: Tier 0 (DCs), Tier 1 (Servers), Tier 2 (Workstations); separate admin identities per tier.

### 3.3 Common tasks (PowerShell snippets)
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

### 3.4 Security hardening
- LAPS/Windows LAPS for local admin password rotation.
- gMSA for services; avoid static passwords and interactive logon.
- Restrict Domain Admins; use Just-In-Time elevation (PIM/PAM) and privileged access workstations.
- Advanced Audit Policy; forward Windows Event Logs to SIEM; monitor DC health.

### 3.5 Operations and health
```powershell
# DC and replication health
dcdiag /v
repadmin /replsummary
repadmin /showrepl

# SYSVOL replication (DFSR vs FRS)
dfsrmig /getglobalstate
```

### 3.6 Hybrid identity (AD ↔ cloud IdP)
- Sync identities with a cloud IdP; filter by OU; handle UPN suffixes.
- Conditional access (MFA, device compliance) for cloud apps; use group-based assignments.
- Understand differences: AD roles (on-prem), cloud directory roles, and resource IAM (e.g., cloud provider RBAC).

### 3.7 Exercises (Zero → Hero)
- Create OU structure and group model (AGDLP); apply NTFS ACLs via Domain Local groups.
- Implement LAPS; verify randomized local admin passwords accessible to the right admins only.
- Configure gMSA for an app service; register SPN; test Kerberos constrained delegation.
- Build a test GPO for security baseline; pilot in a staging OU; measure impact.

--------------------------------------------------------------------------------

## 4) IAM — Zero to Hero

### 4.1 Scope and building blocks
- Subjects: users, service principals, workloads.
- Credentials: passwords, keys, certificates, tokens.
- Tokens: SAML Assertions, OIDC ID Tokens, OAuth2 Access Tokens (often JWTs).
- Policies: Allow/Deny on actions and resources with conditions.
- Governance: JML lifecycle, approvals, reviews, SoD, and audit trails.

### 4.2 Protocols and modern SSO
- SAML 2.0: Browser SSO, XML assertions; common for enterprise SaaS.
- OIDC: Identity layer on OAuth2; provides ID Token; modern web/mobile.
- OAuth2: Delegated authorization. Flows: Authorization Code (PKCE), Client Credentials, Device Code.
- SCIM: Provisioning standard to create/update/deprovision users and groups in apps.

### 4.3 Token anatomy (JWT) — example claims
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

### 4.4 Architecture patterns
- Central IdP (Identity Provider) issues tokens; apps verify tokens and enforce authorization locally or via a gateway.
- Federation with enterprise directories (AD/LDAP) for passwordless SSO to apps.
- Gateway/API layer enforces OAuth scopes/claims centrally; services trust gateway.

### 4.5 Implement OIDC for a web app (high-level)
1) Register an app in the IdP with redirect URIs and PKCE enabled.
2) Client starts Authorization Code + PKCE flow.
3) IdP authenticates user (MFA) and returns code to redirect URI.
4) Client exchanges code + verifier at token endpoint; receives ID/Access/Refresh tokens.
5) Client calls API with Bearer access_token; API validates signature, audience, expiry, and claims.

Authorize URL example
```text
GET /authorize?response_type=code&client_id=CLIENT&redirect_uri=URL&scope=openid%20profile%20email&code_challenge=...&code_challenge_method=S256&state=...
```

### 4.6 Provisioning with SCIM (conceptual)
- IdP pushes user objects and group memberships to SaaS via SCIM.
- Map attributes and groups to application roles; deprovision on termination.

### 4.7 Policy models
- RBAC: Roles grant permissions; simple audits; stable environments.
- ABAC: Attributes (user, resource, context) gate access; dynamic and fine-grained.
- ReBAC: Relationship graphs define who can access what (common in collaboration apps).
- Hybrid: RBAC baseline + ABAC conditions + emergency access.

### 4.8 Cloud IAM examples

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

### 4.9 Authentication hardening
- MFA by default; prefer phishing-resistant methods (FIDO2/WebAuthn).
- Conditional Access: device posture, network, geo, risk signals; continuous access evaluation.
- Secrets: no hardcoded secrets; rotate keys; use KMS/HSM; minimize token lifetimes.

### 4.10 Governance
- Joiner/Mover/Leaver automation; role-based entitlements; exception workflow with approvals.
- Access reviews and recertification; SoD checks and detective controls.
- Logs and analytics: centralized audit and anomaly detection.

### 4.11 Exercises (Zero → Hero)
- Register an OIDC app with Authorization Code + PKCE; obtain tokens; introspect ID token.
- Protect an API with JWT validation; enforce scope and group claims.
- Build SCIM mappings to provision users to a SaaS app and test deprovisioning.
- Add conditional access requiring MFA and compliant device for an admin app.

--------------------------------------------------------------------------------

## 5) RBAC — Zero to Hero

### 5.1 Concepts
- Subject → Role → Permission → Resource.
- NIST RBAC: Core (users, roles, permissions, sessions), Hierarchical (role inheritance), Constrained (SoD and cardinality).
- Administrative RBAC (ARBAC): Who can create/assign roles and manage entitlements.

### 5.2 Role engineering process
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

### 5.3 Implementation patterns
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

### 5.4 SoD and risk controls
- Static SoD: Prevent conflicting assignments concurrently.
- Dynamic SoD: Allow roles but restrict usage in the same session or require dual control.
- Emergency access (break-glass) with time-bound elevation and detailed auditing.

### 5.5 Operations
- Avoid role explosion: prefer composable roles and attributes for edge cases.
- Quarterly access reviews; remove stale memberships; automate recertification.
- Test authorization paths; unit-test permissions and policy evaluation.

### 5.6 Exercises (Zero → Hero)
- Define a role hierarchy for an e-commerce app (viewer → editor → admin) and implement in app and IdP.
- Implement SoD between Payment Creator and Payment Approver; enforce via policy and review.
- Migrate direct user permissions to group-based roles; validate using access logs.

--------------------------------------------------------------------------------

## 6) Crosswalk: Mapping AD, LDAP, IAM, RBAC

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

--------------------------------------------------------------------------------

## 7) Blueprints (Reference Architectures)

1) Windows-centric enterprise (on-prem + cloud)
- AD forest (single domain), Sites/Subnets; OU design for Workstations/Servers/Users/Service Accounts.
- AGDLP for permissions; GPO baselines; LAPS; gMSA; Kerberos constrained delegation.
- Cloud IdP federation; Conditional Access; MFA; group-based app assignments; SCIM to SaaS.

2) Linux-first with OpenLDAP
- DIT: People/Groups/Systems/Services; LDAPS; indexes; memberOf overlay.
- SSSD for NSS/PAM; sudo via LDAP; SSH keys managed in directory (restricted read).
- Replication and monitoring; logs to SIEM.

3) Kubernetes platform with centralized IdP
- OIDC between cluster API server and IdP; groups as claims.
- Namespaces per team; K8s RBAC; admission policies; Secret management via KMS.
- CI/CD integrates with IdP (workload identity) for short-lived credentials.

4) Data warehouse and BI
- Directory groups bound to DB roles; row-level security with attributes.
- SoD between ETL writers and Finance approvers; periodic reviews.
- Centralized query auditing and lineage tracking.

--------------------------------------------------------------------------------

## 8) Security, Compliance, and Governance

Security controls
- MFA everywhere; phishing-resistant factors for admins.
- TLS/LDAPS; cert lifecycle management; pin trusted CAs.
- PAM/PIM for privileged access; just-in-time elevation; PAWs for admins.
- Rotate secrets and keys; hardware-backed storage where possible.

Compliance anchors
- Policy-as-code for IAM; change reviews; traceability to tickets.
- Access recertification; SoD attestation; strong deprovisioning SLAs.
- Data protection: PII minimization in directories; encrypt at rest and in transit.

Monitoring and detection
- Centralized logs (binds, token issuances, auth failures, policy denials).
- Alert on risky sign-ins, impossible travel, unusual consent, token replay.

--------------------------------------------------------------------------------

## 9) Troubleshooting Playbooks

LDAP
- Empty search results: check Base DN, filter, and indexes; verify ACLs.
- TLS errors: CA trust, hostname mismatch, protocol/cipher suites.
- Bind failures: DN resolution, account lockout, password policy.

AD
- Logon issues: time sync (NTP), DNS SRV records, site placement.
- Kerberos failures: SPN duplication, clock skew, constrained delegation scope.
- GPO problems: link order, WMI filter scope, security filtering, RSOP.

IAM
- Token validation errors: clock skew, audience/issuer mismatch, key rotation.
- SAML/OIDC misconfig: redirect URIs, NameID/subject mapping, group claim mapping.
- SCIM issues: attribute mappings, pagination, conflict resolution.

RBAC
- Over/under-permissioned roles: analyze logs, tighten permissions, add ABAC guards.
- SoD conflicts: enforce at request time, monitor drift, and remediate.

--------------------------------------------------------------------------------

## 10) Checklists and Runbooks

LDAP hardening checklist
- [ ] LDAPS/StartTLS enforced; no anonymous bind
- [ ] Indexes for uid, mail, cn, member, memberOf
- [ ] ACLs restrict sensitive attributes; logs shipped centrally
- [ ] Replication with monitoring; regular backups and tested restores

AD hardening checklist
- [ ] Tiered admin model; separate admin accounts; PAWs
- [ ] LAPS/Windows LAPS deployed; gMSA for services
- [ ] Kerberos constrained delegation only; SPNs unique
- [ ] GPO baselines; Advanced Audit Policy; SIEM integration

IAM checklist
- [ ] MFA and Conditional Access; phishing-resistant for admins
- [ ] Short-lived tokens; key rotation; secrets in KMS/HSM
- [ ] SCIM provisioning; JML automation; deprovision SLAs
- [ ] Access reviews; SoD checks; policy-as-code

RBAC checklist
- [ ] Role taxonomy documented; owners assigned
- [ ] SoD constraints defined and enforced
- [ ] Infra-as-code for roles and grants; CI validation
- [ ] Quarterly recertification; drift detection

Runbooks (abbreviated)
- Compromised account: disable, revoke sessions, reset creds, rotate secrets, review logs, re-enable post-review.
- Token signing key rotation: publish new JWKS, support dual keys, cutover, revoke old, verify clients.
- Directory restore: determine authoritative vs non-authoritative; follow tested procedures; validate replication.

--------------------------------------------------------------------------------

## 11) Glossary

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

--------------------------------------------------------------------------------

## 12) Further Reading

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
