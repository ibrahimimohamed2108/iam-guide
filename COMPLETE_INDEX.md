```markdown
# IAM Learning Index

Index of the IAM and security study material, with an honest coverage status for each topic.

## Package Contents

| File | Purpose |
|------|---------|
| `identity-zero-to-hero.md` | Main guide: fundamentals through intermediate implementation |
| `ADVANCED_TOPICS.md` | Enterprise depth: cryptography, threat modeling, Kerberos, incident response, cloud IAM, SoD, federation, forensics, compliance, misconfigurations, operations |
| `QUICK_REFERENCE.md` | Cheat sheet, comparison tables, troubleshooting, pre-deployment checklist |
| `STRUCTURE_GUIDE.md` | Navigation and learning paths |
| `ENHANCEMENT_SUMMARY.md` | Record of changes made to the package |

Read the main guide first, then use the advanced guide for depth.

---

## Topic Coverage

Status key:

- **Advanced guide:** covered in `ADVANCED_TOPICS.md` (section noted)
- **Main guide:** listed for the main guide; verify coverage there before relying on it
- **Not covered:** outside this package; study from other sources

### Identity Fundamentals (Main guide)

- Digital identity types (human and non-human)
- Identity attributes and lifecycle
- Identity stores and repositories
- Joiner, mover, leaver (JML) processes: Main guide; compliance context in advanced guide section 11

### Authentication

- Authentication factors (knowledge, possession, inherence): Main guide; advanced guide section 2.3
- Multi-factor authentication: Main guide
- Passwordless authentication: advanced guide section 2.3
- Certificate-based authentication: advanced guide section 2.1
- Hardware tokens (FIDO2 and WebAuthn): advanced guide section 2.2
- Biometric authentication: advanced guide section 2.3 (as a local unlock for device-bound keys)
- Risk-based authentication: advanced guide section 14.1 (conditional access)

### Authorization

- Access control lists: Main guide
- Role-based access control (RBAC): Main guide; advanced guide sections 7 and 8
- Attribute-based access control (ABAC): Main guide
- Relationship-based access control (ReBAC): Not covered
- Dynamic and context-aware authorization: advanced guide sections 7.2 and 8.3

### Core Security Principles

- Least privilege: advanced guide sections 6 and 15
- Separation of duties (SoD): advanced guide section 7
- Zero trust: advanced guide section 14
- Defense in depth: advanced guide section 15
- Auditability and non-repudiation: advanced guide sections 3 (STRIDE) and 10

### Directory Services

- LDAP directory design, operations, filters, LDAPS and StartTLS: Main guide; advanced guide sections 1.3, 12.1
- LDAP replication, indexing, and performance tuning: Main guide
- Active Directory architecture, GPOs, and group nesting: Main guide
- Kerberos internals and attacks: advanced guide section 4
- Active Directory misconfigurations: advanced guide section 12.2
- LAPS and gMSA: advanced guide sections 4.2 and 12.2

### Modern IAM Protocols

- OAuth 2.0 flows, PKCE, and refresh tokens: Main guide; advanced guide sections 9.4 and 12.3
- OpenID Connect (ID tokens, UserInfo, discovery, JWKS): Main guide; advanced guide section 9.4
- SAML 2.0 assertions, validation, and vulnerabilities: advanced guide section 9
- Token management and revocation: Main guide; advanced guide section 5.1
- Cloud IAM (AWS, Microsoft Entra ID): advanced guide section 6

### Cryptography

- Password hashing (Argon2id, scrypt, PBKDF2, bcrypt): advanced guide section 1.1
- Encryption of secrets at rest and key management: advanced guide section 1.2
- Certificate chains and validation: advanced guide section 1.3
- Symmetric and asymmetric cryptography: advanced guide section 1.4

### Threat Modeling and Attacks

- STRIDE applied to IAM: advanced guide section 3.1
- Credential spraying and directory enumeration: advanced guide section 3.2
- Kerberoasting, AS-REP roasting, Pass-the-Ticket, Golden Ticket: advanced guide section 4.2
- Silver Ticket: Not covered
- Privilege escalation chains: advanced guide section 8

### Cloud and Platform IAM

- AWS IAM (principals, trust policies, permissions boundaries): advanced guide section 6.1
- Microsoft Entra ID (service principals, managed identities, PIM): advanced guide section 6.2
- Kubernetes RBAC (roles, bindings, service accounts, OIDC): Not covered

### Incident Response and Forensics

- Compromise indicators for directory and token systems: advanced guide section 5.1
- Evidence preservation and forensic procedure: advanced guide section 5.2
- Log analysis: advanced guide section 10
- Failed-bind playbook: advanced guide section 13.2

### Compliance

- SOC 2 Trust Services Criteria mapped to IAM: advanced guide section 11.1
- Audit evidence checklist: advanced guide section 11.2
- ISO 27001, NIST SP 800-63B, GDPR, PCI DSS: Not covered in depth; study from the source standards

### Operations

- Monitoring metrics and alert thresholds: advanced guide section 13.1
- Common misconfigurations (LDAP, AD, OAuth2/OIDC): advanced guide section 12
- Production hardening and disaster recovery: Main guide (verify)

### Emerging Topics

- Compromised MFA and help-desk social engineering: advanced guide section 14.1
- Directory supply chain risks: advanced guide section 14.2
- Decentralized identity, blockchain, post-quantum cryptography, behavioral biometrics, AI-assisted attacks: Not covered; these are emerging areas to follow in current sources

---

## Learning Timeline (6 Months)

**Month 1: Foundations**
- Weeks 1-2: Main guide, foundations section
- Week 3: Choose LDAP or Active Directory and complete that section
- Week 4: Advanced guide sections 1 through 3

**Month 2: Modern IAM**
- Weeks 1-2: OAuth 2.0, OIDC, and SAML (main guide, advanced guide section 9)
- Week 3: RBAC and SoD (advanced guide sections 7 and 8)
- Week 4: Advanced guide sections 4 through 6

**Month 3: Cloud and Security**
- Week 1: Cloud IAM (advanced guide section 6)
- Week 2: Threat modeling (advanced guide section 3)
- Week 3: Incident response and forensics (advanced guide sections 5 and 10)
- Week 4: Compliance (advanced guide section 11)

**Month 4: Advanced Topics**
- Weeks 1-2: Kerberos (advanced guide section 4)
- Week 3: Privilege escalation and dynamic SoD (advanced guide sections 7.2 and 8)
- Week 4: Federation and trust (advanced guide section 9)

**Month 5: Operations**
- Week 1: Monitoring and alerting (advanced guide section 13)
- Week 2: Misconfigurations (advanced guide section 12)
- Week 3: Production checklists and hardening (main guide)
- Week 4: Troubleshooting scenarios

**Month 6: Practice**
- Weeks 1-2: Build a lab with OpenLDAP, Active Directory, and an OIDC provider
- Week 3: Run a security assessment against the lab
- Week 4: Document findings and recommendations

---

## Self-Assessment

### Concepts to explain without notes

- [ ] Identity, authentication, and authorization, and how they differ
- [ ] When to use each authentication factor and method
- [ ] LDAP versus Active Directory
- [ ] OAuth 2.0, OIDC, and SAML, and the problem each solves
- [ ] RBAC and SoD, with a static and a dynamic example
- [ ] Common attacks on identity systems and their mitigations

### Hands-on skills

- [ ] Configure an LDAP server with TLS
- [ ] Query and modify directory entries
- [ ] Implement an OAuth 2.0 authorization code flow with PKCE
- [ ] Design a role hierarchy with SoD constraints
- [ ] Read authentication logs and identify a password spray
- [ ] Find security misconfigurations in a directory or OAuth client

### Professional readiness

- [ ] Explain compliance requirements in plain language
- [ ] Document technical findings clearly
- [ ] Know when to escalate an issue
- [ ] Follow change management procedures
- [ ] Practice security testing only on systems you are authorized to test

---

## Notes on This Index

- Items marked "verify" or "Not covered" should be checked against the source files before you rely on them.
- Commands and code in the guides are illustrative. Test them in a lab first.
- This package does not replace official documentation, vendor guides, or the standards it references (NIST SP 800-63B, RFC 9106, OWASP guidance).

---

*Last reviewed: 2026-11-24*
```
