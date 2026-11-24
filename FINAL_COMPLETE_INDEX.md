# IAM Learning Package: Index

This index maps the IAM and security study material to its files and sections. Each topic shows where it is covered and how confident the coverage is. Items marked **Verify** have not been checked against their source file.

## Package Contents

| File | Purpose | Status |
|------|---------|--------|
| `identity-zero-to-hero.md` | Main guide: foundations through intermediate implementation | Verify section coverage |
| `ADVANCED_TOPICS.md` | Enterprise depth: cryptography, threat modeling, Kerberos, incident response, cloud IAM, SoD, federation, forensics, compliance, misconfigurations, operations | Reviewed |
| `LABS_GUIDE.md` | Hands-on lab exercises | Verify contents |
| `QUICK_REFERENCE.md` | Cheat sheet and troubleshooting | Verify contents |
| `STRUCTURE_GUIDE.md` | Navigation and learning paths | Verify contents |
| `ENHANCEMENT_SUMMARY.md` | Change record | Historical; may be removed |
| `COMPLETE_INDEX.md` and `FINAL_COMPLETE_INDEX.md` | Earlier index versions | Superseded by this file; remove after verification |

Read the main guide first, then the advanced guide for depth, then the labs to practice.

---

## Coverage by Topic

Each entry names the file and section that cover the topic. "Not covered" means the package does not address it.

### Identity Fundamentals
- Digital identity types, attributes, and lifecycle: main guide (Verify)
- Identity stores and repositories: main guide (Verify)
- Joiner, mover, leaver processes: main guide (Verify); compliance context in `ADVANCED_TOPICS.md` section 11

### Authentication
- Factors (knowledge, possession, inherence): main guide (Verify); `ADVANCED_TOPICS.md` section 2.3
- Multi-factor authentication: main guide (Verify)
- Passwordless authentication: `ADVANCED_TOPICS.md` section 2.3
- Certificate-based authentication: `ADVANCED_TOPICS.md` section 2.1
- FIDO2 and WebAuthn: `ADVANCED_TOPICS.md` section 2.2
- Risk-based authentication and conditional access: `ADVANCED_TOPICS.md` section 14.1

### Authorization
- Access control lists and RBAC: main guide (Verify); `ADVANCED_TOPICS.md` sections 7 and 8
- ABAC: main guide (Verify)
- Dynamic and context-aware authorization: `ADVANCED_TOPICS.md` sections 7.2 and 8.3
- ReBAC: not covered

### Core Principles
- Least privilege: `ADVANCED_TOPICS.md` sections 6 and 15
- Separation of duties: `ADVANCED_TOPICS.md` section 7
- Zero trust: `ADVANCED_TOPICS.md` section 14
- Defense in depth: `ADVANCED_TOPICS.md` section 15
- Auditability and non-repudiation: `ADVANCED_TOPICS.md` sections 3 and 10

### Directory Services
- LDAP design, operations, filters, LDAPS, and StartTLS: main guide (Verify); `ADVANCED_TOPICS.md` sections 1.3 and 12.1
- LDAP replication, indexing, and tuning: main guide (Verify)
- Active Directory architecture and group nesting: main guide (Verify)
- Kerberos protocol and attacks: `ADVANCED_TOPICS.md` section 4
- AD misconfigurations: `ADVANCED_TOPICS.md` section 12.2

### Modern IAM Protocols
- OAuth 2.0 flows and PKCE: main guide (Verify); `ADVANCED_TOPICS.md` sections 9.4 and 12.3
- OpenID Connect: main guide (Verify); `ADVANCED_TOPICS.md` section 9.4
- SAML 2.0 structure and vulnerabilities: `ADVANCED_TOPICS.md` section 9
- Token revocation and session monitoring: `ADVANCED_TOPICS.md` section 5.1
- Cloud IAM (AWS, Microsoft Entra ID): `ADVANCED_TOPICS.md` section 6

### Cryptography
- Password hashing (Argon2id, scrypt, PBKDF2, bcrypt): `ADVANCED_TOPICS.md` section 1.1
- Secrets at rest and key management: `ADVANCED_TOPICS.md` section 1.2
- Certificate chains and validation: `ADVANCED_TOPICS.md` section 1.3
- Symmetric and asymmetric cryptography: `ADVANCED_TOPICS.md` section 1.4

### Threat Modeling and Attacks
- STRIDE applied to IAM: `ADVANCED_TOPICS.md` section 3.1
- Credential spraying and directory enumeration: `ADVANCED_TOPICS.md` section 3.2
- Kerberoasting, AS-REP roasting, Pass-the-Ticket, Golden Ticket: `ADVANCED_TOPICS.md` section 4.2
- Privilege escalation chains: `ADVANCED_TOPICS.md` section 8
- Silver Ticket: not covered
- Pass-the-Hash: `ADVANCED_TOPICS.md` section 4.2 (NTLM, not Kerberos)

### Cloud and Platform IAM
- AWS IAM: `ADVANCED_TOPICS.md` section 6.1
- Microsoft Entra ID: `ADVANCED_TOPICS.md` section 6.2
- Kubernetes RBAC: not covered

### Incident Response and Forensics
- Compromise indicators: `ADVANCED_TOPICS.md` section 5.1
- Evidence preservation: `ADVANCED_TOPICS.md` section 5.2
- Log analysis: `ADVANCED_TOPICS.md` section 10
- Failed-bind playbook: `ADVANCED_TOPICS.md` section 13.2

### Compliance
- SOC 2 criteria mapped to IAM: `ADVANCED_TOPICS.md` section 11.1
- Audit evidence checklist: `ADVANCED_TOPICS.md` section 11.2
- ISO 27001, NIST SP 800-63B, GDPR, PCI DSS: not covered in depth; use the source standards

### Operations
- Monitoring metrics and alert thresholds: `ADVANCED_TOPICS.md` section 13.1
- Misconfigurations (LDAP, AD, OAuth 2.0/OIDC): `ADVANCED_TOPICS.md` section 12
- Hardening and disaster recovery: main guide (Verify)

### Emerging Topics
- Compromised MFA and help-desk social engineering: `ADVANCED_TOPICS.md` section 14.1
- Directory supply chain risks: `ADVANCED_TOPICS.md` section 14.2
- Decentralized identity, post-quantum cryptography, behavioral biometrics: not covered

---

## Labs

`LABS_GUIDE.md` is listed as containing hands-on exercises. Its contents were not reviewed here, so do not rely on its lab count, scoring rubric, or time estimates until you have checked them. If you keep a scoring rubric, state it as a self-assessment guide, not a certification.

---

## Study Plan (Suggested)

This plan is a starting point. Adjust it to your schedule and to the sections you have verified.

**Month 1: Foundations**
- Weeks 1-2: Main guide, foundations
- Week 3: LDAP or Active Directory, whichever is more relevant to your internship
- Week 4: `ADVANCED_TOPICS.md` sections 1 to 3

**Month 2: Modern IAM**
- Weeks 1-2: OAuth 2.0, OIDC, and SAML (main guide and `ADVANCED_TOPICS.md` section 9)
- Week 3: RBAC and SoD (`ADVANCED_TOPICS.md` sections 7 and 8)
- Week 4: Labs on OAuth 2.0 and RBAC, if `LABS_GUIDE.md` covers them

**Month 3: Cloud and Security**
- Week 1: Cloud IAM (`ADVANCED_TOPICS.md` section 6)
- Week 2: Threat modeling (`ADVANCED_TOPICS.md` section 3)
- Week 3: Incident response and forensics (`ADVANCED_TOPICS.md` sections 5 and 10)
- Week 4: Compliance (`ADVANCED_TOPICS.md` section 11)

**Month 4: Advanced Topics**
- Weeks 1-2: Kerberos (`ADVANCED_TOPICS.md` section 4)
- Week 3: Privilege escalation and dynamic SoD (`ADVANCED_TOPICS.md` sections 7.2 and 8)
- Week 4: Federation and trust (`ADVANCED_TOPICS.md` section 9)

**Month 5: Operations**
- Week 1: Monitoring and alerting (`ADVANCED_TOPICS.md` section 13)
- Week 2: Misconfigurations (`ADVANCED_TOPICS.md` section 12)
- Week 3: Hardening (main guide, verify)
- Week 4: Troubleshooting practice

**Month 6: Practice**
- Weeks 1-2: Build a lab with OpenLDAP, Active Directory (or a test domain), and an OIDC provider
- Week 3: Assess the lab for misconfigurations you are authorized to test
- Week 4: Write up findings and recommendations

---

## Self-Assessment

**Explain without notes**
- [ ] Identity, authentication, and authorization, and how they differ
- [ ] When to use each authentication factor
- [ ] LDAP versus Active Directory
- [ ] OAuth 2.0, OIDC, and SAML, and the problem each solves
- [ ] Static and dynamic SoD, with an example of each
- [ ] Common attacks on identity systems and their mitigations

**Hands-on**
- [ ] Configure an LDAP server with TLS
- [ ] Query and modify directory entries
- [ ] Implement an OAuth 2.0 authorization code flow with PKCE
- [ ] Design a role hierarchy with SoD constraints
- [ ] Identify a password spray in authentication logs
- [ ] Find misconfigurations in a directory or OAuth client

**Professional**
- [ ] Explain compliance requirements in plain language
- [ ] Document technical findings clearly
- [ ] Escalate issues appropriately
- [ ] Follow change management procedures
- [ ] Test security only on systems you are authorized to test

---

## Notes

- Commands and code in the guides are illustrative. Test them in a lab before running them anywhere else.
- This package does not replace vendor documentation or the standards it cites (NIST SP 800-63B, RFC 9106, RFC 6749, OWASP guidance).
- Remove superseded index files (`COMPLETE_INDEX.md`, `FINAL_COMPLETE_INDEX.md`) once this file is confirmed.

*Last reviewed: 2026-11-24*
