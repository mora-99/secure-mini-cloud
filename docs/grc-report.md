# Mora Cloud — Security Controls & Risk Report (GRC)

**Scope:** Mora Cloud lab (Garage S3 storage, Keycloak IAM, Mora Cloud Console) on a single Ubuntu 24.04 VM.
**Author:** Tharul Hettiarachchi · **Frameworks:** ISO/IEC 27001:2022 Annex A, CIS Critical Security Controls v8
**Status:** Lab / portfolio environment — not production.

## 1. Control mapping

| Control implemented | Where | ISO 27001:2022 | CIS v8 |
|---|---|---|---|
| Central identity provider (Keycloak realm `mora-cloud`) | Keycloak | 5.16 Identity management | 5 Account Management |
| MFA (TOTP) for the administrator | Keycloak | 8.5 Secure authentication | 6.5 Require MFA for administrative access |
| Role-based access (admin / developer / auditor) with least privilege | Console `PERMS` | 5.15 Access control, 5.18 Access rights, 8.2 Privileged access rights | 6.8 Define and maintain RBAC |
| Per-key bucket permissions (RW vs read-only) — defense in depth | Garage | 8.3 Information access restriction | 3.3 Configure data access control lists |
| OIDC Authorization Code + PKCE, confidential client, exact redirect URIs | Console ↔ Keycloak | 8.5 Secure authentication | 16 Application Software Security |
| Brute-force lockout | Keycloak | 8.5 Secure authentication | 4 Secure Configuration |
| Secrets kept out of Git (`.gitignore`, chmod 600, generated randomly) | Repo / `.env` | 5.17 Authentication information, 8.4 Access to source code | 3 Data Protection |
| Credential rotation after exposure | Garage keys | 5.17 Authentication information | 5 Account Management |
| Tamper-evident audit log (SHA-256 hash chain) | Console | 8.15 Logging | 8.2 Collect audit logs |
| Alerting on repeated denials / failed sign-ins | Console | 8.16 Monitoring activities | 8.11 Conduct audit log reviews |
| Authentication events stored | Keycloak Events | 8.15 Logging | 8.2 Collect audit logs |
| Services bound to localhost only; minimal exposed ports | Docker Compose | 8.20 Networks security | 4 Secure Configuration, 12 Network Infrastructure Mgmt |
| Security headers, CSRF tokens, output escaping, upload size limit, forced download | Console | 8.28 Secure coding | 16 Application Software Security |
| Version control, documented threat model (STRIDE), attack tests | GitHub repo, docs/ | 8.25 Secure development life cycle, 8.32 Change management | 16 Application Software Security |
| Pinned image versions, memory limits | Docker Compose | 8.9 Configuration management | 4 Secure Configuration |
| VM snapshots per phase | VMware | 8.13 Information backup (partial) | 11 Data Recovery (partial) |

## 2. Risk register (gaps)

Likelihood (L) and Impact (I) scored 1–3. Risk = L × I.

| ID | Risk | L | I | Risk | Treatment | Planned remediation |
|---|---|---|---|---|---|---|
| R1 | No TLS — traffic between browser, console, Keycloak and Garage is plaintext | 1 | 3 | 3 | Accept (localhost only) | Reverse proxy (Caddy/Nginx) with TLS — ISO 8.24 |
| R2 | Keycloak runs in `start-dev` with a temporary bootstrap admin | 2 | 3 | 6 | Mitigate | Permanent admin with MFA, delete temp admin, production mode + Postgres |
| R3 | Audit log stored on the same host — root can rewrite the entire chain | 1 | 3 | 3 | Accept (lab) | Ship logs off-host to SIEM / write-once storage |
| R4 | Garage access keys never expire | 2 | 2 | 4 | Mitigate | Rotation schedule (90 days) + documented procedure |
| R5 | Single node, no off-VM backup of data | 2 | 2 | 4 | Accept (lab) | Scheduled `garage` data export + off-host copy |
| R6 | MFA enforced only for admin, not all users | 2 | 2 | 4 | Mitigate | Make "Configure OTP" a default required action for the realm |
| R7 | Lab client secret exposed during development | 1 | 1 | 1 | Accept | Rotate before any non-lab use |
| R8 | No rate limiting on console endpoints | 1 | 2 | 2 | Accept | Add rate limiting at reverse proxy |

## 3. Evidence
- Least-privilege test: read-only key → `AccessDenied` on write (Phase 1, README).
- MFA login and role display: console screenshot "Welcome Tharul / admin".
- Attack & detect results: `docs/attack-and-detect.md`.
- Audit log integrity check: console → Audit log → "Hash chain intact".

## 4. Management summary
Mora Cloud implements the core identity, access, and logging controls expected of a cloud platform:
central IAM with MFA, least-privilege RBAC enforced at two layers (application and storage),
and tamper-evident audit logging with basic detection. The main residual risks are the lack of TLS,
Keycloak's development mode, and on-host log storage — all accepted for a lab and each has a
documented remediation path.
