
## Mora Cloud Console (Phases 3–7)

A self-hosted cloud portal, like a mini AWS Console / Azure Portal, built on top of the storage and identity layers.

| Phase | Feature | Security highlight |
|---|---|---|
| 3 | Console login via Keycloak (OIDC) | Authorization Code + PKCE, MFA (TOTP), signed session cookie |
| 4 | Storage browser (buckets, upload, download, delete) | RBAC enforced in the app **and** by Garage per-key permissions |
| 5 | Audit log | Every action and denial logged; SHA-256 hash chain makes edits detectable |
| 6 | Attack & detect | Brute force, privilege probing, log tampering, stored XSS tested — see `docs/attack-and-detect.md` |
| 7 | GRC report | Controls mapped to ISO 27001:2022 and CIS v8 + risk register — see `docs/grc-report.md` |

### Roles (least privilege)

| Permission | admin | developer | auditor |
|---|:-:|:-:|:-:|
| List / view / download | ✅ | ✅ | ✅ |
| Upload | ✅ | ✅ | ❌ |
| Delete | ✅ | ❌ | ❌ |
| Read audit log | ✅ | ❌ | ✅ |

Users with write permission get the read-write Garage key; everyone else gets the read-only key,
so even an application bug could not let an auditor write data (defense in depth).

### Run the console
```bash
cd console && . .venv/bin/activate
uvicorn app:app --host 127.0.0.1 --port 8000
```
Secrets live in `console/.env` (gitignored, mode 600): Keycloak client secret, session secret, Garage keys.
