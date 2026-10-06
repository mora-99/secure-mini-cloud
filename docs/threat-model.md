# Threat Model (STRIDE)

## Assets
| Asset | Why it matters |
|---|---|
| Stored objects | Confidentiality and integrity of data |
| S3 access keys | Grant read/write access to buckets |
| `rpc_secret`, admin token | Full control of the storage node |
| Audit logs (Phase 2) | Evidence for detection and investigation |

## Trust boundaries
1. Client ↔ S3 API
2. Host ↔ containers
3. Local repository ↔ GitHub (public)

## STRIDE analysis

| Category | Threat | Mitigation | Status |
|---|---|---|---|
| Spoofing | Stolen access key used to impersonate an app | Separate keys per role; rotation procedure | ✅ |
| Spoofing | Attacker reaches the API over the network | Ports bound to 127.0.0.1 only | ✅ |
| Tampering | Read-only user modifies objects | Read-only key has no write permission | ✅ Verified |
| Tampering | Config altered at runtime | Config mounted read-only | ✅ |
| Repudiation | Actions cannot be traced to a key | Per-request audit logging | ⏳ Phase 2 |
| Information disclosure | Secrets committed to public GitHub | Generated config is git-ignored | ✅ |
| Information disclosure | Credentials leaked via screenshots or chat | Keys loaded from chmod 600 files; leaked keys rotated | ✅ |
| Information disclosure | Traffic sniffed in transit | TLS gateway | ⏳ Planned |
| Denial of service | Container exhausts host memory | 256 MB memory limit | ✅ |
| Denial of service | Request flooding | Rate limiting at gateway | ⏳ Planned |
| Elevation of privilege | App key creates or deletes buckets | Keys lack bucket-creation rights | ✅ |
| Elevation of privilege | Admin API abuse | Token-protected, localhost only | ✅ |

## Accepted risks (current phase)
- No TLS yet: traffic stays inside one VM on localhost.
- Access keys do not expire: manual rotation for now.
