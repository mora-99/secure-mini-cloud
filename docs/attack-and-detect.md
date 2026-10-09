# Phase 6 — Attack & Detect

Each scenario is a realistic attack against Mora Cloud, the control that should stop it,
and where the evidence appears. Fill in the **Result** column after you run it.

| # | Attack | Attacker | Control | Expected result | Evidence | Result |
|---|--------|----------|---------|-----------------|----------|--------|
| A1 | Password brute force on `tharul` (6 wrong passwords) | External | Keycloak brute-force detection + MFA | Account temporarily locked; correct password still blocked until lockout ends | Keycloak → Events → `LOGIN_ERROR` | ☐ |
| A2 | Privilege probing: `dev1` opens `/audit` 3+ times | Insider (developer) | RBAC (`audit:read` not granted) | 403 every time; red alert "possible privilege probing" on Audit log page | Console → Audit log (DENIED rows + alert) | ☐ |
| A3 | Auditor tries to delete / upload | Insider (auditor) | RBAC in console + read-only Garage key | No upload/delete buttons; forced request denied | Console Audit log | ☐ |
| A4 | Storage-layer bypass: write with the read-only key directly via AWS CLI | Insider with stolen RO key | Garage per-key permissions (defense in depth) | `AccessDenied` | Terminal output | ☐ |
| A5 | Log tampering: edit `audit.log` to hide a DENIED event | Insider covering tracks | SHA-256 hash chain | Audit page shows "TAMPERING DETECTED at line N" | Console Audit log | ☐ |
| A6 | Stored XSS: upload `evil.html` containing `<script>` | Malicious user | Forced download (`application/octet-stream`), CSP, output escaping | File downloads, script never runs in the console | Browser | ☐ |
| A7 | Network exposure scan | External | All services bound to 127.0.0.1 | No service on 0.0.0.0 | `ss -tlnp` | ☐ |

## How to run each attack

**A1 — Brute force**
1. Private window → `http://localhost:8000` → Sign in → user `tharul` → wrong password 6 times.
2. Then try the correct password → should still fail (locked).
3. Keycloak admin → mora-cloud → **Events** → see `LOGIN_ERROR` entries.
4. Unlock: Users → tharul → toggle "temporarily locked" off (or wait).

**A2 — Privilege probing**
1. Private window → sign in as `dev1` → open `http://localhost:8000/audit` 3 times.
2. Sign in as `tharul` → **Audit log** → red alert for `dev1`.

**A3 — Auditor write attempt**
1. Sign in as `audit1` → Storage → bucket → no Upload / Delete buttons ("Read-only access").

**A4 — Storage-layer bypass**
```bash
echo test > /tmp/x.txt
aws s3 cp /tmp/x.txt s3://<your-bucket>/x.txt --profile mc-ro
```
Expected: `AccessDenied`.

**A5 — Log tampering**
```bash
cd ~/secure-mini-cloud/console
cp audit.log audit.log.bak
sed -i '0,/"DENIED"/s//"OK"/' audit.log      # attacker hides the first DENIED event
```
Open Audit log → **TAMPERING DETECTED**. Restore: `cp audit.log.bak audit.log`.

**A6 — Stored XSS**
```bash
echo '<script>alert("xss")</script>' > ~/evil.html
```
Upload `evil.html` as tharul → click Download → it saves as a file; no alert box appears in the console.

**A7 — Exposure**
```bash
ss -tlnp | grep -E '3900|3903|8081|8000'
```
Every line must show `127.0.0.1`.

## Detection logic (console)
- Every login, logout, storage action, and denied attempt is written to `console/audit.log` (JSON lines, file mode 600).
- Each entry stores `prev` = hash of previous entry and `hash` = SHA-256 of itself → editing or deleting any line breaks the chain.
- Alert rule: **≥ 3 DENIED** (or **≥ 3 FAILED** sign-ins) by the same user within **15 minutes** → red alert on the Audit log page.

## Known limitation
The hash chain proves tampering by someone who edits single lines. An attacker with root on the VM could
rewrite the whole chain. Production fix: ship logs off-host in real time (e.g. to a SIEM / write-once storage).
