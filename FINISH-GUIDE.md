# Mora Cloud — Finish Guide (Phases 4–7)

Follow top to bottom. Copy-paste each command and use **Ctrl+Shift+V** to paste in the terminal.
Time: about 45 minutes.

---

## Step 1 — Put the files into your repo (2 min)

Download `mora-cloud-phases-4-7.zip` **inside the VM** (open the chat in the VM's Firefox), then run:
```bash
cd ~/Downloads && unzip -o mora-cloud-phases-4-7.zip -d ~/secure-mini-cloud
```
This replaces `console/app.py` and adds `scripts/console-s3-keys.sh`, `docs/attack-and-detect.md`,
`docs/grc-report.md`, `docs/README-phases-3-7.md`, and this guide.

Keep the audit log out of Git:
```bash
cd ~/secure-mini-cloud && echo "console/audit.log*" >> .gitignore
```

## Step 2 — Install the 2 new Python packages (1 min)
```bash
cd ~/secure-mini-cloud/console && . .venv/bin/activate && pip install boto3 python-multipart
```

## Step 3 — Give the console the Garage keys (1 min)
```bash
bash ~/secure-mini-cloud/scripts/console-s3-keys.sh
```
You should see 6 lines with lengths, and none of them should be 0. The secrets are never printed.

## Step 4 — Keycloak settings (10 min)
Open `http://localhost:8081/admin/master/console/#/mora-cloud` and log in as admin.

**4a. Create 2 test users**
For each row: **Users → Add user** → Username → **Create** → **Credentials** tab → **Set password** (Temporary **OFF**) →
**Role mapping** tab → **Assign role** → change the filter to **realm roles** → pick the role → **Assign**.

| Username | First name | Role |
|---|---|---|
| `dev1` | Dev | developer |
| `audit1` | Audit | auditor |

**4b. Brute-force protection**
**Realm settings → Security defenses** tab → **Brute force detection** → Mode **Lockout temporarily**,
Max login failures **5** → **Save**.

**4c. Save login events**
**Realm settings → Events** tab → **User events settings** → Save events **ON** → **Save**.

## Step 5 — Restart the console (1 min)
In the uvicorn terminal press **Ctrl+C**, then:
```bash
cd ~/secure-mini-cloud/console && . .venv/bin/activate && uvicorn app:app --host 127.0.0.1 --port 8000
```

## Step 6 — Test as admin (5 min)
1. Open `http://localhost:8000` → **Sign in** as `tharul` (password + MFA).
2. The top menu now shows **Dashboard · Storage · Audit log**.
3. **Storage** → click your bucket → **Upload** a small file → it appears in the list → **Download** it → **Delete** it.
4. **Audit log** → you see your login, upload, download, delete, and a green **"Hash chain intact"**.
5. 📸 Screenshot: Storage page and Audit log page.

## Step 7 — Attack & Detect (15 min)
Use a **private window** (Ctrl+Shift+P) for each different user.
Run the 7 attacks in `docs/attack-and-detect.md` (A1–A7). The quick ones:

- **A2:** sign in as `dev1` → open `http://localhost:8000/audit` 3 times → 403 each time.
  Then as `tharul` → Audit log → **red alert for dev1**. 📸
- **A3:** sign in as `audit1` → Storage → bucket → "Read-only access", with no Upload or Delete buttons. 📸
- **A5 (tampering):**
  ```bash
  cd ~/secure-mini-cloud/console && cp audit.log audit.log.bak && sed -i '0,/"DENIED"/s//"OK"/' audit.log
  ```
  Refresh the Audit log → **TAMPERING DETECTED** 📸. Then restore it:
  ```bash
  cp audit.log.bak audit.log
  ```
- **A7:**
  ```bash
  ss -tlnp | grep -E '3900|3903|8081|8000'
  ```
  Every line should show 127.0.0.1.

When you finish, mark each ☐ as ✅ in `docs/attack-and-detect.md` (use `nano docs/attack-and-detect.md`).

## Step 8 — README + push to GitHub (3 min)
```bash
cd ~/secure-mini-cloud && cat docs/README-phases-3-7.md >> README.md
```
```bash
cd ~/secure-mini-cloud/console && pip freeze > requirements.txt && cd ..
```
```bash
git add .gitignore README.md console/app.py console/requirements.txt scripts/console-s3-keys.sh docs/ FINISH-GUIDE.md && git status
```
⚠️ Check the list. There must be **NO** `.env`, `audit.log`, or `.venv`. If it looks right:
```bash
git commit -m "Phases 4-7: storage RBAC, tamper-evident audit log, attack & detect, GRC report" && git push
```

## Step 9 — Snapshot
VMware → **VM → Snapshot → Take Snapshot** → `mora-cloud-v1-complete`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: boto3` or `multipart` | You forgot `. .venv/bin/activate`, or Step 2 |
| `KeyError: 'S3_RW_KEY_ID'` | Run Step 3 again, then restart uvicorn |
| Storage page: "No buckets visible" | `docker exec garage /garage bucket list`. If there's no bucket, create one and allow both keys (same as Phase 1) |
| `SignatureDoesNotMatch` / `InvalidAccessKeyId` | The keys in `~/.mc-keys` are old (rotated). Update those files, then run Step 3 again |
| "Address already in use" | The console is already running in another terminal: `pkill -f "uvicorn app:app"` |
| Dev1 is asked to set up OTP | That's normal if OTP is a default required action. Scan it with Google Authenticator |
| Sign-in failed page | Close the tab, open `http://localhost:8000` fresh |

---

## LinkedIn post (copy, add 2–3 screenshots)

> I built my own mini cloud platform — "Mora Cloud" — to learn how AWS and Azure secure things under the hood.
>
> 🔹 S3-compatible object storage (Garage) with least-privilege access keys
> 🔹 Identity & access management with Keycloak: roles, MFA (TOTP), brute-force protection
> 🔹 My own web console with OIDC + PKCE single sign-on
> 🔹 Role-based access enforced at two layers — app and storage (defense in depth)
> 🔹 Tamper-evident audit log (SHA-256 hash chain) with alerts for privilege probing
> 🔹 Attacked it myself: brute force, privilege escalation attempts, log tampering, stored XSS
> 🔹 Mapped every control to ISO 27001:2022 and CIS v8, with a risk register
>
> Biggest lesson: security is not one feature — it's identity, least privilege, logging and governance working together.
>
> Code + threat model + GRC report: github.com/mora-99/secure-mini-cloud
>
> #CloudSecurity #IAM #CyberSecurity #GRC #ISO27001 #Keycloak #DevSecOps
