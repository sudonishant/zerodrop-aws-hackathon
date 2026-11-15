# ZeroDrop v3 Ultra-Pro — < 3 Minute Demo Video Script (Target: 2:35)

> **Rule Check:** Must be under 3:00 minutes, publicly visible (YouTube / Vimeo), no copyrighted music, showing the build running end-to-end.

---

### `0:00 – 0:22` | The Hook & 1-Click Auto-Demo + Pipeline Bar
* **Visual:** Open `https://<your-cloudfront-url>` on Tab 1 (`ZeroDrop v3.0 ULTRA-PRO`), highlight the **Live Serverless Pipeline Bar** + **KMS Key Fingerprint**, and click **▶ Auto-Run Live Security Demo** (or walk through manually).
* **Voiceover:**
  > "Hi! I built **ZeroDrop v3** for the *No Pipeline, No Problem* Weekend Challenge. Developers share `.env` secrets over Slack every day—only for link-preview crawlers to burn one-time links, or 20 concurrent requests to trigger a race leak. ZeroDrop solves this end-to-end with Shamir M-of-N Quorum splitting, an instant owner kill switch, and 100% serverless AWS at **$0 idle compute**."

### `0:22 – 1:05` | Zero-Knowledge + Shamir 2-of-3 Quorum + 2FA Passphrase + Canary Shield
* **Visual:**
  1. Select **2-of-3 Shamir Quorum** + optional **2FA Passphrase** (or **Canary Trap**) → click **Encrypt & Create ZeroDrop**.
  2. Show the 3 distinct Share URLs (`#d=...&s=1-2-3:...`) + the **Owner Panic Kill Switch** (`kill_token`).
  3. Open Unlocker Tab → click **🤖 Simulate Slackbot Crawl** → show **403 BOT_SHIELD_BLOCKED** (plus Canary SNS + CloudWatch Alarm metric!) while status stays `READY`.
  4. Enter a **wrong passphrase** → show **"Checked locally BEFORE calling AWS — secret NOT burned."** Then combine 2 Shamir shares + right passphrase → plaintext decrypts locally!

### `1:05 – 1:45` | Step Functions Break-Glass Approval (`waitForTaskToken`)
* **Visual:**
  1. Quick switch to Tab 1 → select **🛡️ Break-Glass Approval** (Judge Sandbox checked) → click **Encrypt & Create**.
  2. Unlocker Tab → click **🛡️ Request Break-Glass Unlock** → show **`PENDING_APPROVAL`** alongside the **AWS Step Functions Console execution graph paused in blue on `NotifyAndAwaitApproval`**.
  3. Click **Open Owner Review Page** → click **✅ Approve Release** → return to Unlocker Tab to see instant plaintext unlock and the Step Functions graph finishing green through **`ParallelApproveShred`** (`DynamoDB` + `S3` + `SNS`).

### `1:45 – 2:20` | Dual-Mode Race Lab & Hash-Chained KMS Tamper Cascade
* **Visual:**
  1. Show the **Local 20-Thread DB Race** while `local_server.py` is running to compare the synthetic naive case with the atomic emulator result. On a deployed AWS page, click **🌐 Fire 20 Parallel Browser `fetch()` Requests** only for a deliberate live load test; it creates a real drop and sends 20 API claims.
  2. Tab 5 (**Hash-Chained KMS Ledger**): show the full chain verifying **ALL VALID** in browser WebCrypto → click **🧪 Flip 1 Char in Entry #1** (cascade fail!) → click **📄 Export Verifiable HTML Cert** + demonstrate **☠️ Panic Shred Now** killing an active drop!

### `2:20 – 2:38` | CLI, CloudWatch Ops Dashboard & 1-Command Deploy
* **Visual:** Flash `cli/zerodrop_cli.py` pushing `.env` from terminal + **CloudWatch `ZeroDropOpsDashboard`** + `./deploy.sh`.
* **Voiceover:**
  > "Everything—CloudFront, OAC S3, HTTP API, Python 3.13 arm64 Lambdas, Step Functions SDK shred, DynamoDB TTL, KMS P-256, SNS, and a CloudWatch Ops Dashboard—deploys from one SAM template with `./deploy.sh` and scales to zero. Thanks for watching!"
