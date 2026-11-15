# ZeroDrop v4.0 APEX

**Zero-Knowledge, Shamir M-of-N Quorum, Client Preflight Guardrails, 60s Screen Auto-Wipe, Panic-Shreddable, KMS-Chained & Live-SOC Secret Escrow on Serverless AWS**

Built for the AWS Builder Center **Weekend Challenge: No Pipeline, No Problem** — deployed in one command via **AWS SAM** with zero EC2 servers, zero containers, zero CI/CD pipelines, and **$0.00 idle compute cost**.

---

## APEX Capabilities (v4.0)

- **Zero-Knowledge Browser Encryption (`AES-256-GCM`) + Shamir `M-of-N` Quorum Splitting (`GF(256)`) + Optional 2FA Passphrase (`PBKDF2-SHA256`, 120k iter):**
  Split any 256-bit secret key locally into **2-of-3** or **3-of-5** Shamir shares (`#d=...&s=1-2-3:...`) so no single engineer holds the full key, optionally wrapped behind an out-of-band PBKDF2 passphrase verified **locally before claiming** (typos never burn secrets).
- **In-Browser Secret & Shannon Entropy Preflight Scanner (1-Click Guardrails):**
  Detects AWS Keys (`AKIA*`), Private Key PEMs, Stripe Secrets, API Tokens, DB URIs, and high Shannon entropy purely inside browser JS (`0` bytes leave the client), with a **1-click guardrail button** to enable Break-Glass Approval + 2-of-3 Shamir Quorum.
- **Per-Key Masked `.env` Inspector + 60-Second Screen Auto-Wipe:**
  Automatically parses decrypted `.env` configs into masked `KEY=••••` rows with individual eye toggles and per-value copy, backed by a **60-second automatic RAM/DOM wipe countdown** (and instant **Wipe Screen Now** button) against shoulder surfing.
- **Live Zero-Scan AWS Security Operations Center (`Tab 6` & `GET /api/telemetry/soc`):**
  Maintains real-time anonymized security counters (Drops Created, Burned, Bots Blocked, Canary Tripwires, Panic Shreds, Owner Approvals) and a clickable event stream inside a single DynamoDB partition (`PK = "TELEMETRY#GLOBAL"` — **zero table scans, $0.00 idle cost**).
- **Instant Owner Panic Kill Switch (`POST /api/drops/{id}/shred`) & S3 TLS-Only Enforce:**
  Pasted a link into the wrong Slack channel? Trigger `kill_token` to atomically scrub DynamoDB ciphertext, delete any S3 object (`VaultBucketPolicy` denies non-HTTPS via `aws:SecureTransport`), halt Step Functions (`states:StopExecution`), fire SNS, and sign **`OWNER_PANIC_SHREDDED`**.
- **Bot-Proof Edge Shield + Canary Honeypot SNS + CloudWatch Alarm:**
  Crawlers (`Slackbot`, `Discordbot`, `WhatsApp`) receive only the static CloudFront/OAC shell and get `403 BOT_SHIELD_BLOCKED` on `/claim`. Canary Honeypots emit structured JSON logs triggering CloudWatch Metric Filters (`ZeroDrop/Security`), `CanaryTripwireAlarm`, and SNS alerts.
- **Step Functions Break-Glass Approval (`waitForTaskToken`) + Hash-Chained KMS P-256 Receipts + Offline HTML Certificate:**
  Pauses up to 1 hour at `$0` idle compute until owner `APPROVE`/`DENY`, auto-shreds via a **Parallel Direct AWS SDK State**, and exports **offline-verifiable HTML cryptographic audit certificates**.

---

## Quick Start Locally (No AWS Needed)

```bash
# Install the test dependencies, then run the automated verification suite
python3 -m pip install -r requirements-dev.txt
pytest -v tests/test_zerodrop.py

# 2. Launch Local AWS Emulator
python3 local_server.py
# Open http://127.0.0.1:8787

# 3. Try the CLI with 2-of-3 Shamir Quorum, Panic Shred & Live SOC
echo "ROOT_DB_PASS=zd_v4_apex" | python3 cli/zerodrop_cli.py push --url http://127.0.0.1:8787 --shares 3 --threshold 2
python3 cli/zerodrop_cli.py soc --url http://127.0.0.1:8787
```

The **Local 20-Thread DB Race** uses the in-memory emulator only. It is not exposed by the AWS API; the separate browser HTTP race is an explicit live test and creates a real short-lived drop.

---

## One-Command Live AWS Deployment (No Pipelines!)

```bash
./deploy.sh you@example.com
python3 scripts/verify_live_aws.py https://<your-cloudfront-domain>
```

`deploy.sh` generates a fresh private IP-hash salt for each deployment and passes it as a masked CloudFormation parameter. Direct `sam deploy` users must also supply a private random `IpHashSalt` of at least 32 characters.

### Clean Teardown

```bash
WEB_BUCKET=$(aws cloudformation describe-stacks --stack-name zerodrop --query "Stacks[0].Outputs[?OutputKey=='WebBucketName'].OutputValue" --output text)
aws s3 rm "s3://$WEB_BUCKET" --recursive
sam delete --stack-name zerodrop --region us-east-1
```
