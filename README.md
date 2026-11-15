# ZeroDrop v4.0 APEX

**Client-side encrypted secret sharing with Shamir quorums, optional passphrases, atomic claims, owner shred, and an AWS serverless design.**

> **Status for this repository snapshot:** The automated suite and emulator were tested locally only. A short synthetic local walkthrough was recorded for private review; no public video was uploaded and no hackathon submission was made. This project has **not** been deployed to AWS or verified against live AWS services. The SAM template and deployment script describe how to deploy a copy; they do not indicate that a stack is running.

## Capabilities in the code

- **Client-side encryption and Shamir `M-of-N` sharing:** The browser and CLI encrypt before sending payloads. The browser supports 2-of-3 and 3-of-5 shares plus an optional passphrase check performed locally before a claim.
- **Preflight checks and display protections:** The browser includes secret-pattern/entropy checks, masked `.env` viewing, and a timed plaintext display wipe.
- **Atomic claim and owner shred:** The API uses conditional state changes for one-time claims, enforces each drop's configured TTL during fast and approved collection, and supports an owner-held kill token. AWS cleanup integrations are declared in the SAM template.
- **Break-glass workflow and audit receipts:** The code includes an approval workflow and hash-chained receipts. Local tests use the emulator and local signing behavior; AWS Step Functions and KMS behavior have not been verified in a deployment for this snapshot.
- **Aggregate telemetry counters:** `GET /api/telemetry/soc` returns counters and status metadata. It does not expose an event list, drop IDs, or actor IP hashes. The current tests explicitly check that those event details are absent. The page polls the endpoint; this is not a push-based event stream or evidence of a live AWS SOC.
- **AWS resources defined in SAM:** The template declares CloudFront, S3, API Gateway, Lambda, DynamoDB, Step Functions, KMS, SNS, and CloudWatch resources. They have not been deployed for this repository snapshot.

## Expiry and object cleanup

The browser UI offers drop-expiry choices of 15 minutes, 1 hour, 24 hours, and 7 days. The API accepts TTL values from 5 minutes to 7 days, and the CLI defaults to 60 minutes. Each drop stores a `ttl_epoch`, with DynamoDB TTL enabled in the template. Independently, the S3 vault bucket has a **7-day** lifecycle cleanup rule for encrypted objects under `vault/`. This is a backstop, not the configured expiry for every drop or a guarantee of deletion at the exact expiry instant.

## Local quick start

```bash
python3 -m pip install -r requirements-dev.txt
pytest -q
python3 local_server.py
# Open http://127.0.0.1:8787
```

Try the CLI against the local emulator:

```bash
echo 'ROOT_DB_PASS=example' | python3 cli/zerodrop_cli.py push \
  --url http://127.0.0.1:8787 --shares 3 --threshold 2
python3 cli/zerodrop_cli.py soc --url http://127.0.0.1:8787
```

The local 20-thread race test uses the in-memory emulator. A separate browser/API race can be run against a deployed endpoint, but no live AWS race or live AWS verification was performed for this snapshot.

## Deploying your own AWS copy

Deployment requires AWS credentials, AWS CLI, and SAM CLI. These commands are instructions only; they were not run for this snapshot:

```bash
./deploy.sh you@example.com
python3 scripts/verify_live_aws.py https://<your-cloudfront-domain>
```

Run the verification script only after a successful deployment. To remove a deployed copy, follow the teardown steps in the deployment script/project documentation and confirm the target stack before deleting resources.
