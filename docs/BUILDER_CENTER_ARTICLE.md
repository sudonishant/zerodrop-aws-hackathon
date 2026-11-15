# ZeroDrop v4.0 APEX: Client-Side Secret Escrow with Shamir Quorums and Serverless AWS Design

> **Repository status:** This snapshot was exercised with the local test suite and local emulator only. A short synthetic local walkthrough was recorded for private review; it was not uploaded publicly, and no hackathon submission was made. The project has **not** been deployed to AWS or verified against live AWS services. AWS components described below are defined in the SAM template; the design and deployment instructions are not evidence of a running stack.

## The problem

Developers often share database passwords, webhook secrets, `.env` files, or temporary credentials through chat or email. Link-preview bots can consume one-time links, backend-side encryption can expose plaintext to a service operator, and a check-then-delete flow can allow concurrent claims. High-risk secrets may also need an owner approval step and a verifiable audit trail.

## What ZeroDrop implements

1. **Client-side encryption and sharing.** The browser and CLI encrypt payloads before sending them to the service. The browser supports Shamir `M-of-N` key shares and an optional passphrase check performed locally before a claim. The UI can mask `.env` values and wipe the displayed plaintext after a short countdown.
2. **Atomic one-time claim and owner shred.** The API uses conditional updates for one-time claims and enforces each drop's configured TTL on fast and approved collection. A creator-held kill token can request a shred; the SAM template also defines the AWS-side actions for related S3 and workflow cleanup.
3. **Bot and canary handling.** The application includes preview-bot checks and canary-drop handling. The template defines structured logging, a canary metric filter/alarm, and SNS alert resources; these AWS resources were not exercised against a deployed stack in this snapshot.
4. **Break-glass workflow.** The code and SAM template include an owner-approval path using Step Functions task callbacks. The local emulator simulates the workflow-related behavior; it does not demonstrate a live Step Functions execution.
5. **Audit receipts.** The application builds a hash-chained audit trail. In the local emulator, signing uses local OpenSSL-backed behavior; AWS KMS signing and verification have not been validated on a deployed stack here.
6. **Aggregate SOC counters, not an event stream.** The telemetry route returns aggregate counters and status metadata. It does **not** return individual events, drop IDs, or actor IP hashes. The tests assert that the public response has no `events` field and omits those identifiers. Although event records are maintained internally for counter updates, a clickable event stream is not exposed by the current API.

## Expiry and storage lifecycle

Drop expiry and S3 object cleanup are separate controls. The browser UI offers 15-minute, 1-hour, 24-hour, and 7-day drop-expiry choices; the API accepts a TTL from 5 minutes through 7 days, and the CLI defaults to 60 minutes. A `ttl_epoch` is stored for each drop and DynamoDB TTL is enabled in the template. Separately, the S3 `VaultBucket` lifecycle rule is configured to expire `vault/` objects after **7 days** as a cleanup backstop. The diagram's earlier one-day label was incorrect. The seven-day S3 rule is not a claim that every drop remains available for seven days or that lifecycle deletion occurs at the exact expiry instant.

## AWS design in the SAM template

The following describes resources declared in `template.yaml`, not a deployed environment:

| AWS service | Declared role |
| --- | --- |
| **CloudFront + private S3 web bucket** | Serves the browser app and routes `/api/*` to the HTTP API. |
| **API Gateway HTTP API** | Exposes the application routes over HTTPS. “HTTP API v2” is the AWS API type, not a ZeroDrop release label. |
| **Lambda** | Runs the Python API and workflow task handlers. |
| **DynamoDB** | Stores drop metadata, conditional claim state, audit data, and aggregate telemetry; TTL is enabled for drop items. |
| **S3 vault bucket** | Stores encrypted file payloads through presigned transfers; the separate lifecycle backstop is seven days. |
| **Step Functions** | Defines break-glass approval and cleanup orchestration. |
| **KMS, SNS, and CloudWatch** | The template declares signing, alerting, logging, metric, alarm, and dashboard resources. They have not been provisioned or validated in AWS for this snapshot. |

## What was tested locally, and what was not

The automated tests and `local_server.py` use local components, including an in-memory DynamoDB/S3 emulator and local signing behavior. They verify application logic and simulated flows; they are **not AWS integration tests**. The local 20-thread race test is also an emulator test, not a live API load test.

The browser/API race and `scripts/verify_live_aws.py` are intended for a separately deployed endpoint. They were not run against AWS here. Any CloudFront, KMS, Step Functions, SNS, CloudWatch, or live SOC result must therefore be described as unverified until a real deployment is tested. In particular, the current SOC endpoint exposes aggregate counters only, not a live event stream.

## Local checks

```bash
python3 -m pip install -r requirements-dev.txt
pytest -q
python3 local_server.py
# Open http://127.0.0.1:8787
```

The CLI can be pointed at the local server, for example:

```bash
echo 'ROOT_DB_PASS=example' | python3 cli/zerodrop_cli.py push \
  --url http://127.0.0.1:8787 --shares 3 --threshold 2
python3 cli/zerodrop_cli.py soc --url http://127.0.0.1:8787
```

## Deploying a separate copy

The repository includes a deployment recipe, but it was **not run** for this snapshot. To deploy your own copy, configure AWS credentials plus the AWS CLI and SAM CLI, then follow the script's prompts and outputs:

```bash
git clone <your-private-repo-url>
cd zerodrop
./deploy.sh you@example.com
python3 scripts/verify_live_aws.py https://<your-cloudfront-domain>
```

Run live verification only after a successful deployment. No deployment, public video upload, or challenge submission is claimed here.
