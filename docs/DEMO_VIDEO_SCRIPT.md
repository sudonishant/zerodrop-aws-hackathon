# ZeroDrop v4.0 APEX — Local Demo Script

> **Status:** This is a proposed longer storyboard; a separate short synthetic walkthrough was recorded locally for private review. The repository snapshot was tested with the local suite/emulator only and has not been deployed to AWS. No AWS console footage, live AWS verification, public video upload, or hackathon submission is claimed. Any cloud-dependent scene below must wait for a separately deployed and verified environment.

### `0:00–0:22` | The problem and local app

- **Visual:** Start `python3 local_server.py` and open `http://127.0.0.1:8787`. Introduce the project as a client-side secret-sharing prototype with an AWS SAM design, not a currently live service.
- **Voiceover:** “ZeroDrop explores safer ways to share short-lived secrets: encrypt in the client, split keys when needed, and make claims atomic. This recording uses the local emulator; the AWS template is not deployed in this repository snapshot.”

### `0:22–1:05` | Client-side crypto and local checks

- **Visual:** Walk through a local secret creation, Shamir shares, optional passphrase check, and the browser's masked `.env` display. Show the local bot/canary behavior where available.
- **Voiceover:** “The browser performs encryption and checks before the claim request. These are local application behaviors; the screen does not demonstrate a live AWS environment.”

### `1:05–1:45` | Break-glass flow in the emulator

- **Visual:** Request a break-glass unlock, then approve it through the local review flow. Do not show an AWS Step Functions console execution graph.
- **Voiceover:** “The local emulator simulates the approval and callback flow. A live Step Functions execution has not been run for this snapshot.”

### `1:45–2:20` | Race test and audit receipt

- **Visual:** Show the local 20-thread in-memory race test and verify the local hash-chained receipt. If displaying the telemetry panel, describe it as polled aggregate counters only; do not call it an event stream or live AWS SOC.
- **Voiceover:** “The concurrency test here targets the in-memory emulator. The local signing path is not AWS KMS, and the telemetry API returns aggregate counters rather than individual events.”

### `2:20–2:38` | CLI and what remains unverified

- **Visual:** Run the CLI against `http://127.0.0.1:8787`. Do not present CloudWatch dashboards, CloudFront, KMS, or live AWS results as completed work.
- **Voiceover:** “The repository includes a SAM template and deployment script for a separate AWS deployment. Neither deployment nor live verification is part of this demo snapshot.”

## Optional future cloud segment

Only after an actual AWS deployment and a successful run of `scripts/verify_live_aws.py`, a later recording may show the live CloudFront/API behavior and the AWS services that are provisioned. Clearly distinguish that evidence from the local emulator, and do not claim an event stream: the current SOC endpoint exposes aggregate counters only.
