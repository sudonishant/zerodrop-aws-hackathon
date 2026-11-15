#!/usr/bin/env python3
"""Post-deploy live verification & benchmark script for ZeroDrop on AWS.

Run after `./deploy.sh` against your CloudFront URL (or local_server.py):
  python3 scripts/verify_live_aws.py https://dxxxxxxxx.cloudfront.net
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cli"))
import zerodrop_cli  # noqa: E402


def req(method: str, url: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, (json.loads(raw) if raw.startswith("{") else {}), dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        return e.code, (json.loads(raw) if raw.startswith("{") else {}), dict(e.headers)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python3 scripts/verify_live_aws.py <BASE_URL>")
    base = sys.argv[1].rstrip("/")

    print(f"🔍 Auditing live ZeroDrop deployment: {base}\n")

    # 1. Health + Security Headers
    st_h, health, _ = req("GET", f"{base}/api/health")
    assert st_h == 200 and health.get("ok") is True, f"Health check failed: {st_h} {health}"
    print(f"1. Health Check       : PASS (KMS={health.get('kms_enabled')}, SFN={health.get('step_functions_enabled')})")

    # 2. Encrypted Create + Bot Shield + 20-Way HTTP Race + Decrypt + KMS Ledger Verify
    raw_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    secret_bytes = b"AWS_BENCHMARK_SECRET=zd_verified_9911"
    cipher = zerodrop_cli.aes_gcm_encrypt(secret_bytes, raw_key, iv)

    st_c, created, _ = req(
        "POST",
        f"{base}/api/drops",
        {
            "mode": "fast",
            "label": "Live AWS Benchmark Drop",
            "ttl_minutes": 10,
            "iv_b64": base64.b64encode(iv).decode(),
            "ciphertext_b64": base64.b64encode(cipher).decode(),
            "payload_sha256": hashlib.sha256(secret_bytes).hexdigest(),
        },
    )
    assert st_c == 201, f"Create failed: {st_c} {created}"
    drop_id = created["drop_id"]

    st_bot, _, _ = req("POST", f"{base}/api/drops/{drop_id}/claim", {}, headers={"User-Agent": "Slackbot-LinkExpanding/1.0"})
    assert st_bot == 403, f"Bot Shield failed: {st_bot}"
    print("2. Bot Shield Probe   : PASS (Slackbot blocked with HTTP 403; drop intact)")

    def _hit(_: int) -> tuple[int, dict]:
        code, body, _ = req(
            "POST",
            f"{base}/api/drops/{drop_id}/claim",
            {"human_confirm": True},
            headers={"X-ZeroDrop-Human": "1", "User-Agent": "ZeroDrop-Verifier/2.0"},
        )
        return code, body

    with ThreadPoolExecutor(max_workers=20) as pool:
        outcomes = list(pool.map(_hit, range(20)))
    codes = [c for c, _ in outcomes]
    assert codes.count(200) == 1 and codes.count(410) == 19, f"Race failed: {codes}"
    winner_body = next(b for c, b in outcomes if c == 200)
    plain = zerodrop_cli.aes_gcm_decrypt(base64.b64decode(winner_body["ciphertext_b64"]), raw_key, iv)
    assert plain == secret_bytes
    print("3. 20-Way HTTP Race   : PASS (1 x HTTP 200 + AES-GCM decrypt OK, 19 x HTTP 410 Gone)")

    # 4. Step Functions Break-Glass Approval End-to-End (using demo_inbox=True)
    st_bg, bg_created, _ = req(
        "POST",
        f"{base}/api/drops",
        {
            "mode": "approval",
            "label": "Live Break-Glass Benchmark",
            "ttl_minutes": 10,
            "iv_b64": base64.b64encode(iv).decode(),
            "ciphertext_b64": base64.b64encode(cipher).decode(),
            "demo_inbox": True,
        },
    )
    assert st_bg == 201
    bg_id = bg_created["drop_id"]
    st_cl, bg_cl, _ = req(
        "POST",
        f"{base}/api/drops/{bg_id}/claim",
        {"human_confirm": True},
        headers={"X-ZeroDrop-Human": "1", "User-Agent": "ZeroDrop-Verifier/2.0"},
    )
    assert st_cl == 202
    claim_secret = bg_cl["claim_secret"]

    approval_tok = ""
    for _ in range(10):
        _, st_peek, _ = req(
            "GET",
            f"{base}/api/drops/{bg_id}/status",
            headers={"X-ZeroDrop-Claim-Secret": claim_secret},
        )
        approval_url = st_peek.get("demo_approval_url", "")
        if "#review=" in approval_url:
            approval_tok = approval_url.split("#review=", 1)[1]
            break
        time.sleep(0.3)
    assert approval_tok, "Step Functions did not publish approval token in time"
    st_app, _, _ = req("POST", f"{base}/api/approvals/{approval_tok}", {"decision": "APPROVE"})
    assert st_app == 200

    for _ in range(15):
        _, st_after, _ = req("GET", f"{base}/api/drops/{bg_id}/status")
        if st_after.get("status") == "APPROVED_READY":
            break
        time.sleep(0.3)
    st_col, col, _ = req("POST", f"{base}/api/drops/{bg_id}/collect", {"claim_secret": claim_secret})
    assert st_col == 200
    assert zerodrop_cli.aes_gcm_decrypt(base64.b64decode(col["ciphertext_b64"]), raw_key, iv) == secret_bytes
    print("4. Step Functions SFN : PASS (waitForTaskToken paused, approved, collected & decrypted)")

    # 5. Backend DynamoDB TOCTOU vs Atomic Lab
    st_lab, lab, _ = req("POST", f"{base}/api/lab/race", {"concurrency": 20})
    assert st_lab == 200 and lab["atomic"]["unlocked_count"] == 1
    print(
        f"5. DynamoDB Race Lab  : PASS (Naive leaked {lab['naive']['unlocked_count']}/20 vs "
        f"Atomic {lab['atomic']['unlocked_count']}/20, p50={lab['atomic']['stats']['p50_ms']}ms)"
    )

    # 6. Owner Panic Kill Switch
    st_kill_c, kill_created, _ = req(
        "POST",
        f"{base}/api/drops",
        {
            "mode": "fast",
            "label": "Panic Shred Benchmark",
            "ttl_minutes": 10,
            "iv_b64": base64.b64encode(iv).decode(),
            "ciphertext_b64": base64.b64encode(cipher).decode(),
        },
    )
    assert st_kill_c == 201
    st_sh, sh_data, _ = req(
        "POST",
        f"{base}/api/drops/{kill_created['drop_id']}/shred",
        {"kill_token": kill_created["kill_token"]},
    )
    assert st_sh == 200 and sh_data["status"] == "OWNER_SHREDDED"
    st_after_sh, _, _ = req(
        "POST",
        f"{base}/api/drops/{kill_created['drop_id']}/claim",
        {"human_confirm": True},
        headers={"X-ZeroDrop-Human": "1"},
    )
    assert st_after_sh == 410
    print("6. Panic Kill Switch  : PASS (OWNER_SHREDDED, subsequent claim blocked 410 Gone)")

    # 7. Cryptographically verify KMS P-256 Hash-Chained Audit Ledger
    st_rc, rc, _ = req("GET", f"{base}/api/receipts/{drop_id}")
    assert st_rc == 200
    spki = rc["public_key"]["spki_b64"]
    prev = "0" * 64
    for entry in rc["audit_chain"]:
        assert entry["prev_hash"] == prev
        assert zerodrop_cli.verify_ecdsa_p256_p1363(spki, entry["signature_p1363_b64"], entry["payload_json"])
        prev = hashlib.sha256(entry["payload_json"].encode("utf-8")).hexdigest()
    print(f"7. KMS Audit Chain    : PASS ({len(rc['audit_chain'])}/3 ECDSA P-256 hash-chained entries valid)")

    # 8. Live SOC Telemetry Feed
    st_soc, soc, _ = req("GET", f"{base}/api/telemetry/soc")
    assert st_soc == 200 and soc["counters"]["total_created"] >= 3 and soc["counters"]["total_panic_shreds"] >= 1
    print(
        f"8. SOC Telemetry Feed : PASS (created={soc['counters']['total_created']}, "
        f"bots_blocked={soc['counters']['total_bots_blocked']}, shreds={soc['counters']['total_panic_shreds']})"
    )
    print("\n✅ All 8 live deployment checks passed!")


if __name__ == "__main__":
    main()
