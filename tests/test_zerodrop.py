"""Local automated verification suite for ZeroDrop v4.0 APEX (run with pytest)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "cli"))

import api_handler   # noqa: E402
import zerodrop_cli  # noqa: E402
from local_server import build_local_backend  # noqa: E402


def _call_api(method: str, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    event = {
        "rawPath": path,
        "requestContext": {"http": {"method": method, "sourceIp": "203.0.113.42"}},
        "headers": {"host": "d123.cloudfront.net", **(headers or {})},
        "body": json.dumps(body) if body is not None else "",
        "isBase64Encoded": False,
    }
    res = api_handler.lambda_handler(event)
    parsed = json.loads(res["body"]) if res.get("body") else {}
    return res["statusCode"], parsed


def _verify_p1363_with_node(spki_b64: str, sig_p1363_b64: str, payload_json: str) -> bool:
    js = r"""
const { webcrypto } = require('node:crypto');
const [spkiB64, sigB64, msg] = process.argv.slice(1);
(async () => {
  const pub = await webcrypto.subtle.importKey(
    'spki',
    Buffer.from(spkiB64, 'base64'),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
  const ok = await webcrypto.subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    pub,
    Buffer.from(sigB64, 'base64'),
    Buffer.from(msg, 'utf8')
  );
  process.stdout.write(ok ? 'TRUE' : 'FALSE');
})();
"""
    res = subprocess.run(
        ["node", "-e", js, spki_b64, sig_p1363_b64, payload_json],
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout.strip() == "TRUE"


def test_unlock_metadata_is_carried_in_secret_fragment_not_status() -> None:
    html = (ROOT / "web" / "index.html").read_text()
    start = html.index("function buildShareUrl(")
    end = html.index("\n}\n", start) + 2
    builder = html[start:end]
    js = f"""
globalThis.window = {{ location: {{ origin: "https://zerodrop.example" }} }};
{builder}
const url = new URL(buildShareUrl(
  "drop123", "k", "url-key", "drop-iv",
  {{ iv_b64: "check-iv", ct_b64: "check-ct" }},
  {{ threshold: 2, total: 3 }}
));
if (url.search) throw new Error("metadata must not be sent as query parameters");
const params = new URLSearchParams(url.hash.slice(1));
for (const [key, expected] of Object.entries({{
  d: "drop123", k: "url-key", iv: "drop-iv", p: "1",
  pci: "check-iv", pcc: "check-ct", qm: "2", qn: "3"
}})) {{
  if (params.get(key) !== expected) throw new Error(`bad ${{key}} fragment value`);
}}
"""
    subprocess.run(["node", "-e", js], check=True, capture_output=True, text=True)
    assert "activePassphraseCheck = d.passphrase_check" not in html
    assert "activeDropIvB64 = d.iv_b64" not in html
    open_start = html.index("function openGeneratedDrop()")
    open_end = html.index("\n}\n", open_start) + 2
    open_helper = html[open_start:open_end]
    assert 'window.location.hash = lastShareUrl.split("#")[1];' in open_helper
    assert "const suffix =" not in open_helper


def test_receipt_endpoint_fails_closed_on_legacy_private_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    legacy_receipt_payload = {
        "drop_id": "legacy123",
        "label": "PRIVATE_LABEL_SHOULD_NOT_LEAK",
        "outcome": "BURNED_ONCE",
        "claimer_ip_hash": "PRIVATE_IP_HASH_SHOULD_NOT_LEAK",
    }
    legacy_entry_payload = {
        "seq": 1,
        "drop_id": "legacy123",
        "event": "DROP_CREATED",
        "timestamp": "2026-01-01T00:00:00Z",
        "prev_hash": "0" * 64,
        "actor_ip_hash": "PRIVATE_ACTOR_HASH_SHOULD_NOT_LEAK",
        "detail": "PRIVATE_DETAIL_SHOULD_NOT_LEAK",
        "meta": {"payload_sha256": "PRIVATE_CONTENT_HASH_SHOULD_NOT_LEAK"},
    }
    legacy_rows = [
        {
            "drop_id": "legacy123",
            "receipt": {
                "payload": legacy_receipt_payload,
                "payload_json": json.dumps(legacy_receipt_payload),
                "payload_sha256": "0" * 64,
                "signature_p1363_b64": "",
                "key_id": "legacy",
                "algorithm": "ECDSA_P256_SHA256",
                "signed_at": "2026-01-01T00:00:00Z",
            },
            "audit_chain": [],
        },
        {
            "drop_id": "legacy123",
            "audit_chain": [{
                "seq": 1,
                "event": "DROP_CREATED",
                "prev_hash": "0" * 64,
                "entry_sha256": "0" * 64,
                "payload": legacy_entry_payload,
                "payload_json": json.dumps(legacy_entry_payload),
                "signature_p1363_b64": "",
                "key_id": "legacy",
                "algorithm": "ECDSA_P256_SHA256",
            }],
        },
    ]

    class FakeTable:
        def __init__(self, row: dict) -> None:
            self.row = row

        def get_item(self, **_kwargs: object) -> dict:
            return {"Item": self.row}

    for row in legacy_rows:
        monkeypatch.setattr(api_handler, "aws_table", lambda row=row: FakeTable(row))
        response = api_handler._handle_get_receipt("legacy123")
        body = json.loads(response["body"])
        assert response["statusCode"] == 409
        assert body["error"] == "RECEIPT_REDACTED_FOR_PRIVACY"
        rendered = json.dumps(body)
        assert "PRIVATE_" not in rendered
        assert "payload_sha256" not in rendered


def test_sam_asl_loggroups_and_cloudwatch_dashboard() -> None:
    asl = json.loads((ROOT / "statemachine" / "approval_shred.asl.json").read_text())
    assert asl["StartAt"] == "NotifyAndAwaitApproval"
    assert "waitForTaskToken" in asl["States"]["NotifyAndAwaitApproval"]["Resource"]
    assert asl["States"]["ParallelApproveShred"]["Type"] == "Parallel"
    assert asl["States"]["ParallelDenyShred"]["Type"] == "Parallel"
    assert asl["States"]["ParallelApproveShred"]["Next"] == "NotifyApproveShredComplete"
    assert asl["States"]["ParallelDenyShred"]["Next"] == "NotifyDeniedOrExpired"
    assert len(asl["States"]["ParallelApproveShred"]["Branches"]) == 2
    assert len(asl["States"]["ParallelDenyShred"]["Branches"]) == 2
    deny_s3 = asl["States"]["ParallelDenyShred"]["Branches"][1]["States"]["DeleteS3BlobOnDeny"]
    assert deny_s3["Retry"][0]["MaxAttempts"] == 3

    class CFNLoader(yaml.SafeLoader):
        pass

    for tag in ("!Ref", "!Sub", "!GetAtt", "!Not", "!Equals"):
        CFNLoader.add_constructor(tag, lambda loader, node: str(node.value))

    tpl = yaml.load((ROOT / "template.yaml").read_text(), Loader=CFNLoader)
    for res_name in (
        "DropsTable",
        "ApprovalStateMachine",
        "SigningKey",
        "CloudFrontDistribution",
        "VaultBucketPolicy",
        "ApiFunctionLogGroup",
        "WorkflowTaskFunctionLogGroup",
        "ZeroDropOpsDashboard",
        "BotShieldBlockedMetricFilter",
        "CanaryTripwireMetricFilter",
        "PanicShredMetricFilter",
        "CanaryTripwireAlarm",
    ):
        assert res_name in tpl["Resources"]

    # Ensure ApiFunction has SNS publish permissions, PanicShred + SOC routes, states:StopExecution, and LoggingConfig
    api_props = tpl["Resources"]["ApiFunction"]["Properties"]
    assert "LoggingConfig" in api_props
    assert "PanicShred" in api_props["Events"]
    assert "GetSocTelemetry" in api_props["Events"]
    assert "RaceLab" not in api_props["Events"]
    assert "DynamoDBCrudPolicy" not in str(api_props["Policies"])
    assert "S3CrudPolicy" not in str(api_props["Policies"])
    assert any("SNSPublishMessagePolicy" in p for p in api_props["Policies"] if isinstance(p, dict))
    assert "Default" not in tpl["Parameters"]["IpHashSalt"]
    stop_policy = next(
        statement
        for policy in api_props["Policies"]
        if isinstance(policy, dict) and "Statement" in policy
        for statement in policy["Statement"]
        if "states:StopExecution" in statement.get("Action", [])
    )
    assert stop_policy["Resource"] != "*"
    assert "!Ref ApiFunction" not in tpl["Resources"]["ApiFunctionLogGroup"]["Properties"]["LogGroupName"]
    assert "$default" in tpl["Resources"]["ZeroDropOpsDashboard"]["Properties"]["DashboardBody"]
    assert os.access(ROOT / "deploy.sh", os.X_OK)


def test_fast_burn_bot_shield_and_hash_chained_kms_ledger() -> None:
    build_local_backend(grace_seconds=0.2)

    st, created = _call_api(
        "POST",
        "/api/drops",
        {
            "mode": "fast",
            "label": "Stripe Production Key",
            "ttl_minutes": 30,
            "iv_b64": base64.b64encode(b"123456789012").decode(),
            "ciphertext_b64": base64.b64encode(b"X" * 32).decode(),
            "payload_sha256": "deadbeef" * 8,
            "canary_alert": True,
            "quorum": {"threshold": 2, "total": 3},
            "passphrase_check": {
                "iv_b64": base64.b64encode(b"999999999999").decode(),
                "ct_b64": base64.b64encode(b"X" * 32).decode(),
            },
        },
    )
    assert st == 201
    assert created["has_passphrase"] is True
    assert created["canary_alert"] is True
    drop_id = created["drop_id"]

    # Preview bot hitting /claim without human header must be blocked (403) and logged to audit chain
    st_bot, bot_body = _call_api(
        "POST",
        f"/api/drops/{drop_id}/claim",
        {},
        headers={"User-Agent": "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"},
    )
    assert st_bot == 403
    assert bot_body["error"] == "BOT_SHIELD_BLOCKED"

    # Safe status peek verifies passphrase metadata & bot block count
    st_peek, peek = _call_api("GET", f"/api/drops/{drop_id}/status")
    assert st_peek == 200
    assert peek["status"] == "READY"
    for private_field in (
        "has_passphrase", "passphrase_check", "iv_b64", "quorum", "label",
        "filename", "file_size", "canary_alert", "payload_sha256", "bot_detected",
    ):
        assert private_field not in peek
    assert base64.b64encode(b"X" * 32).decode() not in json.dumps(peek)
    assert peek["bot_shield_hits"] == 1
    assert peek["chain_length"] == 2

    # Human claim succeeds ONCE
    st_claim, claimed = _call_api(
        "POST",
        f"/api/drops/{drop_id}/claim",
        {"human_confirm": True},
        headers={"User-Agent": "Mozilla/5.0", "X-ZeroDrop-Human": "1"},
    )
    assert st_claim == 200
    assert claimed["status"] == "BURNED"

    # Second claim MUST fail with 410 Gone
    st_2nd, _ = _call_api(
        "POST",
        f"/api/drops/{drop_id}/claim",
        {"human_confirm": True},
        headers={"User-Agent": "Mozilla/5.0", "X-ZeroDrop-Human": "1"},
    )
    assert st_2nd == 410

    # Verify EVERY entry in the hash-chained KMS ECDSA P-256 ledger
    st_r, rc = _call_api("GET", f"/api/receipts/{drop_id}")
    assert st_r == 200
    spki = rc["public_key"]["spki_b64"]
    chain = rc["audit_chain"]
    assert [e["event"] for e in chain] == ["DROP_CREATED", "BOT_SHIELD_BLOCKED", "BURNED_ONCE"]
    receipt_payload = json.loads(rc["receipt"]["payload_json"])
    assert set(receipt_payload) == {"drop_id", "outcome", "chain_head_sha256", "shred_state"}
    assert not {"label", "claimer_ip_hash", "payload_sha256", "bot_shield_hits"} & set(receipt_payload)
    for entry in chain:
        signed_payload = json.loads(entry["payload_json"])
        assert set(signed_payload) == {"seq", "drop_id", "event", "timestamp", "prev_hash"}
        assert not {"actor_ip_hash", "detail", "meta"} & set(signed_payload)

    expected_prev = "0" * 64
    for entry in chain:
        assert entry["prev_hash"] == expected_prev
        recomputed = hashlib.sha256(entry["payload_json"].encode("utf-8")).hexdigest()
        assert recomputed == entry["entry_sha256"]
        assert _verify_p1363_with_node(spki, entry["signature_p1363_b64"], entry["payload_json"]) is True
        expected_prev = recomputed

    # Tamper 1 char in entry #1 -> signature fails AND downstream chain link breaks!
    tampered_e1 = chain[0]["payload_json"].replace("DROP_CREATED", "DROP_MODIFIED")
    assert _verify_p1363_with_node(spki, chain[0]["signature_p1363_b64"], tampered_e1) is False
    tampered_hash = hashlib.sha256(tampered_e1.encode("utf-8")).hexdigest()
    assert chain[1]["prev_hash"] != tampered_hash


def test_create_rejects_invalid_aes_metadata() -> None:
    build_local_backend()
    base = {
        "mode": "fast",
        "ttl_minutes": 15,
        "iv_b64": base64.b64encode(b"123456789012").decode(),
        "ciphertext_b64": base64.b64encode(b"X" * 32).decode(),
    }
    invalid_payloads = [
        {**base, "iv_b64": "!!!"},
        {**base, "iv_b64": base64.b64encode(b"short-iv").decode()},
        {**base, "ciphertext_b64": "%%%"},
        {**base, "ciphertext_b64": base64.b64encode(b"short").decode()},
    ]
    for payload in invalid_payloads:
        status, response = _call_api("POST", "/api/drops", payload)
        assert status == 400
        assert response["error"] in {"INVALID_IV", "INVALID_CIPHERTEXT"}


def test_20_way_atomic_concurrency_race() -> None:
    build_local_backend()
    st, race = _call_api("POST", "/api/lab/race", {"concurrency": 20})
    assert st == 200
    assert race["naive"]["unlocked_count"] > 1
    assert race["atomic"]["unlocked_count"] == 1
    assert race["atomic"]["blocked_count"] == 19
    assert "p50_ms" in race["atomic"]["stats"]

    st_c, created = _call_api(
        "POST",
        "/api/drops",
        {
            "mode": "fast",
            "label": "Parallel Drop",
            "ttl_minutes": 15,
            "iv_b64": base64.b64encode(b"123456789012").decode(),
            "ciphertext_b64": base64.b64encode(b"X" * 32).decode(),
        },
    )
    assert st_c == 201
    drop_id = created["drop_id"]

    def _hit(_: int) -> int:
        code, _ = _call_api(
            "POST",
            f"/api/drops/{drop_id}/claim",
            {"human_confirm": True},
            headers={"User-Agent": "Mozilla/5.0", "X-ZeroDrop-Human": "1"},
        )
        return code

    with ThreadPoolExecutor(max_workers=20) as pool:
        codes = list(pool.map(_hit, range(20)))

    assert codes.count(200) == 1
    assert codes.count(410) == 19


def test_step_functions_approval_and_deny_flows() -> None:
    backend = build_local_backend(grace_seconds=0.15)

    st, created = _call_api(
        "POST",
        "/api/drops",
        {
            "mode": "approval",
            "label": "Break-Glass Root Kubeconfig",
            "ttl_minutes": 60,
            "iv_b64": base64.b64encode(b"123456789012").decode(),
            "has_file": True,
            "filename": "prod-kubeconfig.yaml",
            "file_size": 2048,
            "demo_inbox": True,
        },
    )
    assert st == 201
    drop_id = created["drop_id"]
    s3_key = created["s3_key"]
    backend["s3"].put_raw(s3_key, b"ENCRYPTED_FILE_BLOB")

    st_req, req_data = _call_api(
        "POST",
        f"/api/drops/{drop_id}/claim",
        {"human_confirm": True},
        headers={"User-Agent": "Mozilla/5.0", "X-ZeroDrop-Human": "1", "Origin": "https://attacker.example"},
    )
    assert st_req == 202
    claim_secret = req_data["claim_secret"]

    _, anonymous_peek = _call_api("GET", f"/api/drops/{drop_id}/status")
    assert "demo_approval_url" not in anonymous_peek
    assert "demo_approval_token" not in anonymous_peek
    _, invalid_peek = _call_api(
        "GET",
        f"/api/drops/{drop_id}/status",
        headers={"X-ZeroDrop-Claim-Secret": "wrong-capability"},
    )
    assert "demo_approval_url" not in invalid_peek
    _, peek = _call_api(
        "GET",
        f"/api/drops/{drop_id}/status",
        headers={"X-ZeroDrop-Claim-Secret": claim_secret},
    )
    assert peek["demo_approval_url"].startswith("http://127.0.0.1:8787/#review=")
    assert "demo_approval_token" not in peek
    approval_token = peek["demo_approval_url"].split("#review=", 1)[1]
    assert "attacker.example" not in peek["demo_approval_url"]

    st_rev, rev = _call_api("GET", f"/api/approvals/{approval_token}")
    assert st_rev == 200 and rev["decision"] == ""

    st_app, _ = _call_api("POST", f"/api/approvals/{approval_token}", {"decision": "APPROVE"})
    assert st_app == 200

    st_col, col = _call_api("POST", f"/api/drops/{drop_id}/collect", {"claim_secret": claim_secret})
    assert st_col == 200 and col["has_file"] is True
    stored = backend["table"].get_item(Key={"drop_id": drop_id})["Item"]
    assert stored["file_shred_token_hash"] == hashlib.sha256(claim_secret.encode()).hexdigest()

    time.sleep(0.35)
    assert backend["s3"].get_raw(s3_key) is None

    _, rc = _call_api("GET", f"/api/receipts/{drop_id}")
    events = [e["event"] for e in rc["audit_chain"]]
    assert events == ["DROP_CREATED", "APPROVAL_REQUESTED", "OWNER_APPROVED", "BURNED_ONCE"]

    # Deny flow
    _, c2 = _call_api(
        "POST",
        "/api/drops",
        {
            "mode": "approval",
            "label": "Sensitive SSH Key",
            "ttl_minutes": 60,
            "iv_b64": base64.b64encode(b"123456789012").decode(),
            "ciphertext_b64": base64.b64encode(b"X" * 32).decode(),
            "demo_inbox": True,
        },
    )
    d2 = c2["drop_id"]
    _, req2 = _call_api("POST", f"/api/drops/{d2}/claim", {"human_confirm": True}, headers={"User-Agent": "Mozilla/5.0", "X-ZeroDrop-Human": "1"})
    _, p2 = _call_api(
        "GET",
        f"/api/drops/{d2}/status",
        headers={"X-ZeroDrop-Claim-Secret": req2["claim_secret"]},
    )
    approval_token2 = p2["demo_approval_url"].split("#review=", 1)[1]
    _call_api("POST", f"/api/approvals/{approval_token2}", {"decision": "DENY"})
    _, p2_after = _call_api("GET", f"/api/drops/{d2}/status")
    assert p2_after["status"] == "DENIED_SHREDDED"


def test_cli_aes_gcm_and_pbkdf2_webcrypto_parity() -> None:
    key = b"K" * 32
    iv = b"I" * 12
    pt = b"API_KEY=zd_cli_secret_987654321"
    ct = zerodrop_cli.aes_gcm_encrypt(pt, key, iv)
    out = zerodrop_cli.aes_gcm_decrypt(ct, key, iv)
    assert out == pt

    # Verify CLI PBKDF2-SHA256 matches browser WebCrypto subtle.deriveKey byte-for-byte
    key_b64u = zerodrop_cli._b64u_encode(key)
    iv_b64 = base64.b64encode(iv).decode()
    passphrase = "correct-horse-battery-staple"
    py_derived = zerodrop_cli.derive_aes_key(key, key_b64u, passphrase, iv_b64)
    ct_2fa = zerodrop_cli.aes_gcm_encrypt(pt, py_derived, iv)

    js = r"""
const { webcrypto } = require('node:crypto');
const [keyB64u, pass, ivB64, ctB64] = process.argv.slice(1);
(async () => {
  const baseMat = await webcrypto.subtle.importKey(
    'raw', new TextEncoder().encode(keyB64u + ':' + pass), 'PBKDF2', false, ['deriveKey']
  );
  const aesKey = await webcrypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new TextEncoder().encode('zerodrop-kdf-v2:' + ivB64), iterations: 120000, hash: 'SHA-256' },
    baseMat, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );
  const plain = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(ivB64, 'base64') }, aesKey, Buffer.from(ctB64, 'base64')
  );
  process.stdout.write(new TextDecoder().decode(plain));
})();
"""
    res = subprocess.run(
        ["node", "-e", js, key_b64u, passphrase, iv_b64, base64.b64encode(ct_2fa).decode()],
        check=True,
        capture_output=True,
        text=True,
    )
    assert res.stdout == pt.decode()


def test_approved_drop_cannot_be_collected_after_configured_ttl() -> None:
    backend = build_local_backend(grace_seconds=5.0)
    _, created = _call_api(
        "POST",
        "/api/drops",
        {
            "mode": "approval",
            "label": "Synthetic expiry regression",
            "ttl_minutes": 5,
            "iv_b64": base64.b64encode(b"123456789012").decode(),
            "ciphertext_b64": base64.b64encode(b"X" * 32).decode(),
            "demo_inbox": True,
        },
    )
    drop_id = created["drop_id"]
    st_req, req = _call_api(
        "POST",
        f"/api/drops/{drop_id}/claim",
        {"human_confirm": True},
        headers={"X-ZeroDrop-Human": "1"},
    )
    assert st_req == 202
    claim_secret = req["claim_secret"]
    backend["table"].update_item(
        Key={"drop_id": drop_id},
        UpdateExpression="SET #st = :approved, claim_secret_hash = :csh, ttl_epoch = :expired",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":approved": "APPROVED_READY",
            ":csh": hashlib.sha256(claim_secret.encode("utf-8")).hexdigest(),
            ":expired": api_handler.utc_epoch() - 1,
        },
    )

    st_collect, result = _call_api("POST", f"/api/drops/{drop_id}/collect", {"claim_secret": claim_secret})
    assert st_collect == 410 and result["error"] == "EXPIRED"
    stored = backend["table"].get_item(Key={"drop_id": drop_id})["Item"]
    assert stored["status"] == "APPROVED_READY"
    assert stored.get("ciphertext_b64")


def test_file_shred_and_approval_grace_expiry() -> None:
    backend = build_local_backend(grace_seconds=0.1)
    # 1. Fast file drop starts PENDING_FILE_SHRED until confirm-shred is called
    _, c1 = _call_api(
        "POST",
        "/api/drops",
        {
            "mode": "fast",
            "label": "Encrypted SSH Cert",
            "ttl_minutes": 15,
            "iv_b64": base64.b64encode(b"123456789012").decode(),
            "has_file": True,
            "filename": "id_ed25519",
            "file_size": 512,
        },
    )
    d1 = c1["drop_id"]
    backend["s3"].put_raw(c1["s3_key"], b"ENC_CERT")
    st_early, _ = _call_api("POST", f"/api/drops/{d1}/confirm-shred", {})
    assert st_early == 400
    assert backend["s3"].get_raw(c1["s3_key"]) == b"ENC_CERT"
    st_cl, cl = _call_api("POST", f"/api/drops/{d1}/claim", {"human_confirm": True}, headers={"X-ZeroDrop-Human": "1"})
    assert st_cl == 200 and cl["shred_state"] == "PENDING_FILE_SHRED"
    assert cl["file_shred_token"]

    st_bad_sh, _ = _call_api("POST", f"/api/drops/{d1}/confirm-shred", {"file_shred_token": "wrong"})
    assert st_bad_sh == 403
    assert backend["s3"].get_raw(c1["s3_key"]) == b"ENC_CERT"
    st_sh, sh = _call_api("POST", f"/api/drops/{d1}/confirm-shred", {"file_shred_token": cl["file_shred_token"]})
    assert st_sh == 200 and sh["s3_deleted"] is True and sh["shred_state"] == "SHREDDED"
    _, rc = _call_api("GET", f"/api/receipts/{d1}")
    assert [e["event"] for e in rc["audit_chain"]] == ["DROP_CREATED", "BURNED_ONCE", "S3_SHREDDED"]

    # 2. Break-glass text drop collected AFTER grace_seconds elapses returns 410 ALREADY_SHREDDED
    _, c2 = _call_api(
        "POST",
        "/api/drops",
        {
            "mode": "approval",
            "label": "Late Collect Secret",
            "ttl_minutes": 15,
            "iv_b64": base64.b64encode(b"123456789012").decode(),
            "ciphertext_b64": base64.b64encode(b"X" * 32).decode(),
            "demo_inbox": True,
        },
    )
    d2 = c2["drop_id"]
    _, req2 = _call_api("POST", f"/api/drops/{d2}/claim", {"human_confirm": True}, headers={"X-ZeroDrop-Human": "1"})
    _, p2 = _call_api(
        "GET",
        f"/api/drops/{d2}/status",
        headers={"X-ZeroDrop-Claim-Secret": req2["claim_secret"]},
    )
    approval_token = p2["demo_approval_url"].split("#review=", 1)[1]
    _call_api("POST", f"/api/approvals/{approval_token}", {"decision": "APPROVE"})
    time.sleep(0.25)
    st_late, late = _call_api("POST", f"/api/drops/{d2}/collect", {"claim_secret": req2["claim_secret"]})
    assert st_late == 410 and late["error"] == "ALREADY_SHREDDED"


def test_shamir_gf256_quorum_cross_interop_and_panic_shred() -> None:
    backend = build_local_backend(grace_seconds=5.0)
    # 1. Shamir 2-of-3 split in Python CLI, reconstruct in Node JS GF(256) (matches browser UI), and 3-of-5 roundtrip
    raw_key = b"\x00\xff\x13\xab" * 8
    shares = zerodrop_cli.shamir_split(raw_key, 2, 3)
    assert len(shares) == 3
    # Any 1 share cannot reconstruct
    try:
        zerodrop_cli.shamir_combine([shares[0]])
        raise AssertionError("1 share should fail threshold 2")
    except ValueError:
        pass
    # Shares 2 & 3 reconstruct identically in Python AND JS
    assert zerodrop_cli.shamir_combine([shares[1], shares[2]]) == raw_key
    with pytest.raises(ValueError, match="matching threshold"):
        zerodrop_cli.shamir_combine([shares[1], shares[2].replace("3-2-3:", "3-3-3:")])
    with pytest.raises(ValueError, match="Duplicate"):
        zerodrop_cli.shamir_combine([shares[0], shares[0]])

    js_combine = r"""
const [s1, s2] = process.argv.slice(1);
function gfMul(a,b){let p=0;for(let i=0;i<8;i++){if(b&1)p^=a;const hi=a&0x80;a=(a<<1)&0xff;if(hi)a^=0x1b;b>>=1;}return p;}
function gfPow(a,e){let r=1;while(e>0){if(e&1)r=gfMul(r,a);a=gfMul(a,a);e>>=1;}return r;}
function gfDiv(a,b){return a===0?0:gfMul(a,gfPow(b,254));}
function parse(s){const [h,b]=s.split(':');const [x,m,n]=h.split('-').map(Number);const pad='='.repeat((4-b.length%4)%4);return {x,m,n,bytes:Buffer.from(b.replace(/-/g,'+').replace(/_/g,'/')+pad,'base64')};}
const pts=[parse(s1),parse(s2)], m=pts[0].m, len=pts[0].bytes.length, out=Buffer.alloc(len);
for(let b=0;b<len;b++){let acc=0;for(let i=0;i<m;i++){let li=1;for(let j=0;j<m;j++)if(i!==j)li=gfMul(li,gfDiv(pts[j].x,pts[j].x^pts[i].x));acc^=gfMul(pts[i].bytes[b],li);}out[b]=acc;}
process.stdout.write(out.toString('hex'));
"""
    res = subprocess.run(["node", "-e", js_combine, shares[0], shares[2]], check=True, capture_output=True, text=True)
    assert res.stdout.strip() == raw_key.hex()

    # 3-of-5 roundtrip
    s35 = zerodrop_cli.shamir_split(raw_key, 3, 5)
    assert zerodrop_cli.shamir_combine([s35[0], s35[2], s35[4]]) == raw_key

    # 2. Owner Panic Kill Switch on PENDING_APPROVAL file drop halts SFN, deletes S3, signs KMS ledger
    st_c, c = _call_api(
        "POST",
        "/api/drops",
        {
            "mode": "approval",
            "label": "Wrong Slack Channel Drop",
            "ttl_minutes": 30,
            "iv_b64": base64.b64encode(b"123456789012").decode(),
            "has_file": True,
            "filename": "mistake.env",
            "file_size": 128,
            "quorum": {"threshold": 2, "total": 3},
            "demo_inbox": True,
        },
    )
    assert st_c == 201 and c["quorum"] == {"threshold": 2, "total": 3} and c["kill_token"]
    drop_id = c["drop_id"]
    kill_token = c["kill_token"]
    backend["s3"].put_raw(c["s3_key"], b"ENC_MISTAKE")

    # Request unlock -> enters PENDING_APPROVAL
    st_req, _ = _call_api("POST", f"/api/drops/{drop_id}/claim", {"human_confirm": True}, headers={"X-ZeroDrop-Human": "1"})
    assert st_req == 202

    # Wrong kill token rejected 403
    st_bad_kill, _ = _call_api("POST", f"/api/drops/{drop_id}/shred", {"kill_token": "wrong-token"})
    assert st_bad_kill == 403

    # Valid kill token vaporizes everything + signs OWNER_PANIC_SHREDDED
    st_kill, kill_out = _call_api("POST", f"/api/drops/{drop_id}/shred", {"kill_token": kill_token})
    assert st_kill == 200 and kill_out["status"] == "OWNER_SHREDDED" and kill_out["s3_deleted"] is True
    assert backend["s3"].get_raw(c["s3_key"]) is None

    # Repeat kill returns 409 ALREADY_TERMINATED
    st_kill2, _ = _call_api("POST", f"/api/drops/{drop_id}/shred", {"kill_token": kill_token})
    assert st_kill2 == 409

    # KMS ledger contains OWNER_PANIC_SHREDDED and fingerprint_sha256 is present
    _, rc = _call_api("GET", f"/api/receipts/{drop_id}")
    assert rc["public_key"]["fingerprint_sha256"]
    assert rc["audit_chain"][-1]["event"] == "OWNER_PANIC_SHREDDED"

    # SOC single-partition telemetry records counters & events without DynamoDB scans
    st_soc, soc = _call_api("GET", "/api/telemetry/soc")
    assert st_soc == 200
    assert soc["counters"]["total_created"] >= 1
    assert soc["counters"]["total_panic_shreds"] >= 1
    assert soc["counters"]["total_approvals"] >= 1
    assert "events" not in soc
    assert drop_id not in json.dumps(soc)
    assert "actor_ip_hash" not in json.dumps(soc)
