"""Shared helpers, AWS client wrappers, KMS ECDSA signing & hash-chain audit helpers for ZeroDrop."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DROPS_TABLE = os.environ.get("DROPS_TABLE", "zerodrop-drops")
VAULT_BUCKET = os.environ.get("VAULT_BUCKET", "")
KMS_KEY_ID = os.environ.get("KMS_KEY_ID", "")
ALERTS_TOPIC_ARN = os.environ.get("ALERTS_TOPIC_ARN", "")
STATE_MACHINE_ARN = os.environ.get("STATE_MACHINE_ARN", "")
IP_HASH_SALT = os.environ.get("IP_HASH_SALT") or secrets.token_hex(32)

GENESIS_HASH = "0" * 64

KNOWN_PREVIEW_BOTS = (
    "slackbot",
    "discordbot",
    "whatsapp",
    "telegrambot",
    "twitterbot",
    "linkedinbot",
    "facebookexternalhit",
    "facebot",
    "applebot",
    "imessage",
    "googlebot",
    "bingbot",
    "skypeuripreview",
    "mattermost",
    "curl/",
    "python-requests",
    "go-http-client",
    "wget/",
)

_BACKEND_OVERRIDE: Optional[Dict[str, Any]] = None
_CACHED_CLIENTS: Dict[str, Any] = {}
_CACHED_PUBKEY: Optional[Dict[str, str]] = None


def set_backend_override(backend: Optional[Dict[str, Any]]) -> None:
    """Inject in-memory AWS emulation backend for local testing without AWS credentials."""
    global _BACKEND_OVERRIDE, _CACHED_PUBKEY
    _BACKEND_OVERRIDE = backend
    _CACHED_PUBKEY = None


def get_backend() -> Optional[Dict[str, Any]]:
    return _BACKEND_OVERRIDE


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_epoch() -> int:
    return int(time.time())


def hash_ip(ip_addr: str) -> str:
    raw = f"{IP_HASH_SALT}:{ip_addr or 'unknown'}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def detect_preview_bot(user_agent: str) -> Optional[str]:
    ua = (user_agent or "").lower()
    for sig in KNOWN_PREVIEW_BOTS:
        if sig in ua:
            return sig.rstrip("/")
    return None


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64_encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64_decode(val: str) -> bytes:
    return base64.b64decode(val.encode("ascii"))


def der_to_p1363(der_sig: bytes, coord_size: int = 32) -> bytes:
    """Convert ASN.1 DER ECDSA signature (from AWS KMS) into IEEE P1363 r||s for WebCrypto."""
    if len(der_sig) < 8 or der_sig[0] != 0x30:
        raise ValueError("Invalid DER ECDSA signature header")

    idx = 2
    if der_sig[1] & 0x80:
        len_bytes = der_sig[1] & 0x7F
        idx = 2 + len_bytes

    if der_sig[idx] != 0x02:
        raise ValueError("Missing INTEGER tag for r")
    r_len = der_sig[idx + 1]
    r_start = idx + 2
    r_raw = der_sig[r_start : r_start + r_len]

    s_idx = r_start + r_len
    if der_sig[s_idx] != 0x02:
        raise ValueError("Missing INTEGER tag for s")
    s_len = der_sig[s_idx + 1]
    s_start = s_idx + 2
    s_raw = der_sig[s_start : s_start + s_len]

    r_fixed = r_raw.lstrip(b"\x00").rjust(coord_size, b"\x00")
    s_fixed = s_raw.lstrip(b"\x00").rjust(coord_size, b"\x00")
    if len(r_fixed) != coord_size or len(s_fixed) != coord_size:
        raise ValueError("ECDSA coordinate exceeds P-256 size")
    return r_fixed + s_fixed


def p1363_to_der(p1363_sig: bytes, coord_size: int = 32) -> bytes:
    """Convert 64-byte IEEE P1363 r||s signature into ASN.1 DER format."""
    r = p1363_sig[:coord_size].lstrip(b"\x00") or b"\x00"
    s = p1363_sig[coord_size:].lstrip(b"\x00") or b"\x00"
    if r[0] & 0x80:
        r = b"\x00" + r
    if s[0] & 0x80:
        s = b"\x00" + s
    r_tlv = bytes([0x02, len(r)]) + r
    s_tlv = bytes([0x02, len(s)]) + s
    body = r_tlv + s_tlv
    return bytes([0x30, len(body)]) + body


def aws_client(service: str) -> Any:
    if _BACKEND_OVERRIDE is not None:
        return _BACKEND_OVERRIDE[service]
    if service not in _CACHED_CLIENTS:
        import boto3
        from botocore.config import Config

        _CACHED_CLIENTS[service] = boto3.client(service, config=Config(max_pool_connections=35))
    return _CACHED_CLIENTS[service]


def aws_table() -> Any:
    if _BACKEND_OVERRIDE is not None:
        return _BACKEND_OVERRIDE["table"]
    if "table" not in _CACHED_CLIENTS:
        import boto3
        from botocore.config import Config

        _CACHED_CLIENTS["table"] = boto3.resource("dynamodb", config=Config(max_pool_connections=35)).Table(DROPS_TABLE)
    return _CACHED_CLIENTS["table"]


def get_signing_public_key() -> Dict[str, str]:
    """Fetch KMS ECDSA P-256 public key in SPKI base64 + PEM formats (cached per container)."""
    global _CACHED_PUBKEY
    if _CACHED_PUBKEY is not None:
        return _CACHED_PUBKEY

    if _BACKEND_OVERRIDE is not None and "kms" in _BACKEND_OVERRIDE:
        res = _BACKEND_OVERRIDE["kms"].get_public_key(KeyId=KMS_KEY_ID or "local-ephemeral-p256")
        spki_der = res["PublicKey"]
        key_id = res.get("KeyId", "local-ephemeral-p256")
    elif KMS_KEY_ID:
        kms = aws_client("kms")
        res = kms.get_public_key(KeyId=KMS_KEY_ID)
        spki_der = res["PublicKey"]
        key_id = res.get("KeyId", KMS_KEY_ID)
    else:
        return {
            "key_id": "disabled",
            "algorithm": "SHA256_UNKEYED",
            "spki_b64": "",
            "fingerprint_sha256": "",
            "pem": "",
        }

    spki_b64 = b64_encode(spki_der)
    fingerprint_sha256 = hashlib.sha256(spki_der).hexdigest()
    lines = [spki_b64[i : i + 64] for i in range(0, len(spki_b64), 64)]
    pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----"
    _CACHED_PUBKEY = {
        "key_id": key_id,
        "algorithm": "ECDSA_P256_SHA256",
        "spki_b64": spki_b64,
        "fingerprint_sha256": fingerprint_sha256,
        "pem": pem,
    }
    return _CACHED_PUBKEY


def sign_receipt(receipt_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Create canonical SHA-256 digest and sign it with AWS KMS ECC_NIST_P256."""
    payload_bytes = canonical_json(receipt_payload)
    digest = hashlib.sha256(payload_bytes).digest()
    digest_hex = digest.hex()

    if _BACKEND_OVERRIDE is not None and "kms" in _BACKEND_OVERRIDE:
        kms = _BACKEND_OVERRIDE["kms"]
        sig_res = kms.sign(
            KeyId=KMS_KEY_ID or "local-ephemeral-p256",
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        der_sig = sig_res["Signature"]
        p1363_sig = der_to_p1363(der_sig)
        key_id = sig_res.get("KeyId", "local-ephemeral-p256")
        alg = "ECDSA_P256_SHA256"
    elif KMS_KEY_ID:
        kms = aws_client("kms")
        sig_res = kms.sign(
            KeyId=KMS_KEY_ID,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        der_sig = sig_res["Signature"]
        p1363_sig = der_to_p1363(der_sig)
        key_id = sig_res.get("KeyId", KMS_KEY_ID)
        alg = "ECDSA_P256_SHA256"
    else:
        der_sig = b""
        p1363_sig = b""
        key_id = "disabled"
        alg = "SHA256_ONLY"

    return {
        "payload": receipt_payload,
        "payload_json": payload_bytes.decode("utf-8"),
        "payload_sha256": digest_hex,
        "signature_der_b64": b64_encode(der_sig) if der_sig else "",
        "signature_p1363_b64": b64_encode(p1363_sig) if p1363_sig else "",
        "key_id": key_id,
        "algorithm": alg,
        "signed_at": utc_now_iso(),
    }


def make_chain_entry(
    existing_chain: Optional[List[Dict[str, Any]]],
    drop_id: str,
    event_name: str,
    actor_ip_hash: str,
    detail: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a tamper-evident hash-chained, KMS-signed audit ledger entry."""
    chain = existing_chain or []
    seq = len(chain) + 1
    prev_hash = chain[-1]["entry_sha256"] if chain else GENESIS_HASH
    body: Dict[str, Any] = {
        "seq": seq,
        "drop_id": drop_id,
        "event": event_name,
        "timestamp": utc_now_iso(),
        "actor_ip_hash": actor_ip_hash,
        "detail": detail,
        "prev_hash": prev_hash,
    }
    if extra:
        body["meta"] = extra
    signed = sign_receipt(body)
    return {
        "seq": seq,
        "event": event_name,
        "prev_hash": prev_hash,
        "entry_sha256": signed["payload_sha256"],
        "payload": body,
        "payload_json": signed["payload_json"],
        "signature_p1363_b64": signed["signature_p1363_b64"],
        "signature_der_b64": signed["signature_der_b64"],
        "key_id": signed["key_id"],
        "algorithm": signed["algorithm"],
    }


def is_conditional_check_failed(exc: Exception) -> bool:
    """Detect DynamoDB ConditionalCheckFailedException across boto3 & local emulator."""
    if getattr(exc, "code", None) == "ConditionalCheckFailedException":
        return True
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        err = response.get("Error", {})
        if err.get("Code") == "ConditionalCheckFailedException":
            return True
    return "ConditionalCheckFailed" in str(exc)


def new_token(nbytes: int = 12) -> str:
    tok = secrets.token_urlsafe(nbytes)
    if tok and tok[0] in "-_":
        tok = secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") + tok[1:]
    return tok


def log_event(event_type: str, **fields: Any) -> None:
    """Emit structured JSON log line for CloudWatch Logs Insights & Metric Filters."""
    payload = {"ts": utc_now_iso(), "service": "ZeroDrop", "event_type": event_type, **fields}
    print(json.dumps(payload, separators=(",", ":"), default=str))


SOC_PK = "TELEMETRY#GLOBAL"


def record_soc_event(
    table: Any,
    event_name: str,
    drop_id: str,
    detail: str,
    actor_ip_hash: str,
    counter_attr: Optional[str] = None,
    kms_head: str = "",
) -> None:
    """Record anonymized security telemetry onto the single-item SOC partition (zero DynamoDB scans)."""
    try:
        cur = table.get_item(Key={"drop_id": SOC_PK}).get("Item") or {}
        events = list(cur.get("events") or [])
        events.insert(
            0,
            {
                "ts": utc_now_iso(),
                "event": event_name,
                "drop_id": drop_id,
                "detail": detail[:140],
                "actor_ip_hash": actor_ip_hash,
                "kms_head": kms_head[:16] if kms_head else "",
            },
        )
        events = events[:30]
        expr = "SET events = :ev, updated_at = :ts"
        vals: Dict[str, Any] = {":ev": events, ":ts": utc_now_iso()}
        if counter_attr:
            expr += f", {counter_attr} = if_not_exists({counter_attr}, :z) + :one"
            vals[":z"] = 0
            vals[":one"] = 1
        table.update_item(
            Key={"drop_id": SOC_PK},
            UpdateExpression=expr,
            ExpressionAttributeValues=vals,
        )
    except Exception:
        pass


def safe_filename(name: str) -> str:
    cleaned = "".join(c if (c.isalnum() or c in "._-") else "_" for c in (name or "secret.bin"))
    return cleaned[:80] or "secret.bin"
