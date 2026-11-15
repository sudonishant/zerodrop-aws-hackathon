"""AWS Lambda HTTP API handler for ZeroDrop."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Tuple

from common import (
    ALERTS_TOPIC_ARN,
    KMS_KEY_ID,
    STATE_MACHINE_ARN,
    VAULT_BUCKET,
    aws_client,
    aws_table,
    detect_preview_bot,
    get_backend,
    get_signing_public_key,
    hash_ip,
    is_conditional_check_failed,
    log_event,
    make_chain_entry,
    new_token,
    record_soc_event,
    safe_filename,
    sign_receipt,
    utc_epoch,
    utc_now_iso,
)

MAX_TEXT_CIPHER_B64_LEN = 256 * 1024  # ~190 KB encrypted text secret
MAX_FILE_BYTES = 25 * 1024 * 1024     # 25 MB encrypted blob via S3 Presigned PUT
MIN_TTL_MIN = 5
MAX_TTL_MIN = 7 * 24 * 60             # 7 days

DROP_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,32}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


def _response(status: int, body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-ZeroDrop-Human",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body, default=str),
    }


def _parse_json_body(event: Dict[str, Any]) -> Dict[str, Any]:
    raw = event.get("body") or ""
    if not raw:
        return {}
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("JSON body must be an object")
    return parsed


def _get_headers(event: Dict[str, Any]) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (event.get("headers") or {}).items()}


def _get_client_meta(event: Dict[str, Any], headers: Dict[str, str]) -> Tuple[str, str]:
    http_ctx = (event.get("requestContext") or {}).get("http") or {}
    source_ip = http_ctx.get("sourceIp") or headers.get("x-forwarded-for", "").split(",")[0].strip() or "unknown"
    ua = headers.get("user-agent", "unknown")[:200]
    return hash_ip(source_ip), ua


def _get_review_base_url(headers: Dict[str, str]) -> str:
    del headers  # Request headers are untrusted and must not influence emailed bearer links.
    base_url = os.environ.get("REVIEW_BASE_URL", "").rstrip("/")
    if base_url.startswith("https://") or base_url.startswith("http://localhost") or base_url.startswith("http://127.0.0.1"):
        return base_url
    return ""


def _presign_s3_put(s3_key: str, content_type: str = "application/octet-stream") -> str:
    if not VAULT_BUCKET:
        return ""
    return aws_client("s3").generate_presigned_url(
        "put_object",
        Params={"Bucket": VAULT_BUCKET, "Key": s3_key, "ContentType": content_type},
        ExpiresIn=120,
    )


def _presign_s3_get(s3_key: str, filename: str) -> str:
    if not VAULT_BUCKET or not s3_key or s3_key == "noop/empty":
        return ""
    return aws_client("s3").generate_presigned_url(
        "get_object",
        Params={
            "Bucket": VAULT_BUCKET,
            "Key": s3_key,
            "ResponseContentDisposition": f'attachment; filename="{safe_filename(filename)}.enc"',
        },
        ExpiresIn=60,
    )


def _delete_s3_object(s3_key: str) -> bool:
    if not VAULT_BUCKET or not s3_key or s3_key == "noop/empty":
        return False
    try:
        aws_client("s3").delete_object(Bucket=VAULT_BUCKET, Key=s3_key)
        return True
    except Exception:
        return False


def _send_canary_sns_alert(drop_id: str, label: str, reason: str, ip_hash: str, ua: str) -> None:
    if not ALERTS_TOPIC_ARN:
        return
    try:
        aws_client("sns").publish(
            TopicArn=ALERTS_TOPIC_ARN,
            Subject=f"[ZeroDrop CANARY ALERT] Tripwire triggered: {label[:40]}",
            Message=(
                f"ZeroDrop Canary Tripwire Triggered!\n"
                f"------------------------------------\n"
                f"Drop ID   : {drop_id}\n"
                f"Label     : {label}\n"
                f"Reason    : {reason}\n"
                f"Actor IP  : sha256:{ip_hash}\n"
                f"User-Agent: {ua}\n"
                f"Time (UTC): {utc_now_iso()}\n"
            ),
        )
    except Exception as exc:
        print(f"Canary SNS alert warning: {exc}")


def _append_audit_entry(
    table: Any,
    drop_id: str,
    event_name: str,
    actor_ip_hash: str,
    detail: str,
    extra: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    item = table.get_item(Key={"drop_id": drop_id}).get("Item") or {}
    chain = list(item.get("audit_chain") or [])
    entry = make_chain_entry(chain, drop_id, event_name, actor_ip_hash, detail, extra)
    chain.append(entry)
    table.update_item(
        Key={"drop_id": drop_id},
        UpdateExpression="SET audit_chain = :ch",
        ExpressionAttributeValues={":ch": chain},
    )
    return chain


def _handle_health() -> Dict[str, Any]:
    pub = get_signing_public_key()
    return _response(
        200,
        {
            "ok": True,
            "service": "ZeroDrop",
            "version": "4.0",
            "local_emulator": get_backend() is not None,
            "kms_enabled": bool(KMS_KEY_ID) or (get_backend() is not None and "kms" in (get_backend() or {})),
            "kms_fingerprint": (pub.get("fingerprint_sha256") or "")[:16],
            "step_functions_enabled": bool(STATE_MACHINE_ARN) or (get_backend() is not None and "stepfunctions" in (get_backend() or {})),
            "timestamp": utc_now_iso(),
        },
    )


def _handle_public_key() -> Dict[str, Any]:
    return _response(200, get_signing_public_key())


def _handle_create_drop(event: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    try:
        data = _parse_json_body(event)
    except Exception as exc:
        return _response(400, {"error": "INVALID_JSON", "message": str(exc)})

    mode = str(data.get("mode", "fast")).lower()
    if mode not in ("fast", "approval"):
        return _response(400, {"error": "INVALID_MODE", "message": "mode must be 'fast' or 'approval'"})

    has_file = bool(data.get("has_file", False))
    ciphertext_b64 = str(data.get("ciphertext_b64") or "")
    iv_b64 = str(data.get("iv_b64") or "")
    label = str(data.get("label") or "Confidential Drop").strip()[:120] or "Confidential Drop"
    payload_sha256 = str(data.get("payload_sha256") or "")[:64]
    demo_inbox = bool(data.get("demo_inbox", False))
    canary_alert = bool(data.get("canary_alert", False))

    passphrase_check = data.get("passphrase_check")
    if passphrase_check is not None:
        if not isinstance(passphrase_check, dict) or not passphrase_check.get("iv_b64") or not passphrase_check.get("ct_b64"):
            return _response(400, {"error": "INVALID_PASSPHRASE_CHECK"})
        check_iv_b64 = str(passphrase_check["iv_b64"])
        check_ct_b64 = str(passphrase_check["ct_b64"])
        if len(check_iv_b64) > 64 or len(check_ct_b64) > 256:
            return _response(400, {"error": "INVALID_PASSPHRASE_CHECK"})
        try:
            check_iv = base64.b64decode(check_iv_b64, validate=True)
            check_ct = base64.b64decode(check_ct_b64, validate=True)
        except (ValueError, UnicodeError):
            return _response(400, {"error": "INVALID_PASSPHRASE_CHECK"})
        if len(check_iv) != 12 or len(check_ct) < 16:
            return _response(400, {"error": "INVALID_PASSPHRASE_CHECK"})
        passphrase_check = {
            "iv_b64": check_iv_b64,
            "ct_b64": check_ct_b64,
        }

    quorum = data.get("quorum")
    if quorum is not None:
        if not isinstance(quorum, dict):
            return _response(400, {"error": "INVALID_QUORUM"})
        try:
            q_m = int(quorum.get("threshold", 2))
            q_n = int(quorum.get("total", 3))
        except (TypeError, ValueError):
            return _response(400, {"error": "INVALID_QUORUM"})
        if q_m < 2 or q_n < q_m or q_n > 10:
            return _response(400, {"error": "INVALID_QUORUM", "message": "Quorum requires 2 <= threshold <= total <= 10"})
        quorum = {"threshold": q_m, "total": q_n}

    try:
        ttl_minutes = int(data.get("ttl_minutes", 60))
    except (TypeError, ValueError):
        return _response(400, {"error": "INVALID_TTL", "message": "ttl_minutes must be an integer"})
    ttl_minutes = max(MIN_TTL_MIN, min(MAX_TTL_MIN, ttl_minutes))

    try:
        iv_bytes = base64.b64decode(iv_b64, validate=True)
    except (ValueError, UnicodeError):
        return _response(400, {"error": "INVALID_IV", "message": "iv_b64 must be valid Base64"})
    if len(iv_bytes) != 12:
        return _response(400, {"error": "INVALID_IV", "message": "AES-GCM IV must be exactly 12 bytes"})

    filename = ""
    file_size = 0
    mime_type = "application/octet-stream"
    s3_key = "noop/empty"
    presigned_put_url = ""

    drop_id = new_token(9)

    if has_file:
        filename = safe_filename(str(data.get("filename") or "secret.bin"))
        try:
            file_size = int(data.get("file_size", 0))
        except (TypeError, ValueError):
            file_size = 0
        if file_size <= 0 or file_size > MAX_FILE_BYTES:
            return _response(400, {"error": "INVALID_FILE_SIZE", "message": f"Encrypted file must be 1 byte to {MAX_FILE_BYTES} bytes"})
        mime_type = str(data.get("mime_type") or "application/octet-stream")[:80]
        s3_key = f"vault/{drop_id}/{filename}.enc"
        presigned_put_url = _presign_s3_put(s3_key, "application/octet-stream")
    else:
        if not ciphertext_b64 or len(ciphertext_b64) > MAX_TEXT_CIPHER_B64_LEN:
            return _response(400, {"error": "INVALID_CIPHERTEXT", "message": "ciphertext_b64 is required (max 256 KB)"})
        try:
            ciphertext_bytes = base64.b64decode(ciphertext_b64, validate=True)
        except (ValueError, UnicodeError):
            return _response(400, {"error": "INVALID_CIPHERTEXT", "message": "ciphertext_b64 must be valid Base64"})
        if len(ciphertext_bytes) < 16:
            return _response(400, {"error": "INVALID_CIPHERTEXT", "message": "AES-GCM ciphertext must include a 16-byte authentication tag"})

    now_iso = utc_now_iso()
    now_epoch = utc_epoch()
    ttl_epoch = now_epoch + ttl_minutes * 60
    ip_hash, _ = _get_client_meta(event, headers)
    kill_token = new_token(18)
    kill_token_hash = hashlib.sha256(kill_token.encode("utf-8")).hexdigest()

    genesis_entry = make_chain_entry(
        [],
        drop_id,
        "DROP_CREATED",
        ip_hash,
        f"Created {mode} drop (file={has_file}, passphrase={bool(passphrase_check)}, canary={canary_alert}, quorum={bool(quorum)})",
        {"payload_sha256": payload_sha256, "ttl_minutes": ttl_minutes},
    )

    item: Dict[str, Any] = {
        "drop_id": drop_id,
        "status": "READY",
        "mode": mode,
        "label": label,
        "iv_b64": iv_b64,
        "has_file": has_file,
        "s3_key": s3_key,
        "filename": filename,
        "file_size": file_size,
        "mime_type": mime_type,
        "payload_sha256": payload_sha256,
        "demo_inbox": demo_inbox,
        "canary_alert": canary_alert,
        "kill_token_hash": kill_token_hash,
        "creator_ip_hash": ip_hash,
        "bot_shield_hits": 0,
        "shred_state": "ACTIVE",
        "created_at": now_iso,
        "ttl_epoch": ttl_epoch,
        "audit_chain": [genesis_entry],
    }
    if passphrase_check is not None:
        item["passphrase_check"] = passphrase_check
    if quorum is not None:
        item["quorum"] = quorum
    if not has_file:
        item["ciphertext_b64"] = ciphertext_b64

    table = aws_table()
    table.put_item(Item=item)
    log_event("DROP_CREATED", drop_id=drop_id, mode=mode, has_file=has_file, canary=canary_alert, quorum=bool(quorum))
    record_soc_event(
        table,
        "DROP_CREATED",
        drop_id,
        f"{mode} drop created (quorum={bool(quorum)}, canary={canary_alert})",
        ip_hash,
        "total_created",
        genesis_entry["entry_sha256"],
    )

    return _response(
        201,
        {
            "drop_id": drop_id,
            "status": "READY",
            "mode": mode,
            "label": label,
            "has_file": has_file,
            "has_passphrase": passphrase_check is not None,
            "quorum": quorum,
            "canary_alert": canary_alert,
            "kill_token": kill_token,
            "s3_key": s3_key if has_file else "",
            "presigned_put_url": presigned_put_url,
            "created_at": now_iso,
            "expires_epoch": ttl_epoch,
            "chain_head_sha256": genesis_entry["entry_sha256"],
            "zero_knowledge": True,
        },
    )


def _handle_get_status(drop_id: str, event: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    if not DROP_ID_RE.match(drop_id):
        return _response(400, {"error": "INVALID_DROP_ID"})

    table = aws_table()
    item = table.get_item(Key={"drop_id": drop_id}).get("Item")
    if not item:
        return _response(404, {"error": "NOT_FOUND", "message": "Drop not found or TTL expired."})

    ip_hash, ua = _get_client_meta(event, headers)
    bot_name = detect_preview_bot(ua)
    bot_hits = int(item.get("bot_shield_hits", 0))
    if bot_name:
        try:
            upd = table.update_item(
                Key={"drop_id": drop_id},
                UpdateExpression="SET bot_shield_hits = if_not_exists(bot_shield_hits, :z) + :one, last_bot_seen = :bot",
                ExpressionAttributeValues={":z": 0, ":one": 1, ":bot": bot_name},
                ReturnValues="UPDATED_NEW",
            )
            bot_hits = int((upd.get("Attributes") or {}).get("bot_shield_hits", bot_hits + 1))
            _append_audit_entry(table, drop_id, "BOT_PEEK_IGNORED", ip_hash, f"Preview crawler '{bot_name}' served safe metadata only")
        except Exception:
            pass

    now_epoch = utc_epoch()
    ttl_epoch = int(item.get("ttl_epoch", 0))
    status = item.get("status", "UNKNOWN")
    if ttl_epoch and ttl_epoch <= now_epoch and status == "READY":
        status = "EXPIRED"

    out: Dict[str, Any] = {
        "drop_id": drop_id,
        "status": status,
        "mode": item.get("mode", "fast"),
        "label": item.get("label", ""),
        "has_file": bool(item.get("has_file", False)),
        "filename": item.get("filename", ""),
        "file_size": int(item.get("file_size", 0)),
        "has_passphrase": bool(item.get("passphrase_check")),
        "passphrase_check": item.get("passphrase_check"),
        "iv_b64": item.get("iv_b64", "") if item.get("passphrase_check") else "",
        "quorum": item.get("quorum"),
        "canary_alert": bool(item.get("canary_alert", False)),
        "created_at": item.get("created_at", ""),
        "expires_epoch": ttl_epoch,
        "burned_at": item.get("burned_at", ""),
        "shred_state": item.get("shred_state", "ACTIVE"),
        "bot_shield_hits": bot_hits,
        "bot_detected": bot_name,
        "has_receipt": bool(item.get("receipt")) or bool(item.get("audit_chain")),
        "chain_length": len(item.get("audit_chain") or []),
    }
    if item.get("demo_inbox") and status == "PENDING_APPROVAL" and item.get("demo_approval_url"):
        out["demo_approval_url"] = item["demo_approval_url"]
        out["demo_approval_token"] = item.get("demo_approval_token", "")

    return _response(200, out)


def _handle_claim_drop(drop_id: str, event: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    if not DROP_ID_RE.match(drop_id):
        return _response(400, {"error": "INVALID_DROP_ID"})

    try:
        data = _parse_json_body(event)
    except Exception:
        data = {}

    ip_hash, ua = _get_client_meta(event, headers)
    simulated_bot = str(data.get("simulated_bot") or "")[:100]
    human_header = headers.get("x-zerodrop-human") == "1" or bool(data.get("human_confirm"))
    bot_name = detect_preview_bot(ua if not simulated_bot else simulated_bot)

    table = aws_table()
    if bot_name and not human_header:
        peek_bot = table.get_item(Key={"drop_id": drop_id}).get("Item") or {}
        try:
            table.update_item(
                Key={"drop_id": drop_id},
                UpdateExpression="SET bot_shield_hits = if_not_exists(bot_shield_hits, :z) + :one, last_bot_seen = :bot",
                ExpressionAttributeValues={":z": 0, ":one": 1, ":bot": bot_name},
            )
            if peek_bot:
                ch_bot = _append_audit_entry(table, drop_id, "BOT_SHIELD_BLOCKED", ip_hash, f"Blocked crawler '{bot_name}' from burning secret")
                log_event("BOT_SHIELD_BLOCKED", drop_id=drop_id, bot=bot_name, canary=bool(peek_bot.get("canary_alert")))
                record_soc_event(
                    table,
                    "BOT_SHIELD_BLOCKED",
                    drop_id,
                    f"Blocked '{bot_name}' crawler before secret burn",
                    ip_hash,
                    "total_bots_blocked",
                    ch_bot[-1]["entry_sha256"] if ch_bot else "",
                )
                if peek_bot.get("canary_alert"):
                    log_event("CANARY_TRIPWIRE", drop_id=drop_id, actor=bot_name)
                    record_soc_event(table, "CANARY_TRIPWIRE", drop_id, f"Canary tripwire tripped by {bot_name}", ip_hash, "total_canary_alerts")
                    _send_canary_sns_alert(drop_id, peek_bot.get("label", ""), f"Blocked bot probe: {bot_name}", ip_hash, ua)
        except Exception:
            pass
        return _response(
            403,
            {
                "error": "BOT_SHIELD_BLOCKED",
                "bot": bot_name,
                "message": f"Bot Shield stopped '{bot_name}' from burning this secret.",
            },
        )

    peek = table.get_item(Key={"drop_id": drop_id}).get("Item")
    if not peek:
        return _response(404, {"error": "NOT_FOUND", "message": "Drop not found or expired."})

    mode = peek.get("mode", "fast")
    now_iso = utc_now_iso()
    now_epoch = utc_epoch()

    if mode == "fast":
        peek_has_file = bool(peek.get("has_file", False))
        file_shred_token = new_token(18) if peek_has_file else ""
        update_expression = "SET #st = :burned, burned_at = :now, shred_state = :shredded, claimer_ip_hash = :iph, claimer_ua = :ua REMOVE ciphertext_b64"
        expression_values = {
            ":burned": "BURNED",
            ":ready": "READY",
            ":shredded": "PENDING_FILE_SHRED" if peek_has_file else "SHREDDED",
            ":now": now_iso,
            ":iph": ip_hash,
            ":ua": ua,
            ":now_epoch": now_epoch,
        }
        if file_shred_token:
            update_expression = update_expression.replace(
                " REMOVE ciphertext_b64",
                ", file_shred_token_hash = :file_shred_hash REMOVE ciphertext_b64",
            )
            expression_values[":file_shred_hash"] = hashlib.sha256(file_shred_token.encode("utf-8")).hexdigest()
        try:
            res = table.update_item(
                Key={"drop_id": drop_id},
                UpdateExpression=update_expression,
                ConditionExpression="#st = :ready AND attribute_not_exists(burned_at) AND ttl_epoch > :now_epoch",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues=expression_values,
                ReturnValues="ALL_OLD",
            )
        except Exception as exc:
            if is_conditional_check_failed(exc):
                return _response(
                    410,
                    {
                        "error": "ALREADY_BURNED_OR_EXPIRED",
                        "message": "This secret was already claimed and shredded, or has expired.",
                    },
                )
            raise

        old_item = res.get("Attributes") or {}
        has_file = bool(old_item.get("has_file", False))
        s3_key = str(old_item.get("s3_key") or "noop/empty")
        filename = str(old_item.get("filename") or "secret.bin")
        presigned_get_url = _presign_s3_get(s3_key, filename) if has_file else ""

        existing_chain = list(old_item.get("audit_chain") or [])
        burn_entry = make_chain_entry(
            existing_chain,
            drop_id,
            "BURNED_ONCE",
            ip_hash,
            "Secret atomically claimed via DynamoDB ConditionExpression and ciphertext scrubbed",
            {
                "payload_sha256": old_item.get("payload_sha256", ""),
                "bot_shield_hits": int(old_item.get("bot_shield_hits", 0)),
            },
        )
        existing_chain.append(burn_entry)

        receipt_payload = {
            "drop_id": drop_id,
            "label": old_item.get("label", ""),
            "mode": "fast",
            "outcome": "BURNED_ONCE",
            "created_at": old_item.get("created_at", ""),
            "burned_at": now_iso,
            "claimer_ip_hash": ip_hash,
            "payload_sha256": old_item.get("payload_sha256", ""),
            "bot_shield_hits": int(old_item.get("bot_shield_hits", 0)),
            "chain_head_sha256": burn_entry["entry_sha256"],
            "shred_state": "PENDING_FILE_SHRED" if has_file else "SHREDDED",
        }
        receipt = sign_receipt(receipt_payload)

        try:
            table.update_item(
                Key={"drop_id": drop_id},
                UpdateExpression="SET receipt = :rcpt, audit_chain = :ch",
                ExpressionAttributeValues={":rcpt": receipt, ":ch": existing_chain},
            )
        except Exception:
            pass

        if old_item.get("canary_alert"):
            log_event("CANARY_TRIPWIRE", drop_id=drop_id, actor="human_claim")
            record_soc_event(table, "CANARY_TRIPWIRE", drop_id, "Canary honeypot unlocked", ip_hash, "total_canary_alerts", burn_entry["entry_sha256"])
            _send_canary_sns_alert(drop_id, old_item.get("label", ""), "Canary drop unlocked (BURNED_ONCE)", ip_hash, ua)
        log_event("DROP_BURNED", drop_id=drop_id, mode="fast", has_file=has_file)
        record_soc_event(table, "BURNED_ONCE", drop_id, "Fast atomic burn completed once", ip_hash, "total_burned", burn_entry["entry_sha256"])

        return _response(
            200,
            {
                "drop_id": drop_id,
                "status": "BURNED",
                "shred_state": "PENDING_FILE_SHRED" if has_file else "SHREDDED",
                "mode": "fast",
                "label": old_item.get("label", ""),
                "iv_b64": old_item.get("iv_b64", ""),
                "ciphertext_b64": old_item.get("ciphertext_b64", ""),
                "has_file": has_file,
                "filename": filename,
                "mime_type": old_item.get("mime_type", "application/octet-stream"),
                "presigned_get_url": presigned_get_url,
                "file_shred_token": file_shred_token,
                "receipt": receipt,
                "audit_chain": existing_chain,
            },
        )

    # Approval-gated Break-Glass mode
    claim_secret = new_token(18)
    claim_secret_hash = hashlib.sha256(claim_secret.encode("utf-8")).hexdigest()

    try:
        res = table.update_item(
            Key={"drop_id": drop_id},
            UpdateExpression=(
                "SET #st = :pending, requested_at = :now, claim_secret_hash = :csh, "
                "requester_ip_hash = :iph, requester_ua = :ua"
            ),
            ConditionExpression="#st = :ready AND attribute_not_exists(burned_at) AND ttl_epoch > :now_epoch",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":pending": "PENDING_APPROVAL",
                ":ready": "READY",
                ":now": now_iso,
                ":csh": claim_secret_hash,
                ":iph": ip_hash,
                ":ua": ua,
                ":now_epoch": now_epoch,
            },
            ReturnValues="ALL_NEW",
        )
    except Exception as exc:
        if is_conditional_check_failed(exc):
            return _response(
                409,
                {
                    "error": "ALREADY_REQUESTED_OR_BURNED",
                    "message": "Break-glass approval was already requested or this drop has already burned.",
                },
            )
        raise

    updated_item = res.get("Attributes") or {}
    ch_req = _append_audit_entry(table, drop_id, "APPROVAL_REQUESTED", ip_hash, "Started Step Functions waitForTaskToken workflow")
    record_soc_event(table, "APPROVAL_REQUESTED", drop_id, "Step Functions paused awaiting owner decision", ip_hash, "total_approvals", ch_req[-1]["entry_sha256"])

    if updated_item.get("canary_alert"):
        log_event("CANARY_TRIPWIRE", drop_id=drop_id, actor="approval_request")
        record_soc_event(table, "CANARY_TRIPWIRE", drop_id, "Canary break-glass request triggered", ip_hash, "total_canary_alerts")
        _send_canary_sns_alert(drop_id, updated_item.get("label", ""), "Canary Break-Glass unlock requested", ip_hash, ua)
    log_event("APPROVAL_REQUESTED", drop_id=drop_id)

    sfn_input = {
        "drop_id": drop_id,
        "label": updated_item.get("label", "Confidential Drop"),
        "mode": "approval",
        "has_file": bool(updated_item.get("has_file", False)),
        "s3_key": str(updated_item.get("s3_key") or "noop/empty"),
        "requester_ip_hash": ip_hash,
        "requester_ua": ua,
        "review_base_url": _get_review_base_url(headers),
        "demo_inbox": bool(updated_item.get("demo_inbox", False)),
    }

    sfn = aws_client("stepfunctions")
    exec_name = f"zd-{drop_id}-{now_epoch}-{new_token(3)}"[:80]
    exec_res = sfn.start_execution(
        stateMachineArn=STATE_MACHINE_ARN or "arn:aws:states:us-east-1:000000000000:stateMachine:ZeroDropLocal",
        name=exec_name,
        input=json.dumps(sfn_input),
    )
    execution_arn = exec_res.get("executionArn", "")

    table.update_item(
        Key={"drop_id": drop_id},
        UpdateExpression="SET execution_arn = :earn",
        ExpressionAttributeValues={":earn": execution_arn},
    )

    return _response(
        202,
        {
            "drop_id": drop_id,
            "status": "PENDING_APPROVAL",
            "mode": "approval",
            "claim_secret": claim_secret,
            "execution_arn": execution_arn,
            "message": "Step Functions workflow paused at $0 idle cost awaiting owner approval.",
        },
    )


def _handle_collect_approved(drop_id: str, event: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    if not DROP_ID_RE.match(drop_id):
        return _response(400, {"error": "INVALID_DROP_ID"})

    try:
        data = _parse_json_body(event)
    except Exception as exc:
        return _response(400, {"error": "INVALID_JSON", "message": str(exc)})

    claim_secret = str(data.get("claim_secret") or "")
    if not claim_secret:
        return _response(400, {"error": "MISSING_CLAIM_SECRET"})

    claim_secret_hash = hashlib.sha256(claim_secret.encode("utf-8")).hexdigest()
    now_iso = utc_now_iso()
    ip_hash, _ = _get_client_meta(event, headers)
    table = aws_table()

    peek = table.get_item(Key={"drop_id": drop_id}).get("Item")
    if not peek:
        return _response(404, {"error": "NOT_FOUND"})
    peek_has_file = bool(peek.get("has_file", False))
    if not peek_has_file and not peek.get("ciphertext_b64"):
        return _response(410, {"error": "ALREADY_SHREDDED", "message": "Grace period elapsed and Step Functions already shredded this secret."})

    update_expression = "SET #st = :burned, burned_at = :now, shred_state = :shredded"
    if peek_has_file:
        update_expression += ", file_shred_token_hash = :csh"
    update_expression += " REMOVE ciphertext_b64"
    update_values = {
        ":burned": "BURNED",
        ":approved": "APPROVED_READY",
        ":shredded": "PENDING_FILE_SHRED" if peek_has_file else "SHREDDED",
        ":csh": claim_secret_hash,
        ":now": now_iso,
    }
    try:
        res = table.update_item(
            Key={"drop_id": drop_id},
            UpdateExpression=update_expression,
            ConditionExpression="#st = :approved AND claim_secret_hash = :csh AND attribute_not_exists(burned_at)",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues=update_values,
            ReturnValues="ALL_OLD",
        )
    except Exception as exc:
        if is_conditional_check_failed(exc):
            return _response(403, {"error": "NOT_APPROVED_OR_ALREADY_COLLECTED"})
        raise

    old_item = res.get("Attributes") or {}
    has_file = bool(old_item.get("has_file", False))
    s3_key = str(old_item.get("s3_key") or "noop/empty")
    filename = str(old_item.get("filename") or "secret.bin")
    presigned_get_url = _presign_s3_get(s3_key, filename) if has_file else ""
    chain = _append_audit_entry(table, drop_id, "BURNED_ONCE", ip_hash, "Approved recipient collected payload once; ciphertext scrubbed")
    record_soc_event(
        table,
        "BURNED_ONCE",
        drop_id,
        "Break-glass approved secret collected once",
        ip_hash,
        "total_burned",
        chain[-1]["entry_sha256"] if chain else "",
    )

    return _response(
        200,
        {
            "drop_id": drop_id,
            "status": "BURNED",
            "shred_state": "PENDING_FILE_SHRED" if has_file else "SHREDDED",
            "mode": "approval",
            "label": old_item.get("label", ""),
            "iv_b64": old_item.get("iv_b64", ""),
            "ciphertext_b64": old_item.get("ciphertext_b64", ""),
            "has_file": has_file,
            "filename": filename,
            "mime_type": old_item.get("mime_type", "application/octet-stream"),
            "presigned_get_url": presigned_get_url,
            "receipt": old_item.get("receipt"),
            "audit_chain": chain,
        },
    )


def _handle_confirm_shred(drop_id: str, event: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    if not DROP_ID_RE.match(drop_id):
        return _response(400, {"error": "INVALID_DROP_ID"})
    try:
        data = _parse_json_body(event)
    except Exception:
        return _response(400, {"error": "INVALID_JSON"})
    file_shred_token = str(data.get("file_shred_token") or "")
    if not file_shred_token:
        return _response(400, {"error": "MISSING_FILE_SHRED_TOKEN"})
    table = aws_table()
    item = table.get_item(Key={"drop_id": drop_id}).get("Item")
    if not item:
        return _response(404, {"error": "NOT_FOUND"})
    if not item.get("has_file") or item.get("status") != "BURNED" or item.get("shred_state") != "PENDING_FILE_SHRED":
        return _response(409, {"error": "FILE_NOT_READY_TO_SHRED"})
    token_hash = hashlib.sha256(file_shred_token.encode("utf-8")).hexdigest()
    expected_hash = str(item.get("file_shred_token_hash") or "")
    if not expected_hash or not hmac.compare_digest(expected_hash, token_hash):
        return _response(403, {"error": "INVALID_FILE_SHRED_TOKEN"})

    ip_hash, _ = _get_client_meta(event, headers)
    s3_key = str(item.get("s3_key") or "noop/empty")
    deleted = _delete_s3_object(s3_key)
    if not deleted:
        return _response(502, {"error": "S3_DELETE_FAILED", "shred_state": "PENDING_FILE_SHRED"})
    try:
        table.update_item(
            Key={"drop_id": drop_id},
            UpdateExpression="SET shred_state = :shredded, shredded_at = :now",
            ConditionExpression="#st = :burned AND shred_state = :pending AND file_shred_token_hash = :token_hash",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":burned": "BURNED",
                ":pending": "PENDING_FILE_SHRED",
                ":shredded": "SHREDDED",
                ":now": utc_now_iso(),
                ":token_hash": token_hash,
            },
        )
    except Exception as exc:
        if is_conditional_check_failed(exc):
            return _response(409, {"error": "FILE_ALREADY_SHREDDED"})
        raise
    _append_audit_entry(table, drop_id, "S3_SHREDDED", ip_hash, f"Encrypted S3 blob '{s3_key}' deleted immediately after browser decrypt")
    return _response(200, {"drop_id": drop_id, "s3_deleted": deleted, "shred_state": "SHREDDED"})


def _handle_owner_panic_shred(drop_id: str, event: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    """Immediate owner-initiated kill switch: scrubs ciphertext, S3 blob, SFN execution & signs KMS ledger."""
    if not DROP_ID_RE.match(drop_id):
        return _response(400, {"error": "INVALID_DROP_ID"})
    try:
        data = _parse_json_body(event)
    except Exception as exc:
        return _response(400, {"error": "INVALID_JSON", "message": str(exc)})

    kill_token = str(data.get("kill_token") or "")
    if not kill_token:
        return _response(400, {"error": "MISSING_KILL_TOKEN"})

    table = aws_table()
    peek = table.get_item(Key={"drop_id": drop_id}).get("Item")
    if not peek:
        return _response(404, {"error": "NOT_FOUND"})

    expected_hash = str(peek.get("kill_token_hash") or "")
    provided_hash = hashlib.sha256(kill_token.encode("utf-8")).hexdigest()
    if not expected_hash or not hmac.compare_digest(expected_hash, provided_hash):
        return _response(403, {"error": "INVALID_KILL_TOKEN", "message": "Invalid owner kill token."})

    now_iso = utc_now_iso()
    ip_hash, _ = _get_client_meta(event, headers)

    try:
        res = table.update_item(
            Key={"drop_id": drop_id},
            UpdateExpression="SET #st = :shred_st, shred_state = :shredded, burned_at = :now, shredded_at = :now REMOVE ciphertext_b64",
            ConditionExpression="attribute_exists(drop_id) AND #st <> :burned AND #st <> :denied AND #st <> :shred_st",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":shred_st": "OWNER_SHREDDED",
                ":shredded": "SHREDDED",
                ":burned": "BURNED",
                ":denied": "DENIED_SHREDDED",
                ":now": now_iso,
            },
            ReturnValues="ALL_OLD",
        )
    except Exception as exc:
        if is_conditional_check_failed(exc):
            return _response(409, {"error": "ALREADY_TERMINATED", "message": "Drop was already burned, denied, or shredded."})
        raise

    old_item = res.get("Attributes") or {}
    s3_key = str(old_item.get("s3_key") or "noop/empty")
    s3_deleted = _delete_s3_object(s3_key) if old_item.get("has_file") else False

    exec_arn = str(old_item.get("execution_arn") or "")
    if exec_arn:
        try:
            aws_client("stepfunctions").stop_execution(
                executionArn=exec_arn,
                error="OwnerPanicShred",
                cause=f"Owner triggered immediate panic kill switch at {now_iso}",
            )
        except Exception:
            pass

    chain = list(old_item.get("audit_chain") or [])
    kill_entry = make_chain_entry(
        chain,
        drop_id,
        "OWNER_PANIC_SHREDDED",
        ip_hash,
        "Owner invoked instant kill switch; ciphertext scrubbed, S3 deleted, Step Functions halted",
        {"s3_deleted": s3_deleted},
    )
    chain.append(kill_entry)

    receipt = sign_receipt(
        {
            "drop_id": drop_id,
            "label": old_item.get("label", ""),
            "mode": old_item.get("mode", "fast"),
            "outcome": "OWNER_PANIC_SHREDDED",
            "created_at": old_item.get("created_at", ""),
            "shredded_at": now_iso,
            "actor_ip_hash": ip_hash,
            "chain_head_sha256": kill_entry["entry_sha256"],
            "shred_state": "SHREDDED",
        }
    )
    table.update_item(
        Key={"drop_id": drop_id},
        UpdateExpression="SET receipt = :rcpt, audit_chain = :ch",
        ExpressionAttributeValues={":rcpt": receipt, ":ch": chain},
    )

    if ALERTS_TOPIC_ARN:
        try:
            aws_client("sns").publish(
                TopicArn=ALERTS_TOPIC_ARN,
                Subject=f"[ZeroDrop PANIC SHRED] Drop {drop_id} destroyed by owner",
                Message=f"ZeroDrop Kill Switch activated for {drop_id} ({old_item.get('label', '')}) at {now_iso}.",
            )
        except Exception:
            pass

    log_event("OWNER_PANIC_SHREDDED", drop_id=drop_id, s3_deleted=s3_deleted)
    record_soc_event(
        table,
        "OWNER_PANIC_SHREDDED",
        drop_id,
        "Owner triggered immediate panic kill switch",
        ip_hash,
        "total_panic_shreds",
        kill_entry["entry_sha256"],
    )
    return _response(
        200,
        {
            "drop_id": drop_id,
            "status": "OWNER_SHREDDED",
            "shred_state": "SHREDDED",
            "s3_deleted": s3_deleted,
            "receipt": receipt,
            "audit_chain": chain,
        },
    )


def _handle_get_approval(token: str) -> Dict[str, Any]:
    if not TOKEN_RE.match(token):
        return _response(400, {"error": "INVALID_TOKEN"})
    table = aws_table()
    item = table.get_item(Key={"drop_id": f"APPROVAL#{token}"}).get("Item")
    if not item:
        return _response(404, {"error": "APPROVAL_NOT_FOUND"})
    return _response(
        200,
        {
            "token": token,
            "target_drop_id": item.get("target_drop_id", ""),
            "label": item.get("label", ""),
            "requester_ip_hash": item.get("requester_ip_hash", ""),
            "requester_ua": item.get("requester_ua", ""),
            "created_at": item.get("created_at", ""),
            "consumed_at": item.get("consumed_at", ""),
            "decision": item.get("decision", ""),
        },
    )


def _handle_post_approval(token: str, event: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    if not TOKEN_RE.match(token):
        return _response(400, {"error": "INVALID_TOKEN"})
    try:
        data = _parse_json_body(event)
    except Exception as exc:
        return _response(400, {"error": "INVALID_JSON", "message": str(exc)})

    decision = str(data.get("decision", "")).upper()
    if decision not in ("APPROVE", "DENY"):
        return _response(400, {"error": "INVALID_DECISION", "message": "decision must be APPROVE or DENY"})

    table = aws_table()
    now_iso = utc_now_iso()
    ip_hash, _ = _get_client_meta(event, headers)
    try:
        res = table.update_item(
            Key={"drop_id": f"APPROVAL#{token}"},
            UpdateExpression="SET consumed_at = :now, decision = :dec",
            ConditionExpression="attribute_exists(task_token) AND attribute_not_exists(consumed_at)",
            ExpressionAttributeValues={":now": now_iso, ":dec": decision},
            ReturnValues="ALL_OLD",
        )
    except Exception as exc:
        if is_conditional_check_failed(exc):
            return _response(409, {"error": "APPROVAL_ALREADY_USED_OR_MISSING"})
        raise

    old_item = res.get("Attributes") or {}
    task_token = old_item["task_token"]
    target_drop_id = old_item["target_drop_id"]
    sfn = aws_client("stepfunctions")

    if decision == "APPROVE":
        sfn.send_task_success(
            taskToken=task_token,
            output=json.dumps({"decision": "APPROVE", "approved_at": now_iso}),
        )
    else:
        ch_den = _append_audit_entry(table, target_drop_id, "OWNER_DENIED", ip_hash, "Owner denied break-glass access; Step Functions ParallelDenyShred triggered")
        record_soc_event(
            table,
            "OWNER_DENIED",
            target_drop_id,
            "Owner denied break-glass request; SFN parallel shred triggered",
            ip_hash,
            None,
            ch_den[-1]["entry_sha256"] if ch_den else "",
        )
        sfn.send_task_failure(
            taskToken=task_token,
            error="DeniedByOwner",
            cause=f"Owner denied break-glass request at {now_iso}",
        )

    return _response(
        200,
        {
            "ok": True,
            "decision": decision,
            "target_drop_id": target_drop_id,
            "processed_at": now_iso,
        },
    )


def _handle_get_receipt(drop_id: str) -> Dict[str, Any]:
    if not DROP_ID_RE.match(drop_id):
        return _response(400, {"error": "INVALID_DROP_ID"})
    item = aws_table().get_item(Key={"drop_id": drop_id}).get("Item")
    if not item:
        return _response(404, {"error": "NOT_FOUND"})
    receipt = item.get("receipt")
    audit_chain = item.get("audit_chain") or []
    if not receipt and not audit_chain:
        return _response(404, {"error": "RECEIPT_NOT_READY", "status": item.get("status", "")})
    return _response(
        200,
        {
            "drop_id": drop_id,
            "status": item.get("status", ""),
            "shred_state": item.get("shred_state", ""),
            "receipt": receipt,
            "audit_chain": audit_chain,
            "public_key": get_signing_public_key(),
        },
    )


def _latency_stats(results: List[Dict[str, Any]]) -> Dict[str, float]:
    vals = sorted(float(r["ms"]) for r in results)
    if not vals:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    p50 = vals[len(vals) // 2]
    p95 = vals[min(len(vals) - 1, int(len(vals) * 0.95))]
    return {"p50_ms": p50, "p95_ms": p95, "max_ms": vals[-1]}


def _handle_race_lab(event: Dict[str, Any]) -> Dict[str, Any]:
    """Run a live 20-thread DynamoDB concurrency race comparing Naive vs Atomic ConditionExpression."""
    try:
        data = _parse_json_body(event)
    except Exception:
        data = {}

    concurrency = max(5, min(30, int(data.get("concurrency", 20))))
    table = aws_table()
    ttl_epoch = utc_epoch() + 300
    run_id = new_token(6)
    naive_id = f"RACE_NAIVE_{run_id}"
    atomic_id = f"RACE_ATOMIC_{run_id}"

    table.put_item(
        Item={
            "drop_id": naive_id,
            "status": "READY",
            "ciphertext_b64": "SECRET_PAYLOAD_SHOULD_READ_ONCE",
            "ttl_epoch": ttl_epoch,
        }
    )
    table.put_item(
        Item={
            "drop_id": atomic_id,
            "status": "READY",
            "ciphertext_b64": "SECRET_PAYLOAD_SHOULD_READ_ONCE",
            "ttl_epoch": ttl_epoch,
        }
    )

    def _attempt_naive(idx: int) -> Dict[str, Any]:
        t0 = time.perf_counter()
        item = table.get_item(Key={"drop_id": naive_id}).get("Item") or {}
        if item.get("status") == "READY":
            time.sleep(0.02)
            table.update_item(
                Key={"drop_id": naive_id},
                UpdateExpression="SET #st = :b",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":b": "BURNED"},
            )
            ms = round((time.perf_counter() - t0) * 1000, 1)
            return {"worker": idx, "result": "UNLOCKED", "ms": ms}
        ms = round((time.perf_counter() - t0) * 1000, 1)
        return {"worker": idx, "result": "BLOCKED", "ms": ms}

    def _attempt_atomic(idx: int) -> Dict[str, Any]:
        t0 = time.perf_counter()
        try:
            table.update_item(
                Key={"drop_id": atomic_id},
                UpdateExpression="SET #st = :b, burned_by = :w REMOVE ciphertext_b64",
                ConditionExpression="#st = :r AND attribute_not_exists(burned_by)",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":b": "BURNED", ":r": "READY", ":w": idx},
                ReturnValues="ALL_OLD",
            )
            ms = round((time.perf_counter() - t0) * 1000, 1)
            return {"worker": idx, "result": "UNLOCKED", "ms": ms}
        except Exception as exc:
            ms = round((time.perf_counter() - t0) * 1000, 1)
            if is_conditional_check_failed(exc):
                return {"worker": idx, "result": "BLOCKED_410", "ms": ms}
            return {"worker": idx, "result": f"ERROR:{exc}", "ms": ms}

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        naive_results: List[Dict[str, Any]] = list(pool.map(_attempt_naive, range(1, concurrency + 1)))
        atomic_results: List[Dict[str, Any]] = list(pool.map(_attempt_atomic, range(1, concurrency + 1)))

    naive_unlocked = sum(1 for r in naive_results if r["result"] == "UNLOCKED")
    atomic_unlocked = sum(1 for r in atomic_results if r["result"] == "UNLOCKED")

    return _response(
        200,
        {
            "run_id": run_id,
            "concurrency": concurrency,
            "naive": {
                "unlocked_count": naive_unlocked,
                "blocked_count": concurrency - naive_unlocked,
                "stats": _latency_stats(naive_results),
                "results": naive_results,
                "verdict": f"RACE LEAK: {naive_unlocked}/{concurrency} callers extracted the one-time secret!",
            },
            "atomic": {
                "unlocked_count": atomic_unlocked,
                "blocked_count": concurrency - atomic_unlocked,
                "stats": _latency_stats(atomic_results),
                "results": atomic_results,
                "verdict": f"SAFE: {atomic_unlocked}/{concurrency} unlocked; {concurrency - atomic_unlocked} atomically blocked (410 Gone).",
            },
        },
    )


def _handle_get_soc() -> Dict[str, Any]:
    item = aws_table().get_item(Key={"drop_id": "TELEMETRY#GLOBAL"}).get("Item") or {}
    return _response(
        200,
        {
            "counters": {
                "total_created": int(item.get("total_created", 0)),
                "total_burned": int(item.get("total_burned", 0)),
                "total_bots_blocked": int(item.get("total_bots_blocked", 0)),
                "total_canary_alerts": int(item.get("total_canary_alerts", 0)),
                "total_panic_shreds": int(item.get("total_panic_shreds", 0)),
                "total_approvals": int(item.get("total_approvals", 0)),
            },
            "events": item.get("events") or [],
            "updated_at": item.get("updated_at", ""),
            "kms_fingerprint": (get_signing_public_key().get("fingerprint_sha256") or "")[:16],
            "idle_cost_usd": 0.0,
        },
    )


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    http_ctx = (event.get("requestContext") or {}).get("http") or {}
    method = str(http_ctx.get("method") or event.get("httpMethod") or "GET").upper()
    path = str(event.get("rawPath") or event.get("path") or "/")
    headers = _get_headers(event)

    if method == "OPTIONS":
        return _response(204, {})

    try:
        if method == "GET" and path == "/api/health":
            return _handle_health()
        if method == "GET" and path == "/api/public-key":
            return _handle_public_key()
        if method == "GET" and path == "/api/telemetry/soc":
            return _handle_get_soc()
        if method == "POST" and path == "/api/drops":
            return _handle_create_drop(event, headers)
        if method == "POST" and path == "/api/lab/race" and get_backend() is not None:
            return _handle_race_lab(event)

        m_status = re.match(r"^/api/drops/([^/]+)/status$", path)
        if method == "GET" and m_status:
            return _handle_get_status(m_status.group(1), event, headers)

        m_claim = re.match(r"^/api/drops/([^/]+)/claim$", path)
        if method == "POST" and m_claim:
            return _handle_claim_drop(m_claim.group(1), event, headers)

        m_collect = re.match(r"^/api/drops/([^/]+)/collect$", path)
        if method == "POST" and m_collect:
            return _handle_collect_approved(m_collect.group(1), event, headers)

        m_shred = re.match(r"^/api/drops/([^/]+)/confirm-shred$", path)
        if method == "POST" and m_shred:
            return _handle_confirm_shred(m_shred.group(1), event, headers)

        m_kill = re.match(r"^/api/drops/([^/]+)/shred$", path)
        if method == "POST" and m_kill:
            return _handle_owner_panic_shred(m_kill.group(1), event, headers)

        m_receipt = re.match(r"^/api/receipts/([^/]+)$", path)
        if method == "GET" and m_receipt:
            return _handle_get_receipt(m_receipt.group(1))

        m_approval = re.match(r"^/api/approvals/([^/]+)$", path)
        if m_approval:
            if method == "GET":
                return _handle_get_approval(m_approval.group(1))
            if method == "POST":
                return _handle_post_approval(m_approval.group(1), event, headers)

        return _response(404, {"error": "ROUTE_NOT_FOUND", "method": method, "path": path})
    except Exception as exc:
        return _response(500, {"error": "INTERNAL_ERROR", "message": str(exc)})
