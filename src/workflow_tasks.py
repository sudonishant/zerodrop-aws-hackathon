"""AWS Step Functions task handler for ZeroDrop break-glass approval & KMS audit receipts."""

from __future__ import annotations

from typing import Any, Dict

from common import (
    ALERTS_TOPIC_ARN,
    aws_client,
    aws_table,
    log_event,
    make_chain_entry,
    new_token,
    record_soc_event,
    sign_receipt,
    utc_epoch,
    utc_now_iso,
)


def _handle_notify_approval(event: Dict[str, Any]) -> Dict[str, Any]:
    """Store TaskToken under a short scanner-safe approval token and notify owner via Amazon SNS."""
    drop_id = str(event["drop_id"])
    task_token = str(event["task_token"])
    label = str(event.get("label") or "Confidential Drop")
    requester_ip_hash = str(event.get("requester_ip_hash") or "unknown")
    requester_ua = str(event.get("requester_ua") or "unknown")
    review_base_url = str(event.get("review_base_url") or "").rstrip("/")
    demo_inbox = bool(event.get("demo_inbox", False))

    approval_token = new_token(16)
    now_iso = utc_now_iso()
    ttl_epoch = utc_epoch() + 3600

    table = aws_table()
    table.put_item(
        Item={
            "drop_id": f"APPROVAL#{approval_token}",
            "target_drop_id": drop_id,
            "task_token": task_token,
            "label": label,
            "requester_ip_hash": requester_ip_hash,
            "requester_ua": requester_ua,
            "created_at": now_iso,
            "ttl_epoch": ttl_epoch,
        }
    )

    review_url = f"{review_base_url}/#review={approval_token}" if review_base_url else f"#review={approval_token}"

    if demo_inbox:
        table.update_item(
            Key={"drop_id": drop_id},
            UpdateExpression="SET demo_approval_url = :url, demo_approval_token = :tok",
            ExpressionAttributeValues={":url": review_url, ":tok": approval_token},
        )

    if ALERTS_TOPIC_ARN:
        message = (
            f"ZeroDrop Break-Glass Access Request\n"
            f"-----------------------------------\n"
            f"Secret Label : {label}\n"
            f"Drop ID      : {drop_id}\n"
            f"Requester IP : sha256:{requester_ip_hash}\n"
            f"User-Agent   : {requester_ua}\n"
            f"Requested At : {now_iso}\n\n"
            f"Scanner-Safe Review Link (requires explicit click):\n"
            f"{review_url}\n\n"
            f"This AWS Step Functions workflow is paused at $0 compute cost.\n"
            f"If you do not approve within 60 minutes, the drop auto-shreds."
        )
        try:
            aws_client("sns").publish(
                TopicArn=ALERTS_TOPIC_ARN,
                Subject=f"[ZeroDrop] Approval needed: {label[:45]}",
                Message=message,
            )
        except Exception as exc:
            print(f"SNS publish warning: {exc}")

    log_event("SFN_NOTIFY_APPROVAL", drop_id=drop_id, approval_token=approval_token)
    return {"notified": True, "approval_token": approval_token}


def _handle_release_and_sign(event: Dict[str, Any]) -> Dict[str, Any]:
    """Atomically transition PENDING_APPROVAL -> APPROVED_READY and sign KMS Audit Chain + Receipt."""
    drop_id = str(event["drop_id"])
    requester_ip_hash = str(event.get("requester_ip_hash") or "unknown")
    now_iso = utc_now_iso()
    table = aws_table()

    item = table.get_item(Key={"drop_id": drop_id}).get("Item") or {}
    has_file = bool(item.get("has_file", False))
    s3_key = str(item.get("s3_key") or "noop/empty")
    label = str(item.get("label") or "Confidential Drop")

    chain = list(item.get("audit_chain") or [])
    approved_entry = make_chain_entry(
        chain,
        drop_id,
        "OWNER_APPROVED",
        requester_ip_hash,
        "Owner resumed Step Functions via SendTaskSuccess; release authorized once",
        {"has_file": has_file},
    )
    chain.append(approved_entry)

    receipt_payload = {
        "drop_id": drop_id,
        "label": label,
        "mode": "approval",
        "outcome": "OWNER_APPROVED_UNLOCK",
        "created_at": item.get("created_at", ""),
        "approved_at": now_iso,
        "requester_ip_hash": requester_ip_hash,
        "payload_sha256": item.get("payload_sha256", ""),
        "bot_shield_hits": int(item.get("bot_shield_hits", 0)),
        "chain_head_sha256": approved_entry["entry_sha256"],
        "shred_state": "GRACE_SHRED_SCHEDULED",
    }
    receipt = sign_receipt(receipt_payload)

    table.update_item(
        Key={"drop_id": drop_id},
        UpdateExpression="SET #st = :approved, approved_at = :now, receipt = :rcpt, audit_chain = :ch",
        ConditionExpression="#st = :pending",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":approved": "APPROVED_READY",
            ":pending": "PENDING_APPROVAL",
            ":now": now_iso,
            ":rcpt": receipt,
            ":ch": chain,
        },
    )
    log_event("SFN_OWNER_APPROVED", drop_id=drop_id, has_file=has_file)
    record_soc_event(
        table,
        "OWNER_APPROVED",
        drop_id,
        "Owner resumed Step Functions via SendTaskSuccess",
        requester_ip_hash,
        None,
        approved_entry["entry_sha256"],
    )

    return {
        "receipt_id": drop_id,
        "s3_key": s3_key if has_file else "noop/empty",
        "summary": f"ZeroDrop {drop_id} ({label}) approved at {now_iso} with KMS signature.",
    }


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    action = event.get("action")
    if action == "notify_approval":
        return _handle_notify_approval(event)
    if action == "release_and_sign":
        return _handle_release_and_sign(event)
    raise ValueError(f"Unsupported workflow action: {action}")
