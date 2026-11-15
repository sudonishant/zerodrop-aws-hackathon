#!/usr/bin/env python3
"""Zero-dependency local AWS Serverless emulator for ZeroDrop.

Emulates DynamoDB Conditional Updates, S3 Presigned PUT/GET, Step Functions
waitForTaskToken callbacks, Amazon SNS notifications, and real ECDSA P-256
signing (via OpenSSL) so ZeroDrop runs identically on localhost before SAM deploy.
"""

from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

import api_handler  # noqa: E402
import common       # noqa: E402
import workflow_tasks  # noqa: E402


class ConditionalCheckFailed(Exception):
    code = "ConditionalCheckFailedException"


class InMemoryDynamoTable:
    """Thread-safe DynamoDB emulator supporting ZeroDrop ConditionExpressions & UpdateExpressions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: Dict[str, Dict[str, Any]] = {}

    def put_item(self, Item: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._items[Item["drop_id"]] = copy.deepcopy(Item)
        return {}

    def get_item(self, Key: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            item = self._items.get(Key["drop_id"])
            return {"Item": copy.deepcopy(item)} if item is not None else {}

    def _eval_condition(self, item: Optional[Dict[str, Any]], expr: str, names: Dict[str, str], vals: Dict[str, Any]) -> bool:
        if not expr:
            return True
        if item is None:
            return False

        clauses = [c.strip() for c in expr.split(" AND ")]
        for c in clauses:
            if c.startswith("attribute_not_exists("):
                attr = c[len("attribute_not_exists(") : -1].strip()
                attr = names.get(attr, attr)
                if attr in item:
                    return False
            elif c.startswith("attribute_exists("):
                attr = c[len("attribute_exists(") : -1].strip()
                attr = names.get(attr, attr)
                if attr not in item:
                    return False
            elif " <> " in c:
                lhs, rhs = [x.strip() for x in c.split(" <> ", 1)]
                attr = names.get(lhs, lhs)
                forbidden = vals[rhs]
                if item.get(attr) == forbidden:
                    return False
            elif " = " in c:
                lhs, rhs = [x.strip() for x in c.split(" = ", 1)]
                attr = names.get(lhs, lhs)
                expected = vals[rhs]
                if item.get(attr) != expected:
                    return False
            elif " > " in c:
                lhs, rhs = [x.strip() for x in c.split(" > ", 1)]
                attr = names.get(lhs, lhs)
                expected = vals[rhs]
                if int(item.get(attr, 0)) <= int(expected):
                    return False
            else:
                raise ValueError(f"Unsupported condition clause in emulator: {c}")
        return True

    def update_item(
        self,
        Key: Dict[str, Any],
        UpdateExpression: str,
        ConditionExpression: str = "",
        ExpressionAttributeNames: Optional[Dict[str, str]] = None,
        ExpressionAttributeValues: Optional[Dict[str, Any]] = None,
        ReturnValues: str = "NONE",
    ) -> Dict[str, Any]:
        names = ExpressionAttributeNames or {}
        vals = ExpressionAttributeValues or {}
        pk = Key["drop_id"]

        with self._lock:
            existing = self._items.get(pk)
            if ConditionExpression and not self._eval_condition(existing, ConditionExpression, names, vals):
                raise ConditionalCheckFailed("ConditionalCheckFailedException")
            if existing is None:
                existing = {"drop_id": pk}
            old_copy = copy.deepcopy(existing)
            new_item = copy.deepcopy(existing)
            updated_attrs: Dict[str, Any] = {}

            set_part = ""
            remove_part = ""
            m = re.match(r"^(?:SET\s+(.*?))?(?:\s+REMOVE\s+(.*))?$", UpdateExpression.strip())
            if m:
                set_part = (m.group(1) or "").strip()
                remove_part = (m.group(2) or "").strip()

            if set_part:
                # Split on commas outside parentheses (e.g., if_not_exists(a, :z))
                assignments = re.split(r",\s*(?![^()]*\))", set_part)
                for assign in assignments:
                    lhs, rhs = [x.strip() for x in assign.split("=", 1)]
                    attr = names.get(lhs, lhs)
                    m_inc = re.match(r"^if_not_exists\(([^,]+),\s*([^)]+)\)\s*\+\s*(.+)$", rhs)
                    if m_inc:
                        base_attr = names.get(m_inc.group(1).strip(), m_inc.group(1).strip())
                        default_v = vals[m_inc.group(2).strip()]
                        add_v = vals[m_inc.group(3).strip()]
                        new_val = int(new_item.get(base_attr, default_v)) + int(add_v)
                    else:
                        new_val = copy.deepcopy(vals[rhs])
                    new_item[attr] = new_val
                    updated_attrs[attr] = copy.deepcopy(new_val)

            if remove_part:
                for rem in remove_part.split(","):
                    attr = names.get(rem.strip(), rem.strip())
                    new_item.pop(attr, None)

            self._items[pk] = new_item

        if ReturnValues == "ALL_OLD":
            return {"Attributes": old_copy}
        if ReturnValues == "ALL_NEW":
            return {"Attributes": copy.deepcopy(new_item)}
        if ReturnValues == "UPDATED_NEW":
            return {"Attributes": updated_attrs}
        return {}


class InMemoryS3:
    def __init__(self, base_url_fn) -> None:
        self._lock = threading.Lock()
        self._objects: Dict[str, bytes] = {}
        self._base_url_fn = base_url_fn

    def generate_presigned_url(self, operation: str, Params: Dict[str, Any], ExpiresIn: int = 60) -> str:
        key = Params["Key"]
        return f"{self._base_url_fn()}/_local_s3/{urllib.parse.quote(key)}"

    def put_raw(self, key: str, data: bytes) -> None:
        with self._lock:
            self._objects[key] = data

    def get_raw(self, key: str) -> Optional[bytes]:
        with self._lock:
            return self._objects.get(key)

    def delete_object(self, Bucket: str, Key: str) -> Dict[str, Any]:
        with self._lock:
            self._objects.pop(Key, None)
        return {}


class LocalKmsSigner:
    """Real ECDSA NIST P-256 signer via OpenSSL CLI (identical math to AWS KMS ECC_NIST_P256)."""

    def __init__(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="zerodrop-kms-")
        self._priv_pem = Path(self._tmpdir.name) / "p256_priv.pem"
        self._pub_der = Path(self._tmpdir.name) / "p256_pub.der"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self._priv_pem)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "ec", "-in", str(self._priv_pem), "-pubout", "-outform", "DER", "-out", str(self._pub_der)],
            check=True,
            capture_output=True,
        )
        self._spki_der = self._pub_der.read_bytes()
        self.key_id = "arn:aws:kms:local:000000000000:key/zerodrop-p256-emu"

    def get_public_key(self, KeyId: str) -> Dict[str, Any]:
        return {"KeyId": self.key_id, "PublicKey": self._spki_der}

    def sign(self, KeyId: str, Message: bytes, MessageType: str = "DIGEST", SigningAlgorithm: str = "ECDSA_SHA_256") -> Dict[str, Any]:
        with tempfile.NamedTemporaryFile(dir=self._tmpdir.name, delete=True) as f:
            f.write(Message)
            f.flush()
            res = subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-inkey", str(self._priv_pem), "-in", f.name],
                check=True,
                capture_output=True,
            )
        return {"KeyId": self.key_id, "Signature": res.stdout}


class LocalSns:
    def publish(self, TopicArn: str, Subject: str, Message: str) -> Dict[str, Any]:
        print(f"\n[LOCAL SNS -> {Subject}]\n{Message}\n")
        return {"MessageId": common.new_token(8)}


class LocalStepFunctions:
    """Simulates AWS Step Functions waitForTaskToken + Choice + Parallel Shred."""

    def __init__(self, table: InMemoryDynamoTable, s3: InMemoryS3, grace_seconds: float = 2.0) -> None:
        self._lock = threading.Lock()
        self._executions: Dict[str, Dict[str, Any]] = {}
        self._tokens: Dict[str, str] = {}
        self._table = table
        self._s3 = s3
        self._grace_seconds = grace_seconds

    def start_execution(self, stateMachineArn: str, name: str, input: str) -> Dict[str, Any]:
        payload = json.loads(input)
        exec_arn = f"arn:aws:states:local:000000000000:execution:ZeroDrop:{name}"
        task_token = "sfn-tok-" + common.new_token(16)
        with self._lock:
            self._executions[exec_arn] = {"state": "WAITING_TASK_TOKEN", "input": payload}
            self._tokens[task_token] = exec_arn

        workflow_tasks.lambda_handler(
            {
                "action": "notify_approval",
                "task_token": task_token,
                **payload,
            }
        )
        return {"executionArn": exec_arn}

    def send_task_success(self, taskToken: str, output: str) -> Dict[str, Any]:
        with self._lock:
            exec_arn = self._tokens.pop(taskToken, None)
            if not exec_arn:
                raise RuntimeError("Invalid or expired TaskToken")
            rec = self._executions[exec_arn]
            rec["state"] = "APPROVED_RUNNING"
        inp = rec["input"]
        rel = workflow_tasks.lambda_handler(
            {
                "action": "release_and_sign",
                "drop_id": inp["drop_id"],
                "requester_ip_hash": inp.get("requester_ip_hash", ""),
                "requester_ua": inp.get("requester_ua", ""),
            }
        )

        def _grace_shred() -> None:
            time.sleep(self._grace_seconds)
            self._table.update_item(
                Key={"drop_id": inp["drop_id"]},
                UpdateExpression="SET shred_state = :shredded, shredded_at = :ts REMOVE ciphertext_b64",
                ExpressionAttributeValues={":shredded": "SHREDDED", ":ts": common.utc_now_iso()},
            )
            self._s3.delete_object(Bucket="local", Key=rel.get("s3_key", "noop/empty"))
            with self._lock:
                self._executions[exec_arn]["state"] = "SUCCEEDED"

        threading.Thread(target=_grace_shred, daemon=True).start()
        return {}

    def send_task_failure(self, taskToken: str, error: str = "", cause: str = "") -> Dict[str, Any]:
        with self._lock:
            exec_arn = self._tokens.pop(taskToken, None)
            if not exec_arn:
                raise RuntimeError("Invalid or expired TaskToken")
            rec = self._executions[exec_arn]
            rec["state"] = "DENIED_SHREDDED"
        inp = rec["input"]
        now = common.utc_now_iso()
        self._table.update_item(
            Key={"drop_id": inp["drop_id"]},
            UpdateExpression="SET #st = :denied, shred_state = :shredded, burned_at = :ts, shredded_at = :ts REMOVE ciphertext_b64",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":denied": "DENIED_SHREDDED", ":shredded": "SHREDDED", ":ts": now},
        )
        self._s3.delete_object(Bucket="local", Key=inp.get("s3_key", "noop/empty"))
        return {}

    def stop_execution(self, executionArn: str, error: str = "", cause: str = "") -> Dict[str, Any]:
        with self._lock:
            rec = self._executions.get(executionArn)
            if rec:
                rec["state"] = "ABORTED"
                for tok, arn in list(self._tokens.items()):
                    if arn == executionArn:
                        self._tokens.pop(tok, None)
        return {"stopDate": common.utc_now_iso()}


def build_local_backend(base_url: str = "http://127.0.0.1:8787", grace_seconds: float = 2.0) -> Dict[str, Any]:
    os.environ["VAULT_BUCKET"] = "local-zerodrop-vault"
    os.environ["REVIEW_BASE_URL"] = base_url or "http://127.0.0.1:8787"
    os.environ["KMS_KEY_ID"] = "local-ephemeral-p256"
    os.environ["ALERTS_TOPIC_ARN"] = "arn:aws:sns:local:000000000000:ZeroDropAlerts"
    os.environ["STATE_MACHINE_ARN"] = "arn:aws:states:local:000000000000:stateMachine:ZeroDrop"
    common.VAULT_BUCKET = os.environ["VAULT_BUCKET"]
    common.KMS_KEY_ID = os.environ["KMS_KEY_ID"]
    common.ALERTS_TOPIC_ARN = os.environ["ALERTS_TOPIC_ARN"]
    common.STATE_MACHINE_ARN = os.environ["STATE_MACHINE_ARN"]
    api_handler.VAULT_BUCKET = common.VAULT_BUCKET
    api_handler.KMS_KEY_ID = common.KMS_KEY_ID
    api_handler.ALERTS_TOPIC_ARN = common.ALERTS_TOPIC_ARN
    api_handler.STATE_MACHINE_ARN = common.STATE_MACHINE_ARN
    workflow_tasks.ALERTS_TOPIC_ARN = common.ALERTS_TOPIC_ARN

    table = InMemoryDynamoTable()
    s3 = InMemoryS3(lambda: base_url)
    kms = LocalKmsSigner()
    sns = LocalSns()
    sfn = LocalStepFunctions(table, s3, grace_seconds=grace_seconds)

    backend = {
        "table": table,
        "s3": s3,
        "kms": kms,
        "sns": sns,
        "stepfunctions": sfn,
    }
    common.set_backend_override(backend)
    return backend


class LocalRequestHandler(BaseHTTPRequestHandler):
    backend: Dict[str, Any] = {}
    html_bytes: bytes = b""

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _dispatch_api(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/_local_s3/"):
            key = urllib.parse.unquote(parsed.path[len("/_local_s3/") :])
            s3: InMemoryS3 = self.backend["s3"]
            if method == "PUT":
                s3.put_raw(key, self._read_body())
                self.send_response(200)
                self.end_headers()
                return
            if method == "GET":
                blob = s3.get_raw(key)
                if blob is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(blob)))
                self.end_headers()
                self.wfile.write(blob)
                return

        if method == "GET" and parsed.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(self.html_bytes)))
            self.end_headers()
            self.wfile.write(self.html_bytes)
            return

        body_bytes = self._read_body()
        event = {
            "rawPath": parsed.path,
            "requestContext": {
                "http": {
                    "method": method,
                    "sourceIp": self.client_address[0],
                }
            },
            "headers": {k: v for k, v in self.headers.items()},
            "body": body_bytes.decode("utf-8", errors="replace"),
            "isBase64Encoded": False,
        }
        res = api_handler.lambda_handler(event)
        status = int(res.get("statusCode", 500))
        payload = res.get("body", "").encode("utf-8")
        self.send_response(status)
        for k, v in (res.get("headers") or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def do_GET(self) -> None:
        self._dispatch_api("GET")

    def do_POST(self) -> None:
        self._dispatch_api("POST")

    def do_PUT(self) -> None:
        self._dispatch_api("PUT")

    def do_OPTIONS(self) -> None:
        self._dispatch_api("OPTIONS")


class ZeroDropHTTPServer(ThreadingHTTPServer):
    request_queue_size = 64
    daemon_threads = True


def main() -> None:
    port = int(os.environ.get("PORT", "8787"))
    host = os.environ.get("HOST", "0.0.0.0")
    html_path = ROOT / "web" / "index.html"
    LocalRequestHandler.html_bytes = html_path.read_bytes()
    LocalRequestHandler.backend = build_local_backend("", grace_seconds=45.0)
    server = ZeroDropHTTPServer((host, port), LocalRequestHandler)
    print(f"🚀 ZeroDrop Local AWS Emulator listening on http://{host}:{port}")
    print("   Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down ZeroDrop local server.")
        server.server_close()


if __name__ == "__main__":
    main()
