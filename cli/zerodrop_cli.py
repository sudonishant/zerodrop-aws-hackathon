#!/usr/bin/env python3
"""ZeroDrop v3.0 Ultra-Pro CLI — Zero-Knowledge Encrypt, Shamir Split, Panic Shred & Verify.

Usage:
  cat .env | python3 cli/zerodrop_cli.py push --url http://127.0.0.1:8787 --label "Prod Env"
  cat .env | python3 cli/zerodrop_cli.py push --url http://127.0.0.1:8787 --shares 3 --threshold 2
  python3 cli/zerodrop_cli.py pull "http://127.0.0.1:8787/#d=...&k=..."
  python3 cli/zerodrop_cli.py pull "http://127.0.0.1:8787/#d=...&s=1-2-3:..." --share "2-2-3:..."
  python3 cli/zerodrop_cli.py shred --url http://127.0.0.1:8787 --drop-id <id> --kill-token <tok>
  python3 cli/zerodrop_cli.py verify --url http://127.0.0.1:8787 --drop-id <id>
  python3 cli/zerodrop_cli.py race --url http://127.0.0.1:8787
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Tuple


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode(val: str) -> bytes:
    pad = "=" * ((4 - len(val) % 4) % 4)
    return base64.urlsafe_b64decode((val + pad).encode("ascii"))


# --- GF(256) Shamir Secret Sharing (AES polynomial 0x11b, matches WebCrypto UI) ---
def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_pow(a: int, e: int) -> int:
    res = 1
    while e > 0:
        if e & 1:
            res = _gf_mul(res, a)
        a = _gf_mul(a, a)
        e >>= 1
    return res


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    if a == 0:
        return 0
    return _gf_mul(a, _gf_pow(b, 254))


def shamir_split(secret_bytes: bytes, threshold: int, total: int) -> List[str]:
    if threshold < 2 or total < threshold or total > 10:
        raise ValueError("Shamir requires 2 <= threshold <= total <= 10")
    length = len(secret_bytes)
    bufs = [bytearray(length) for _ in range(total)]
    for i, sb in enumerate(secret_bytes):
        coeffs = [sb] + list(secrets.token_bytes(threshold - 1))
        for x in range(1, total + 1):
            y = 0
            for k in range(threshold - 1, -1, -1):
                y = _gf_mul(y, x) ^ coeffs[k]
            bufs[x - 1][i] = y
    return [f"{idx + 1}-{threshold}-{total}:{_b64u_encode(bytes(b))}" for idx, b in enumerate(bufs)]


def _extract_share_token(raw: str) -> str:
    s = raw.strip()
    if "#" in s:
        frag = urllib.parse.parse_qs(s.split("#", 1)[1])
        if frag.get("s"):
            return frag["s"][0]
    return s


def shamir_combine(share_strings: List[str]) -> bytes:
    seen = set()
    pts = []
    for raw in share_strings:
        tok = _extract_share_token(raw)
        if not tok:
            continue
        try:
            x_m_n, b64_part = tok.split(":", 1)
            header = x_m_n.split("-")
            if len(header) != 3 or not b64_part or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in b64_part):
                raise ValueError("malformed share")
            x, m, n = (int(v) for v in header)
            share_bytes = _b64u_decode(b64_part)
        except (ValueError, TypeError):
            raise ValueError("Malformed Shamir share") from None
        if m < 2 or n < m or n > 10 or x < 1 or x > n or not share_bytes:
            raise ValueError("Invalid Shamir share metadata")
        if pts and (m, n, len(share_bytes)) != (pts[0][1], pts[0][2], len(pts[0][3])):
            raise ValueError("Shamir shares must have matching threshold, total, and byte length")
        if x in seen:
            raise ValueError(f"Duplicate Shamir share index: {x}")
        seen.add(x)
        pts.append((x, m, n, share_bytes))
    if not pts:
        raise ValueError("No valid Shamir shares provided")
    m_req = pts[0][1]
    length = len(pts[0][3])
    if len(pts) < m_req:
        raise ValueError(f"Need at least {m_req} distinct Shamir shares (got {len(pts)})")
    use = pts[:m_req]
    out = bytearray(length)
    for b in range(length):
        acc = 0
        for i in range(m_req):
            li = 1
            for j in range(m_req):
                if i != j:
                    li = _gf_mul(li, _gf_div(use[j][0], use[j][0] ^ use[i][0]))
            acc ^= _gf_mul(use[i][3][b], li)
        out[b] = acc
    return bytes(out)


def derive_aes_key(raw_key: bytes, key_b64u: str, passphrase: str, iv_b64: str) -> bytes:
    """Match WebCrypto deriveAesKey() byte-for-byte using PBKDF2-SHA256 (120,000 iterations)."""
    if not passphrase:
        return raw_key
    return hashlib.pbkdf2_hmac(
        "sha256",
        f"{key_b64u}:{passphrase}".encode("utf-8"),
        f"zerodrop-kdf-v2:{iv_b64}".encode("utf-8"),
        120000,
        dklen=32,
    )


def aes_gcm_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(key).encrypt(iv, plaintext, None)
    except ImportError:
        if not shutil.which("node"):
            raise RuntimeError("Install 'cryptography' or have Node.js available.")
        js = (
            "const c=require('node:crypto');"
            "const [k,iv,pt]=process.argv.slice(1).map(x=>Buffer.from(x,'base64'));"
            "const ci=c.createCipheriv('aes-256-gcm',k,iv);"
            "const out=Buffer.concat([ci.update(pt),ci.final(),ci.getAuthTag()]);"
            "process.stdout.write(out.toString('base64'));"
        )
        res = subprocess.run(
            ["node", "-e", js, base64.b64encode(key).decode(), base64.b64encode(iv).decode(), base64.b64encode(plaintext).decode()],
            check=True,
            capture_output=True,
            text=True,
        )
        return base64.b64decode(res.stdout.strip())


def aes_gcm_decrypt(ciphertext_with_tag: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(key).decrypt(iv, ciphertext_with_tag, None)
    except ImportError:
        if not shutil.which("node"):
            raise RuntimeError("Install 'cryptography' or have Node.js available.")
        js = (
            "const c=require('node:crypto');"
            "const [k,iv,ct]=process.argv.slice(1).map(x=>Buffer.from(x,'base64'));"
            "const tag=ct.subarray(ct.length-16), body=ct.subarray(0,ct.length-16);"
            "const d=c.createDecipheriv('aes-256-gcm',k,iv); d.setAuthTag(tag);"
            "process.stdout.write(Buffer.concat([d.update(body),d.final()]).toString('base64'));"
        )
        res = subprocess.run(
            ["node", "-e", js, base64.b64encode(key).decode(), base64.b64encode(iv).decode(), base64.b64encode(ciphertext_with_tag).decode()],
            check=True,
            capture_output=True,
            text=True,
        )
        return base64.b64decode(res.stdout.strip())


def verify_ecdsa_p256_p1363(spki_b64: str, sig_p1363_b64: str, payload_json: str) -> bool:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        pub = serialization.load_der_public_key(base64.b64decode(spki_b64))
        raw = base64.b64decode(sig_p1363_b64)
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        pub.verify(encode_dss_signature(r, s), payload_json.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except ImportError:
        pass
    except Exception:
        return False

    if shutil.which("node"):
        js = (
            "const {webcrypto}=require('node:crypto');"
            "const [spki,sig,msg]=process.argv.slice(1);"
            "(async()=>{"
            "const k=await webcrypto.subtle.importKey('spki',Buffer.from(spki,'base64'),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);"
            "const ok=await webcrypto.subtle.verify({name:'ECDSA',hash:{name:'SHA-256'}},k,Buffer.from(sig,'base64'),Buffer.from(msg,'utf8'));"
            "process.stdout.write(ok?'1':'0');"
            "})();"
        )
        res = subprocess.run(["node", "-e", js, spki_b64, sig_p1363_b64, payload_json], check=True, capture_output=True, text=True)
        return res.stdout.strip() == "1"
    raise RuntimeError("Install 'cryptography' or have Node.js available for P-256 verification.")


def http_json(method: str, url: str, payload: Dict[str, Any] | None = None, headers: Dict[str, str] | None = None) -> Tuple[int, Dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def cmd_push(args: argparse.Namespace) -> None:
    if args.text:
        plaintext = args.text.encode("utf-8")
    elif not sys.stdin.isatty():
        plaintext = sys.stdin.read().encode("utf-8")
    else:
        raise SystemExit("Pipe secret via stdin or pass --text")

    raw_key = secrets.token_bytes(32)
    key_b64u = _b64u_encode(raw_key)
    iv = secrets.token_bytes(12)
    iv_b64 = base64.b64encode(iv).decode("ascii")
    aes_key = derive_aes_key(raw_key, key_b64u, args.passphrase, iv_b64)
    ciphertext = aes_gcm_encrypt(plaintext, aes_key, iv)
    payload_sha256 = hashlib.sha256(plaintext).hexdigest()

    quorum = None
    shares: List[str] = []
    if args.shares > 1:
        quorum = {"threshold": args.threshold, "total": args.shares}
        shares = shamir_split(raw_key, args.threshold, args.shares)

    passphrase_check = None
    if args.passphrase:
        iv_chk = secrets.token_bytes(12)
        ct_chk = aes_gcm_encrypt(b"ZERODROP_KEY_OK", aes_key, iv_chk)
        passphrase_check = {
            "iv_b64": base64.b64encode(iv_chk).decode("ascii"),
            "ct_b64": base64.b64encode(ct_chk).decode("ascii"),
        }

    base = args.url.rstrip("/")
    status, data = http_json(
        "POST",
        f"{base}/api/drops",
        {
            "mode": args.mode,
            "label": args.label,
            "ttl_minutes": args.ttl,
            "iv_b64": iv_b64,
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "payload_sha256": payload_sha256,
            "canary_alert": args.canary,
            "passphrase_check": passphrase_check,
            "quorum": quorum,
        },
    )
    if status != 201:
        raise SystemExit(f"Failed ({status}): {data}")

    suffix = "&p=1" if args.passphrase else ""
    print("✅ ZeroDrop v4 APEX Created (Key stayed local; AES-256-GCM)")
    print(f"   Drop ID     : {data['drop_id']}")
    print(f"   Kill Token  : {data.get('kill_token', '')}")
    print(f"   Mode        : {data['mode']}")
    print(f"   Genesis Hash: {data.get('chain_head_sha256', '')}")
    if shares:
        print(f"   Quorum      : {args.threshold}-of-{args.shares} Shamir GF(256)")
        for idx, sh in enumerate(shares, 1):
            print(f"   Share #{idx}    : {base}/#d={data['drop_id']}&s={sh}{suffix}")
    else:
        print(f"   Share URL   : {base}/#d={data['drop_id']}&k={key_b64u}{suffix}")


def cmd_pull(args: argparse.Namespace) -> None:
    parsed = urllib.parse.urlparse(args.share_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    frag = urllib.parse.parse_qs(parsed.fragment)
    drop_id = (frag.get("d") or [""])[0]
    key_b64u = (frag.get("k") or [""])[0]
    first_share = (frag.get("s") or [""])[0]
    if not drop_id or (not key_b64u and not first_share):
        raise SystemExit("Invalid ZeroDrop share URL (missing #d=...&k=... or #d=...&s=...)")

    if first_share:
        all_shares = [first_share] + list(args.share or [])
        raw_key = shamir_combine(all_shares)
        key_b64u = _b64u_encode(raw_key)
    else:
        raw_key = _b64u_decode(key_b64u)

    st_meta, meta = http_json("GET", f"{base}/api/drops/{drop_id}/status")
    if st_meta != 200:
        raise SystemExit(f"Status peek failed ({st_meta}): {meta}")

    if meta.get("has_passphrase"):
        if not args.passphrase:
            raise SystemExit("Passphrase required! Pass --passphrase <secret>")
        aes_key = derive_aes_key(raw_key, key_b64u, args.passphrase, meta["iv_b64"])
        chk = meta.get("passphrase_check") or {}
        try:
            ok_bytes = aes_gcm_decrypt(base64.b64decode(chk["ct_b64"]), aes_key, base64.b64decode(chk["iv_b64"]))
            if ok_bytes != b"ZERODROP_KEY_OK":
                raise ValueError("mismatch")
        except Exception:
            raise SystemExit("❌ Wrong passphrase or bad Shamir share! Checked locally BEFORE burning — secret stays intact on AWS.")

    status, data = http_json(
        "POST",
        f"{base}/api/drops/{drop_id}/claim",
        {"human_confirm": True},
        headers={"X-ZeroDrop-Human": "1", "User-Agent": "ZeroDrop-CLI/3.0"},
    )
    if status != 200:
        raise SystemExit(f"Claim failed ({status}): {data}")

    iv = base64.b64decode(data["iv_b64"])
    aes_key = derive_aes_key(raw_key, key_b64u, args.passphrase if meta.get("has_passphrase") else "", data["iv_b64"])
    ciphertext = base64.b64decode(data["ciphertext_b64"])
    plaintext = aes_gcm_decrypt(ciphertext, aes_key, iv)
    print(plaintext.decode("utf-8", errors="replace"))


def cmd_shred(args: argparse.Namespace) -> None:
    base = args.url.rstrip("/")
    status, data = http_json(
        "POST",
        f"{base}/api/drops/{args.drop_id}/shred",
        {"kill_token": args.kill_token},
    )
    if status != 200:
        raise SystemExit(f"Panic Shred failed ({status}): {data}")
    print(f"☠️ Drop {args.drop_id} permanently shredded: status={data['status']}, s3_deleted={data['s3_deleted']}")


def cmd_verify(args: argparse.Namespace) -> None:
    base = args.url.rstrip("/")
    status, data = http_json("GET", f"{base}/api/receipts/{args.drop_id}")
    if status != 200:
        raise SystemExit(f"Failed ({status}): {data}")

    spki = data["public_key"]["spki_b64"]
    chain = data.get("audit_chain") or []
    prev_hash = "0" * 64
    for entry in chain:
        msg = entry["payload_json"]
        recomputed = hashlib.sha256(msg.encode("utf-8")).hexdigest()
        sig_ok = verify_ecdsa_p256_p1363(spki, entry["signature_p1363_b64"], msg)
        if not sig_ok or entry["prev_hash"] != prev_hash or recomputed != entry["entry_sha256"]:
            raise SystemExit(f"❌ Chain verification failed at seq #{entry['seq']} ({entry['event']})")
        print(f"  ✅ #{entry['seq']} {entry['event']} | hash={recomputed[:16]}... | KMS P-256 SIG VALID")
        prev_hash = recomputed
    print(f"🔐 Verified {len(chain)}/{len(chain)} hash-chained KMS ECDSA P-256 entries for drop {args.drop_id}.")


def cmd_race(args: argparse.Namespace) -> None:
    base = args.url.rstrip("/")
    status, data = http_json("POST", f"{base}/api/lab/race", {"concurrency": args.n})
    if status != 200:
        raise SystemExit(f"Failed ({status}): {data}")
    print(f"Naive  ({args.n} threads): {data['naive']['verdict']} | p50={data['naive']['stats']['p50_ms']}ms")
    print(f"Atomic ({args.n} threads): {data['atomic']['verdict']} | p50={data['atomic']['stats']['p50_ms']}ms")


def cmd_soc(args: argparse.Namespace) -> None:
    base = args.url.rstrip("/")
    status, data = http_json("GET", f"{base}/api/telemetry/soc")
    if status != 200:
        raise SystemExit(f"Failed ({status}): {data}")
    c = data["counters"]
    print("🛡️  ZeroDrop Live AWS SOC Counters:")
    print(
        f"   Created={c['total_created']} | Burned={c['total_burned']} | "
        f"BotsBlocked={c['total_bots_blocked']} | Canary={c['total_canary_alerts']} | "
        f"PanicShreds={c['total_panic_shreds']} | Approvals={c['total_approvals']}"
    )
    for ev in (data.get("events") or [])[:8]:
        print(f"   - [{ev['ts']}] {ev['event']} ({ev['drop_id']}): {ev['detail']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ZeroDrop v3 Zero-Knowledge CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_push = sub.add_parser("push", help="Encrypt stdin/text locally and upload ciphertext")
    p_push.add_argument("--url", required=True, help="ZeroDrop base URL")
    p_push.add_argument("--label", default="CLI Secret Drop")
    p_push.add_argument("--mode", choices=["fast", "approval"], default="fast")
    p_push.add_argument("--ttl", type=int, default=60)
    p_push.add_argument("--text", default="")
    p_push.add_argument("--passphrase", default="")
    p_push.add_argument("--shares", type=int, default=1, help="Split key into N Shamir shares (e.g. 3)")
    p_push.add_argument("--threshold", type=int, default=2, help="M shares required to reconstruct (e.g. 2)")
    p_push.add_argument("--canary", action="store_true")
    p_push.set_defaults(func=cmd_push)

    p_pull = sub.add_parser("pull", help="Claim once and decrypt locally from #d=...&k=... or #d=...&s=...")
    p_pull.add_argument("share_url")
    p_pull.add_argument("--share", action="append", default=[], help="Additional Shamir share token or URL")
    p_pull.add_argument("--passphrase", default="")
    p_pull.set_defaults(func=cmd_pull)

    p_shred = sub.add_parser("shred", help="Trigger instant Owner Panic Kill Switch")
    p_shred.add_argument("--url", required=True)
    p_shred.add_argument("--drop-id", required=True)
    p_shred.add_argument("--kill-token", required=True)
    p_shred.set_defaults(func=cmd_shred)

    p_ver = sub.add_parser("verify", help="Verify hash-chained KMS P-256 audit ledger")
    p_ver.add_argument("--url", required=True)
    p_ver.add_argument("--drop-id", required=True)
    p_ver.set_defaults(func=cmd_verify)

    p_race = sub.add_parser("race", help="Run 20-thread DynamoDB concurrency race proof")
    p_race.add_argument("--url", required=True)
    p_race.add_argument("-n", type=int, default=20)
    p_race.set_defaults(func=cmd_race)

    p_soc = sub.add_parser("soc", help="Fetch live anonymized AWS SOC telemetry & counters")
    p_soc.add_argument("--url", required=True)
    p_soc.set_defaults(func=cmd_soc)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
