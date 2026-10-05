#!/usr/bin/env python3
"""
tests/e2e/common/crypto_oracle.py
Independent authoritative cryptographic oracle for JOCKY E2E verification.
Provides RFC 8032 Ed25519 signing/verification, SHA-256 payload hashing,
and forensic provenance validation.
"""

import sys
import os
import json
import hashlib
import argparse
from typing import Tuple, List, Dict, Any, Optional

# --- RFC 8032 Pure-Python Ed25519 Implementation ---
# Reference: RFC 8032 Section 5.1
b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

def expmod(base: int, exp: int, m: int) -> int:
    return pow(base, exp, m)

def inv(x: int) -> int:
    return expmod(x, q - 2, q)

d = -121665 * inv(121666) % q
I = expmod(2, (q - 1) // 4, q)

def xrecover(y: int) -> int:
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x

By = 4 * inv(5) % q
Bx = xrecover(By)
B = [Bx % q, By % q]

def edwards(P: List[int], Q: List[int]) -> List[int]:
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2) % q
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2) % q
    return [x3, y3]

def scalarmult(P: List[int], e: int) -> List[int]:
    if e == 0:
        return [0, 1]
    Q = scalarmult(P, e // 2)
    Q = edwards(Q, Q)
    if e & 1:
        Q = edwards(Q, P)
    return Q

def encodeint(y: int) -> bytes:
    return y.to_bytes(32, byteorder="little")

def encodepoint(P: List[int]) -> bytes:
    x = P[0]
    y = P[1]
    bits = (y & ((1 << 255) - 1)) | ((x & 1) << 255)
    return bits.to_bytes(32, byteorder="little")

def decodeint(s: bytes) -> int:
    return int.from_bytes(s, byteorder="little")

def decodepoint(s: bytes) -> Optional[List[int]]:
    if len(s) != 32:
        return None
    clamp = int.from_bytes(s, byteorder="little")
    y = clamp & ((1 << 255) - 1)
    x_bit = clamp >> 255
    x = xrecover(y)
    if (x & 1) != x_bit:
        x = q - x
    P = [x, y]
    # Check on curve
    if (-x * x + y * y - 1 - d * x * x * y * y) % q != 0:
        return None
    return P

def H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()

def publickey(sk: bytes) -> bytes:
    h = H(sk)
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    A = scalarmult(B, a)
    return encodepoint(A)

def Hint(m: bytes) -> int:
    h = H(m)
    return int.from_bytes(h, byteorder="little")

def signature(m: bytes, sk: bytes, pk: bytes) -> bytes:
    h = H(sk)
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    r = Hint(h[32:] + m)
    R = scalarmult(B, r)
    k = Hint(encodepoint(R) + pk + m)
    S = (r + k * a) % l
    return encodepoint(R) + encodeint(S)

def checkvalid(sig: bytes, m: bytes, pk: bytes) -> bool:
    if len(sig) != 64 or len(pk) != 32:
        return False
    R = decodepoint(sig[:32])
    if R is None:
        return False
    A = decodepoint(pk)
    if A is None:
        return False
    S = decodeint(sig[32:])
    if S >= l:
        return False
    k = Hint(encodepoint(R) + pk + m)
    v1 = scalarmult(B, S)
    v2 = edwards(R, scalarmult(A, k))
    return v1 == v2

# --- Canonical Serialization Helpers ---

def canonical_receipt_bytes(receipt_dict: Dict[str, Any]) -> bytes:
    """Matches jockey-evidence canonical_receipt_for_signing."""
    canonical = {
        "id": receipt_dict["id"],
        "evidence_id": receipt_dict["evidence_id"],
        "run_id": receipt_dict["run_id"],
        "collector": receipt_dict["collector"],
        "collector_version": receipt_dict["collector_version"],
        "public_key": receipt_dict["public_key"],
        "payload_hash": receipt_dict["payload_hash"],
        "payload_hash_algo": receipt_dict["payload_hash_algo"],
        "timestamp": receipt_dict["timestamp"],
        "host_info": receipt_dict["host_info"]
    }
    return json.dumps(canonical, separators=(',', ':'), sort_keys=False).encode('utf-8')

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def bitflip_hex(hex_str: str, bit_pos: int = 0) -> str:
    """Flip a single bit in a hex-encoded string."""
    raw = bytearray(bytes.fromhex(hex_str))
    byte_idx = bit_pos // 8
    bit_idx = bit_pos % 8
    raw[byte_idx] ^= (1 << bit_idx)
    return raw.hex()

# --- Provenance Chain Validation ---

def verify_provenance_chain(records: List[Dict[str, Any]]) -> Tuple[bool, str]:
    if not records:
        return False, "Empty provenance chain"
    
    prev_output_hashes: List[str] = []
    for i, rec in enumerate(records):
        if i == 0:
            if rec.get("prev_provenance_id") is not None:
                return False, f"Root provenance has non-null prev_provenance_id: {rec.get('prev_provenance_id')}"
            if rec.get("input_hashes") != []:
                return False, f"Root provenance must have empty input_hashes, got: {rec.get('input_hashes')}"
        else:
            prev_id = records[i - 1]["id"]
            if rec.get("prev_provenance_id") != prev_id:
                return False, f"Provenance chain broken at step {i}: expected prev_id {prev_id}, got {rec.get('prev_provenance_id')}"
            if rec.get("input_hashes") != prev_output_hashes:
                return False, f"Provenance hash mismatch at step {i}: expected inputs {prev_output_hashes}, got {rec.get('input_hashes')}"
        
        prev_output_hashes = rec.get("output_hashes", [])
    
    return True, "Provenance chain valid"

# --- CLI Dispatch ---

def main():
    parser = argparse.ArgumentParser(description="JOCKY Cryptographic & Provenance Oracle")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # hash
    p_hash = subparsers.add_parser("hash")
    p_hash.add_argument("file", help="Path to file to compute sha256 for")

    # verify-receipt
    p_vr = subparsers.add_parser("verify-receipt")
    p_vr.add_argument("--evidence", required=True, help="Evidence JSON path")
    p_vr.add_argument("--receipt", required=True, help="Receipt JSON path")

    # verify-chain
    p_vc = subparsers.add_parser("verify-chain")
    p_vc.add_argument("chain_file", help="Provenance chain JSON array path")

    # bitflip
    p_bf = subparsers.add_parser("bitflip")
    p_bf.add_argument("hex_str", help="Hex string to bitflip")
    p_bf.add_argument("--bit", type=int, default=0, help="Bit index to flip")

    # generate-keypair
    p_gk = subparsers.add_parser("generate-keypair")

    # sign-receipt
    p_sr = subparsers.add_parser("sign-receipt")
    p_sr.add_argument("--receipt", required=True, help="Receipt JSON path without signature")
    p_sr.add_argument("--sk-hex", required=True, help="32-byte secret key hex")

    args = parser.parse_args()

    if args.command == "hash":
        with open(args.file, "rb") as f:
            print(compute_sha256(f.read()))
        sys.exit(0)

    elif args.command == "bitflip":
        print(bitflip_hex(args.hex_str, args.bit))
        sys.exit(0)

    elif args.command == "generate-keypair":
        sk = os.urandom(32)
        pk = publickey(sk)
        print(json.dumps({
            "secret_key": sk.hex(),
            "public_key": pk.hex()
        }))
        sys.exit(0)

    elif args.command == "sign-receipt":
        with open(args.receipt, "r") as f:
            rec = json.load(f)
        sk = bytes.fromhex(args.sk_hex)
        pk = bytes.fromhex(rec["public_key"])
        msg = canonical_receipt_bytes(rec)
        sig = signature(msg, sk, pk)
        rec["signature"] = sig.hex()
        with open(args.receipt, "w") as f:
            json.dump(rec, f, indent=2)
        print(rec["signature"])
        sys.exit(0)

    elif args.command == "verify-receipt":
        with open(args.evidence, "r") as f:
            ev = json.load(f)
        with open(args.receipt, "r") as f:
            rec = json.load(f)

        # 1. Payload hash check
        if ev.get("hash") != rec.get("payload_hash"):
            print(f"FAIL: Hash mismatch: evidence={ev.get('hash')}, receipt={rec.get('payload_hash')}")
            sys.exit(1)

        # 2. Evidence ID match
        if ev.get("id") != rec.get("evidence_id"):
            print("FAIL: Evidence ID mismatch")
            sys.exit(1)

        # 3. Ed25519 signature check
        msg = canonical_receipt_bytes(rec)
        sig = bytes.fromhex(rec["signature"])
        pk = bytes.fromhex(rec["public_key"])

        if not checkvalid(sig, msg, pk):
            print("FAIL: Ed25519 signature invalid")
            sys.exit(1)

        print("PASS: Receipt signature and hash valid")
        sys.exit(0)

    elif args.command == "verify-chain":
        with open(args.chain_file, "r") as f:
            chain = json.load(f)
        valid, msg = verify_provenance_chain(chain)
        if valid:
            print(f"PASS: {msg}")
            sys.exit(0)
        else:
            print(f"FAIL: {msg}")
            sys.exit(1)

if __name__ == "__main__":
    main()
