"""Versioned Python boundary for the native arkworks invoice proof engine."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

NATIVE_PROOF_VERSION = "ledgerguard-native-groth16-v1"
MAX_NATIVE_PROOF_BYTES = 4 * 1024 * 1024


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("native proof binary field must be a string")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("malformed native proof binary field") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("noncanonical native proof binary field")
    return raw


@dataclass(frozen=True)
class NativeInvoiceProof:
    proof: bytes
    tax_rate_bps: int
    subtotal: int
    total: int
    item_count: int

    def to_json(self) -> str:
        payload = {
            "version": NATIVE_PROOF_VERSION,
            "proof_b64": _b64(self.proof),
            "tax_rate_bps": self.tax_rate_bps,
            "subtotal": self.subtotal,
            "total": self.total,
            "item_count": self.item_count,
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "NativeInvoiceProof":
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_NATIVE_PROOF_BYTES:
            raise ValueError("native proof envelope is oversized")
        payload = json.loads(raw)
        expected = {"version", "proof_b64", "tax_rate_bps", "subtotal", "total", "item_count"}
        if not isinstance(payload, dict) or set(payload) != expected or payload["version"] != NATIVE_PROOF_VERSION:
            raise ValueError("unsupported native proof envelope")
        values = (payload["tax_rate_bps"], payload["subtotal"], payload["total"], payload["item_count"])
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("invalid native proof public inputs")
        proof = _unb64(payload["proof_b64"])
        if not proof or len(proof) > MAX_NATIVE_PROOF_BYTES:
            raise ValueError("invalid native proof size")
        return cls(proof, *values)


def _native_module():
    try:
        import ledgerguard_zkp_native
    except ImportError as exc:
        raise RuntimeError("build the native PyO3 extension before using native proofs") from exc
    return ledgerguard_zkp_native


def generate_native_proof(
    proving_key: bytes,
    line_items: list[int],
    tax_rate_bps: int,
    subtotal: int,
    tax: int,
    total: int,
    remainder: int,
) -> NativeInvoiceProof:
    if type(tax_rate_bps) is not int or not 0 <= tax_rate_bps <= 10_000:
        raise ValueError("tax_rate_bps out of range")
    if not isinstance(line_items, list) or not (1 <= len(line_items) <= 100):
        raise ValueError("invalid line-item count")
    if any(type(value) is not int or value < 0 for value in line_items):
        raise ValueError("line items must be nonnegative integers")
    proof = _native_module().prove_native(
        proving_key, line_items, tax_rate_bps, subtotal, tax, total, remainder
    )
    return NativeInvoiceProof(proof, tax_rate_bps, subtotal, total, len(line_items))


def verify_native_proof(verifying_key: bytes, proof: NativeInvoiceProof) -> bool:
    return bool(_native_module().verify_native(
        verifying_key, proof.proof, proof.tax_rate_bps, proof.subtotal, proof.total
    ))
