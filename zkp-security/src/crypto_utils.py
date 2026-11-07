"""
crypto_utils.py – Cryptographic utilities for the ZKP-Security module.
======================================================================

Provides:
  - SecureHasher:     SHA3-based hashing with domain separation
  - KeyManager:       HKDF-based key derivation, no hardcoded secrets
  - ProofSerializer:  JSON-safe serialisation / deserialisation of proofs
  - TimestampSigner:  HMAC-based timestamp binding for proof replay protection
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
import re
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from .exceptions import KeyDerivationError, ProofExpiredError


# ---------------------------------------------------------------------------
# SecureHasher
# ---------------------------------------------------------------------------

class SecureHasher:
    """
    Domain-separated SHA-3-256 hashing.

    All hashes are prefixed with a domain tag so that digests from different
    contexts are always distinct, preventing cross-protocol attacks.
    """

    DOMAIN_INVOICE   = b"LedgerGuard|invoice|v1"
    DOMAIN_PROOF     = b"LedgerGuard|proof|v1"
    DOMAIN_TIMESTAMP = b"LedgerGuard|timestamp|v1"

    @staticmethod
    def hash(domain: bytes, *parts: bytes) -> bytes:
        """Return SHA3-256(domain_len || domain || len(p1) || p1 || …)."""
        h = hashlib.sha3_256()
        h.update(struct.pack(">I", len(domain)))
        h.update(domain)
        for p in parts:
            h.update(struct.pack(">I", len(p)))
            h.update(p)
        return h.digest()

    @classmethod
    def hash_invoice(cls, invoice_data: dict[str, Any]) -> bytes:
        """
        Produce a canonical hash of an invoice dict.
        Keys are sorted to guarantee determinism.
        """
        canonical = json.dumps(invoice_data, sort_keys=True, separators=(",", ":"))
        return cls.hash(cls.DOMAIN_INVOICE, canonical.encode("utf-8"))

    @classmethod
    def hash_proof_payload(cls, *parts: bytes) -> bytes:
        """Hash proof-related bytes with proof domain tag."""
        return cls.hash(cls.DOMAIN_PROOF, *parts)


# ---------------------------------------------------------------------------
# KeyManager
# ---------------------------------------------------------------------------

class KeyManager:
    """
    HKDF-based key derivation manager.

    **Never hardcodes secrets.** Production requires root IKM at runtime,
    typically from a secrets manager. Ephemeral key generation is restricted
    to explicit test/development mode or an explicit constructor option.

    Usage::

        # In production, configure LEDGERGUARD_ZKP_IKM from a secrets manager:
        km = KeyManager()

        signing_key = km.derive("invoice-signing", length=32)
    """

    _ENV_VAR = "LEDGERGUARD_ZKP_IKM"

    def __init__(
        self,
        ikm: bytes | None = None,
        *,
        key_id: str | None = None,
        verification_ikms: dict[str, bytes] | None = None,
        allow_ephemeral: bool | None = None,
    ) -> None:
        mode = os.environ.get("LEDGERGUARD_ZKP_MODE", "production").lower()
        if allow_ephemeral is None:
            allow_ephemeral = mode in {"test", "development"}

        if ikm is None:
            env_val = os.environ.get(self._ENV_VAR)
            if env_val:
                try:
                    ikm = base64.b64decode(env_val, validate=True)
                except Exception as exc:
                    raise KeyDerivationError(
                        f"{self._ENV_VAR} must be valid base64."
                    ) from exc
            elif allow_ephemeral:
                ikm = secrets.token_bytes(32)
            else:
                raise KeyDerivationError(
                    f"{self._ENV_VAR} must be configured outside test/development mode."
                )

        self._validate_ikm(ikm, "active")
        active_id = key_id or os.environ.get("LEDGERGUARD_ZKP_KEY_ID", "v1")
        self._validate_key_id(active_id)
        keys = dict(verification_ikms or {})

        previous_env = os.environ.get("LEDGERGUARD_ZKP_PREVIOUS_KEYS")
        if previous_env and verification_ikms is None:
            try:
                decoded_previous = json.loads(previous_env)
                if not isinstance(decoded_previous, dict):
                    raise ValueError("must be a JSON object")
                keys = {
                    str(previous_id): base64.b64decode(value, validate=True)
                    for previous_id, value in decoded_previous.items()
                }
            except Exception as exc:
                raise KeyDerivationError(
                    "LEDGERGUARD_ZKP_PREVIOUS_KEYS must be a JSON object of base64 keys."
                ) from exc

        self._validate_key_id(active_id)
        for previous_id, previous_ikm in keys.items():
            self._validate_key_id(previous_id)
            self._validate_ikm(previous_ikm, previous_id)
            if previous_id == active_id:
                raise KeyDerivationError("Active and previous key IDs must be distinct.")

        self._active_key_id = active_id
        self._ikms = {active_id: bytes(ikm), **keys}

    @staticmethod
    def _validate_ikm(ikm: bytes, key_id: str) -> None:
        if not isinstance(ikm, bytes) or len(ikm) < 32:
            raise KeyDerivationError(
                f"Key material for {key_id!r} must contain at least 32 bytes."
            )

    @staticmethod
    def _validate_key_id(key_id: str) -> None:
        if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", key_id):
            raise KeyDerivationError("Key IDs must be 1-32 safe ASCII characters.")

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    @property
    def verification_key_ids(self) -> tuple[str, ...]:
        return tuple(self._ikms)

    def derive(
        self,
        purpose: str,
        length: int = 32,
        *,
        key_id: str | None = None,
    ) -> bytes:
        """
        Derive a purpose-specific key using HKDF-SHA256.

        Args:
            purpose: Human-readable label (e.g., "timestamp-signing").
            length:  Output length in bytes.

        Returns:
            Derived key bytes.
        """
        selected_id = key_id or self._active_key_id
        try:
            selected_ikm = self._ikms[selected_id]
        except KeyError as exc:
            raise KeyDerivationError(f"Unknown key ID {selected_id!r}.") from exc
        if not isinstance(purpose, str) or not purpose or len(purpose.encode("utf-8")) > 256:
            raise KeyDerivationError("Purpose must be a non-empty string of at most 256 bytes.")
        if type(length) is not int or not (1 <= length <= 255 * 32):
            raise KeyDerivationError("HKDF output length must be in [1, 8160].")
        hkdf = HKDF(
            algorithm  = hashes.SHA256(),
            length     = length,
            salt       = b"LedgerGuard-ZKP-salt-v1",
            info       = f"{selected_id}|{purpose}".encode("utf-8"),
            backend    = default_backend(),
        )
        return hkdf.derive(selected_ikm)


# ---------------------------------------------------------------------------
# TimestampSigner  (replay-attack protection)
# ---------------------------------------------------------------------------

class TimestampSigner:
    """
    Binds a proof context to a freshness window using HMAC-SHA256.

    Freshness is not replay prevention. Invoice replay protection is provided
    by the one-time challenge store.

    Usage::

        signer   = TimestampSigner(key_manager)
        ts_token = signer.sign_now()              # include in proof
        signer.verify(ts_token, max_age_seconds=300)   # on verifier side
    """

    def __init__(self, key_manager: KeyManager, max_age_seconds: int = 3600) -> None:
        if type(max_age_seconds) is not int or max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be a positive integer.")
        self._key_manager = key_manager
        self._max_age = max_age_seconds

    def sign_now(self, context: str | bytes = b"") -> str:
        """
        Return a base64-encoded  "timestamp|HMAC" token for the current time.
        """
        ts = str(int(time.time()))
        context_bytes = context.encode("utf-8") if isinstance(context, str) else context
        if not isinstance(context_bytes, bytes) or len(context_bytes) > 4096:
            raise ValueError("Timestamp context must be bytes or a string of at most 4096 bytes.")
        key_id = self._key_manager.active_key_id
        key = self._key_manager.derive("timestamp-signing", key_id=key_id)
        payload = self._message(key_id, ts, context_bytes)
        mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return base64.b64encode(f"{key_id}|{ts}|{mac}".encode("ascii")).decode("ascii")

    @staticmethod
    def _message(key_id: str, timestamp: str, context: bytes) -> bytes:
        return (
            b"LedgerGuard|timestamp|v2|"
            + key_id.encode("ascii")
            + b"|"
            + timestamp.encode("ascii")
            + struct.pack(">I", len(context))
            + context
        )

    def verify(
        self,
        token: str,
        max_age_seconds: int | None = None,
        context: str | bytes = b"",
    ) -> None:
        """
        Verify a timestamp token.

        Raises:
            ProofExpiredError: if the token is too old or the HMAC is invalid.
        """
        max_age = self._max_age if max_age_seconds is None else max_age_seconds
        if type(max_age) is not int or max_age <= 0:
            raise ValueError("max_age_seconds must be a positive integer.")
        context_bytes = context.encode("utf-8") if isinstance(context, str) else context
        if not isinstance(context_bytes, bytes) or len(context_bytes) > 4096:
            raise ProofExpiredError("Malformed timestamp context.")
        try:
            decoded = base64.b64decode(token.encode("ascii"), validate=True).decode("ascii")
            key_id, ts_str, mac_received = decoded.split("|")
            self._key_manager._validate_key_id(key_id)
            if not re.fullmatch(r"[0-9]{1,12}", ts_str):
                raise ValueError("Invalid timestamp.")
            ts = int(ts_str)
            if not re.fullmatch(r"[0-9a-f]{64}", mac_received):
                raise ValueError("Invalid MAC encoding.")
        except Exception as exc:
            raise ProofExpiredError("Malformed timestamp token.") from exc

        try:
            key = self._key_manager.derive("timestamp-signing", key_id=key_id)
        except KeyDerivationError as exc:
            raise ProofExpiredError("Timestamp key ID is not trusted.") from exc
        payload = self._message(key_id, ts_str, context_bytes)
        mac_expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac_expected, mac_received):
            raise ProofExpiredError("Timestamp token HMAC is invalid – possible tampering.")

        age = int(time.time()) - ts
        if age > max_age or age < -60:   # allow 60 s clock skew
            raise ProofExpiredError(
                f"Proof timestamp is {age}s old (max allowed: {max_age}s)."
            )


# ---------------------------------------------------------------------------
# ProofSerializer
# ---------------------------------------------------------------------------

class ProofSerializer:
    """
    JSON-safe serialisation and deserialisation of all proof types.

    Integers are stored as hex strings to avoid JSON precision loss on
    very large 256-bit numbers.
    """

    @staticmethod
    def int_to_hex(v: int) -> str:
        return hex(v)

    @staticmethod
    def hex_to_int(s: str) -> int:
        if (
            not isinstance(s, str)
            or len(s) > 66
            or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", s)
        ):
            raise ValueError("Invalid canonical hexadecimal integer.")
        return int(s, 16)

    @staticmethod
    def bytes_to_b64(b: bytes) -> str:
        if not isinstance(b, bytes):
            raise TypeError("Binary proof values must be bytes.")
        return base64.b64encode(b).decode()

    @staticmethod
    def b64_to_bytes(s: str) -> bytes:
        if not isinstance(s, str):
            raise ValueError("Base64 value must be a string.")
        try:
            encoded = s.encode("ascii")
            decoded = base64.b64decode(encoded, validate=True)
        except (UnicodeEncodeError, ValueError, base64.binascii.Error) as exc:
            raise ValueError("Base64 value is malformed.") from exc
        if len(decoded) > 4096 or base64.b64encode(decoded).decode("ascii") != s:
            raise ValueError("Base64 value is noncanonical or oversized.")
        return decoded

    @classmethod
    def serialise_schnorr(cls, proof) -> dict[str, Any]:  # type: ignore[override]
        from .zkp_core import SchnorrProof
        return {
            "type": "SchnorrProof",
            "announcement_bytes": cls.bytes_to_b64(proof.announcement_bytes),
            "challenge":          cls.int_to_hex(proof.challenge),
            "response":           cls.int_to_hex(proof.response),
            "public_point_bytes": cls.bytes_to_b64(proof.public_point_bytes),
            "domain_tag":         proof.domain_tag,
        }

    @classmethod
    def deserialise_schnorr(cls, data: dict[str, Any]):  # type: ignore[override]
        from .zkp_core import SchnorrProof
        expected = {
            "type",
            "announcement_bytes",
            "challenge",
            "response",
            "public_point_bytes",
            "domain_tag",
        }
        if not isinstance(data, dict) or set(data) != expected or data.get("type") != "SchnorrProof":
            raise ValueError("Malformed Schnorr proof data.")
        return SchnorrProof(
            announcement_bytes = cls.b64_to_bytes(data["announcement_bytes"]),
            challenge          = cls.hex_to_int(data["challenge"]),
            response           = cls.hex_to_int(data["response"]),
            public_point_bytes = cls.b64_to_bytes(data["public_point_bytes"]),
            domain_tag         = data["domain_tag"],
        )

    @classmethod
    def serialise_bit_proof(cls, bp) -> dict[str, Any]:  # type: ignore[override]
        return {
            "commitment_bytes": cls.bytes_to_b64(bp.commitment_bytes),
            "R0_bytes": cls.bytes_to_b64(bp.R0_bytes),
            "c0": cls.int_to_hex(bp.c0),
            "s0": cls.int_to_hex(bp.s0),
            "R1_bytes": cls.bytes_to_b64(bp.R1_bytes),
            "c1": cls.int_to_hex(bp.c1),
            "s1": cls.int_to_hex(bp.s1),
            "challenge": cls.int_to_hex(bp.challenge),
        }

    @classmethod
    def deserialise_bit_proof(cls, data: dict[str, Any]):  # type: ignore[override]
        from .zkp_core import BitProof
        expected = {
            "commitment_bytes",
            "R0_bytes",
            "c0",
            "s0",
            "R1_bytes",
            "c1",
            "s1",
            "challenge",
        }
        if not isinstance(data, dict) or set(data) != expected:
            raise ValueError("Malformed range bit proof data.")
        return BitProof(
            commitment_bytes = cls.b64_to_bytes(data["commitment_bytes"]),
            R0_bytes = cls.b64_to_bytes(data["R0_bytes"]),
            c0       = cls.hex_to_int(data["c0"]),
            s0       = cls.hex_to_int(data["s0"]),
            R1_bytes = cls.b64_to_bytes(data["R1_bytes"]),
            c1       = cls.hex_to_int(data["c1"]),
            s1       = cls.hex_to_int(data["s1"]),
            challenge = cls.hex_to_int(data["challenge"]),
        )

    @classmethod
    def serialise_range_proof(cls, rp) -> dict[str, Any]:  # type: ignore[override]
        return {
            "type": "RangeProof",
            "bit_proofs": [cls.serialise_bit_proof(bp) for bp in rp.bit_proofs],
            "total_commitment_bytes": cls.bytes_to_b64(rp.total_commitment_bytes),
            "domain_tag": rp.domain_tag,
        }

    @classmethod
    def deserialise_range_proof(cls, data: dict[str, Any]):  # type: ignore[override]
        from .zkp_core import RangeProof
        expected = {"type", "bit_proofs", "total_commitment_bytes", "domain_tag"}
        if (
            not isinstance(data, dict)
            or set(data) != expected
            or data.get("type") != "RangeProof"
            or not isinstance(data.get("bit_proofs"), list)
            or len(data["bit_proofs"]) > 128
        ):
            raise ValueError("Malformed range proof data.")
        return RangeProof(
            bit_proofs = [cls.deserialise_bit_proof(bp) for bp in data["bit_proofs"]],
            total_commitment_bytes = cls.b64_to_bytes(data["total_commitment_bytes"]),
            domain_tag = data["domain_tag"],
        )

    @classmethod
    def serialise_linear_proof(cls, lp) -> dict[str, Any]:  # type: ignore[override]
        return {
            "type": "LinearRelationProof",
            "commitment_subtotal_bytes": cls.bytes_to_b64(lp.commitment_subtotal_bytes),
            "commitment_tax_bytes":      cls.bytes_to_b64(lp.commitment_tax_bytes),
            "commitment_total_bytes":    cls.bytes_to_b64(lp.commitment_total_bytes),
            "domain_tag":           lp.domain_tag,
        }

    @classmethod
    def deserialise_linear_proof(cls, data: dict[str, Any]):  # type: ignore[override]
        from .zkp_core import LinearRelationProof
        expected = {
            "type",
            "commitment_subtotal_bytes",
            "commitment_tax_bytes",
            "commitment_total_bytes",
            "domain_tag",
        }
        if (
            not isinstance(data, dict)
            or set(data) != expected
            or data.get("type") != "LinearRelationProof"
        ):
            raise ValueError("Malformed linear relation proof data.")
        return LinearRelationProof(
            commitment_subtotal_bytes = cls.b64_to_bytes(data["commitment_subtotal_bytes"]),
            commitment_tax_bytes      = cls.b64_to_bytes(data["commitment_tax_bytes"]),
            commitment_total_bytes    = cls.b64_to_bytes(data["commitment_total_bytes"]),
            domain_tag           = data["domain_tag"],
        )
