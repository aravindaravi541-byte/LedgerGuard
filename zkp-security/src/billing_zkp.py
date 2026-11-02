"""
billing_zkp.py – ZKP-based private billing verification for LedgerGuard.
=========================================================================

This module is the primary entry point for the billing verification system.
It ties together:
  - Pedersen commitments to individual billing amounts
  - Context-bound range proofs for line items and aggregate amounts
  - Linear-relation proof (subtotal + tax = total)
  - Strict tax quotient/remainder proof with integer half-up rounding
  - Transcript binding to invoice metadata, tenant, reference and challenge
  - Timestamp freshness plus durable one-time challenge replay protection

Data model for a billing invoice (PRIVATE – never transmitted):
    InvoiceData:
        invoice_id:   str       unique identifier
        line_items:   list[int] individual amounts in integer cents
        tax_rate_bps: int       tax rate in basis points (100 bps = 1%)
        subtotal:     int       sum of line items in cents
        tax_amount:   int       half-up integer tax calculation in minor units
        total:        int       total = subtotal + tax_amount
        currency:     str       ISO 4217 currency code

PUBLIC proof (InvoiceProof) contains only:
  - Commitments and ZK proofs  (no raw amounts)
  - Invoice ID, tenant, currency and tax rate (public metadata)
  - Context-bound timestamp and verifier-issued challenge

The verifier can confirm:
  ✓ Each committed amount is non-negative (range proof)
  ✓ subtotal = sum of line items (linear relation)
  ✓ total = subtotal + tax (linear relation)
  ✓ The proof transcript is bound to the invoice and tenant context
  ✓ The one-time verifier challenge is fresh and unconsumed
  ✓ A trusted invoice reference matches when one is supplied

The proof alone does not authenticate who issued an invoice. That depends on
the host application's authenticated tenant and trusted invoice record.
"""

from __future__ import annotations

import json
import hmac
import re
from dataclasses import dataclass, field, asdict, fields
from typing import Any

from .zkp_core import (
    PedersenCommitment,
    RangeProver,
    RangeVerifier,
    LinearRelationProver,
    LinearRelationVerifier,
    StrictTaxProof,
    TaxRelationProver,
    TaxRelationVerifier,
    _decode_point,
    secp256k1_group,
)
from .crypto_utils import (
    SecureHasher,
    KeyManager,
    ProofSerializer,
    TimestampSigner,
)
from .exceptions import (
    InvalidProofError,
    ProofExpiredError,
    ZKPSecurityError,
)
from .replay import ChallengeStore, SQLiteChallengeStore

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_LINE_ITEMS = 1000
MAX_INVOICE_ID_BYTES = 128
MAX_PROOF_JSON_BYTES = 16 * 1024 * 1024

# RANGE_PROOF_BITS controls the bit-length of the range proof:
#   32 bits → max value 4,294,967,295  (£42,949,672.95) – sufficient for billing
#   64 bits → max value 18,446,744,073,709,551,615 – maximum security
#
# Override via environment variable ZKP_RANGE_BITS=32 (e.g., in test/CI environments).
# Production deployments should use 32 (fast, secure enough) or 64 (maximum security).
import os as _os
RANGE_PROOF_BITS: int = int(_os.environ.get("ZKP_RANGE_BITS", "32"))
del _os
if not (16 <= RANGE_PROOF_BITS <= 64):
    raise ValueError("ZKP_RANGE_BITS must be in [16, 64].")
MAX_AMOUNT_CENTS = (1 << RANGE_PROOF_BITS) - 1
MAX_TOTAL_CENTS = 2 * MAX_AMOUNT_CENTS

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class InvoiceData:
    """
    Private invoice data held by the prover.

    IMPORTANT: This object must NEVER leave the prover's trust boundary.
    Only InvoiceProof is transmitted to verifiers.
    """
    invoice_id:   str
    line_items:   list[int]      # amounts in integer cents, all non-negative
    tax_rate_bps: int            # tax rate in basis points (e.g. 2000 = 20%)
    currency:     str = "GBP"

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if (
            not isinstance(self.invoice_id, str)
            or not self.invoice_id
            or len(self.invoice_id.encode("utf-8")) > MAX_INVOICE_ID_BYTES
            or any(ord(ch) < 32 for ch in self.invoice_id)
        ):
            raise ValueError("invoice_id must be 1-128 UTF-8 bytes without control characters.")
        if not isinstance(self.line_items, list) or not self.line_items:
            raise ValueError("line_items must not be empty.")
        if any(
            type(v) is not int or not (0 <= v <= MAX_AMOUNT_CENTS)
            for v in self.line_items
        ):
            raise ValueError(
                f"Line item amounts must be integers in [0, {MAX_AMOUNT_CENTS}]."
            )
        if len(self.line_items) > MAX_LINE_ITEMS:
            raise ValueError(f"Too many line items (max {MAX_LINE_ITEMS}).")
        if type(self.tax_rate_bps) is not int or not (0 <= self.tax_rate_bps <= 10_000):
            raise ValueError("tax_rate_bps must be in [0, 10000].")
        if not isinstance(self.currency, str) or not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise ValueError("currency must be an uppercase ISO 4217 code.")
        if self.subtotal > MAX_AMOUNT_CENTS:
            raise ValueError(f"Subtotal must not exceed {MAX_AMOUNT_CENTS}.")
        if self.total > MAX_TOTAL_CENTS:
            raise ValueError(f"Total must not exceed {MAX_TOTAL_CENTS}.")

    @property
    def subtotal(self) -> int:
        return sum(self.line_items)

    @property
    def tax_amount(self) -> int:
        return (self.subtotal * self.tax_rate_bps + 5000) // 10_000

    @property
    def total(self) -> int:
        return self.subtotal + self.tax_amount

    def canonical_hash(self) -> bytes:
        """
        Deterministic SHA3-256 hash of the full invoice (tamper detection).
        This unkeyed helper is suitable for local integrity checks only; use
        BillingProver.invoice_reference() for references exposed to verifiers.
        """
        self.validate()
        return SecureHasher.hash(
            SecureHasher.DOMAIN_INVOICE,
            self.canonical_bytes(),
        )

    def canonical_bytes(self) -> bytes:
        """Return the versioned canonical serialization hashed for references."""
        self.validate()
        payload = {
            "schema": "ledgerguard-invoice-v1",
            "invoice_id":   self.invoice_id,
            "line_items":   self.line_items,
            "tax_rate_bps": self.tax_rate_bps,
            "subtotal":     self.subtotal,
            "tax_amount":   self.tax_amount,
            "total":        self.total,
            "currency":     self.currency,
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")


@dataclass
class LineItemProof:
    """ZKP material for a single line item."""
    range_proof_data: dict[str, Any]          # serialised RangeProof
    commitment_bytes_b64: str                 # commitment to this line item


@dataclass
class InvoiceProof:
    """
    Verifier-facing proof object.  Contains NO raw billing amounts.

    Transmitted to the verifier (e.g., the Flask backend or an auditor).
    """
    invoice_id:       str
    tenant_id:        str
    currency:         str
    challenge_token:  str
    proof_context:    str
    tax_rate_bps:     int

    # Line-item range proofs (prove each amount ≥ 0)
    line_item_proofs: list[LineItemProof]
    subtotal_range_proof_data: dict[str, Any]
    tax_range_proof_data: dict[str, Any]
    total_range_proof_data: dict[str, Any]

    # Sum proof: subtotal = sum of line items
    subtotal_commitment_b64: str
    sum_proof_data: dict[str, Any]          # homomorphic sum statement metadata

    # Billing relation proof: total = subtotal + tax
    tax_commitment_b64:   str
    total_commitment_b64: str
    billing_relation_proof_data: dict[str, Any]  # serialised LinearRelationProof
    tax_relation_proof_data: dict[str, Any]

    # Keyed reference to canonical invoice contents; trust is external
    invoice_hash_b64: str

    # Context-bound freshness token; replay is controlled by challenge store
    timestamp_token: str

    # Metadata
    proof_version: str = "2.0"

    def to_json(self) -> str:
        """Serialise to a JSON string safe for transmission."""
        return json.dumps(asdict(self), separators=(",", ":"), allow_nan=False)

    @classmethod
    def from_json(cls, raw: str) -> "InvoiceProof":
        """Deserialise from a JSON string."""
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_PROOF_JSON_BYTES:
            raise ValueError("Invoice proof JSON exceeds the allowed size.")

        def unique_object(pairs):
            output = {}
            for key, value in pairs:
                if key in output:
                    raise ValueError("Duplicate JSON keys are not allowed.")
                output[key] = value
            return output

        d = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(d, dict):
            raise ValueError("Invoice proof JSON must contain an object.")
        field_names = {f.name for f in fields(cls)}
        unknown = set(d) - field_names
        if unknown:
            raise ValueError(f"Unexpected invoice proof fields: {sorted(unknown)}")
        if not isinstance(d.get("line_item_proofs"), list):
            raise ValueError("line_item_proofs must be an array.")
        d["line_item_proofs"] = [
            LineItemProof(**lip) if isinstance(lip, dict) else lip
            for lip in d.get("line_item_proofs", [])
        ]
        return cls(**d)


@dataclass
class ProofVerificationResult:
    """
    Structured result returned by BillingVerifier.verify().
    """
    is_valid:              bool
    invoice_id:            str
    checks_passed:         list[str]   = field(default_factory=list)
    checks_failed:         list[str]   = field(default_factory=list)
    error_message:         str         = ""
    cryptographic_proof_valid: bool = False
    trusted_reference_verified: bool = False
    invoice_authenticity_verified: bool = False

    def raise_if_invalid(self) -> None:
        """Raise InvalidProofError if verification failed."""
        if not self.is_valid:
            raise InvalidProofError(
                f"Proof for invoice {self.invoice_id!r} is invalid: "
                f"{self.error_message or self.checks_failed}"
            )


def _statement_context(
    invoice_id: str,
    tenant_id: str,
    currency: str,
    invoice_hash: bytes,
    challenge_token: str,
) -> str:
    return SecureHasher.hash(
        b"LedgerGuard|invoice-statement|v2",
        invoice_id.encode("utf-8"),
        tenant_id.encode("utf-8"),
        currency.encode("ascii"),
        invoice_hash,
        challenge_token.encode("ascii"),
    ).hex()


def _serialise_tax_proof(proof: StrictTaxProof) -> dict[str, Any]:
    serializer = ProofSerializer
    return {
        "type": "StrictTaxProof",
        "tax_rate_bps": proof.tax_rate_bps,
        "c_rem_b64": serializer.bytes_to_b64(proof.c_rem_bytes),
        "c_rem_dual_b64": serializer.bytes_to_b64(proof.c_rem_dual_bytes),
        "rem_range_proof": serializer.serialise_range_proof(proof.rem_range_proof),
        "rem_dual_range_proof": serializer.serialise_range_proof(
            proof.rem_dual_range_proof
        ),
        "schnorr_sum_dual": serializer.serialise_schnorr(proof.schnorr_sum_dual),
        "domain_tag": proof.domain_tag,
    }


def _deserialise_tax_proof(data: dict[str, Any]) -> StrictTaxProof:
    if not isinstance(data, dict) or data.get("type") != "StrictTaxProof":
        raise ValueError("Malformed tax relation proof.")
    expected = {
        "type",
        "tax_rate_bps",
        "c_rem_b64",
        "c_rem_dual_b64",
        "rem_range_proof",
        "rem_dual_range_proof",
        "schnorr_sum_dual",
        "domain_tag",
    }
    if set(data) != expected:
        raise ValueError("Unexpected or missing tax relation proof fields.")
    serializer = ProofSerializer
    return StrictTaxProof(
        tax_rate_bps=data["tax_rate_bps"],
        c_rem_bytes=serializer.b64_to_bytes(data["c_rem_b64"]),
        c_rem_dual_bytes=serializer.b64_to_bytes(data["c_rem_dual_b64"]),
        rem_range_proof=serializer.deserialise_range_proof(
            data["rem_range_proof"]
        ),
        rem_dual_range_proof=serializer.deserialise_range_proof(
            data["rem_dual_range_proof"]
        ),
        schnorr_sum_dual=serializer.deserialise_schnorr(data["schnorr_sum_dual"]),
        domain_tag=data["domain_tag"],
    )


# ---------------------------------------------------------------------------
# BillingProver
# ---------------------------------------------------------------------------

class BillingProver:
    """
    Generates a ZKP-based proof for a private invoice.

    Usage::

        prover = BillingProver()
        proof  = prover.prove(invoice_data)
        json_proof = proof.to_json()        # safe to send to verifier
    """

    def __init__(self, key_manager: KeyManager | None = None) -> None:
        self._km = key_manager or KeyManager()
        self._range_prover   = RangeProver(bit_length=RANGE_PROOF_BITS)
        self._linear_prover  = LinearRelationProver()
        self._tax_prover     = TaxRelationProver()
        self._ts_signer      = TimestampSigner(self._km)
        self._serialiser     = ProofSerializer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def prove(
        self,
        invoice: InvoiceData,
        *,
        tenant_id: str,
        challenge_token: str,
    ) -> InvoiceProof:
        """
        Generate a complete ZKP proof for the given invoice.

        Args:
            invoice: Private InvoiceData (NEVER leaves the prover).

        Returns:
            InvoiceProof – safe to transmit to any verifier.

        Raises:
            ZKPSecurityError on internal failures.
        """
        try:
            return self._build_proof(invoice, tenant_id, challenge_token)
        except ZKPSecurityError:
            raise
        except Exception as exc:
            raise ZKPSecurityError(f"Proof generation failed: {exc}") from exc

    def invoice_reference(self, invoice: InvoiceData) -> bytes:
        """Create the keyed canonical invoice reference stored by the backend."""
        key = self._km.derive("invoice-reference", length=32)
        digest = SecureHasher.hash(
            SecureHasher.DOMAIN_INVOICE,
            invoice.canonical_bytes(),
        )
        return hmac.new(
            key,
            b"LedgerGuard|trusted-invoice-reference|v2|" + digest,
            "sha256",
        ).digest()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_proof(
        self,
        invoice: InvoiceData,
        tenant_id: str,
        challenge_token: str,
    ) -> InvoiceProof:
        invoice.validate()
        if (
            not isinstance(tenant_id, str)
            or not tenant_id
            or len(tenant_id.encode("utf-8")) > 128
            or any(ord(ch) < 32 for ch in tenant_id)
        ):
            raise ValueError("tenant_id must be 1-128 UTF-8 bytes without control characters.")
        if not isinstance(challenge_token, str) or not (32 <= len(challenge_token) <= 256):
            raise ValueError("A verifier-issued challenge token is required.")

        invoice_hash = self.invoice_reference(invoice)
        context = _statement_context(
            invoice.invoice_id,
            tenant_id,
            invoice.currency,
            invoice_hash,
            challenge_token,
        )
        tag_base = f"LedgerGuard|invoice-proof|v2|{context}"

        # 1. Commit to and range-prove each line item
        line_item_proofs: list[LineItemProof] = []
        li_commitments: list[PedersenCommitment] = []

        for idx, amount in enumerate(invoice.line_items):
            rp, comm = self._range_prover.prove(
                amount, domain_tag=f"{tag_base}|line-item|{idx}"
            )
            rp_data = self._serialiser.serialise_range_proof(rp)
            line_item_proofs.append(
                LineItemProof(
                    range_proof_data      = rp_data,
                    commitment_bytes_b64  = ProofSerializer.bytes_to_b64(
                        comm.public_point_bytes()
                    ),
                )
            )
            li_commitments.append(comm)

        # 2. Build commitment to subtotal and prove it equals sum of line items
        subtotal_comm, sum_proof_data = self._prove_sum(
            li_commitments, invoice.subtotal, tag_base
        )
        subtotal_range, subtotal_range_commitment = self._range_prover.prove(
            invoice.subtotal,
            f"{tag_base}|subtotal",
            blinding=subtotal_comm.blinding,
        )
        if subtotal_range_commitment.point != subtotal_comm.point:
            raise ValueError("Subtotal range proof does not match subtotal commitment.")

        # 3. Commit to tax and total, prove linear relation
        tax_comm   = PedersenCommitment.commit(invoice.tax_amount)
        tax_range, tax_range_commitment = self._range_prover.prove(
            invoice.tax_amount,
            f"{tag_base}|tax",
            blinding=tax_comm.blinding,
        )

        # Bind total commitment to be exactly subtotal + tax homomorphically
        # We re-commit total using subtotal + tax blinding so the check passes
        bound_total = subtotal_comm.add(tax_comm)
        total_range, total_range_commitment = RangeProver(
            bit_length=RANGE_PROOF_BITS + 1
        ).prove(
            invoice.total,
            f"{tag_base}|total",
            blinding=bound_total.blinding,
        )
        if (
            tax_range_commitment.point != tax_comm.point
            or total_range_commitment.point != bound_total.point
        ):
            raise ValueError("Tax or total range proof does not match its commitment.")

        billing_lp = self._linear_prover.prove(
            subtotal_comm, tax_comm, bound_total,
            domain_tag=f"{tag_base}|billing_relation",
        )
        billing_relation_data = self._serialiser.serialise_linear_proof(billing_lp)
        tax_relation = self._tax_prover.prove(
            subtotal_comm,
            tax_comm,
            invoice.tax_rate_bps,
            domain_tag=f"{tag_base}|tax_relation",
        )

        # 4. Keyed reference to the canonical private invoice
        inv_hash_b64 = ProofSerializer.bytes_to_b64(invoice_hash)

        # 5. Timestamp freshness token bound to the statement
        ts_token = self._ts_signer.sign_now(context)

        return InvoiceProof(
            invoice_id       = invoice.invoice_id,
            tenant_id        = tenant_id,
            currency         = invoice.currency,
            challenge_token  = challenge_token,
            proof_context    = context,
            tax_rate_bps     = invoice.tax_rate_bps,
            line_item_proofs = line_item_proofs,
            subtotal_range_proof_data = self._serialiser.serialise_range_proof(
                subtotal_range
            ),
            tax_range_proof_data = self._serialiser.serialise_range_proof(tax_range),
            total_range_proof_data = self._serialiser.serialise_range_proof(total_range),
            subtotal_commitment_b64  = ProofSerializer.bytes_to_b64(
                subtotal_comm.public_point_bytes()
            ),
            sum_proof_data           = sum_proof_data,
            tax_commitment_b64       = ProofSerializer.bytes_to_b64(
                tax_comm.public_point_bytes()
            ),
            total_commitment_b64     = ProofSerializer.bytes_to_b64(
                bound_total.public_point_bytes()
            ),
            billing_relation_proof_data = billing_relation_data,
            tax_relation_proof_data = _serialise_tax_proof(tax_relation),
            invoice_hash_b64         = inv_hash_b64,
            timestamp_token          = ts_token,
        )

    def _prove_sum(
        self,
        li_commitments: list[PedersenCommitment],
        subtotal: int,
        tag_base: str,
    ) -> tuple[PedersenCommitment, dict[str, Any]]:
        """
        Prove subtotal = sum of line item commitments homomorphically.

        We build the subtotal commitment by homomorphic addition of all
        line item commitments.  The verifier repeats this addition on the
        public points.
        """
        if not li_commitments or sum(c.value for c in li_commitments) != subtotal:
            raise ValueError("Subtotal witness does not match line item commitments.")
        # Homomorphic sum of all line item commitments
        agg = li_commitments[0]
        for c in li_commitments[1:]:
            agg = agg.add(c)
        # agg now commits to subtotal = sum of line items

        sum_proof_data = {
            "type": "HomomorphicSumProof",
            "num_items": len(li_commitments),
            "schnorr_blinding_proofs": [],
        }
        return agg, sum_proof_data

# ---------------------------------------------------------------------------
# BillingVerifier
# ---------------------------------------------------------------------------

class BillingVerifier:
    """
    Verifies a ZKP-based InvoiceProof.

    The verifier NEVER sees raw billing amounts. It checks that:
    1. Each line item commitment passes its range proof.
    2. The subtotal commitment equals the homomorphic sum of line items.
    3. Tax obeys the bounded integer relation and defined rounding rule.
    4. The total commitment equals subtotal + tax.
    5. Metadata is bound to the transcript and tenant context.
    6. A trusted invoice reference matches when provided.
    7. A verifier-issued challenge is consumed once.

    Usage requires verifier-issued challenge and authenticated tenant::

    challenge, _ = verifier.issue_challenge(invoice_id, tenant_id)
    proof = prover.prove(
        invoice, tenant_id=tenant_id, challenge_token=challenge
    )
    result = verifier.verify(proof, tenant_id=tenant_id)
    """

    def __init__(
        self,
        key_manager: KeyManager | None = None,
        max_proof_age_seconds: int = 3600,
        challenge_store: ChallengeStore | None = None,
    ) -> None:
        self._km               = key_manager or KeyManager()
        self._range_verifier   = RangeVerifier(bit_length=RANGE_PROOF_BITS)
        self._total_range_verifier = RangeVerifier(bit_length=RANGE_PROOF_BITS + 1)
        self._linear_verifier  = LinearRelationVerifier()
        self._tax_verifier     = TaxRelationVerifier()
        self._ts_signer        = TimestampSigner(self._km, max_proof_age_seconds)
        self._serialiser       = ProofSerializer()
        if challenge_store is None:
            mode = __import__("os").environ.get("LEDGERGUARD_ZKP_MODE", "production").lower()
            if mode not in {"test", "development"}:
                raise ValueError("A durable ChallengeStore is required outside test/development mode.")
            challenge_store = SQLiteChallengeStore(":memory:")
        self._challenge_store = challenge_store

    def issue_challenge(
        self,
        invoice_id: str,
        tenant_id: str,
        ttl_seconds: int = 300,
    ) -> tuple[str, int]:
        """Issue a one-time challenge bound to an invoice and tenant."""
        return self._challenge_store.issue(tenant_id, invoice_id, ttl_seconds)

    def verify(
        self,
        proof: InvoiceProof,
        *,
        tenant_id: str | None,
        expected_invoice_hash_b64: str | None = None,
    ) -> ProofVerificationResult:
        """
        Verify the proof statement in the authenticated caller's tenant context.

        Without ``expected_invoice_hash_b64``, this verifies proof mathematics
        and transcript integrity only; it does not authenticate invoice contents.
        A valid proof consumes its verifier-issued challenge exactly once.
        """
        passed: list[str] = []
        failed: list[str] = []
        errors: list[str] = []
        cryptographic_valid = False
        invoice_id = getattr(proof, "invoice_id", "")

        def reject(check: str, message: str) -> None:
            failed.append(check)
            errors.append(message)

        try:
            if not isinstance(proof, InvoiceProof) or proof.proof_version != "2.0":
                raise ValueError("Unsupported or malformed invoice proof.")
            if (
                not isinstance(proof.invoice_id, str)
                or not proof.invoice_id
                or len(proof.invoice_id.encode("utf-8")) > MAX_INVOICE_ID_BYTES
                or not isinstance(proof.tenant_id, str)
                or not proof.tenant_id
                or len(proof.tenant_id.encode("utf-8")) > 128
                or not isinstance(proof.currency, str)
                or not re.fullmatch(r"[A-Z]{3}", proof.currency)
                or type(proof.tax_rate_bps) is not int
                or not (0 <= proof.tax_rate_bps <= 10000)
                or not isinstance(proof.challenge_token, str)
                or not (32 <= len(proof.challenge_token) <= 256)
                or not isinstance(proof.proof_context, str)
                or not re.fullmatch(r"[0-9a-f]{64}", proof.proof_context)
                or not isinstance(proof.line_item_proofs, list)
                or not (1 <= len(proof.line_item_proofs) <= MAX_LINE_ITEMS)
            ):
                raise ValueError("Invalid invoice proof metadata or bounds.")
            if tenant_id is None or tenant_id != proof.tenant_id:
                reject("tenant_context", "Proof tenant does not match authenticated tenant.")

            invoice_hash = ProofSerializer.b64_to_bytes(proof.invoice_hash_b64)
            if len(invoice_hash) != 32:
                raise ValueError("Invoice hash must be exactly 32 bytes.")
            context = _statement_context(
                proof.invoice_id,
                proof.tenant_id,
                proof.currency,
                invoice_hash,
                proof.challenge_token,
            )
            if not hmac.compare_digest(context, proof.proof_context):
                reject("proof_context", "Proof context does not match invoice metadata.")
            else:
                passed.append("proof_context")
                passed.append("invoice_id_binding")
                try:
                    self._ts_signer.verify(proof.timestamp_token, context=context)
                    passed.append("timestamp_freshness")
                except ProofExpiredError:
                    reject("timestamp_freshness", "Proof timestamp token is invalid or expired.")

            if expected_invoice_hash_b64 is not None:
                expected_hash = ProofSerializer.b64_to_bytes(expected_invoice_hash_b64)
                if len(expected_hash) != 32 or not hmac.compare_digest(
                    invoice_hash, expected_hash
                ):
                    reject("trusted_invoice_reference", "Trusted invoice reference mismatch.")
                else:
                    passed.append("trusted_invoice_reference")

            tag_base = f"LedgerGuard|invoice-proof|v2|{context}"
            for idx, line_proof in enumerate(proof.line_item_proofs):
                if not isinstance(line_proof, LineItemProof):
                    reject(f"line_item_range_proof[{idx}]", "Malformed line-item proof.")
                    continue
                range_proof = self._serialiser.deserialise_range_proof(
                    line_proof.range_proof_data
                )
                commitment = ProofSerializer.b64_to_bytes(
                    line_proof.commitment_bytes_b64
                )
                if commitment != range_proof.total_commitment_bytes:
                    reject(
                        f"line_item_range_binding[{idx}]",
                        "Range proof commitment differs from line-item commitment.",
                    )
                    continue
                if not self._range_verifier.verify(
                    range_proof,
                    expected_domain_tag=f"{tag_base}|line-item|{idx}",
                ):
                    reject(f"line_item_range_proof[{idx}]", "Invalid line-item range proof.")
                else:
                    passed.append(f"line_item_range_proof[{idx}]")
            if not any(item.startswith("line_item_range") for item in failed):
                passed.append("all_line_item_range_proofs")

            sum_data = proof.sum_proof_data
            if (
                not isinstance(sum_data, dict)
                or set(sum_data) != {"type", "num_items", "schnorr_blinding_proofs"}
                or sum_data.get("type") != "HomomorphicSumProof"
                or sum_data.get("num_items") != len(proof.line_item_proofs)
                or sum_data.get("schnorr_blinding_proofs") != []
            ):
                reject("homomorphic_sum_metadata", "Malformed homomorphic sum metadata.")
            else:
                from .zkp_core import _point_add

                aggregate = None
                for line_proof in proof.line_item_proofs:
                    point = _decode_point(
                        ProofSerializer.b64_to_bytes(line_proof.commitment_bytes_b64)
                    )
                    aggregate = _point_add(aggregate, point)
                subtotal_bytes = ProofSerializer.b64_to_bytes(
                    proof.subtotal_commitment_b64
                )
                subtotal_point = _decode_point(subtotal_bytes)
                if aggregate is None or aggregate != subtotal_point:
                    reject("homomorphic_sum", "Subtotal is not the sum of line items.")
                else:
                    passed.append("homomorphic_sum")

            range_claims = (
                (
                    "subtotal",
                    proof.subtotal_range_proof_data,
                    proof.subtotal_commitment_b64,
                    self._range_verifier,
                ),
                (
                    "tax",
                    proof.tax_range_proof_data,
                    proof.tax_commitment_b64,
                    self._range_verifier,
                ),
                (
                    "total",
                    proof.total_range_proof_data,
                    proof.total_commitment_b64,
                    self._total_range_verifier,
                ),
            )
            for label, proof_data, commitment_b64, range_verifier in range_claims:
                range_proof = self._serialiser.deserialise_range_proof(proof_data)
                commitment = ProofSerializer.b64_to_bytes(commitment_b64)
                if commitment != range_proof.total_commitment_bytes:
                    reject(f"{label}_range_binding", f"{label} range proof is detached.")
                elif not range_verifier.verify(
                    range_proof,
                    expected_domain_tag=f"{tag_base}|{label}",
                ):
                    reject(f"{label}_range_proof", f"Invalid {label} range proof.")
                else:
                    passed.append(f"{label}_range_proof")

            linear_proof = self._serialiser.deserialise_linear_proof(
                proof.billing_relation_proof_data
            )
            top_level_commitments = (
                ProofSerializer.b64_to_bytes(proof.subtotal_commitment_b64),
                ProofSerializer.b64_to_bytes(proof.tax_commitment_b64),
                ProofSerializer.b64_to_bytes(proof.total_commitment_b64),
            )
            if (
                top_level_commitments
                != (
                    linear_proof.commitment_subtotal_bytes,
                    linear_proof.commitment_tax_bytes,
                    linear_proof.commitment_total_bytes,
                )
            ):
                reject("billing_relation_commitment_match", "Billing commitments do not match.")
            elif not self._linear_verifier.verify(
                linear_proof,
                expected_domain_tag=f"{tag_base}|billing_relation",
            ):
                reject("billing_relation_proof", "Total is not subtotal plus tax.")
            else:
                passed.append("billing_relation_proof")

            tax_proof = _deserialise_tax_proof(proof.tax_relation_proof_data)
            if not self._tax_verifier.verify(
                tax_proof,
                top_level_commitments[0],
                top_level_commitments[1],
                expected_domain_tag=f"{tag_base}|tax_relation",
                expected_tax_rate_bps=proof.tax_rate_bps,
            ):
                reject("tax_calculation_proof", "Tax does not match the stated rate and rounding rule.")
            else:
                passed.append("tax_calculation_proof")

            cryptographic_valid = not any(
                check not in {"tenant_context", "trusted_invoice_reference"}
                for check in failed
            )
            if not failed:
                if not self._challenge_store.consume(
                    proof.challenge_token, proof.tenant_id, proof.invoice_id
                ):
                    reject("challenge_replay", "Challenge is invalid, expired, or already consumed.")
                else:
                    passed.append("challenge_consumed_once")
        except Exception as exc:
            reject("proof_validation", "Malformed or invalid proof data.")
            errors.append(str(exc))

        is_valid = not failed
        return ProofVerificationResult(
            is_valid=is_valid,
            invoice_id=invoice_id,
            checks_passed=passed,
            checks_failed=failed,
            error_message="; ".join(errors),
            cryptographic_proof_valid=cryptographic_valid,
            trusted_reference_verified=(
                expected_invoice_hash_b64 is not None
                and "trusted_invoice_reference" in passed
            ),
            invoice_authenticity_verified=False,
        )

    def verify_with_invoice_hash(
        self,
        proof: InvoiceProof,
        expected_invoice_hash_b64: str,
        *,
        tenant_id: str,
    ) -> ProofVerificationResult:
        """
        Extended verification that also checks the invoice hash matches.
        Call this when you have access to a stored invoice hash (e.g., from DB).

        This detects post-signing tampering of the invoice data.
        """
        return self.verify(
            proof,
            tenant_id=tenant_id,
            expected_invoice_hash_b64=expected_invoice_hash_b64,
        )
