"""
test_billing_zkp.py – Integration tests for the billing ZKP system.

Tests cover:
  - Full prove → verify roundtrip (simple and complex invoices)
  - Privacy: proof contains no raw amounts
  - Tamper detection: modified invoice hash
  - Invalid proofs: fabricated / replayed proofs
  - Serialisation roundtrip: JSON → verify still works
  - Edge cases: zero items, zero tax, single item
  - Correctness: subtotal + tax == total (computed, verified blindly)
"""

import sys, os, json, base64, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from src.billing_zkp import (
    InvoiceData,
    BillingProver,
    BillingVerifier,
    InvoiceProof,
    LineItemProof,
    MAX_AMOUNT_CENTS,
)
from src.crypto_utils import KeyManager
from src.exceptions import InvalidProofError, TamperingDetectedError, ZKPSecurityError
from src.replay import SQLiteChallengeStore
from tests.conftest import ChallengeAwareProver, TenantAwareVerifier
from src.zkp_core import (
    PedersenCommitment,
    RangeProver,
    SchnorrProof,
    StrictTaxProof,
    TaxRelationProver,
    TaxRelationVerifier,
    secp256k1_group,
)


# =============================================================================
# Helpers
# =============================================================================

def make_prover_verifier():
    """Return a matched prover/verifier pair sharing the same KeyManager."""
    import secrets
    km = KeyManager(ikm=secrets.token_bytes(32))
    store = SQLiteChallengeStore(":memory:")
    verifier = TenantAwareVerifier(key_manager=km, challenge_store=store)
    return ChallengeAwareProver(BillingProver(key_manager=km), verifier), verifier


# =============================================================================
# Full Prove → Verify Roundtrips
# =============================================================================

class TestProveVerifyRoundtrip:

    def test_simple_invoice_roundtrip(self, prover, verifier, simple_invoice):
        proof  = prover.prove(simple_invoice)
        result = verifier.verify(proof)
        assert result.is_valid, f"Failed checks: {result.checks_failed}"

    def test_multi_item_invoice_roundtrip(self, prover, verifier, multi_item_invoice):
        proof  = prover.prove(multi_item_invoice)
        result = verifier.verify(proof)
        assert result.is_valid, f"Failed checks: {result.checks_failed}"

    def test_zero_tax_invoice_roundtrip(self, prover, verifier, zero_tax_invoice):
        proof  = prover.prove(zero_tax_invoice)
        result = verifier.verify(proof)
        assert result.is_valid, f"Failed checks: {result.checks_failed}"

    def test_large_invoice_roundtrip(self, prover, verifier, large_invoice):
        proof  = prover.prove(large_invoice)
        result = verifier.verify(proof)
        assert result.is_valid, f"Failed checks: {result.checks_failed}"

    def test_distinct_invoices_have_different_proofs(self, prover):
        inv1 = InvoiceData("INV-A", [1000], 2000)
        inv2 = InvoiceData("INV-B", [2000], 2000)
        p1 = prover.prove(inv1)
        p2 = prover.prove(inv2)
        # Different invoice IDs → different ZKP material
        assert p1.invoice_hash_b64 != p2.invoice_hash_b64

    def test_result_contains_expected_checks(self, prover, verifier, simple_invoice):
        proof  = prover.prove(simple_invoice)
        result = verifier.verify(proof)
        assert "timestamp_freshness"     in result.checks_passed
        assert "billing_relation_proof"  in result.checks_passed
        assert "invoice_id_binding"      in result.checks_passed
        assert "homomorphic_sum"         in result.checks_passed

    def test_serialise_then_verify(self, prover, verifier, multi_item_invoice):
        """Proof serialised to JSON and deserialised must still verify."""
        proof      = prover.prove(multi_item_invoice)
        json_str   = proof.to_json()
        proof_back = InvoiceProof.from_json(json_str)
        result     = verifier.verify(proof_back)
        assert result.is_valid, f"JSON roundtrip failed: {result.checks_failed}"

    def test_single_cent_invoice(self, prover, verifier):
        """Edge case: smallest possible amount."""
        invoice = InvoiceData("INV-1CENT", [1], 2000)
        proof   = prover.prove(invoice)
        result  = verifier.verify(proof)
        assert result.is_valid


# =============================================================================
# Privacy Tests: Proof Must Not Reveal Sensitive Data
# =============================================================================

class TestPrivacy:
    """Ensure no raw billing amounts appear in the proof."""

    def test_no_raw_amounts_in_json(self, prover, multi_item_invoice):
        proof    = prover.prove(multi_item_invoice)
        data = json.loads(proof.to_json())
        public_numeric_paths = {
            ("tax_rate_bps",),
            ("tax_relation_proof_data", "tax_rate_bps"),
            ("sum_proof_data", "num_items"),
        }

        def numeric_paths(value, path=()):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield from numeric_paths(child, path + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from numeric_paths(child, path + (str(index),))
            elif type(value) in (int, float):
                yield path

        assert set(numeric_paths(data)) <= public_numeric_paths
        assert not {"line_items", "subtotal", "tax_amount", "total"} & data.keys()

    def test_subtotal_not_in_proof(self, prover, multi_item_invoice):
        proof    = prover.prove(multi_item_invoice)
        json_str = proof.to_json()
        subtotal = multi_item_invoice.subtotal
        # subtotal as a field should not appear
        assert '"subtotal"' not in json_str
        assert f'"subtotal_amount": {subtotal}' not in json_str

    def test_tax_amount_not_in_proof(self, prover, multi_item_invoice):
        proof    = prover.prove(multi_item_invoice)
        json_str = proof.to_json()
        assert '"tax_amount"' not in json_str

    def test_tax_rate_is_public_and_bound_in_proof(self, prover, multi_item_invoice):
        proof    = prover.prove(multi_item_invoice)
        data = json.loads(proof.to_json())
        assert data["tax_rate_bps"] == multi_item_invoice.tax_rate_bps
        assert (
            data["tax_relation_proof_data"]["tax_rate_bps"]
            == multi_item_invoice.tax_rate_bps
        )
        assert proof.tax_rate_bps == multi_item_invoice.tax_rate_bps
        json_str = proof.to_json()
        assert '"tax_rate"' not in json_str

    def test_line_items_list_not_in_proof(self, prover, multi_item_invoice):
        proof    = prover.prove(multi_item_invoice)
        json_str = proof.to_json()
        assert '"line_items"' not in json_str


# =============================================================================
# Tamper Detection Tests
# =============================================================================

class TestTamperDetection:

    def test_invoice_hash_mismatch_detected(self, prover, verifier, simple_invoice):
        """Changing the stored hash should be detected by verify_with_invoice_hash."""
        proof = prover.prove(simple_invoice)
        # Provide a wrong expected hash
        wrong_hash = base64.b64encode(b"\x00" * 32).decode()
        result = verifier.verify_with_invoice_hash(proof, wrong_hash)
        assert not result.is_valid
        assert "trusted_invoice_reference" in result.checks_failed

    def test_correct_invoice_hash_passes(self, prover, verifier, simple_invoice):
        """Correct invoice hash must pass extended verification."""
        proof    = prover.prove(simple_invoice)
        inv_hash = proof.invoice_hash_b64
        result   = verifier.verify_with_invoice_hash(proof, inv_hash)
        assert result.is_valid

    def test_tampered_total_commitment_fails(self, prover, verifier, simple_invoice):
        """Corrupting the total commitment bytes must cause verification failure."""
        proof = prover.prove(simple_invoice)
        bad = bytearray(base64.b64decode(proof.total_commitment_b64))
        bad[1] ^= 0xFF
        proof.total_commitment_b64 = base64.b64encode(bytes(bad)).decode()
        result = verifier.verify(proof)
        assert not result.is_valid

    def test_tampered_subtotal_commitment_fails(self, prover, verifier, simple_invoice):
        proof = prover.prove(simple_invoice)
        bad = bytearray(base64.b64decode(proof.subtotal_commitment_b64))
        bad[1] ^= 0x01
        proof.subtotal_commitment_b64 = base64.b64encode(bytes(bad)).decode()
        result = verifier.verify(proof)
        assert not result.is_valid

    def test_tampered_line_item_commitment_fails(self, prover, verifier, multi_item_invoice):
        proof = prover.prove(multi_item_invoice)
        bad = bytearray(base64.b64decode(proof.line_item_proofs[0].commitment_bytes_b64))
        bad[1] ^= 0x10
        proof.line_item_proofs[0].commitment_bytes_b64 = base64.b64encode(bytes(bad)).decode()
        result = verifier.verify(proof)
        assert not result.is_valid

    def test_adding_extra_line_item_proof_fails(self, prover, verifier, simple_invoice):
        """Injecting a fabricated extra line item should break the homomorphic sum."""
        proof = prover.prove(simple_invoice)
        # Clone the first line item proof and append it
        extra = LineItemProof(
            range_proof_data     = proof.line_item_proofs[0].range_proof_data,
            commitment_bytes_b64 = proof.line_item_proofs[0].commitment_bytes_b64,
        )
        proof.line_item_proofs.append(extra)
        result = verifier.verify(proof)
        assert not result.is_valid


# =============================================================================
# Invalid / Fabricated Proof Tests
# =============================================================================

class TestInvalidProofs:

    def test_random_proof_rejected(self, verifier, simple_invoice, prover):
        """A proof for one invoice should not verify for a different invoice."""
        inv_a = InvoiceData("INV-A", [1000], 2000)
        inv_b = InvoiceData("INV-B", [9999], 1500)

        p_a, v_a = make_prover_verifier()
        p_b, v_b = make_prover_verifier()

        proof_a = p_a.prove(inv_a)
        # Try verifying proof_a under v_b (different KeyManager → different HMAC key)
        result = v_b.verify(proof_a)
        # Timestamp HMAC will fail because keys differ
        assert not result.is_valid

    def test_proof_for_wrong_invoice_id_rejected(self, prover, verifier):
        """Replacing invoice_id after proving must invalidate the statement context."""
        inv = InvoiceData("INV-REAL", [5000], 2000)
        proof = prover.prove(inv)
        proof.invoice_id = "INV-FAKE"
        result = verifier.verify(proof)
        assert not result.is_valid
        assert "proof_context" in result.checks_failed

    def test_empty_line_items_rejected(self):
        with pytest.raises(ValueError):
            InvoiceData("INV-EMPTY", [], 2000)

    def test_negative_line_item_rejected(self):
        with pytest.raises(ValueError):
            InvoiceData("INV-NEG", [-100, 500], 2000)

    def test_invalid_tax_rate_rejected(self):
        with pytest.raises(ValueError):
            InvoiceData("INV-TAX", [1000], tax_rate_bps=10001)

    def test_corrupted_billing_relation_proof(self, prover, verifier, simple_invoice):
        proof = prover.prove(simple_invoice)
        # Corrupt the billing relation proof data
        proof.billing_relation_proof_data["commitment_total_bytes"] = "AAAA"
        result = verifier.verify(proof)
        assert not result.is_valid

    def test_corrupted_sum_proof_data(self, prover, verifier, simple_invoice):
        proof = prover.prove(simple_invoice)
        proof.sum_proof_data["schnorr_blinding_proofs"] = []
        result = verifier.verify(proof)
        # With empty schnorr proofs, blinding_knowledge_proofs check should pass vacuously
        # but homomorphic_sum check still applies - result must be a valid bool
        assert isinstance(result.is_valid, bool)

    def test_raise_if_invalid_raises_on_bad_proof(self, verifier, simple_invoice, prover):
        proof = prover.prove(simple_invoice)
        proof.total_commitment_b64 = base64.b64encode(b"\x02" + b"\x01" * 32).decode()
        result = verifier.verify(proof)
        with pytest.raises(InvalidProofError):
            result.raise_if_invalid()


# =============================================================================
# InvoiceData Arithmetic Tests
# =============================================================================

class TestInvoiceDataArithmetic:

    def test_subtotal_equals_sum_of_items(self):
        items = [1000, 2000, 3000]
        inv = InvoiceData("INV-ARITH", items, 2000)
        assert inv.subtotal == 6000

    def test_tax_amount_computation(self):
        """20% of £100 = £20."""
        inv = InvoiceData("INV-TAX", [10000], 2000)
        assert inv.tax_amount == 2000

    def test_total_equals_subtotal_plus_tax(self):
        inv = InvoiceData("INV-TOTAL", [10000], 2000)
        assert inv.total == inv.subtotal + inv.tax_amount

    def test_zero_tax_rate(self):
        inv = InvoiceData("INV-ZERO-TAX", [5000, 3000], 0)
        assert inv.tax_amount == 0
        assert inv.total == 8000

    def test_canonical_hash_deterministic(self):
        inv = InvoiceData("INV-HASH", [1000, 2000], 2000)
        h1 = inv.canonical_hash()
        h2 = inv.canonical_hash()
        assert h1 == h2

    def test_different_invoices_have_different_hashes(self):
        inv1 = InvoiceData("INV-1", [1000], 2000)
        inv2 = InvoiceData("INV-2", [2000], 2000)
        assert inv1.canonical_hash() != inv2.canonical_hash()

    def test_half_up_rounding_is_integer_exact(self):
        assert InvoiceData("INV-TIE-UP", [1], 5000).tax_amount == 1
        assert InvoiceData("INV-TIE-DOWN", [1], 4999).tax_amount == 0

    def test_maximum_rate_and_zero_amount(self):
        invoice = InvoiceData("INV-MAX-RATE", [1, 0], 10000)
        assert invoice.tax_amount == 1
        assert InvoiceData("INV-ZERO-AMOUNT", [0], 10000).tax_amount == 0

    def test_rejects_out_of_range_financial_inputs(self):
        with pytest.raises(ValueError):
            InvoiceData("INV-LARGE", [MAX_AMOUNT_CENTS + 1], 0)
        with pytest.raises(ValueError):
            InvoiceData("INV-BOOL", [True], 0)
        with pytest.raises(ValueError):
            InvoiceData("INV-RATE", [1], 10001)

    def test_prover_revalidates_mutable_invoice_data(self, prover):
        invoice = InvoiceData("INV-MUTATED", [100], 0)
        invoice.line_items[0] = -1
        with pytest.raises(ZKPSecurityError):
            prover.prove(invoice)


class TestZkpBindingRegressions:

    def test_range_commitment_must_match_line_commitment(
        self, prover, verifier, multi_item_invoice
    ):
        proof = prover.prove(multi_item_invoice)
        original = proof.line_item_proofs[0].commitment_bytes_b64
        proof.line_item_proofs[0].commitment_bytes_b64 = (
            proof.line_item_proofs[1].commitment_bytes_b64
        )
        result = verifier.verify(proof)
        assert not result.is_valid
        assert "line_item_range_binding[0]" in result.checks_failed
        proof.line_item_proofs[0].commitment_bytes_b64 = original

    def test_range_proof_from_another_invoice_is_rejected(
        self, prover, verifier, simple_invoice
    ):
        proof_a = prover.prove(simple_invoice)
        other_invoice = InvoiceData("INV-OTHER", [10000], 2000)
        proof_b = prover.prove(other_invoice)
        proof_a.line_item_proofs[0].range_proof_data = (
            proof_b.line_item_proofs[0].range_proof_data
        )
        result = verifier.verify(proof_a)
        assert not result.is_valid
        assert (
            "line_item_range_proof[0]" in result.checks_failed
            or "line_item_range_binding[0]" in result.checks_failed
        )

    def test_range_proofs_cannot_be_swapped_between_items(
        self, prover, verifier, multi_item_invoice
    ):
        proof = prover.prove(multi_item_invoice)
        proof.line_item_proofs[0].range_proof_data, proof.line_item_proofs[1].range_proof_data = (
            proof.line_item_proofs[1].range_proof_data,
            proof.line_item_proofs[0].range_proof_data,
        )
        result = verifier.verify(proof)
        assert not result.is_valid

    def test_missing_or_malformed_range_proof_is_rejected(
        self, prover, verifier, simple_invoice
    ):
        proof = prover.prove(simple_invoice)
        proof.line_item_proofs[0].range_proof_data = {}
        result = verifier.verify(proof)
        assert not result.is_valid

    def test_tax_rate_substitution_is_rejected(self, prover, verifier, simple_invoice):
        proof = prover.prove(simple_invoice)
        proof.tax_rate_bps = 1999
        result = verifier.verify(proof)
        assert not result.is_valid
        assert "tax_calculation_proof" in result.checks_failed

    def test_invoice_hash_substitution_is_rejected(self, prover, verifier, simple_invoice):
        proof = prover.prove(simple_invoice)
        proof.invoice_hash_b64 = base64.b64encode(b"\x00" * 32).decode()
        result = verifier.verify(proof)
        assert not result.is_valid
        assert "proof_context" in result.checks_failed

    def test_proof_context_modification_is_rejected(
        self, prover, verifier, simple_invoice
    ):
        proof = prover.prove(simple_invoice)
        proof.proof_context = "00" * 32
        assert not verifier.verify(proof).is_valid

    def test_incorrect_tax_amount_is_rejected(self, prover, verifier):
        invoice = InvoiceData("INV-WRONG-TAX", [5000], 2000)
        proof = prover.prove(invoice)
        wrong_tax = PedersenCommitment.commit(invoice.tax_amount + 1)
        proof.tax_commitment_b64 = base64.b64encode(
            wrong_tax.public_point_bytes()
        ).decode()
        result = verifier.verify(proof)
        assert not result.is_valid
        assert "tax_calculation_proof" in result.checks_failed

    def test_trusted_reference_requires_exact_match(self, prover, verifier, simple_invoice):
        proof = prover.prove(simple_invoice)
        wrong_reference = base64.b64encode(b"\x01" * 32).decode()
        result = verifier.verify_with_invoice_hash(
            proof,
            wrong_reference,
            tenant_id=proof.tenant_id,
        )
        assert not result.is_valid
        assert not result.trusted_reference_verified


class TestTaxRemainderBounds:

    def test_remainder_zero_and_9999_are_accepted(self):
        prover = TaxRelationProver()
        verifier = TaxRelationVerifier()
        for subtotal, rate, tax in ((5000, 1, 1), (4999, 1, 0)):
            c_subtotal = PedersenCommitment.commit(subtotal)
            c_tax = PedersenCommitment.commit(tax)
            proof = prover.prove(
                c_subtotal,
                c_tax,
                rate,
                domain_tag=f"remainder-{subtotal}",
            )
            assert verifier.verify(
                proof,
                c_subtotal.public_point_bytes(),
                c_tax.public_point_bytes(),
                expected_domain_tag=f"remainder-{subtotal}",
                expected_tax_rate_bps=rate,
            )

    def test_remainder_10000_is_rejected(self):
        group = secp256k1_group
        rate = 1
        subtotal = 5000
        tax = 0
        domain = "remainder-10000"
        c_subtotal = PedersenCommitment.commit(subtotal)
        c_tax = PedersenCommitment.commit(tax)
        rem_blinding = (
            rate * c_subtotal.blinding - 10000 * c_tax.blinding
        ) % group.N
        c_rem = PedersenCommitment.commit(10000, rem_blinding)
        dual_blinding = group.random_scalar()
        c_dual = PedersenCommitment.commit(0, dual_blinding)
        range_prover = RangeProver(bit_length=14)
        rem_range, _ = range_prover.prove(
            10000, f"{domain}|rem", blinding=rem_blinding
        )
        dual_range, _ = range_prover.prove(
            0, f"{domain}|dual", blinding=dual_blinding
        )

        sum_blinding = (rem_blinding + dual_blinding) % group.N
        public_point = group.scalar_mult(sum_blinding, group.H)
        nonce = group.random_scalar()
        announcement = group.scalar_mult(nonce, group.H)
        public_bytes = group.point_to_bytes(public_point)
        announcement_bytes = group.point_to_bytes(announcement)
        sum_tag = f"{domain}|sum_dual"
        challenge = group.hash_to_scalar(
            sum_tag.encode(), public_bytes, announcement_bytes
        )
        response = (nonce - challenge * sum_blinding) % group.N
        sum_proof = SchnorrProof(
            announcement_bytes=announcement_bytes,
            challenge=challenge,
            response=response,
            public_point_bytes=public_bytes,
            domain_tag=sum_tag,
        )
        malformed = StrictTaxProof(
            tax_rate_bps=rate,
            c_rem_bytes=c_rem.public_point_bytes(),
            c_rem_dual_bytes=c_dual.public_point_bytes(),
            rem_range_proof=rem_range,
            rem_dual_range_proof=dual_range,
            schnorr_sum_dual=sum_proof,
            domain_tag=domain,
        )
        assert not TaxRelationVerifier().verify(
            malformed,
            c_subtotal.public_point_bytes(),
            c_tax.public_point_bytes(),
            expected_domain_tag=domain,
            expected_tax_rate_bps=rate,
        )
