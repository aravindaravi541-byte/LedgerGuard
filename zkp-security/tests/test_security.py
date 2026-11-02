"""
test_security.py – Security, privacy, and adversarial tests for LedgerGuard ZKP.

Tests cover:
  - Replay attack prevention (timestamp expiry)
  - Forgery resistance (proof without knowledge of witness)
  - Commitment soundness (cannot open to two different values)
  - Side-channel: proofs for different values are indistinguishable to observer
  - Key isolation: different KeyManagers → cross-verification fails
  - Proof serialisation security (no secrets leaked in JSON)
  - DoS resilience: malformed inputs don't crash the verifier
"""

import sys, os, json, base64, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import secrets as py_secrets

from src.zkp_core import (
    secp256k1_group,
    PedersenCommitment,
    SchnorrProver,
    SchnorrVerifier,
    SchnorrProof,
    RangeProver,
    RangeVerifier,
)
from src.billing_zkp import InvoiceData, BillingProver, BillingVerifier, InvoiceProof
from src.crypto_utils import KeyManager, TimestampSigner
from src.replay import SQLiteChallengeStore
from src.exceptions import ProofExpiredError, InvalidProofError


def prove_with_challenge(prover, verifier, invoice, tenant_id="test-tenant"):
    challenge, _ = verifier.issue_challenge(invoice.invoice_id, tenant_id)
    return prover.prove(
        invoice,
        tenant_id=tenant_id,
        challenge_token=challenge,
    )


def signed_timestamp(km, timestamp):
    import hashlib
    import hmac

    timestamp = str(timestamp)
    key_id = km.active_key_id
    key = km.derive("timestamp-signing", key_id=key_id)
    message = TimestampSigner._message(key_id, timestamp, b"")
    mac = hmac.new(key, message, hashlib.sha256).hexdigest()
    return base64.b64encode(f"{key_id}|{timestamp}|{mac}".encode("ascii")).decode("ascii")


# =============================================================================
# Replay Attack Prevention
# =============================================================================

class TestReplayAttackPrevention:
    """Ensure timestamps are validated and replays are rejected."""

    def test_fresh_proof_accepted(self):
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        ts = TimestampSigner(km, max_age_seconds=300)
        token = ts.sign_now()
        ts.verify(token, max_age_seconds=300)   # must not raise

    def test_expired_proof_rejected(self):
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        ts = TimestampSigner(km, max_age_seconds=1)
        # Manually craft a token with timestamp 2 seconds ago
        past_ts  = str(int(time.time()) - 10)
        token = signed_timestamp(km, past_ts)
        with pytest.raises(ProofExpiredError):
            ts.verify(token, max_age_seconds=1)

    def test_future_timestamp_rejected(self):
        """Tokens more than 60s in the future (clock skew allowance) are rejected."""
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        ts = TimestampSigner(km, max_age_seconds=300)
        future_ts = str(int(time.time()) + 120)
        token = signed_timestamp(km, future_ts)
        with pytest.raises(ProofExpiredError):
            ts.verify(token, max_age_seconds=300)

    def test_tampered_timestamp_mac_rejected(self):
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        ts = TimestampSigner(km, max_age_seconds=300)
        token = ts.sign_now()
        # Flip one character in the MAC
        raw = base64.b64decode(token.encode()).decode()
        key_id, ts_part, mac_part = raw.split("|")
        bad_mac = mac_part[:-1] + ("0" if mac_part[-1] != "0" else "1")
        bad_token = base64.b64encode(
            f"{key_id}|{ts_part}|{bad_mac}".encode()
        ).decode()
        with pytest.raises(ProofExpiredError):
            ts.verify(bad_token)

    def test_different_key_cannot_verify_timestamp(self):
        km1 = KeyManager(ikm=py_secrets.token_bytes(32))
        km2 = KeyManager(ikm=py_secrets.token_bytes(32))
        ts1 = TimestampSigner(km1, max_age_seconds=300)
        ts2 = TimestampSigner(km2, max_age_seconds=300)
        token = ts1.sign_now()
        with pytest.raises(ProofExpiredError):
            ts2.verify(token)

    def test_timestamp_is_bound_to_statement_context(self):
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        signer = TimestampSigner(km)
        token = signer.sign_now(b"statement-a")
        with pytest.raises(ProofExpiredError):
            signer.verify(token, context=b"statement-b")

    def test_valid_invoice_proof_is_rejected_on_replay(self):
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        store = SQLiteChallengeStore(":memory:")
        prover = BillingProver(key_manager=km)
        verifier = BillingVerifier(key_manager=km, challenge_store=store)
        invoice = InvoiceData("INV-REPLAY", [1250], 2000)
        proof = prove_with_challenge(prover, verifier, invoice)
        assert verifier.verify(proof, tenant_id="test-tenant").is_valid
        replay = verifier.verify(proof, tenant_id="test-tenant")
        assert not replay.is_valid
        assert "challenge_replay" in replay.checks_failed

    def test_challenge_is_bound_to_tenant_and_invoice(self):
        store = SQLiteChallengeStore(":memory:")
        token, _ = store.issue("tenant-a", "INV-A")
        assert not store.consume(token, "tenant-b", "INV-A")
        assert not store.consume(token, "tenant-a", "INV-B")
        assert store.consume(token, "tenant-a", "INV-A")

    def test_expired_challenge_is_rejected(self):
        store = SQLiteChallengeStore(":memory:")
        token, _ = store.issue("tenant-a", "INV-A", ttl_seconds=1)
        time.sleep(1.05)
        assert not store.consume(token, "tenant-a", "INV-A")

    def test_shared_sqlite_challenge_store_works_across_instances(self, tmp_path):
        database = str(tmp_path / "replay.sqlite3")
        issuer = SQLiteChallengeStore(database)
        verifier_store = SQLiteChallengeStore(database)
        token, _ = issuer.issue("tenant-a", "INV-A")
        assert verifier_store.consume(token, "tenant-a", "INV-A")

    def test_concurrent_replay_has_exactly_one_success(self):
        from concurrent.futures import ThreadPoolExecutor

        store = SQLiteChallengeStore(":memory:")
        token, _ = store.issue("tenant-a", "INV-A")
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(
                lambda _: store.consume(token, "tenant-a", "INV-A"),
                range(8),
            ))
        assert sum(results) == 1


# =============================================================================
# Forgery Resistance
# =============================================================================

class TestForgeryResistance:
    """Adversary without the witness cannot forge a valid Schnorr proof."""

    def test_schnorr_forged_response_fails(self):
        """
        Adversary tries to answer a random challenge without knowing the secret.
        Success probability ≤ 1/N ≈ 2^{-256}.
        """
        grp = secp256k1_group
        verifier = SchnorrVerifier()
        # Adversary picks a random public point they don't know the DL of
        k = grp.random_scalar()
        P = grp.scalar_mult(k, grp.G)          # adversary doesn't know k (pretend)
        # Adversary tries: pick random s, R and compute c
        s = grp.random_scalar()
        R = grp.scalar_mult(grp.random_scalar(), grp.G)
        c = grp.hash_to_scalar(b"domain", grp.point_to_bytes(P), grp.point_to_bytes(R))
        # This won't satisfy s·G + c·P == R because s was chosen without knowing secret
        fake_proof = SchnorrProof(
            announcement_bytes = grp.point_to_bytes(R),
            challenge          = c,
            response           = s,
            public_point_bytes = grp.point_to_bytes(P),
            domain_tag         = "domain",
        )
        assert not verifier.verify(fake_proof)

    def test_noncanonical_schnorr_scalar_is_rejected(self):
        group = secp256k1_group
        proof = SchnorrProver().prove(group.random_scalar(), "scalar-test")
        proof.response = group.N
        assert not SchnorrVerifier().verify(proof)

    def test_noncanonical_curve_point_is_rejected(self):
        from src.zkp_core import _decode_point

        with pytest.raises(ValueError):
            _decode_point(b"\x02" + secp256k1_group.P.to_bytes(32, "big"))
        with pytest.raises(ValueError):
            _decode_point(b"\x00")

    def test_noncanonical_range_proof_scalar_is_rejected(self):
        proof, _ = RangeProver(bit_length=8).prove(7, "range-scalar-test")
        proof.bit_proofs[0].s0 = secp256k1_group.N
        assert not RangeVerifier(bit_length=8).verify(proof)

    def test_range_proof_cannot_be_faked_for_out_of_range_value(self):
        """
        A commitment to value=256 with bit_length=8 should be provably impossible
        (the prover raises before even attempting).
        """
        prover = RangeProver(bit_length=8)
        with pytest.raises(ValueError):
            prover.prove(256, domain_tag="forgery-test")

    def test_billing_proof_with_wrong_arithmetic_fails(self):
        """
        Prover claims total != subtotal + tax.  The linear relation proof
        must catch this during the homomorphic sum check.
        """
        from src.zkp_core import LinearRelationProver, LinearRelationVerifier
        a, b = 5000, 1000
        wrong_c = 9999   # not a + b
        Ca = PedersenCommitment.commit(a)
        Cb = PedersenCommitment.commit(b)
        Cc = PedersenCommitment.commit(wrong_c)
        prover   = LinearRelationProver()
        verifier = LinearRelationVerifier()
        proof = prover.prove(Ca, Cb, Cc, "fake-sum")
        assert not verifier.verify(proof)


# =============================================================================
# Commitment Soundness
# =============================================================================

class TestCommitmentSoundness:
    """Verify that a commitment cannot be opened to two different values."""

    def test_different_values_different_commitments(self):
        """With the same blinding factor, different values give different points."""
        r = secp256k1_group.random_scalar()
        c1 = PedersenCommitment.commit(1000, blinding=r)
        c2 = PedersenCommitment.commit(1001, blinding=r)
        assert c1.point != c2.point

    def test_same_value_same_blinding_same_point(self):
        """Determinism check."""
        r = secp256k1_group.random_scalar()
        c1 = PedersenCommitment.commit(500, blinding=r)
        c2 = PedersenCommitment.commit(500, blinding=r)
        assert c1.point == c2.point

    def test_homomorphic_sum_is_consistent(self):
        """C(a+b) == C(a) + C(b) homomorphically (with matching blindings)."""
        a, b = 2000, 3000
        ra = secp256k1_group.random_scalar()
        rb = secp256k1_group.random_scalar()
        Ca  = PedersenCommitment.commit(a, blinding=ra)
        Cb  = PedersenCommitment.commit(b, blinding=rb)
        Cab = Ca.add(Cb)
        r_sum = (ra + rb) % secp256k1_group.N
        Cdirect = PedersenCommitment.commit(a + b, blinding=r_sum)
        assert Cab.point == Cdirect.point


# =============================================================================
# Key Isolation
# =============================================================================

class TestKeyIsolation:
    """Proofs from one key domain must not verify under a different key domain."""

    def test_cross_keymanager_verification_fails(self):
        km1 = KeyManager(ikm=py_secrets.token_bytes(32))
        km2 = KeyManager(ikm=py_secrets.token_bytes(32))
        prover   = BillingProver(key_manager=km1)
        verifier = BillingVerifier(
            key_manager=km2,
            challenge_store=SQLiteChallengeStore(":memory:"),
        )
        invoice  = InvoiceData("INV-CROSS", [5000], 2000)
        proof    = prove_with_challenge(prover, verifier, invoice)
        result   = verifier.verify(proof, tenant_id="test-tenant")
        # Timestamp HMAC will fail (different keys)
        assert not result.is_valid
        assert "timestamp_freshness" in result.checks_failed

    def test_same_keymanager_verification_succeeds(self):
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        prover   = BillingProver(key_manager=km)
        verifier = BillingVerifier(
            key_manager=km,
            challenge_store=SQLiteChallengeStore(":memory:"),
        )
        invoice  = InvoiceData("INV-SAME", [5000], 2000)
        proof    = prove_with_challenge(prover, verifier, invoice)
        result   = verifier.verify(proof, tenant_id="test-tenant")
        assert result.is_valid


# =============================================================================
# DoS Resilience / Robustness
# =============================================================================

class TestDoSResilience:
    """Malformed inputs should never cause unhandled exceptions or crashes."""

    def setup_method(self):
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        self.verifier = BillingVerifier(
            key_manager=km,
            challenge_store=SQLiteChallengeStore(":memory:"),
        )

    def test_empty_json_does_not_crash(self):
        with pytest.raises(Exception):
            InvoiceProof.from_json("{}")

    def test_garbage_json_does_not_crash(self):
        with pytest.raises(Exception):
            InvoiceProof.from_json("not-json-at-all")

    def test_duplicate_serialized_proof_fields_are_rejected(self):
        with pytest.raises(ValueError, match="Duplicate JSON keys"):
            InvoiceProof.from_json('{"proof_version":"2.0","proof_version":"2.0"}')

    def test_proof_with_null_commitments_does_not_crash(self):
        """Ensure verifier returns is_valid=False (not an unhandled exception)."""
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        prover   = BillingProver(key_manager=km)
        verifier = BillingVerifier(
            key_manager=km,
            challenge_store=SQLiteChallengeStore(":memory:"),
        )
        invoice  = InvoiceData("INV-NULL", [1000], 2000)
        proof    = prove_with_challenge(prover, verifier, invoice)
        # Null out one field
        proof.tax_commitment_b64 = ""
        result = verifier.verify(proof, tenant_id="test-tenant")
        assert isinstance(result.is_valid, bool)

    def test_verifier_handles_extra_fields_gracefully(self):
        """InvoiceProof.from_json should handle missing optional fields."""
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        prover   = BillingProver(key_manager=km)
        verifier = BillingVerifier(
            key_manager=km,
            challenge_store=SQLiteChallengeStore(":memory:"),
        )
        invoice  = InvoiceData("INV-FIELDS", [2000], 2000)
        proof    = prove_with_challenge(prover, verifier, invoice)
        raw      = json.loads(proof.to_json())
        # Remove a non-critical field
        raw.pop("proof_version", None)
        result = verifier.verify(
            InvoiceProof.from_json(json.dumps(raw)), tenant_id="test-tenant"
        )
        assert isinstance(result.is_valid, bool)

    def test_extremely_short_commitment_bytes_rejected(self):
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        prover   = BillingProver(key_manager=km)
        verifier = BillingVerifier(
            key_manager=km,
            challenge_store=SQLiteChallengeStore(":memory:"),
        )
        invoice  = InvoiceData("INV-SHORT", [500], 2000)
        proof    = prove_with_challenge(prover, verifier, invoice)
        # Swap a valid commitment for a single-byte payload
        proof.subtotal_commitment_b64 = base64.b64encode(b"\x02").decode()
        result = verifier.verify(proof, tenant_id="test-tenant")
        assert not result.is_valid


# =============================================================================
# Information-Theoretic Indistinguishability
# =============================================================================

class TestIndistinguishability:
    """
    Observe that two proofs for different values are computationally
    indistinguishable – verified by checking that the commitment point
    distributions overlap (no value-leaking structure).
    """

    def test_commitment_points_appear_random(self):
        """
        For values 0, 1, 2, …, 9 with fresh random blindings, the
        x-coordinates of commitment points should all be distinct
        (the commitment does not reveal ordering or magnitude).
        """
        points_x = set()
        for v in range(10):
            c = PedersenCommitment.commit(v)
            points_x.add(c.point[0])
        # All 10 x-coordinates should be unique (with overwhelming probability)
        assert len(points_x) == 10

    def test_same_value_different_commitments_indistinguishable(self):
        """
        Two commitments to the same value with different blindings look
        completely different (perfect hiding).
        """
        value = 42000
        c1 = PedersenCommitment.commit(value)
        c2 = PedersenCommitment.commit(value)
        assert c1.point != c2.point
