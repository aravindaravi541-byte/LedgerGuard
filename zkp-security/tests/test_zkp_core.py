"""
test_zkp_core.py – Unit tests for the ZKP primitives.

Tests cover:
  - EC point arithmetic correctness
  - Pedersen commitment hiding and binding properties
  - Schnorr proof generation and verification
  - Range proof soundness (valid values pass, invalid values cannot be proved)
  - Linear relation proof correctness
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import secrets

from src.zkp_core import (
    secp256k1_group,
    _point_add,
    _scalar_mult,
    _decode_point,
    PedersenCommitment,
    SchnorrProver,
    SchnorrVerifier,
    SchnorrProof,
    RangeProver,
    RangeVerifier,
    LinearRelationProver,
    LinearRelationVerifier,
)


# =============================================================================
# EC group arithmetic
# =============================================================================

class TestECGroupArithmetic:
    """Validate secp256k1 group laws."""

    def test_generator_on_curve(self):
        """G should satisfy the curve equation y^2 = x^3 + 7 (mod p)."""
        G = secp256k1_group.G
        p = secp256k1_group.P
        x, y = G
        assert pow(y, 2, p) == (pow(x, 3, p) + 7) % p

    def test_h_on_curve(self):
        """H (second generator) should also lie on the curve."""
        H = secp256k1_group.H
        p = secp256k1_group.P
        x, y = H
        assert pow(y, 2, p) == (pow(x, 3, p) + 7) % p

    def test_g_and_h_are_distinct(self):
        """G and H must be different points (otherwise Pedersen is broken)."""
        assert secp256k1_group.G != secp256k1_group.H

    def test_identity_element(self):
        """P + O = P for any point P."""
        G = secp256k1_group.G
        result = _point_add(G, None)
        assert result == G

    def test_inverse_gives_identity(self):
        """P + (-P) = O."""
        G = secp256k1_group.G
        neg_G = (G[0], secp256k1_group.P - G[1])
        result = _point_add(G, neg_G)
        assert result is None

    def test_scalar_mult_by_zero_gives_identity(self):
        assert _scalar_mult(0, secp256k1_group.G) is None

    def test_scalar_mult_by_order_gives_identity(self):
        """n·G should be the point at infinity."""
        result = secp256k1_group.scalar_mult(secp256k1_group.N, secp256k1_group.G)
        assert result is None

    def test_distributive_law(self):
        """(a + b)·G == a·G + b·G."""
        grp = secp256k1_group
        a = grp.random_scalar()
        b = grp.random_scalar()
        ab = (a + b) % grp.N
        lhs = grp.scalar_mult(ab, grp.G)
        aG  = grp.scalar_mult(a,  grp.G)
        bG  = grp.scalar_mult(b,  grp.G)
        rhs = grp.add(aG, bG)
        assert lhs == rhs

    def test_point_encoding_roundtrip(self):
        """Decode(Encode(P)) == P for random points."""
        grp = secp256k1_group
        for _ in range(5):
            k = grp.random_scalar()
            P = grp.scalar_mult(k, grp.G)
            encoded = grp.point_to_bytes(P)
            decoded = _decode_point(encoded)
            assert decoded == P

    def test_decode_rejects_invalid_prefix(self):
        with pytest.raises(ValueError):
            _decode_point(b"\x04" + b"\x00" * 32)

    def test_decode_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            _decode_point(b"\x02" + b"\x00" * 31)


# =============================================================================
# Pedersen Commitments
# =============================================================================

class TestPedersenCommitments:
    """Validate Pedersen commitment properties."""

    def test_commit_is_deterministic_given_blinding(self):
        """Same (value, blinding) always produces the same commitment point."""
        r = secp256k1_group.random_scalar()
        c1 = PedersenCommitment.commit(1000, blinding=r)
        c2 = PedersenCommitment.commit(1000, blinding=r)
        assert c1.point == c2.point

    def test_different_blindings_give_different_commitments(self):
        """Hiding: different blindings → different commitment points (with high prob)."""
        r1 = secp256k1_group.random_scalar()
        r2 = secp256k1_group.random_scalar()
        c1 = PedersenCommitment.commit(1000, blinding=r1)
        c2 = PedersenCommitment.commit(1000, blinding=r2)
        assert c1.point != c2.point

    def test_homomorphic_addition(self):
        """C(a) + C(b) == C(a+b) with blinding r_a + r_b."""
        a, b = 3000, 7000
        ra = secp256k1_group.random_scalar()
        rb = secp256k1_group.random_scalar()
        Ca = PedersenCommitment.commit(a, blinding=ra)
        Cb = PedersenCommitment.commit(b, blinding=rb)
        Cab = Ca.add(Cb)
        direct = PedersenCommitment.commit(a + b, blinding=(ra + rb) % secp256k1_group.N)
        assert Cab.point == direct.point
        assert Cab.value == a + b

    def test_commitment_to_zero(self):
        """Committing to zero should still produce a valid curve point."""
        c = PedersenCommitment.commit(0)
        assert c.point is not None
        assert c.value == 0

    def test_negative_value_rejected(self):
        with pytest.raises(ValueError):
            PedersenCommitment.commit(-1)

    def test_commitment_point_on_curve(self):
        """The commitment point must satisfy the secp256k1 curve equation."""
        c = PedersenCommitment.commit(12345)
        x, y = c.point
        p = secp256k1_group.P
        assert pow(y, 2, p) == (pow(x, 3, p) + 7) % p

    def test_public_point_bytes_length(self):
        """Compressed SEC1 encoding is always 33 bytes."""
        c = PedersenCommitment.commit(999)
        assert len(c.public_point_bytes()) == 33


# =============================================================================
# Schnorr Proofs
# =============================================================================

class TestSchnorrProofs:
    """Validate Schnorr proof generation and verification."""

    def setup_method(self):
        self.prover   = SchnorrProver()
        self.verifier = SchnorrVerifier()

    def test_valid_proof_verifies(self):
        secret = secp256k1_group.random_scalar()
        proof  = self.prover.prove(secret, domain_tag="test|unit")
        assert self.verifier.verify(proof)

    def test_proof_is_non_deterministic(self):
        """Two proofs for the same secret use different nonces → different announcements."""
        secret = secp256k1_group.random_scalar()
        p1 = self.prover.prove(secret, domain_tag="test")
        p2 = self.prover.prove(secret, domain_tag="test")
        assert p1.announcement_bytes != p2.announcement_bytes

    def test_wrong_domain_fails(self):
        """A proof generated under one domain tag must not verify under another."""
        secret = secp256k1_group.random_scalar()
        proof  = self.prover.prove(secret, domain_tag="domain-A")
        tampered = SchnorrProof(
            announcement_bytes = proof.announcement_bytes,
            challenge          = proof.challenge,
            response           = proof.response,
            public_point_bytes = proof.public_point_bytes,
            domain_tag         = "domain-B",
        )
        assert not self.verifier.verify(tampered)

    def test_tampered_response_fails(self):
        secret = secp256k1_group.random_scalar()
        proof  = self.prover.prove(secret, domain_tag="test")
        tampered = SchnorrProof(
            announcement_bytes = proof.announcement_bytes,
            challenge          = proof.challenge,
            response           = (proof.response + 1) % secp256k1_group.N,
            public_point_bytes = proof.public_point_bytes,
            domain_tag         = proof.domain_tag,
        )
        assert not self.verifier.verify(tampered)

    def test_tampered_announcement_fails(self):
        secret = secp256k1_group.random_scalar()
        proof  = self.prover.prove(secret, domain_tag="test")
        # Corrupt one byte in announcement
        ann_bad = bytearray(proof.announcement_bytes)
        ann_bad[1] ^= 0xFF
        tampered = SchnorrProof(
            announcement_bytes = bytes(ann_bad),
            challenge          = proof.challenge,
            response           = proof.response,
            public_point_bytes = proof.public_point_bytes,
            domain_tag         = proof.domain_tag,
        )
        assert not self.verifier.verify(tampered)

    def test_random_proof_fails(self):
        """A completely random proof should not verify."""
        grp = secp256k1_group
        fake_secret = grp.random_scalar()
        fake_P = grp.scalar_mult(fake_secret, grp.G)
        fake_R = grp.scalar_mult(grp.random_scalar(), grp.G)
        fake = SchnorrProof(
            announcement_bytes = grp.point_to_bytes(fake_R),
            challenge          = grp.random_scalar(),
            response           = grp.random_scalar(),
            public_point_bytes = grp.point_to_bytes(fake_P),
            domain_tag         = "test",
        )
        assert not self.verifier.verify(fake)

    def test_multiple_distinct_secrets(self):
        """Proofs for different secrets should all independently verify."""
        for _ in range(5):
            secret = secp256k1_group.random_scalar()
            proof  = self.prover.prove(secret, domain_tag="multi-test")
            assert self.verifier.verify(proof)


# =============================================================================
# Range Proofs
# =============================================================================

class TestRangeProofs:
    """Validate range proof soundness and completeness."""

    def setup_method(self):
        self.prover   = RangeProver(bit_length=8)    # 8-bit for speed
        self.verifier = RangeVerifier(bit_length=8)

    def test_zero_in_range(self):
        rp, _ = self.prover.prove(0, domain_tag="range-test")
        assert self.verifier.verify(rp)

    def test_max_value_in_range(self):
        rp, _ = self.prover.prove(255, domain_tag="range-test")  # 2^8 - 1
        assert self.verifier.verify(rp)

    def test_middle_value_in_range(self):
        rp, _ = self.prover.prove(127, domain_tag="range-test")
        assert self.verifier.verify(rp)

    def test_out_of_range_raises(self):
        with pytest.raises(ValueError, match="out of range"):
            self.prover.prove(256, domain_tag="range-test")   # 2^8

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            self.prover.prove(-1, domain_tag="range-test")

    def test_wrong_num_bits_fails(self):
        """A proof with wrong bit_length should fail on a verifier with different params."""
        rp, _ = self.prover.prove(5, domain_tag="range-test")
        # Verifier with different bit length rejects
        verifier_16 = RangeVerifier(bit_length=16)
        assert not verifier_16.verify(rp)

    def test_tampered_bit_proof_fails(self):
        """Flipping a byte in a bit commitment should cause verification failure."""
        rp, _ = self.prover.prove(42, domain_tag="tamper-test")
        # Corrupt the first bit proof's commitment
        bad_bytes = bytearray(rp.bit_proofs[0].commitment_bytes)
        bad_bytes[1] ^= 0x01
        rp.bit_proofs[0].commitment_bytes = bytes(bad_bytes)
        assert not self.verifier.verify(rp)

    def test_several_random_values(self):
        """Spot-check multiple random 8-bit values."""
        for v in [1, 50, 100, 200, 254]:
            rp, _ = self.prover.prove(v, domain_tag=f"rnd-{v}")
            assert self.verifier.verify(rp), f"Range proof failed for value {v}"


# =============================================================================
# Linear Relation Proofs
# =============================================================================

class TestLinearRelationProofs:
    """Validate linear relation (a + b = c) proofs."""

    def setup_method(self):
        self.prover   = LinearRelationProver()
        self.verifier = LinearRelationVerifier()

    def test_valid_relation(self):
        a, b = 3000, 7500
        Ca = PedersenCommitment.commit(a)
        Cb = PedersenCommitment.commit(b)
        Cc = Ca.add(Cb)
        proof = self.prover.prove(Ca, Cb, Cc, "test-linear")
        assert self.verifier.verify(proof)

    def test_wrong_total_fails(self):
        a, b = 3000, 7500
        Ca = PedersenCommitment.commit(a)
        Cb = PedersenCommitment.commit(b)
        # Wrong total: commit to a different value
        Cc_wrong = PedersenCommitment.commit(a + b + 1)
        proof = self.prover.prove(Ca, Cb, Cc_wrong, "test-linear-wrong")
        assert not self.verifier.verify(proof)

    def test_zero_addend(self):
        """a + 0 = a should work."""
        a = 5000
        Ca = PedersenCommitment.commit(a)
        Cb = PedersenCommitment.commit(0)
        Cc = Ca.add(Cb)
        proof = self.prover.prove(Ca, Cb, Cc, "test-linear-zero")
        assert self.verifier.verify(proof)

    def test_tampered_commitment_fails(self):
        a, b = 1000, 2000
        Ca = PedersenCommitment.commit(a)
        Cb = PedersenCommitment.commit(b)
        Cc = Ca.add(Cb)
        proof = self.prover.prove(Ca, Cb, Cc, "test-tamper")
        # Corrupt subtotal commitment bytes
        bad = bytearray(proof.commitment_subtotal_bytes)
        bad[1] ^= 0xFF
        proof.commitment_subtotal_bytes = bytes(bad)
        assert not self.verifier.verify(proof)

