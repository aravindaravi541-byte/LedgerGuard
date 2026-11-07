"""
test_crypto_utils.py – Unit tests for cryptographic utilities.
"""

import sys, os, base64, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import secrets as py_secrets

from src.crypto_utils import SecureHasher, KeyManager, ProofSerializer, TimestampSigner
from src.exceptions import KeyDerivationError, ProofExpiredError
from src.zkp_core import (
    SchnorrProver, SchnorrVerifier,
    RangeProver, RangeVerifier,
)


class TestSecureHasher:

    def test_same_input_same_output(self):
        h1 = SecureHasher.hash(b"domain", b"data")
        h2 = SecureHasher.hash(b"domain", b"data")
        assert h1 == h2

    def test_different_domain_different_hash(self):
        h1 = SecureHasher.hash(b"domain-A", b"data")
        h2 = SecureHasher.hash(b"domain-B", b"data")
        assert h1 != h2

    def test_hash_invoice_is_deterministic(self):
        data = {"invoice_id": "X", "total": 100}
        h1 = SecureHasher.hash_invoice(data)
        h2 = SecureHasher.hash_invoice(data)
        assert h1 == h2

    def test_hash_invoice_key_order_independent(self):
        """JSON keys must be sorted so order doesn't affect the hash."""
        d1 = {"a": 1, "b": 2}
        d2 = {"b": 2, "a": 1}
        assert SecureHasher.hash_invoice(d1) == SecureHasher.hash_invoice(d2)

    def test_output_is_32_bytes(self):
        h = SecureHasher.hash(b"domain", b"test")
        assert len(h) == 32


class TestKeyManager:

    def test_ephemeral_key_allowed_in_explicit_test_mode(self):
        km = KeyManager()
        key = km.derive("test-purpose")
        assert len(key) == 32

    def test_missing_production_key_fails_closed(self, monkeypatch):
        monkeypatch.setenv("LEDGERGUARD_ZKP_MODE", "production")
        monkeypatch.delenv("LEDGERGUARD_ZKP_IKM", raising=False)
        with pytest.raises(KeyDerivationError):
            KeyManager()

    def test_short_environment_key_is_rejected(self, monkeypatch):
        monkeypatch.setenv("LEDGERGUARD_ZKP_MODE", "production")
        monkeypatch.setenv("LEDGERGUARD_ZKP_IKM", base64.b64encode(b"x" * 16).decode())
        with pytest.raises(KeyDerivationError):
            KeyManager()

    def test_explicit_ikm(self):
        ikm = py_secrets.token_bytes(32)
        km  = KeyManager(ikm=ikm)
        k1  = km.derive("purpose-A")
        k2  = km.derive("purpose-A")
        assert k1 == k2

    def test_different_purposes_different_keys(self):
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        k1 = km.derive("purpose-A")
        k2 = km.derive("purpose-B")
        assert k1 != k2

    def test_different_ikm_different_derived_keys(self):
        km1 = KeyManager(ikm=py_secrets.token_bytes(32))
        km2 = KeyManager(ikm=py_secrets.token_bytes(32))
        k1  = km1.derive("same-purpose")
        k2  = km2.derive("same-purpose")
        assert k1 != k2

    def test_too_short_ikm_rejected(self):
        with pytest.raises(KeyDerivationError):
            KeyManager(ikm=b"\x00" * 8)

    def test_custom_length(self):
        km = KeyManager(ikm=py_secrets.token_bytes(32))
        k64 = km.derive("big-key", length=64)
        assert len(k64) == 64

    def test_shared_key_material_is_consistent_across_instances(self):
        ikm = py_secrets.token_bytes(32)
        first = KeyManager(ikm=ikm)
        second = KeyManager(ikm=ikm)
        assert first.derive("timestamp-signing") == second.derive("timestamp-signing")

    def test_previous_key_can_verify_during_rotation(self):
        old_ikm = py_secrets.token_bytes(32)
        old_manager = KeyManager(ikm=old_ikm, key_id="old")
        rotated_manager = KeyManager(
            ikm=py_secrets.token_bytes(32),
            key_id="new",
            verification_ikms={"old": old_ikm},
        )
        token = TimestampSigner(old_manager).sign_now(b"context")
        TimestampSigner(rotated_manager).verify(token, context=b"context")


class TestProofSerializer:

    def test_schnorr_roundtrip(self):
        prover = SchnorrProver()
        from src.zkp_core import secp256k1_group
        secret = secp256k1_group.random_scalar()
        proof  = prover.prove(secret, "serialise-test")
        data   = ProofSerializer.serialise_schnorr(proof)
        back   = ProofSerializer.deserialise_schnorr(data)
        verifier = SchnorrVerifier()
        assert verifier.verify(back)

    def test_range_proof_roundtrip(self):
        prover   = RangeProver(bit_length=8)
        verifier = RangeVerifier(bit_length=8)
        rp, _    = prover.prove(42, "serial-range")
        data     = ProofSerializer.serialise_range_proof(rp)
        back     = ProofSerializer.deserialise_range_proof(data)
        assert verifier.verify(back)

    def test_int_hex_roundtrip(self):
        n = 2**255 + 12345
        assert ProofSerializer.hex_to_int(ProofSerializer.int_to_hex(n)) == n

    def test_bytes_b64_roundtrip(self):
        b = py_secrets.token_bytes(64)
        assert ProofSerializer.b64_to_bytes(ProofSerializer.bytes_to_b64(b)) == b
