"""
conftest.py – Shared pytest fixtures for the ZKP-Security test suite.
"""

import sys
import os
import pytest

# Ephemeral keys and in-memory replay state are permitted only in this test
# process; production defaults fail closed.
os.environ.setdefault("LEDGERGUARD_ZKP_MODE", "test")

# Ensure src is importable from the repo root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.zkp_core import secp256k1_group, PedersenCommitment
from src.billing_zkp import InvoiceData, BillingProver, BillingVerifier
from src.crypto_utils import KeyManager
from src.replay import SQLiteChallengeStore


class ChallengeAwareProver:
    """Test adapter obtains the challenge from the paired verifier."""

    def __init__(self, prover, verifier):
        self._prover = prover
        self._verifier = verifier

    def prove(self, invoice, tenant_id="test-tenant", challenge_token=None):
        if challenge_token is None:
            challenge_token, _ = self._verifier.issue_challenge(
                invoice.invoice_id, tenant_id
            )
        return self._prover.prove(
            invoice,
            tenant_id=tenant_id,
            challenge_token=challenge_token,
        )


class TenantAwareVerifier(BillingVerifier):
    """Test adapter supplies the fixture tenant unless a test overrides it."""

    def verify(self, proof, *, tenant_id=None, expected_invoice_hash_b64=None):
        return super().verify(
            proof,
            tenant_id=tenant_id or proof.tenant_id,
            expected_invoice_hash_b64=expected_invoice_hash_b64,
        )

    def verify_with_invoice_hash(
        self, proof, expected_invoice_hash_b64, *, tenant_id=None
    ):
        return super().verify_with_invoice_hash(
            proof,
            expected_invoice_hash_b64,
            tenant_id=tenant_id or proof.tenant_id,
        )


# ---------------------------------------------------------------------------
# Shared key manager (ephemeral – consistent within a test session)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def key_manager():
    """Session-scoped KeyManager with a fixed random IKM (no env var needed)."""
    import secrets
    return KeyManager(ikm=secrets.token_bytes(32))


@pytest.fixture(scope="session")
def challenge_store():
    return SQLiteChallengeStore(":memory:")


@pytest.fixture(scope="session")
def verifier(key_manager, challenge_store):
    return TenantAwareVerifier(
        key_manager=key_manager,
        challenge_store=challenge_store,
    )


@pytest.fixture(scope="session")
def prover(key_manager, verifier):
    return ChallengeAwareProver(
        BillingProver(key_manager=key_manager),
        verifier,
    )


# ---------------------------------------------------------------------------
# Standard invoice fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def simple_invoice():
    """Single line item, 20% VAT."""
    return InvoiceData(
        invoice_id   = "INV-TEST-001",
        line_items   = [10000],      # £100.00
        tax_rate_bps = 2000,         # 20% VAT
        currency     = "GBP",
    )


@pytest.fixture
def multi_item_invoice():
    """Three line items, 20% VAT."""
    return InvoiceData(
        invoice_id   = "INV-TEST-002",
        line_items   = [5000, 3000, 2000],  # £50, £30, £20
        tax_rate_bps = 2000,
        currency     = "GBP",
    )


@pytest.fixture
def zero_tax_invoice():
    """Invoice with 0% tax."""
    return InvoiceData(
        invoice_id   = "INV-TEST-003",
        line_items   = [7500, 2500],
        tax_rate_bps = 0,
        currency     = "USD",
    )


@pytest.fixture
def large_invoice():
    """Multi-item invoice to stress test range & linear proofs."""
    return InvoiceData(
        invoice_id   = "INV-TEST-MULTI",
        line_items   = [1000 + i * 37 for i in range(5)],
        tax_rate_bps = 1750,   # 17.5%
        currency     = "GBP",
    )
