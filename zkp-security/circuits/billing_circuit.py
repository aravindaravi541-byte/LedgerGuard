"""
billing_circuit.py – High-level billing verification circuit definitions.
=========================================================================

A "circuit" in this context is a named verification recipe: a sequence of
ZKP checks that must all pass for a billing claim to be accepted.  Circuits
are named and versioned so the verifier and prover can agree on the exact
set of rules without embedding logic in the transport layer.

Available circuits:
    SIMPLE_INVOICE     – single line item, no tax
    STANDARD_INVOICE   – multiple line items, standard VAT
    MULTI_CURRENCY     – multiple line items, currency conversion (planned)

Each circuit returns a CircuitResult with pass/fail per constraint.
"""

from __future__ import annotations

import sys
import os

# Make the repo root importable regardless of how this module is invoked
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from src.billing_zkp import InvoiceProof, ProofVerificationResult, BillingVerifier
from src.crypto_utils import KeyManager
from src.replay import ChallengeStore


# ---------------------------------------------------------------------------
# Circuit registry
# ---------------------------------------------------------------------------

class CircuitName(str, Enum):
    SIMPLE_INVOICE   = "SIMPLE_INVOICE_v1"
    STANDARD_INVOICE = "STANDARD_INVOICE_v1"


@dataclass
class CircuitResult:
    circuit_name: str
    is_valid: bool
    verification_result: ProofVerificationResult
    additional_checks: dict[str, bool] = field(default_factory=dict)


class BillingCircuit:
    """
    A named, versioned billing verification circuit.
    """

    def __init__(
        self,
        name: CircuitName,
        verifier: BillingVerifier | None = None,
    ) -> None:
        self.name = name
        self._verifier = verifier or BillingVerifier()

    def run(self, proof: InvoiceProof, *, tenant_id: str) -> CircuitResult:
        result = self._verifier.verify(proof, tenant_id=tenant_id)
        extra  = self._circuit_specific_checks(proof, result)
        is_valid = result.is_valid and all(extra.values())
        return CircuitResult(
            circuit_name         = self.name.value,
            is_valid             = is_valid,
            verification_result  = result,
            additional_checks    = extra,
        )

    def _circuit_specific_checks(
        self,
        proof: InvoiceProof,
        result: ProofVerificationResult,
    ) -> dict[str, bool]:
        if self.name == CircuitName.SIMPLE_INVOICE:
            return {
                "single_line_item": len(proof.line_item_proofs) == 1,
            }
        elif self.name == CircuitName.STANDARD_INVOICE:
            return {
                "has_line_items":        len(proof.line_item_proofs) >= 1,
                "has_tax_commitment":    bool(proof.tax_commitment_b64),
                "has_total_commitment":  bool(proof.total_commitment_b64),
            }
        return {}


# ---------------------------------------------------------------------------
# Circuit factory
# ---------------------------------------------------------------------------

def get_circuit(
    name: CircuitName,
    key_manager: KeyManager | None = None,
    challenge_store: ChallengeStore | None = None,
) -> BillingCircuit:
    """
    Retrieve a pre-configured billing circuit by name.
    """
    verifier = BillingVerifier(
        key_manager=key_manager,
        challenge_store=challenge_store,
    )
    return BillingCircuit(name=name, verifier=verifier)
