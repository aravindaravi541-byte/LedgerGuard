"""
LedgerGuard ZKP-Security Module
================================
Zero-Knowledge Proof and Security sub-system for private billing verification.

Public surface:
    - BillingProver   : generates ZKP proofs for invoices
    - BillingVerifier : verifies ZKP proofs without learning private values
    - InvoiceProof    : structured proof object (serialisable)
    - ProofVerificationResult : structured verification result
    - ZKPSecurityError : base exception for this module
"""

from .zkp_core import (
    secp256k1_group,
    PedersenCommitment,
    SchnorrProver,
    SchnorrVerifier,
)
from .billing_zkp import (
    BillingProver,
    BillingVerifier,
    InvoiceProof,
    ProofVerificationResult,
)
from .crypto_utils import (
    SecureHasher,
    KeyManager,
    ProofSerializer,
)
from .exceptions import (
    ZKPSecurityError,
    InvalidProofError,
    TamperingDetectedError,
    ProofExpiredError,
    CommitmentMismatchError,
)

__version__ = "1.0.0"
__author__ = "Member 4 – ZKP & Security"

__all__ = [
    # ZKP core
    "secp256k1_group",
    "PedersenCommitment",
    "SchnorrProver",
    "SchnorrVerifier",
    # Billing ZKP
    "BillingProver",
    "BillingVerifier",
    "InvoiceProof",
    "ProofVerificationResult",
    # Crypto utilities
    "SecureHasher",
    "KeyManager",
    "ProofSerializer",
    # Exceptions
    "ZKPSecurityError",
    "InvalidProofError",
    "TamperingDetectedError",
    "ProofExpiredError",
    "CommitmentMismatchError",
]

