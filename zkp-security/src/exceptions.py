"""
exceptions.py – Custom exception hierarchy for the ZKP-Security module.

All public-facing errors derive from ZKPSecurityError so callers can catch
them at any granularity.
"""


class ZKPSecurityError(Exception):
    """Base exception for all ZKP-Security module errors."""


class InvalidProofError(ZKPSecurityError):
    """Raised when a proof fails mathematical verification.

    This may mean the proof was fabricated, corrupted, or produced with
    incorrect witness values.
    """


class TamperingDetectedError(ZKPSecurityError):
    """Raised when invoice data does not match the committed values inside
    the proof.  Indicates possible post-signing modification of billing data.
    """


class ProofExpiredError(ZKPSecurityError):
    """Raised when a proof is presented after its validity window has elapsed."""


class CommitmentMismatchError(ZKPSecurityError):
    """Raised when a Pedersen commitment does not match the claimed value."""


class KeyDerivationError(ZKPSecurityError):
    """Raised on failure to derive or load cryptographic keys."""

