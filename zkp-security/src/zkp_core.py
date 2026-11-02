"""
zkp_core.py – Real Zero-Knowledge Proof primitives for LedgerGuard.
====================================================================

Implements:
  1. secp256k1 elliptic-curve group arithmetic in pure Python. Scalar
     multiplication is variable-time and is not suitable for side-channel
     sensitive production use.
  2. Pedersen commitments  C = v·G + r·H  over secp256k1.
  3. Schnorr Sigma-protocol (made non-interactive via Fiat-Shamir transform)
     for discrete-log relations in the range and tax protocols.
  4. Range-proof circuit: proves 0 ≤ v < 2^n without revealing v.
  5. Bounded tax quotient/remainder proof for a public basis-point rate.

Security status
---------------
These protocols are implemented as a research/academic demonstration. Their
security has not been independently reviewed or formally established. Do not
interpret equations, tests, or comments as a proof of production soundness or
zero knowledge. Python arithmetic is variable-time.

References
----------
* Pedersen (1991) "Non-interactive and information-theoretic secure verifiable
  secret sharing." CRYPTO 1991.
* Schnorr (1991) "Efficient signature generation by smart cards."
  Journal of Cryptology 4(3).
* Fiat & Shamir (1987) "How to prove yourself." CRYPTO 1986.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# secp256k1 group parameters (SECG SEC 2, section 2.4.1)
# ---------------------------------------------------------------------------

_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Point at infinity (identity element)
_INF: Optional[Tuple[int, int]] = None

# ---------------------------------------------------------------------------
# Low-level field / group arithmetic
# ---------------------------------------------------------------------------

def _modinv(a: int, m: int) -> int:
    """Modular inverse via Fermat's little theorem (m is prime)."""
    return pow(a, m - 2, m)


def _point_add(
    P: Optional[Tuple[int, int]],
    Q: Optional[Tuple[int, int]],
) -> Optional[Tuple[int, int]]:
    """Affine point addition on secp256k1."""
    if P is _INF:
        return Q
    if Q is _INF:
        return P
    Px, Py = P
    Qx, Qy = Q
    if Px == Qx:
        if (Py + Qy) % _P == 0:          # P == -Q → identity
            return _INF
        # Point doubling
        lam = (3 * Px * Px % _P * _modinv(2 * Py, _P)) % _P
    else:
        lam = ((Qy - Py) % _P * _modinv((Qx - Px) % _P, _P)) % _P
    x3 = (lam * lam - Px - Qx) % _P
    y3 = (lam * (Px - x3) - Py) % _P
    return (x3, y3)


def _jacobian_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1, z1 = P
    x2, y2, z2 = Q
    if z1 == 0: return Q
    if z2 == 0: return P
    z1z1 = (z1 * z1) % _P
    z2z2 = (z2 * z2) % _P
    u1 = (x1 * z2z2) % _P
    u2 = (x2 * z1z1) % _P
    s1 = (y1 * z2 * z2z2) % _P
    s2 = (y2 * z1 * z1z1) % _P
    if u1 == u2:
        if s1 != s2: return (1, 1, 0)
        return _jacobian_double(P)
    h = (u2 - u1) % _P
    i = (4 * h * h) % _P
    j = (h * i) % _P
    r = (2 * (s2 - s1)) % _P
    v = (u1 * i) % _P
    x3 = (r * r - j - 2 * v) % _P
    y3 = (r * (v - x3) - 2 * s1 * j) % _P
    z3 = (((z1 + z2)**2 - z1z1 - z2z2) * h) % _P
    return (x3, y3, z3)

def _jacobian_double(P):
    if P is None or P[2] == 0: return (1, 1, 0)
    X, Y, Z = P
    YY = (Y * Y) % _P
    S = (4 * X * YY) % _P
    M = (3 * X * X) % _P
    X3 = (M * M - 2 * S) % _P
    Y3 = (M * (S - X3) - 8 * YY * YY) % _P
    Z3 = (2 * Y * Z) % _P
    return (X3, Y3, Z3)

def _from_jacobian(P):
    if P is None or P[2] == 0: return _INF
    zinv = pow(P[2], _P - 2, _P)
    zinv2 = (zinv * zinv) % _P
    return ((P[0] * zinv2) % _P, (P[1] * zinv2 * zinv) % _P)

def _scalar_mult(k: int, P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """
    Fast Jacobian-coordinate scalar multiplication on secp256k1.
    Avoids expensive field inversions until the final projective conversion.
    """
    k = k % _N
    if k == 0 or P is _INF:
        return _INF
    R = (1, 1, 0)
    P_jac = (P[0], P[1], 1)
    while k > 0:
        if k & 1:
            R = _jacobian_add(R, P_jac)
        P_jac = _jacobian_double(P_jac)
        k >>= 1
    return _from_jacobian(R)


def _point_to_bytes(P: Optional[Tuple[int, int]]) -> bytes:
    """Compressed SEC1 encoding of a curve point."""
    if P is _INF:
        return b"\x00"
    x, y = P
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# Public group object (singleton-like namespace)
# ---------------------------------------------------------------------------

class _Secp256k1Group:
    """
    Immutable descriptor of the secp256k1 group.  Exposes only what callers
    need: the generator G, the second independent generator H (for Pedersen),
    the group order N, and the field prime P.
    """
    P: int = _P
    N: int = _N
    G: Tuple[int, int] = (_Gx, _Gy)

    # H is deterministically derived from a fixed domain seed. The discrete
    # log relation is intended to be unknown; this custom derivation has not
    # been independently reviewed.
    _H_SEED: bytes = b"LedgerGuard-Pedersen-H-v1"

    def __init__(self) -> None:
        self.H: Tuple[int, int] = self._derive_h()

    def _derive_h(self) -> Tuple[int, int]:
        """
        Deterministically derive a second generator H such that nobody knows
        log_G(H).  We hash the seed to a candidate x and test for curve
        membership, incrementing a counter until we find a valid point.
        This custom try-and-increment derivation is not a standards-based
        hash-to-curve implementation.
        """
        counter = 0
        while True:
            digest = hashlib.sha3_256(
                self._H_SEED + counter.to_bytes(4, "big")
            ).digest()
            x = int.from_bytes(digest, "big") % self.P
            # y² = x³ + 7  (secp256k1: a=0, b=7)
            rhs = (pow(x, 3, self.P) + 7) % self.P
            y_sq = rhs
            # Tonelli-Shanks: p ≡ 3 (mod 4)  →  y = y_sq^((p+1)/4)
            y = pow(y_sq, (self.P + 1) // 4, self.P)
            if pow(y, 2, self.P) == y_sq:
                return (x, y)
            counter += 1

    def scalar_mult(self, k: int, P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        return _scalar_mult(k, P)

    def add(
        self,
        P: Optional[Tuple[int, int]],
        Q: Optional[Tuple[int, int]],
    ) -> Optional[Tuple[int, int]]:
        return _point_add(P, Q)

    def point_to_bytes(self, P: Optional[Tuple[int, int]]) -> bytes:
        return _point_to_bytes(P)

    def random_scalar(self) -> int:
        """Cryptographically secure random scalar in [1, N-1]."""
        while True:
            k = int.from_bytes(secrets.token_bytes(32), "big")
            if 1 <= k < self.N:
                return k

    def hash_to_scalar(self, *parts: bytes) -> int:
        """
        Fiat-Shamir hash: H(parts…) → scalar in Z_N.
        Uses SHA3-256 and length-prefixed transcript parts.
        """
        h = hashlib.sha3_256()
        h.update(b"LedgerGuard-ZKP-v1|")
        for p in parts:
            h.update(len(p).to_bytes(4, "big"))
            h.update(p)
        return int.from_bytes(h.digest(), "big") % self.N


# Module-level singleton
secp256k1_group = _Secp256k1Group()


# ---------------------------------------------------------------------------
# Pedersen Commitments
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PedersenCommitment:
    """
    A Pedersen commitment to an integer value v with blinding factor r:

        C = v·G + r·H

    Properties:
        - Computationally binding:  finding v', r' s.t. v'·G + r'·H = C
          requires solving ECDLP.
        - Hiding is intended from a fresh random blinding factor. This custom
          implementation has not received independent cryptographic review.
    """
    point: Tuple[int, int]      # The curve point C
    value: int                  # Committed value v  (KEPT SECRET from verifier)
    blinding: int               # Blinding factor r  (KEPT SECRET from verifier)

    @classmethod
    def commit(cls, value: int, blinding: Optional[int] = None) -> "PedersenCommitment":
        """
        Create a Pedersen commitment to `value`.

        Args:
            value:    Non-negative integer to commit to.  For billing amounts,
                      pass in integer cents (e.g. £12.50 → 1250).
            blinding: Optional blinding factor.  If None, a fresh random
                      scalar is generated securely.

        Returns:
            PedersenCommitment instance.
        """
        grp = secp256k1_group
        if type(value) is not int or not (0 <= value < grp.N):
            raise ValueError("Committed value must be an integer in [0, N).")
        if blinding is not None and (
            type(blinding) is not int or not (1 <= blinding < grp.N)
        ):
            raise ValueError("Blinding factor must be an integer in [1, N).")
        v = value
        r = blinding if blinding is not None else grp.random_scalar()
        vG = grp.scalar_mult(v, grp.G)
        rH = grp.scalar_mult(r, grp.H)
        C  = grp.add(vG, rH)
        if C is None:
            raise ValueError("Commitment resulted in point at infinity – invalid inputs.")
        return cls(point=C, value=value, blinding=r)

    def public_point_bytes(self) -> bytes:
        """Serialise the public commitment point to bytes (verifier-safe)."""
        return secp256k1_group.point_to_bytes(self.point)

    def add(self, other: "PedersenCommitment") -> "PedersenCommitment":
        """
        Homomorphic addition: C_a + C_b commits to (v_a + v_b) with
        blinding (r_a + r_b).  Enables aggregation without re-committing.
        """
        grp = secp256k1_group
        new_point   = grp.add(self.point, other.point)
        new_value   = self.value   + other.value
        new_blinding = (self.blinding + other.blinding) % grp.N
        if new_point is None:
            raise ValueError("Homomorphic sum resulted in point at infinity.")
        return PedersenCommitment(
            point    = new_point,
            value    = new_value,
            blinding = new_blinding,
        )


# ---------------------------------------------------------------------------
# Schnorr Sigma-Protocol (Non-Interactive via Fiat-Shamir)
# ---------------------------------------------------------------------------

@dataclass
class SchnorrProof:
    """
    Proof of knowledge of a discrete logarithm x such that P = x·G.

    Fields (all public – safe to transmit to verifier):
        announcement_bytes: compressed SEC1 encoding of nonce·G
        challenge:          Fiat-Shamir challenge (integer mod N)
        response:           s = nonce - challenge·x  (mod N)
        public_point_bytes: compressed SEC1 encoding of P = x·G
        domain_tag:         context string binding this proof to its use-case
    """
    announcement_bytes: bytes
    challenge: int
    response: int
    public_point_bytes: bytes
    domain_tag: str


class SchnorrProver:
    """
    Generates non-interactive Schnorr proofs of discrete-log knowledge.

    Usage::

        prover = SchnorrProver()
        proof  = prover.prove(secret_scalar, domain_tag="invoice#42")
    """

    def __init__(self) -> None:
        self._grp = secp256k1_group

    def prove(self, secret: int, domain_tag: str) -> SchnorrProof:
        """
        Prove knowledge of `secret` such that public_point = secret·G.

        The proof is non-interactive (Fiat-Shamir):
            1. Commit:    R = k·G   (k random nonce)
            2. Challenge: c = H(domain_tag || public_point || R)
            3. Response:  s = k - c·secret  (mod N)
        """
        grp = self._grp
        if type(secret) is not int or not (1 <= secret < grp.N):
            raise ValueError("Secret scalar must be an integer in [1, N).")
        if not isinstance(domain_tag, str) or len(domain_tag.encode("utf-8")) > 1024:
            raise ValueError("domain_tag must be a string of at most 1024 bytes.")
        P = grp.scalar_mult(secret, grp.G)
        if P is None:
            raise ValueError("Secret scalar is zero – invalid.")

        k = grp.random_scalar()
        R = grp.scalar_mult(k, grp.G)
        if R is None:
            raise ValueError("Nonce scalar is zero – invalid.")

        P_bytes = grp.point_to_bytes(P)
        R_bytes = grp.point_to_bytes(R)
        tag_bytes = domain_tag.encode("utf-8")

        c = grp.hash_to_scalar(tag_bytes, P_bytes, R_bytes)
        s = (k - c * secret) % grp.N

        return SchnorrProof(
            announcement_bytes = R_bytes,
            challenge          = c,
            response           = s,
            public_point_bytes = P_bytes,
            domain_tag         = domain_tag,
        )


class SchnorrVerifier:
    """
    Verifies non-interactive Schnorr proofs.

    Usage::

        verifier = SchnorrVerifier()
        ok       = verifier.verify(proof)
    """

    def __init__(self) -> None:
        self._grp = secp256k1_group

    def verify(
        self,
        proof: SchnorrProof,
        expected_domain_tag: str | None = None,
    ) -> bool:
        """
        Verify a Schnorr proof.

        Check: s·G + c·P == R
        where P = public_point, R = announcement.
        Returns True iff the proof is mathematically valid.
        """
        grp = self._grp
        try:
            if (
                not isinstance(proof.domain_tag, str)
                or len(proof.domain_tag.encode("utf-8")) > 1024
                or (expected_domain_tag is not None and proof.domain_tag != expected_domain_tag)
                or type(proof.challenge) is not int
                or type(proof.response) is not int
                or not (0 <= proof.challenge < grp.N)
                or not (0 <= proof.response < grp.N)
            ):
                return False
            # Re-derive R from proof components
            c = proof.challenge
            s = proof.response
            # Decode public point P
            P = _decode_point(proof.public_point_bytes)
            # Decode announcement R
            R_claimed = _decode_point(proof.announcement_bytes)

            sG  = grp.scalar_mult(s, grp.G)
            cP  = grp.scalar_mult(c, P)
            R_computed = grp.add(sG, cP)

            if R_computed != R_claimed:
                return False

            # Re-derive challenge and compare
            tag_bytes = proof.domain_tag.encode("utf-8")
            c_recomputed = grp.hash_to_scalar(
                tag_bytes,
                proof.public_point_bytes,
                proof.announcement_bytes,
            )
            return hmac.compare_digest(
                c.to_bytes(32, "big"),
                c_recomputed.to_bytes(32, "big"),
            )
        except Exception:  # noqa: BLE001
            return False


# ---------------------------------------------------------------------------
# Linear-Relation Proof  (used for billing totals)
# ---------------------------------------------------------------------------
#
# Proves: committed value C_total = C_subtotal + C_tax
#         i.e., total = subtotal + tax  without revealing any of the values.
#
# This public equation alone is not a proof of witness knowledge. The complete
# invoice verifier combines it with context-bound range proofs and the tax
# relation proof.

@dataclass
class LinearRelationProof:
    """
    Public statement that C_total = C_subtotal + C_tax.

    Fields (all verifier-safe):
        commitment_subtotal_bytes: public commitment to subtotal
        commitment_tax_bytes:      public commitment to tax amount
        commitment_total_bytes:    public commitment to total
        domain_tag:                context string
    """
    commitment_subtotal_bytes: bytes
    commitment_tax_bytes: bytes
    commitment_total_bytes: bytes
    domain_tag: str


class LinearRelationProver:
    """
    Packages the public linear relation over Pedersen commitments.
    """

    def prove(
        self,
        c_subtotal: PedersenCommitment,
        c_tax: PedersenCommitment,
        c_total: PedersenCommitment,
        domain_tag: str,
    ) -> LinearRelationProof:
        """
        Prove that the total commitment is the homomorphic sum of the other two.
        """
        if not isinstance(domain_tag, str) or len(domain_tag.encode("utf-8")) > 1024:
            raise ValueError("domain_tag must be a string of at most 1024 bytes.")

        return LinearRelationProof(
            commitment_subtotal_bytes = c_subtotal.public_point_bytes(),
            commitment_tax_bytes      = c_tax.public_point_bytes(),
            commitment_total_bytes    = c_total.public_point_bytes(),
            domain_tag                = domain_tag,
        )


class LinearRelationVerifier:
    """
    Verifies a LinearRelationProof.
    """

    def __init__(self) -> None:
        self._grp = secp256k1_group

    def verify(
        self,
        proof: LinearRelationProof,
        expected_domain_tag: str | None = None,
    ) -> bool:
        """
        Checks the public commitment equation C_sub + C_tax == C_total.
        Separate range and tax proofs establish the values/openings required
        by the complete invoice statement.
        """
        grp = self._grp
        try:
            if (
                not isinstance(proof.domain_tag, str)
                or (expected_domain_tag is not None and proof.domain_tag != expected_domain_tag)
            ):
                return False
            C_sub   = _decode_point(proof.commitment_subtotal_bytes)
            C_tax   = _decode_point(proof.commitment_tax_bytes)
            C_total = _decode_point(proof.commitment_total_bytes)

            # 1. Homomorphic sum
            C_sum = grp.add(C_sub, C_tax)
            if C_sum != C_total:
                return False

            return True
        except Exception:  # noqa: BLE001
            return False


# ---------------------------------------------------------------------------
# Strict Tax Calculation Proof (S * R + 5000 = 10000 * Tax + rem, 0 <= rem < 10000)
# ---------------------------------------------------------------------------

@dataclass
class StrictTaxProof:
    """
    Cryptographic proof that Tax = round(Subtotal * tax_rate_bps / 10000)
    with strict non-leaking mathematical constraint 0 <= remainder < 10000.

    Fields:
        tax_rate_bps:       Claimed tax rate in basis points (public)
        c_rem_bytes:        Commitment to remainder rem
        c_rem_dual_bytes:   Commitment to rem_dual = 9999 - rem
        rem_range_proof:    14-bit RangeProof proving 0 <= rem < 16384
        rem_dual_range_proof: 14-bit RangeProof proving 0 <= rem_dual < 16384
        schnorr_sum_dual:   Schnorr proof opening c_rem + c_rem_dual - 9999*G as multiple of H
        domain_tag:         Context string
    """
    tax_rate_bps: int
    c_rem_bytes: bytes
    c_rem_dual_bytes: bytes
    rem_range_proof: RangeProof
    rem_dual_range_proof: RangeProof
    schnorr_sum_dual: SchnorrProof
    domain_tag: str


class TaxRelationProver:
    """
    Generates strict Zero-Knowledge Tax Verification proofs.
    """

    def __init__(self) -> None:
        self._grp = secp256k1_group
        self._range_prover = RangeProver(bit_length=14)
        self._schnorr_prover = SchnorrProver()

    def prove(
        self,
        c_subtotal: PedersenCommitment,
        c_tax: PedersenCommitment,
        tax_rate_bps: int,
        domain_tag: str,
    ) -> StrictTaxProof:
        grp = self._grp
        R = tax_rate_bps
        if type(R) is not int or not (0 <= R <= 10000):
            raise ValueError("tax_rate_bps must be an integer in [0, 10000].")
        S = c_subtotal.value
        Tax = c_tax.value

        numerator = S * R + 5000
        rem = numerator % 10000
        expected_tax = numerator // 10000

        if Tax != expected_tax:
            raise ValueError(
                f"Tax commitment value {Tax} does not match rounded tax {expected_tax} for subtotal {S} and rate {R}"
            )

        # r_rem = R * r_s - 10000 * r_t (mod N)
        r_rem = (R * c_subtotal.blinding - 10000 * c_tax.blinding) % grp.N
        c_rem = PedersenCommitment.commit(rem, blinding=r_rem)

        # Dual value to strictly enforce rem < 10000:
        # rem + rem_dual = 9999.
        rem_dual = 9999 - rem
        r_dual = grp.random_scalar()
        c_dual = PedersenCommitment.commit(rem_dual, blinding=r_dual)

        # Range proofs (14 bits: covers [0, 16384))
        # Since rem >= 0, rem_dual >= 0, and rem + rem_dual = 9999,
        # it is mathematically impossible for rem >= 10000!
        rp_rem, rp_rem_commitment = self._range_prover.prove(
            rem, f"{domain_tag}|rem", blinding=r_rem
        )
        rp_dual, rp_dual_commitment = self._range_prover.prove(
            rem_dual, f"{domain_tag}|dual", blinding=r_dual
        )
        if (
            rp_rem_commitment.point != c_rem.point
            or rp_dual_commitment.point != c_dual.point
        ):
            raise ValueError("Tax remainder range proofs do not match their commitments.")

        # Prove c_rem + c_dual commits to 9999
        r_sum_dual = (r_rem + r_dual) % grp.N
        # (c_rem + c_dual) - 9999*G = r_sum_dual * H
        # We can prove knowledge of r_sum_dual with base H (or mapped generator)
        # Using Schnorr on generator H:
        nonce = grp.random_scalar()
        R_ann = grp.scalar_mult(nonce, grp.H)
        P_pt = grp.scalar_mult(r_sum_dual, grp.H)
        P_bytes = grp.point_to_bytes(P_pt)
        R_bytes = grp.point_to_bytes(R_ann)
        ch = grp.hash_to_scalar(f"{domain_tag}|sum_dual".encode("utf-8"), P_bytes, R_bytes)
        resp = (nonce - ch * r_sum_dual) % grp.N
        schnorr_sum = SchnorrProof(
            announcement_bytes=R_bytes,
            challenge=ch,
            response=resp,
            public_point_bytes=P_bytes,
            domain_tag=f"{domain_tag}|sum_dual",
        )

        return StrictTaxProof(
            tax_rate_bps=tax_rate_bps,
            c_rem_bytes=c_rem.public_point_bytes(),
            c_rem_dual_bytes=c_dual.public_point_bytes(),
            rem_range_proof=rp_rem,
            rem_dual_range_proof=rp_dual,
            schnorr_sum_dual=schnorr_sum,
            domain_tag=domain_tag,
        )


class TaxRelationVerifier:
    """
    Verifies strict Zero-Knowledge Tax Verification proofs.
    """

    def __init__(self) -> None:
        self._grp = secp256k1_group
        self._range_verifier = RangeVerifier(bit_length=14)

    def verify(
        self,
        proof: StrictTaxProof,
        c_subtotal_bytes: bytes,
        c_tax_bytes: bytes,
        expected_domain_tag: str | None = None,
        expected_tax_rate_bps: int | None = None,
    ) -> bool:
        grp = self._grp
        try:
            R = proof.tax_rate_bps
            if (
                type(R) is not int
                or not (0 <= R <= 10000)
                or not isinstance(proof.domain_tag, str)
                or (expected_domain_tag is not None and proof.domain_tag != expected_domain_tag)
                or (expected_tax_rate_bps is not None and R != expected_tax_rate_bps)
            ):
                return False

            C_sub = _decode_point(c_subtotal_bytes)
            C_tax = _decode_point(c_tax_bytes)
            C_rem = _decode_point(proof.c_rem_bytes)
            C_dual = _decode_point(proof.c_rem_dual_bytes)

            # 1. Homomorphic equation:
            # R * C_sub + 5000*G - 10000*C_tax == C_rem
            R_Csub = grp.scalar_mult(R, C_sub)
            five_k_G = grp.scalar_mult(5000, grp.G)
            lhs = grp.add(R_Csub, five_k_G)
            ten_k_C_tax = grp.scalar_mult(10000, C_tax)
            neg_ten_k = grp.scalar_mult(grp.N - 1, ten_k_C_tax)
            expected_C_rem = grp.add(lhs, neg_ten_k)

            if C_rem != expected_C_rem:
                return False

            # 2. Strict remainder bounds via dual range proof:
            # Check 0 <= rem < 16384
            if not self._range_verifier.verify(
                proof.rem_range_proof,
                expected_domain_tag=f"{proof.domain_tag}|rem",
            ):
                return False
            # Check that range proof commitment matches C_rem
            if _decode_point(proof.rem_range_proof.total_commitment_bytes) != C_rem:
                return False

            # Check 0 <= rem_dual < 16384
            if not self._range_verifier.verify(
                proof.rem_dual_range_proof,
                expected_domain_tag=f"{proof.domain_tag}|dual",
            ):
                return False
            # Check that range proof commitment matches C_dual
            if _decode_point(proof.rem_dual_range_proof.total_commitment_bytes) != C_dual:
                return False

            # 3. Check C_rem + C_dual commits to 9999:
            # (C_rem + C_dual) - 9999*G == proof.schnorr_sum_dual.public_point (on base H)
            C_sum = grp.add(C_rem, C_dual)
            neg_9999_G = grp.scalar_mult(grp.N - 9999, grp.G)
            diff = grp.add(C_sum, neg_9999_G)
            claimed_H_point = _decode_point(proof.schnorr_sum_dual.public_point_bytes)
            if diff != claimed_H_point:
                return False

            # Verify Schnorr proof on generator H
            sp = proof.schnorr_sum_dual
            expected_sum_tag = f"{proof.domain_tag}|sum_dual"
            if (
                sp.domain_tag != expected_sum_tag
                or type(sp.challenge) is not int
                or type(sp.response) is not int
                or not (0 <= sp.challenge < grp.N)
                or not (0 <= sp.response < grp.N)
            ):
                return False
            sH = grp.scalar_mult(sp.response, grp.H)
            cP = grp.scalar_mult(sp.challenge, claimed_H_point)
            R_computed = grp.add(sH, cP)
            R_claimed = _decode_point(sp.announcement_bytes)
            if R_computed != R_claimed:
                return False

            tag_bytes = expected_sum_tag.encode("utf-8")
            c_recomputed = grp.hash_to_scalar(tag_bytes, sp.public_point_bytes, sp.announcement_bytes)
            if sp.challenge != c_recomputed:
                return False

            return True
        except Exception:  # noqa: BLE001
            return False


# ---------------------------------------------------------------------------
# Range Proof (bit-decomposition, prove 0 ≤ v < 2^n)
# ---------------------------------------------------------------------------
#
# Strategy: Prover decomposes v into bits b_0…b_{n-1} and commits to each bit
# individually.  For each bit commitment C_i, prover shows that C_i commits
# to either 0 or 1 using an OR-proof (disjunctive Sigma protocol).
#
# This is a standard technique from Camenisch & Stadler (1997).

@dataclass
class BitProof:
    """OR-proof that a Pedersen commitment commits to either 0 or 1."""
    commitment_bytes: bytes          # C = b·G + r·H
    # Simulated branch for b=0: (R0, c0, s0)
    R0_bytes: bytes
    c0: int
    s0: int
    # Simulated branch for b=1: (R1, c1, s1)
    R1_bytes: bytes
    c1: int
    s1: int
    # Overall Fiat-Shamir challenge
    challenge: int


@dataclass
class RangeProof:
    """
    Proves 0 ≤ value < 2^n without revealing value.

    Fields (all verifier-safe):
        bit_proofs:    one BitProof per bit of the committed value
        total_commitment_bytes: C = sum of bit commitments = value·G + r_total·H
        domain_tag:    context string
    """
    bit_proofs: list[BitProof]
    total_commitment_bytes: bytes
    domain_tag: str


class RangeProver:
    """Generates a range proof for a secret value."""

    def __init__(self, bit_length: int = 64) -> None:
        if type(bit_length) is not int or not (1 <= bit_length <= 128):
            raise ValueError("bit_length must be in [1, 128].")
        self._n = bit_length
        self._grp = secp256k1_group

    def prove(
        self,
        value: int,
        domain_tag: str,
        blinding: int | None = None,
    ) -> tuple[RangeProof, PedersenCommitment]:
        """
        Prove 0 ≤ value < 2^n.

        Returns:
            (RangeProof, aggregated PedersenCommitment)
        """
        grp = self._grp
        if not (0 <= value < 2 ** self._n):
            raise ValueError(
                f"Value {value} is out of range [0, 2^{self._n})."
            )
        if not isinstance(domain_tag, str) or len(domain_tag.encode("utf-8")) > 1024:
            raise ValueError("domain_tag must be a string of at most 1024 bytes.")
        if blinding is not None and (
            type(blinding) is not int or not (1 <= blinding < grp.N)
        ):
            raise ValueError("blinding must be an integer in [1, N).")

        bits = [(value >> i) & 1 for i in range(self._n)]
        while True:
            bit_blindings = [grp.random_scalar() for _ in range(self._n)]
            if blinding is None:
                break
            weighted_prefix = sum(
                (pow(2, i, grp.N) * bit_blindings[i]) for i in range(self._n - 1)
            ) % grp.N
            top_weight_inverse = pow(pow(2, self._n - 1, grp.N), -1, grp.N)
            bit_blindings[-1] = ((blinding - weighted_prefix) * top_weight_inverse) % grp.N
            if all(bit_blindings):
                break
        bit_commitments: list[PedersenCommitment] = []
        bit_proofs: list[BitProof] = []

        for i, b in enumerate(bits):
            r = bit_blindings[i]
            C = PedersenCommitment.commit(b, blinding=r)
            bp = self._bit_or_proof(b, r, C, f"{domain_tag}|bit{i}")
            bit_commitments.append(C)
            bit_proofs.append(bp)

        # Aggregate: C_total = sum 2^i · C_i
        # (Homomorphic: total_value·G + total_blinding·H)
        agg = _aggregate_bit_commitments(bit_commitments, grp)
        rp = RangeProof(
            bit_proofs            = bit_proofs,
            total_commitment_bytes = grp.point_to_bytes(agg.point),
            domain_tag            = domain_tag,
        )
        return rp, agg

    def _bit_or_proof(
        self,
        b: int,
        r: int,
        C: PedersenCommitment,
        tag: str,
    ) -> BitProof:
        """
        Disjunctive Schnorr proof: C commits to 0 OR C−G commits to 0.
        Uses the standard OR-composition simulation technique.
        """
        grp = self._grp
        C_point = C.point
        G = grp.G
        H = grp.H

        if b == 0:
            # Real branch: prove C = 0·G + r·H  (i.e., r·H = C)
            # Simulated branch: C − G commits to something (b=1 side)
            k_real = grp.random_scalar()
            R0 = grp.scalar_mult(k_real, H)   # nonce for real (b=0) branch
            R0_bytes = grp.point_to_bytes(R0)

            # Simulate b=1 branch: pick random c1, s1
            c1 = grp.random_scalar()
            s1 = grp.random_scalar()
            # For b=1 branch announcement: R1 = s1·H + c1·(C − G)
            C_minus_G = grp.add(C_point, grp.scalar_mult(grp.N - 1, G))
            s1H  = grp.scalar_mult(s1, H)
            c1CG = grp.scalar_mult(c1, C_minus_G)
            R1 = grp.add(s1H, c1CG)
            R1_bytes = grp.point_to_bytes(R1)

            # Overall challenge
            c_total = grp.hash_to_scalar(
                tag.encode(), grp.point_to_bytes(C_point), R0_bytes, R1_bytes
            )
            c0 = (c_total - c1) % grp.N
            s0 = (k_real - c0 * r) % grp.N

        else:  # b == 1
            # Real branch: prove (C − G) = 0·G + r·H
            # Simulate b=0 branch
            k_real = grp.random_scalar()
            C_minus_G = grp.add(C_point, grp.scalar_mult(grp.N - 1, G))
            R1 = grp.scalar_mult(k_real, H)   # nonce for real (b=1) branch
            R1_bytes = grp.point_to_bytes(R1)

            # Simulate b=0 branch
            c0 = grp.random_scalar()
            s0 = grp.random_scalar()
            s0H  = grp.scalar_mult(s0, H)
            c0C  = grp.scalar_mult(c0, C_point)
            R0 = grp.add(s0H, c0C)
            R0_bytes = grp.point_to_bytes(R0)

            c_total = grp.hash_to_scalar(
                tag.encode(), grp.point_to_bytes(C_point), R0_bytes, R1_bytes
            )
            c1 = (c_total - c0) % grp.N
            s1 = (k_real - c1 * r) % grp.N

        return BitProof(
            commitment_bytes = grp.point_to_bytes(C_point),
            R0_bytes = R0_bytes,
            c0       = c0,
            s0       = s0,
            R1_bytes = R1_bytes,
            c1       = c1,
            s1       = s1,
            challenge = (c0 + c1) % grp.N,
        )


class RangeVerifier:
    """Verifies a RangeProof."""

    def __init__(self, bit_length: int = 64) -> None:
        if type(bit_length) is not int or not (1 <= bit_length <= 128):
            raise ValueError("bit_length must be in [1, 128].")
        self._n = bit_length
        self._grp = secp256k1_group

    def verify(
        self,
        proof: RangeProof,
        expected_domain_tag: str | None = None,
    ) -> bool:
        """
        Verify all bit proofs and the aggregate commitment.
        Returns True iff the range proof is valid.
        """
        grp = self._grp
        if (
            not isinstance(proof.domain_tag, str)
            or len(proof.domain_tag.encode("utf-8")) > 1024
            or (expected_domain_tag is not None and proof.domain_tag != expected_domain_tag)
            or not isinstance(proof.bit_proofs, list)
            or len(proof.bit_proofs) != self._n
        ):
            return False
        try:
            bit_points: list[Optional[Tuple[int, int]]] = []
            for i, bp in enumerate(proof.bit_proofs):
                tag = f"{proof.domain_tag}|bit{i}"
                if not self._verify_bit_proof(bp, tag):
                    return False
                bit_points.append(_decode_point(bp.commitment_bytes))

            # Recompute aggregate
            agg_point = _reconstruct_aggregate(bit_points, grp)
            claimed = _decode_point(proof.total_commitment_bytes)
            return agg_point == claimed
        except Exception:  # noqa: BLE001
            return False

    def _verify_bit_proof(self, bp: BitProof, tag: str) -> bool:
        """
        Verify OR-proof: C commits to 0 OR C−G commits to 0.
        Checks both branches using the Sigma-protocol equations.
        """
        grp = self._grp
        G = grp.G
        H = grp.H
        try:
            if any(
                type(scalar) is not int or not (0 <= scalar < grp.N)
                for scalar in (bp.c0, bp.s0, bp.c1, bp.s1, bp.challenge)
            ):
                return False
            C = _decode_point(bp.commitment_bytes)
            R0 = _decode_point(bp.R0_bytes)
            R1 = _decode_point(bp.R1_bytes)

            # Re-derive overall challenge
            c_total = grp.hash_to_scalar(
                tag.encode(), bp.commitment_bytes, bp.R0_bytes, bp.R1_bytes
            )
            # Check c0 + c1 == c_total (mod N)
            if (bp.c0 + bp.c1) % grp.N != c_total:
                return False

            # Check b=0 branch: s0·H + c0·C == R0
            lhs0 = grp.add(grp.scalar_mult(bp.s0, H), grp.scalar_mult(bp.c0, C))
            if lhs0 != R0:
                return False

            # Check b=1 branch: s1·H + c1·(C−G) == R1
            C_minus_G = grp.add(C, grp.scalar_mult(grp.N - 1, G))
            lhs1 = grp.add(
                grp.scalar_mult(bp.s1, H),
                grp.scalar_mult(bp.c1, C_minus_G),
            )
            if lhs1 != R1:
                return False

            return True
        except Exception:  # noqa: BLE001
            return False


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _decode_point(data: bytes) -> Optional[Tuple[int, int]]:
    """
    Decode a canonical, non-identity compressed SEC1 curve point.
    Identity is not valid proof input and is rejected to prevent degenerate
    Schnorr statements and commitment-opening leakage.
    """
    if not isinstance(data, bytes):
        raise ValueError("Point encoding must be bytes.")
    if data == b"\x00":
        raise ValueError("Identity point is not valid proof input.")
    if len(data) != 33 or data[0] not in (0x02, 0x03):
        raise ValueError(f"Invalid compressed point encoding (len={len(data)}).")
    x = int.from_bytes(data[1:], "big")
    if x >= _P:
        raise ValueError("Point encoding is noncanonical.")
    rhs = (pow(x, 3, _P) + 7) % _P
    y = pow(rhs, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != rhs:
        raise ValueError("Decoded point is not on the curve.")
    if (y % 2) != (data[0] - 2):
        y = _P - y
    if y >= _P or (y % 2) != (data[0] - 2):
        raise ValueError("Point encoding has invalid parity.")
    return (x, y)


def _aggregate_bit_commitments(
    bit_commitments: list[PedersenCommitment],
    grp: _Secp256k1Group,
) -> PedersenCommitment:
    """
    Compute C_total = sum_i 2^i · C_i  (homomorphic bit aggregation).
    The resulting commitment has value = original_value and
    blinding = sum_i 2^i · r_i.
    """
    total_value = 0
    total_blind = 0
    agg_point: Optional[Tuple[int, int]] = None

    for i, c in enumerate(bit_commitments):
        weight = pow(2, i)
        weighted_point = grp.scalar_mult(weight, c.point)
        agg_point = grp.add(agg_point, weighted_point)
        total_value += weight * c.value
        total_blind  = (total_blind + weight * c.blinding) % grp.N

    if agg_point is None:
        raise ValueError("Aggregate commitment is point at infinity.")
    return PedersenCommitment(point=agg_point, value=total_value, blinding=total_blind)


def _reconstruct_aggregate(
    bit_points: list[Optional[Tuple[int, int]]],
    grp: _Secp256k1Group,
) -> Optional[Tuple[int, int]]:
    """Reconstruct the aggregate point from bit commitment points (verifier side)."""
    agg: Optional[Tuple[int, int]] = None
    for i, P in enumerate(bit_points):
        weight = pow(2, i)
        weighted = grp.scalar_mult(weight, P)
        agg = grp.add(agg, weighted)
    return agg
