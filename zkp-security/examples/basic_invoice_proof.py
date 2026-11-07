"""
basic_invoice_proof.py – End-to-end example: prove and verify an invoice.

Run:
    cd zkp-security
    python examples/basic_invoice_proof.py

This example demonstrates the full prove → serialise → verify cycle
as it would occur in LedgerGuard's backend.
"""

import sys, os, base64
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.billing_zkp import InvoiceData, BillingProver, BillingVerifier
from src.crypto_utils import KeyManager
from src.replay import SQLiteChallengeStore
import secrets

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

print("=" * 60)
print("LedgerGuard ZKP – Private Invoice Verification Example")
print("=" * 60)

# In production: load IKM from a secrets manager.
# Here we use a fresh random IKM for demonstration.
ikm = secrets.token_bytes(32)
km  = KeyManager(ikm=ikm)

prover   = BillingProver(key_manager=km)
verifier = BillingVerifier(
    key_manager=km,
    challenge_store=SQLiteChallengeStore(":memory:"),
)

# ---------------------------------------------------------------------------
# 1. Create a private invoice
# ---------------------------------------------------------------------------

invoice = InvoiceData(
    invoice_id   = "INV-2024-00042",
    line_items   = [12000, 8500, 4750],   # £120.00, £85.00, £47.50 in pence
    tax_rate_bps = 2000,                  # 20% VAT
    currency     = "GBP",
)

print(f"\nPrivate Invoice (NEVER TRANSMITTED):")
print(f"  Invoice ID   : {invoice.invoice_id}")
print(f"  Line items   : {invoice.line_items}  (pence)")
print(f"  Subtotal     : {invoice.subtotal}p = £{invoice.subtotal/100:.2f}")
print(f"  Tax (20%)    : {invoice.tax_amount}p = £{invoice.tax_amount/100:.2f}")
print(f"  Total        : {invoice.total}p = £{invoice.total/100:.2f}")

# ---------------------------------------------------------------------------
# 2. Generate ZKP proof (prover side)
# ---------------------------------------------------------------------------

print("\n[PROVER] Generating ZKP proof...")
challenge, _ = verifier.issue_challenge(invoice.invoice_id, "demo-tenant")
proof = prover.prove(
    invoice,
    tenant_id="demo-tenant",
    challenge_token=challenge,
)
print(f"[PROVER] Proof generated for invoice {proof.invoice_id}")
print(f"[PROVER] Proof version: {proof.proof_version}")
print(f"[PROVER] Number of line item proofs: {len(proof.line_item_proofs)}")

# Serialise to JSON (safe to transmit)
proof_json = proof.to_json()
proof_size = len(proof_json)
print(f"[PROVER] Serialised proof size: {proof_size:,} bytes")

# ---------------------------------------------------------------------------
# 3. Verify proof (verifier side) – no amounts revealed
# ---------------------------------------------------------------------------

print("\n[VERIFIER] Verifying proof...")
proof_received = proof.__class__.from_json(proof_json)
result = verifier.verify(proof_received, tenant_id="demo-tenant")

print(f"[VERIFIER] Proof valid: {result.is_valid}")
print(f"[VERIFIER] Checks passed: {result.checks_passed}")
if result.checks_failed:
    print(f"[VERIFIER] Checks FAILED: {result.checks_failed}")

# ---------------------------------------------------------------------------
# 4. Extended verification with invoice hash
# ---------------------------------------------------------------------------

print("\n[VERIFIER] Extended verification (invoice hash binding)...")
trusted_challenge, _ = verifier.issue_challenge(
    invoice.invoice_id, "demo-tenant"
)
trusted_proof = prover.prove(
    invoice,
    tenant_id="demo-tenant",
    challenge_token=trusted_challenge,
)
stored_hash = base64.b64encode(
    prover.invoice_reference(invoice)
).decode("ascii")  # resolve from trusted canonical invoice data in production
ext_result  = verifier.verify_with_invoice_hash(
    trusted_proof,
    stored_hash,
    tenant_id="demo-tenant",
)
print(f"[VERIFIER] Extended verification valid: {ext_result.is_valid}")
print(f"[VERIFIER] Checks passed: {ext_result.checks_passed}")

# ---------------------------------------------------------------------------
# 5. Demonstrate tamper detection
# ---------------------------------------------------------------------------

print("\n[ATTACK] Attempting to tamper with total commitment...")
attack_challenge, _ = verifier.issue_challenge(
    invoice.invoice_id, "demo-tenant"
)
attack_proof = prover.prove(
    invoice,
    tenant_id="demo-tenant",
    challenge_token=attack_challenge,
)
tampered_proof = proof.__class__.from_json(attack_proof.to_json())
bad_bytes      = bytearray(base64.b64decode(tampered_proof.total_commitment_b64))
bad_bytes[1]  ^= 0xFF
tampered_proof.total_commitment_b64 = base64.b64encode(bytes(bad_bytes)).decode()
attack_result  = verifier.verify(tampered_proof, tenant_id="demo-tenant")
print(f"[ATTACK] Tampered proof valid: {attack_result.is_valid}")
print(f"[ATTACK] Failed checks: {attack_result.checks_failed}")

print("\n" + "=" * 60)
print("Example complete. The verifier confirmed billing correctness")
print("WITHOUT learning any raw invoice amounts.")
print("=" * 60)
