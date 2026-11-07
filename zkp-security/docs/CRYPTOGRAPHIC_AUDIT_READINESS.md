# Cryptographic Audit Readiness

No independent cryptographic review has been completed. This is a review
packet, not an audit report or certification.

## Threat model

Attackers may submit arbitrary proof bytes, malformed encodings, substituted
tenant or invoice identifiers, altered references, expired timestamps, and
replayed challenges. The host backend must authenticate callers, authorize
tenant access, provide finalized invoice records, and resolve trusted invoice
references.

## Current native scope

`native/src/lib.rs` uses arkworks Groth16 over BLS12-381. It proves private
line items, tax, and remainder with public `tax_rate_bps`, `subtotal`, and
`total`. This deliberately documented limitation means it is not yet a
replacement for the legacy confidential BillingProver/BillingVerifier path.
The native proof also does not currently bind tenant, invoice reference,
timestamp, or replay challenge inside the circuit.

## Assumptions and setup

- Groth16 soundness, zero knowledge, and pairing-group assumptions hold.
- The proving and verification keys come from a correct trusted setup.
- Production requires a documented multi-party ceremony or independently
  generated setup, toxic-waste destruction, authenticated verification-key
  distribution, key versioning, and rotation.
- OS randomness and the pinned arkworks dependencies behave as expected.
- Legacy HMAC keys, backend records, and replay storage remain protected by
  the host deployment.

## Review surface

Review `native/src/lib.rs`, `src/zkp_core.py`, `src/billing_zkp.py`,
`src/crypto_utils.py`, and `src/replay.py`. Check arithmetic, ranges,
rounding, serialization, context binding, replay handling, setup ceremony,
key handling, and Python/native error boundaries.

## Side-channel status

Rust and arkworks do not establish application-wide constant-time behavior.
Witness-dependent circuit construction, proving, serialization, allocation,
PyO3 conversion, and the legacy Python path have not had specialist
constant-time analysis. No complete side-channel guarantee is claimed.

## Independent-review checklist

- [ ] Verify all public/private inputs and monetary confidentiality.
- [ ] Verify range, overflow, carry, tax, rounding, and remainder constraints.
- [ ] Verify native binding of tenant, invoice ID, reference, timestamp, and
      challenge before any production switch.
- [ ] Review trusted setup, toxic-waste handling, key distribution, and
      rotation.
- [ ] Attack proof, context, serialization, and replay boundaries.
- [ ] Assess timing, cache, branch, allocator, and memory-access leakage.
- [ ] Review dependency versions, advisories, reproducible builds, and release
      configuration.
- [ ] Produce an independent signed report with residual-risk findings.

The production migration remains blocked until a commitment-capable circuit
hides subtotal and total and binds the legacy context in the native statement.
