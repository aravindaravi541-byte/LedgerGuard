# Native invoice proof engine

This crate is the first migration stage for LedgerGuard. It uses arkworks
Groth16 over BLS12-381 and proves the invoice arithmetic statement:

- public `tax_rate_bps`, `subtotal`, and `total`;
- private bounded `u64` line items, tax, and rounding remainder;
- `sum(line_items) = subtotal`;
- `subtotal * tax_rate_bps + 5000 = tax * 10000 + remainder`;
- `total = subtotal + tax` and `remainder < 10000`.

Build and test from `zkp-security/native` with `cargo test`.

This crate is not yet the Python production path. PyO3 bindings and a
versioned envelope exist, but the native circuit currently exposes subtotal
and total and does not bind tenant, invoice reference, timestamp, or replay
challenge inside the circuit. The existing Python proof format is therefore
not treated as compatible with this Groth16 proof.

Groth16 uses the framework RNG interface requiring `RngCore + CryptoRng`.
This does not establish that every operation in the application is
constant-time; timing and side-channel properties of the full stack still
require review.

The test setup is not production key material. Production requires a
documented multi-party ceremony, toxic-waste destruction, authenticated
verification-key distribution, key versioning, and rotation procedures.
