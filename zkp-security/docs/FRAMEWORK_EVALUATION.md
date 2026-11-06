# ZKP Framework Evaluation

This is a design evaluation, not a migration. The current Python protocol is
still custom, unaudited, and variable-time. No framework is added until a
compatible circuit, serialization format, and interoperability test vector
are agreed and implemented.

## Statement to preserve

The existing statement proves nonnegative bounded integer line items, their
subtotal, half-up tax
`tax = (subtotal * tax_rate_bps + 5000) // 10000`, a remainder in `[0,10000)`,
and `total = subtotal + tax`. Invoice ID, tenant, currency, tax rate, keyed
reference, and challenge are public transcript context. The backend reference
is still required for authenticity.

All candidate systems can express the arithmetic only after circuit redesign:
integer values need explicit bit decomposition/range constraints, and the
rounding quotient/remainder relation must be represented as constraints rather
than copied from Python. Existing secp256k1 Pedersen commitments are not
automatically compatible with another proof system's commitment generators or
curve.

| Framework | Fit for this statement | Main trade-off | Decision |
|---|---|---|---|
| arkworks | Strong Rust R1CS/field/curve building blocks; suitable for a custom circuit and native verifier | Requires selecting a proving system, curve, commitment scheme, and new wire format | Best general migration foundation |
| Halo2 | Strong circuit model for arithmetic, range checks, and public/private columns; supports the needed redesign | Rust integration, proving-key/circuit versioning, and a new commitment/transcript model | Viable alternative; evaluate if Halo2 ecosystem is preferred |
| Circom/snarkjs | Can express the constraints and has reusable integer/comparator templates | JavaScript/toolchain boundary, proving-system setup/artifacts, and commitment incompatibility | Viable for a new circuit service, not an in-module drop-in |
| Dalek Bulletproofs | Native range proofs and Pedersen commitments are close to the current motivation | The maintained API is Rust/Ristretto; its programmable constraint API is explicitly experimental, so custom tax/total constraints are not a safe drop-in | Not selected for the full invoice statement |

The comparison is based on the maintained project documentation and
repositories: [arkworks](https://arkworks.rs/), [Halo2 Book](https://zcash.github.io/halo2/),
[Circom documentation](https://docs.circom.io/), and the
[Dalek Bulletproofs repository](https://github.com/dalek-cryptography/bulletproofs).

## Migration plan

1. Specify a circuit with fixed-width unsigned integers, explicit carry and
   remainder constraints, and public inputs for the metadata digest and rate.
2. Choose a curve and commitment scheme; publish versioned test vectors for
   valid, boundary, overflow, tenant-substitution, and reference-substitution
   cases.
3. Implement Rust prover/verifier bindings behind a versioned adapter. Keep the
   current verifier available during compatibility testing.
4. Require byte-for-byte serialization and transcript compatibility tests before
   changing callers. Do not reuse current proofs as if they were framework
   proofs.

## Current status

Migration is not safely completable inside this Python-only module without
changing proof mathematics and deployment boundaries. Stage 1 is now
implemented under `native/`: an arkworks Groth16 circuit with native proof
generation, verification, serialization, and tamper/tax regression tests.

Stage 2 is partially implemented: PyO3 bindings, a versioned native proof
envelope, native tests, and benchmarks exist. Cross-language compatibility is
limited to the native Python wrapper. The old Python verifier remains active
because the native circuit currently exposes subtotal and total and does not
bind legacy tenant, reference, timestamp, or challenge context inside the
proof. Independent cryptographic review and a complete constant-time
assessment remain unresolved. Backend authentication, trusted invoice
records, and durable multi-host replay remain backend-dependent. See
`docs/CRYPTOGRAPHIC_AUDIT_READINESS.md`.
