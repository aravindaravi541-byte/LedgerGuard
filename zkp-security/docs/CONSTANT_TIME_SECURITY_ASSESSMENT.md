# Constant-Time and Side-Channel Security Assessment

This assessment records implementation evidence and limitations. It is not an
independent side-channel certification.

## Execution-path inventory

| Component | Secret-dependent operation | Classification | Remediation/status |
|---|---|---|---|
| `src/zkp_core.py` | Python big-integer modular inversion, Jacobian arithmetic, and scalar multiplication | C/D | Legacy path remains variable-time; no safe drop-in replacement for its custom Pedersen protocol was found |
| `src/billing_zkp.py` | Witness validation, commitment arithmetic, proof construction | B/C | Kept as legacy active path because native semantics are not yet compatible |
| Rust circuit construction | Witness values are allocated into fixed-width `UInt64` variables; loop count is the public circuit size | B | Item-count mismatch is rejected; witness-dependent proving behavior still requires specialist review |
| arkworks Groth16 proving | Field arithmetic, MSM, FFT, and pairing-related proving work | B/D | Rust/arkworks alone does not establish application-level constant time |
| arkworks verification | Public-proof parsing, field/pairing verification | B | Inputs are bounded and malformed proofs fail closed; constant-time guarantee is not established |
| Serialization/PyO3 | Variable-length input parsing, allocation, and error paths | C | Added proof/key size limits and generic failure behavior; timing remains observable |
| Key generation | OS-backed randomness through `OsRng` | A for randomness source | Randomness source is appropriate; surrounding key handling still needs operational review |

## Secret-dependent behavior found

The legacy Python implementation uses variable-time `pow` and a
bit-dependent double-and-add loop in `_scalar_mult`. Python integer allocation
and garbage collection are also outside a constant-time model. These are real
side-channel risks if an attacker can measure the prover or verifier locally or
through a sufficiently precise remote oracle.

The Rust circuit allocates fixed-width bit variables for each witness value,
but Groth16 proving includes data-dependent arithmetic and memory behavior not
covered by an application-level constant-time guarantee. Proof serialization
length is currently fixed for the Groth16 proof type, while key and envelope
parsing remains variable-length.

## Fixes implemented

- Native proof bytes are bounded to 4096 bytes before deserialization.
- Native proving/verifying key inputs are bounded to 64 MiB at the PyO3 edge.
- Native verification rejects empty proofs and tax rates above 10,000 before
  cryptographic work.
- Native proving keys record their fixed item count and reject mismatched
  witness lengths.
- Native failures return generic errors and do not include witnesses or key
  material.
- OS randomness is used for native setup and proof generation.

These changes reduce malformed-input and resource-exhaustion exposure; they do
not make the complete execution path constant-time.

## Timing methodology

The existing native benchmark can be run with:

```powershell
cd zkp-security/native
cargo run --release --bin invoice-benchmark
```

It reports setup, proving, verification, and proof size. Timing distributions
must be collected on an isolated machine over many trials, with fixed CPU
frequency and process affinity where possible. Compare distributions for
different witness values using robust summaries and a statistical test such as
Welch's t-test or a permutation test, while recording CPU, OS, compiler, and
dependency versions. No noisy local benchmark can prove constant-time behavior.

## Remaining risks and required review

No authoritative constant-time guarantee has been established for the complete
arkworks Groth16 proving path, pairing implementation, allocator, PyO3
conversion, error handling, or legacy Python cryptography. A specialist must
review source and perform side-channel measurements before any constant-time
claim. The legacy Python path must not be used for high-risk local-secret
workloads until replaced by a compatible reviewed native circuit.
