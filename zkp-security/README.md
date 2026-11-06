# LedgerGuard ZKP Security Module

This package demonstrates private billing verification using Pedersen
commitments and custom Schnorr/OR range proofs over secp256k1. It is a research
and academic implementation, **not an independently audited or production-
certified cryptographic system**.

## What the proof verifies

For a version 2 invoice proof, the verifier checks that:

- Every line-item range proof certifies the exact commitment used in the
  subtotal sum, and each transcript is bound to the tenant, invoice, item
  position, canonical reference, and one-time challenge.
- The subtotal commitment is the homomorphic sum of the line-item commitments.
- The tax commitment satisfies
  `tax = (subtotal * tax_rate_bps + 5000) // 10000`, using integer minor units
  and nonnegative half-up rounding.
- The remainder `r` is strictly in `[0, 10000)`. Two 14-bit range proofs
  establish `0 <= r < 16384` and `0 <= 9999-r < 16384`; a proof that their
  committed sum is exactly 9999 excludes every remainder >= 10000.
- The total commitment is the sum of subtotal and tax, with bounded values
  that prevent modular wraparound from representing a different integer sum.
- The claimed invoice ID and metadata match the proof transcript. This is
  binding, **not proof that the invoice ID is authentic**.
- A trusted invoice reference matches when the caller supplies one, and the
  verifier-issued challenge has not expired or already been consumed.

The tax rate, invoice ID, tenant ID, currency, line-item count, commitments,
proof, and one-time challenge are public. Monetary amounts remain witnesses to
the proof. The public invoice reference is a keyed HMAC over the complete
canonical invoice serialization; the backend must retain the matching trusted
reference. A proof without that reference establishes mathematical proof
validity only, not invoice authenticity.

## Quickstart

Validated here with Python 3.12.10; no other Python version is claimed as
tested. From the project root, install dependencies and run validation:

```powershell
python -m pip install -r requirements.txt
python -m pytest -v
python -m compileall src circuits tests examples
python -m pytest --collect-only -q
```

Run both demonstrations:

```powershell
$env:LEDGERGUARD_ZKP_MODE = "development"
python examples/basic_invoice_proof.py
python examples/flask_integration_example.py
```

The example uses a process-local key and in-memory replay store. Neither is
suitable for a production deployment.

The Flask example uses a fixed local demonstration bearer token, generated
in-process key material, and in-memory invoice and challenge stores. These
are local-only and must not be reused in a deployment.

## Library workflow

```python
import base64
from src.billing_zkp import BillingProver, BillingVerifier, InvoiceData
from src.crypto_utils import KeyManager
from src.replay import SQLiteChallengeStore

keys = KeyManager()  # Reads LEDGERGUARD_ZKP_IKM and LEDGERGUARD_ZKP_KEY_ID.
store = SQLiteChallengeStore(r"C:\service-data\zkp-replay.sqlite3")
prover = BillingProver(keys)
verifier = BillingVerifier(keys, challenge_store=store)

invoice = InvoiceData("INV-2026-001", [1250, 750], 2000, "GBP")
trusted_reference = prover.invoice_reference(invoice)
challenge, expires_at = verifier.issue_challenge(invoice.invoice_id, "tenant-42")
proof = prover.prove(
    invoice,
    tenant_id="tenant-42",
    challenge_token=challenge,
)
result = verifier.verify_with_invoice_hash(
    proof,
    base64.b64encode(trusted_reference).decode("ascii"),
    tenant_id="tenant-42",
)
```

The backend should issue challenges only after authorizing the tenant and
invoice. It should persist `invoice_reference()` from canonical finalized
invoice data, then pass the trusted stored reference to verification. A valid
challenge is consumed atomically after proof checks succeed. The consuming
store must be shared by all verifier workers.

## Flask integration

Use `create_zkp_blueprint` and supply the host application's authentication
callback, tenant-scoped canonical invoice loader, trusted-reference resolver,
shared `KeyManager`, and durable `ChallengeStore`. The module does not create
credentials or accept financial amounts from API callers. See
[`docs/INTEGRATION.md`](docs/INTEGRATION.md). The compatibility export
`zkp_bp` is deliberately unconfigured and returns `503`.

## Key and replay configuration

Production `KeyManager()` requires `LEDGERGUARD_ZKP_IKM` to contain base64
encoding of at least 32 secret bytes. Set a stable `LEDGERGUARD_ZKP_KEY_ID`.
Optional `LEDGERGUARD_ZKP_PREVIOUS_KEYS` is a JSON object mapping previous key
IDs to base64 key material for timestamp-token verification during rotation.
Load all values from a secrets manager; do not place secrets in source control
or logs. Without an explicit test/development mode, missing key material fails
closed.

`SQLiteChallengeStore` provides atomic single-use challenges on a shared local
SQLite database. Multi-host deployments should inject a challenge store backed
by their transactional database with an atomic consume operation.

## Security limitations

- The module includes a native Rust-based Groth16 implementation using arkworks over BLS12-381, alongside legacy custom Python cryptographic components. The native implementation does not yet fully replace the existing Python-based billing proof workflow.

- The legacy Python elliptic-curve arithmetic and custom proof protocols have not received independent cryptographic review or formal verification. Python big-integer operations are not guaranteed to execute in constant time and may expose timing or other implementation-level side channels.

- The native Rust implementation has undergone security hardening, including bounded proof and key deserialization, public-input validation, circuit item-count enforcement, improved error handling, and OS-backed randomness. However, these improvements do not establish constant-time execution or independently verified cryptographic security.

- The complete native proving and verification execution paths have not been established to provide constant-time behavior. Potential timing and side-channel considerations remain around Groth16 operations, witness-dependent circuit construction, memory allocation, serialization, deserialization, and Python/PyO3 runtime boundaries.

- The implementation has not undergone an independent cryptographic audit, formal verification, comprehensive side-channel assessment, or production security certification. Automated test results alone do not establish these guarantees.

- Groth16 relies on trusted-setup assumptions. Production deployment requires an appropriately conducted and documented setup process, secure proving-key handling, verification-key integrity, and defined key lifecycle and rotation procedures. The production readiness of these processes has not been independently established.

- Proof validity does not independently establish invoice authenticity. A trusted backend record or authenticated invoice reference, together with an appropriate verification and trust policy, is required to establish the authenticity of the underlying business data.

- Proof validity, transcript binding, and trusted-reference comparison do not replace backend authentication, tenant authorization, idempotent business processing, secure deployment, or appropriate access control.

- Local SQLite-based replay protection and cross-instance replay checks are implemented and tested. However, durable, coordinated replay protection across multiple hosts or distributed application instances requires an appropriate shared backend or persistent coordination mechanism.

- The native implementation must preserve the existing billing workflow's privacy and security semantics, including confidential monetary values, tenant binding, invoice-reference binding, timestamp binding, and replay protection, before it can fully replace the legacy BillingProver/BillingVerifier workflow.

## Limitation status

- **Implemented and tested:** Strict point/scalar validation, transcript binding, canonical invoice serialization, trusted-reference comparison, replay checks, and bounded proof parsing have been implemented or improved and are covered by automated tests.

- **Native ZKP implementation:** A Rust-based Groth16 proof engine using arkworks over BLS12-381, PyO3 bindings, versioned proof-envelope serialization, and benchmark tooling have been implemented.

- **Native security hardening:** Proof and key deserialization limits, public-input validation, empty-proof rejection, circuit item-count enforcement, generic native error handling, and OS-backed randomness have been implemented or improved.

- **Test status:** The reported Python test suite passes with 147 tests, and the native Rust test suite passes with 3 tests. These results demonstrate automated test coverage, not independent cryptographic assurance.

- **Billing API migration:** Full migration of the existing BillingProver/BillingVerifier APIs to the native implementation remains incomplete. The native circuit and integration must preserve confidential invoice monetary values and all existing tenant, invoice-reference, timestamp, and replay bindings before this migration can be considered complete.

- **Constant-time security:** Complete constant-time execution has not been established. Legacy Python arithmetic, native Groth16 operations, circuit construction, memory allocation, serialization, and Python/PyO3 runtime behavior require further assessment and independent specialist review.

- **Independent assurance:** Independent cryptographic review, formal verification, comprehensive side-channel assessment, and production security certification remain outstanding.

- **Backend and deployment integration:** Invoice authenticity, backend authentication, tenant authorization, durable multi-host replay protection, idempotent business processing, production key management, and secure deployment require appropriate backend and operational integration.

- **Framework migration:** Migration to an established native ZKP framework has been partially implemented using arkworks Groth16. The native implementation is not yet a complete replacement for the legacy billing proof workflow. See [`docs/FRAMEWORK_EVALUATION.md`](docs/FRAMEWORK_EVALUATION.md).
