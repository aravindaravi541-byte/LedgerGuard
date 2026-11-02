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

- The elliptic-curve arithmetic and proof protocols are custom pure Python.
  They have not received independent cryptographic review, formal verification,
  side-channel analysis, or production certification.
- Python big-integer operations are not constant-time. Do not treat this code
  as resistant to local timing/cache side channels.
- The implementation does not prove invoice authenticity by itself. A trusted
  backend record or authenticated reference is required; external auditors
  need that reference and an appropriate trust policy.
- Proof validity and reference equality do not replace backend authentication,
  tenant authorization, idempotent business processing, secure deployment, or
  key-rotation procedures.
- For production, evaluate migration to an independently reviewed ZKP stack
  (for example arkworks/Halo2, Circom/snarkjs, or a suitable audited
  Bulletproofs implementation). This package currently uses no external ZKP
  library and makes no claim that its custom protocols are production-secure.
