# Backend Integration Contract

## Required host responsibilities

The ZKP package is not an authentication service and must not be exposed as an
unauthenticated public endpoint. The host backend must:

- Authenticate callers and authorize proof generation and verification.
- Derive the tenant exclusively from authenticated identity, never from an
  untrusted request field.
- Load finalized invoice data through a tenant-scoped canonical data-access
  function.
- Persist a trusted keyed invoice reference alongside that finalized record.
- Resolve that reference by authorized `(invoice_id, tenant_id)` lookup during
  verification.
- Configure shared IKM/key IDs and a replay store shared by all verifier
  workers.
- Apply transport-level rate limits and operational monitoring.

The API limits POST request bodies to 8 MiB by default and proof invoices to
100 line items. The underlying library permits up to 1000 line items, but a
proof is large and computationally expensive; applications should use a
smaller deployment-specific cap.

## Configure the Flask blueprint

```python
import os
from flask import Flask
from src.api import Principal, create_zkp_blueprint
from src.crypto_utils import KeyManager
from src.replay import SQLiteChallengeStore

def authenticate(request):
    # Delegate authentication to the existing host middleware/session.
    identity = request.environ.get("authenticated_identity")
    if identity is None:
        return None
    return Principal(
        tenant_id=identity.tenant_id,
        can_prove=identity.can_generate_invoice_proofs,
        can_verify=identity.can_verify_invoice_proofs,
    )

def load_invoice(invoice_id, tenant_id):
    # Query only a finalized invoice owned by tenant_id.
    return billing_repository.get_finalized_invoice(tenant_id, invoice_id)

def resolve_invoice_hash(invoice_id, tenant_id):
    # Return the previously persisted keyed reference, never a request value.
    return billing_repository.get_zkp_reference(tenant_id, invoice_id)

key_manager = KeyManager()  # Reads shared secrets-manager environment config.
challenge_store = SQLiteChallengeStore(
    os.environ["LEDGERGUARD_ZKP_REPLAY_DB"]
)
zkp_blueprint = create_zkp_blueprint(
    key_manager=key_manager,
    challenge_store=challenge_store,
    authenticate=authenticate,
    load_invoice=load_invoice,
    resolve_invoice_hash=resolve_invoice_hash,
)

app = Flask(__name__)
app.register_blueprint(zkp_blueprint, url_prefix="/zkp")
```

In a multi-host deployment, replace SQLite with a `ChallengeStore`
implementation backed by shared transactional storage. `consume` must be an
atomic compare-and-set: exactly one caller can change an unexpired challenge
from unused to consumed.

## Store canonical invoice references

At invoice finalization, generate the reference with the same configured
`BillingProver`/`KeyManager` used by the module and store the base64 encoding
with the invoice record:

```python
reference = prover.invoice_reference(finalized_invoice)
reference_b64 = base64.b64encode(reference).decode("ascii")
repository.save_zkp_reference(
    tenant_id,
    finalized_invoice.invoice_id,
    reference_b64,
)
```

`InvoiceData.canonical_bytes()` is deterministic and covers the ID, ordered
line items, rate, subtotal, tax, total, currency, and schema version. Do not
reconstruct the reference from user-submitted values. The proof reference is
keyed, so it is not an unkeyed public checksum; verifiers require the trusted
reference from the repository. `InvoiceData.canonical_hash()` is unkeyed and
should be used only for local integrity checks, not exposed as a substitute
for the trusted keyed reference.

## HTTP protocol

All POST endpoints require JSON and authenticated host permissions.

### `POST /zkp/challenge`

Request:

```json
{"invoice_id": "INV-2026-001"}
```

The host confirms tenant ownership before issuing a challenge. Response:

```json
{
  "challenge_token": "opaque-random-token",
  "expires_at": 1793622000,
  "invoice_id": "INV-2026-001"
}
```

### `POST /zkp/prove`

The caller supplies only the invoice ID and verifier-issued token; the module
loads amounts from canonical backend data:

```json
{
  "invoice_id": "INV-2026-001",
  "challenge_token": "opaque-random-token"
}
```

Response: `201` with a serialized `InvoiceProof`. Caller-supplied amount,
currency, rate, or other unexpected fields are rejected.

### `POST /zkp/verify`

Request:

```json
{"proof": { "...": "InvoiceProof version 2.0" }}
```

The backend derives the tenant from authentication, checks the proof's tenant
matches, retrieves the trusted reference, and passes both to the verifier.
The caller cannot provide an expected hash. A cryptographically invalid or
replayed proof returns `422`; malformed requests return `400`; missing
authentication returns `401`; authorization failures return `403`; unavailable
trusted invoice references return `404`; oversized requests return `413`.

The response contains separate `cryptographic_proof_valid`,
`trusted_reference_verified`, and `invoice_authenticity_verified` fields.
Authenticity is not asserted by the ZKP module; it remains a host trust-policy
decision.

## Direct Python workflow

1. The authorized backend asks the verifier to issue a challenge for the
   tenant/invoice.
2. The prover receives canonical invoice data, tenant ID, and challenge token.
3. The backend persists the proof and keyed invoice reference.
4. Verification receives the authenticated tenant and trusted reference.
5. On successful validation, the challenge store atomically consumes the
   challenge. The backend should still enforce business idempotency for invoice
   processing and handle a response lost after successful consumption.

## Key management and rotation

Production `KeyManager()` requires `LEDGERGUARD_ZKP_IKM` (base64, at least 32
bytes). Set `LEDGERGUARD_ZKP_KEY_ID`; during rotation,
`LEDGERGUARD_ZKP_PREVIOUS_KEYS` may contain a JSON object of previous key IDs
to base64 key material. New tokens/references use the active key. Previous
keys are retained only to verify tokens/references they created. Remove old
keys after the maximum proof/challenge validity and reference-retention policy
allows. Key distribution and storage belong to the host deployment.

Ephemeral keys and in-memory challenge storage are only appropriate for
explicit test/development use. Missing production key configuration fails
closed.
