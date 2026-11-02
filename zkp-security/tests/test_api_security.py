import base64
import secrets

from flask import Flask

from src.api import Principal, create_zkp_blueprint, zkp_bp
from src.billing_zkp import BillingProver, InvoiceData
from src.crypto_utils import KeyManager
from src.replay import SQLiteChallengeStore


def build_app(
    *,
    max_request_bytes=8 * 1024 * 1024,
    trusted_reference=True,
    invoice=None,
):
    invoice = invoice or InvoiceData("INV-API-001", [2500, 750], 2000, "GBP")
    invoices = {("tenant-a", invoice.invoice_id): invoice}
    key_manager = KeyManager(ikm=secrets.token_bytes(32))
    reference_prover = BillingProver(key_manager=key_manager)

    def authenticate(request):
        authorization = request.headers.get("Authorization")
        if authorization not in {"Bearer tenant-a", "Bearer tenant-b"}:
            return None
        tenant_id = authorization.removeprefix("Bearer ")
        return Principal(
            tenant_id,
            can_prove=True,
            can_verify=tenant_id == "tenant-a",
        )

    def load_invoice(invoice_id, tenant_id):
        return invoices.get((tenant_id, invoice_id))

    def resolve_hash(invoice_id, tenant_id):
        if not trusted_reference:
            return None
        loaded = load_invoice(invoice_id, tenant_id)
        if loaded is None:
            return None
        return base64.b64encode(
            reference_prover.invoice_reference(loaded)
        ).decode("ascii")

    app = Flask(__name__)
    app.register_blueprint(
        create_zkp_blueprint(
            key_manager=key_manager,
            challenge_store=SQLiteChallengeStore(":memory:"),
            authenticate=authenticate,
            load_invoice=load_invoice,
            resolve_invoice_hash=resolve_hash,
            max_request_bytes=max_request_bytes,
        ),
        url_prefix="/zkp",
    )
    return app


def test_unauthenticated_proof_generation_is_rejected():
    client = build_app().test_client()
    response = client.post(
        "/zkp/challenge",
        json={"invoice_id": "INV-API-001"},
    )
    assert response.status_code == 401


def test_missing_verify_permission_is_rejected():
    client = build_app().test_client()
    response = client.post(
        "/zkp/verify",
        json={"proof": {}},
        headers={"Authorization": "Bearer tenant-b"},
    )
    assert response.status_code == 403


def test_wrong_tenant_cannot_load_invoice():
    client = build_app().test_client()
    response = client.post(
        "/zkp/challenge",
        json={"invoice_id": "INV-API-001"},
        headers={"Authorization": "Bearer tenant-b"},
    )
    assert response.status_code == 404


def test_unconfigured_compatibility_blueprint_fails_closed():
    app = Flask(__name__)
    app.register_blueprint(zkp_bp, url_prefix="/zkp")
    assert app.test_client().post("/zkp/prove").status_code == 503


def test_api_rejects_caller_supplied_invoice_amounts():
    client = build_app().test_client()
    response = client.post(
        "/zkp/prove",
        json={
            "invoice_id": "INV-API-001",
            "line_items": [1],
            "tax_rate_bps": 0,
            "challenge_token": "x" * 40,
        },
        headers={"Authorization": "Bearer tenant-a"},
    )
    assert response.status_code == 400


def test_api_rejects_oversized_request_body():
    client = build_app(max_request_bytes=1024).test_client()
    response = client.post(
        "/zkp/challenge",
        data=b'{"invoice_id":"' + b"x" * 1100 + b'"}',
        content_type="application/json",
        headers={"Authorization": "Bearer tenant-a"},
    )
    assert response.status_code == 413


def test_api_enforces_line_item_limit():
    invoice = InvoiceData("INV-API-001", [1] * 101, 0, "GBP")
    client = build_app(invoice=invoice).test_client()
    response = client.post(
        "/zkp/challenge",
        json={"invoice_id": invoice.invoice_id},
        headers={"Authorization": "Bearer tenant-a"},
    )
    assert response.status_code == 413


def test_api_requires_trusted_invoice_reference():
    client = build_app(trusted_reference=False).test_client()
    headers = {"Authorization": "Bearer tenant-a"}
    challenge = client.post(
        "/zkp/challenge",
        json={"invoice_id": "INV-API-001"},
        headers=headers,
    )
    assert challenge.status_code == 201
    proof = client.post(
        "/zkp/prove",
        json={
            "invoice_id": "INV-API-001",
            "challenge_token": challenge.get_json()["challenge_token"],
        },
        headers=headers,
    )
    assert proof.status_code == 201
    response = client.post(
        "/zkp/verify",
        json={"proof": proof.get_json()["proof"]},
        headers=headers,
    )
    assert response.status_code == 404
