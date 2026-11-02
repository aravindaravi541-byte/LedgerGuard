"""Runnable demonstration of the host-authenticated Flask integration.

The hard-coded demo bearer token and in-memory invoice/replay storage are for
local examples only. Production must inject the host application's real
authentication, tenant-scoped data access, shared key, and durable challenge
store.
"""

import base64
import os
import secrets
import sys

from flask import Flask

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api import Principal, create_zkp_blueprint
from src.billing_zkp import BillingProver, InvoiceData
from src.crypto_utils import KeyManager
from src.replay import SQLiteChallengeStore


def create_app():
    invoice = InvoiceData(
        invoice_id="INV-FLASK-001",
        line_items=[5000, 3000],
        tax_rate_bps=2000,
        currency="GBP",
    )
    invoices = {invoice.invoice_id: invoice}
    key_manager = KeyManager(ikm=secrets.token_bytes(32))
    reference_prover = BillingProver(key_manager=key_manager)

    def authenticate(request):
        if request.headers.get("Authorization") != "Bearer local-demo-only":
            return None
        return Principal("demo-tenant", can_prove=True, can_verify=True)

    def load_invoice(invoice_id, tenant_id):
        return invoices.get(invoice_id) if tenant_id == "demo-tenant" else None

    def resolve_invoice_hash(invoice_id, tenant_id):
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
            resolve_invoice_hash=resolve_invoice_hash,
        ),
        url_prefix="/zkp",
    )
    return app


def run_integration_test():
    app = create_app()
    client = app.test_client()
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer local-demo-only",
    }

    health = client.get("/zkp/health")
    assert health.status_code == 200

    challenge_response = client.post(
        "/zkp/challenge",
        json={"invoice_id": "INV-FLASK-001"},
        headers=headers,
    )
    assert challenge_response.status_code == 201
    challenge = challenge_response.get_json()["challenge_token"]

    proof_response = client.post(
        "/zkp/prove",
        json={
            "invoice_id": "INV-FLASK-001",
            "challenge_token": challenge,
        },
        headers=headers,
    )
    assert proof_response.status_code == 201, proof_response.get_json()

    verify_response = client.post(
        "/zkp/verify",
        json={"proof": proof_response.get_json()["proof"]},
        headers=headers,
    )
    assert verify_response.status_code == 200, verify_response.get_json()
    assert verify_response.get_json()["is_valid"] is True
    print("Authenticated tenant-scoped Flask prove/verify flow: OK")


if __name__ == "__main__":
    run_integration_test()
