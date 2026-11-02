"""Flask integration boundary for the LedgerGuard ZKP module.

The host billing backend supplies authentication, tenant-scoped invoice
loading, trusted invoice-reference lookup, shared key material, and a durable
challenge store. This module intentionally does not implement a second
authentication system or accept caller-authored financial amounts.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Callable

from flask import Blueprint, Request, jsonify, request
from werkzeug.exceptions import BadRequest

from . import __version__
from .billing_zkp import BillingProver, BillingVerifier, InvoiceData, InvoiceProof
from .crypto_utils import KeyManager
from .replay import ChallengeStore

logger = logging.getLogger(__name__)

MAX_API_REQUEST_BYTES = 8 * 1024 * 1024
MAX_API_LINE_ITEMS = 100


@dataclass(frozen=True)
class Principal:
    """Authenticated host-application identity and endpoint permissions."""

    tenant_id: str
    can_prove: bool = False
    can_verify: bool = False


Authenticate = Callable[[Request], Principal | None]
InvoiceLoader = Callable[[str, str], InvoiceData | None]
InvoiceReferenceResolver = Callable[[str, str], str | None]


def create_zkp_blueprint(
    *,
    key_manager: KeyManager,
    challenge_store: ChallengeStore,
    authenticate: Authenticate,
    load_invoice: InvoiceLoader,
    resolve_invoice_hash: InvoiceReferenceResolver,
    max_request_bytes: int = MAX_API_REQUEST_BYTES,
) -> Blueprint:
    """Create an enabled blueprint from trusted host-backend integrations.

    ``authenticate`` must validate credentials and return an authenticated
    tenant plus endpoint permissions. ``load_invoice`` must enforce tenant
    ownership and return canonical finalized invoice data. The hash resolver
    must retrieve the canonical hash from an authenticated backend record.
    """
    if not callable(authenticate) or not callable(load_invoice) or not callable(resolve_invoice_hash):
        raise ValueError("Authentication and trusted invoice callbacks are required.")
    if not isinstance(key_manager, KeyManager) or challenge_store is None:
        raise ValueError("Explicit key management and a shared challenge store are required.")
    if type(max_request_bytes) is not int or not (1024 <= max_request_bytes <= 16 * 1024 * 1024):
        raise ValueError("max_request_bytes must be in [1024, 16777216].")

    bp = Blueprint("zkp", __name__)
    prover = BillingProver(key_manager=key_manager)
    verifier = BillingVerifier(
        key_manager=key_manager,
        challenge_store=challenge_store,
    )

    def valid_identifier(value: object, max_bytes: int) -> bool:
        if not isinstance(value, str) or not value:
            return False
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return len(encoded) <= max_bytes and not any(ord(char) < 32 for char in value)

    def body_json() -> dict:
        raw = request.environ.get("ledgerguard.zkp.body")
        if not isinstance(raw, bytes):
            raise BadRequest("Invalid request body.")

        def unique_object(pairs):
            output = {}
            for key, value in pairs:
                if key in output:
                    raise BadRequest("Duplicate JSON object keys are not allowed.")
                output[key] = value
            return output

        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BadRequest("Request body must be valid JSON.") from exc
        if not isinstance(data, dict):
            raise BadRequest("Request body must be a JSON object.")
        return data

    def principal_for(permission: str) -> Principal | tuple:
        try:
            principal = authenticate(request)
        except Exception:
            logger.exception("Host authentication callback failed.")
            return jsonify({"error": "Authentication service unavailable."}), 503
        if principal is None:
            return jsonify({"error": "Authentication required."}), 401
        if (
            not isinstance(principal, Principal)
            or not valid_identifier(principal.tenant_id, 128)
            or type(principal.can_prove) is not bool
            or type(principal.can_verify) is not bool
        ):
            logger.error("Authentication callback returned an invalid principal.")
            return jsonify({"error": "Request cannot be authorized."}), 403
        if not getattr(principal, permission):
            return jsonify({"error": "Insufficient permission."}), 403
        return principal

    @bp.before_request
    def enforce_request_limits():
        if request.method != "POST":
            return None
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json."}), 415
        if request.content_length is not None and request.content_length > max_request_bytes:
            return jsonify({"error": "Request body exceeds the allowed size."}), 413
        raw = request.stream.read(max_request_bytes + 1)
        if len(raw) > max_request_bytes:
            return jsonify({"error": "Request body exceeds the allowed size."}), 413
        request.environ["ledgerguard.zkp.body"] = raw
        return None

    @bp.get("/health")
    def health():
        return jsonify({
            "status": "ready",
            "module": "zkp-security",
            "version": __version__,
            "features": [
                "pedersen_commitments",
                "schnorr_proofs",
                "context_bound_range_proofs",
                "strict_tax_relation_proof",
                "one_time_challenges",
            ],
        }), 200

    @bp.post("/challenge")
    def issue_challenge():
        principal = principal_for("can_prove")
        if not isinstance(principal, Principal):
            return principal
        try:
            body = body_json()
            if set(body) != {"invoice_id"}:
                return jsonify({"error": "Expected only invoice_id."}), 400
            invoice_id = body["invoice_id"]
            if (
                not valid_identifier(invoice_id, 128)
            ):
                return jsonify({"error": "Invalid invoice_id."}), 400
            invoice = load_invoice(invoice_id, principal.tenant_id)
            if not isinstance(invoice, InvoiceData) or invoice.invoice_id != invoice_id:
                return jsonify({"error": "Invoice not found."}), 404
            if len(invoice.line_items) > MAX_API_LINE_ITEMS:
                return jsonify({"error": "Invoice exceeds the API line-item limit."}), 413
            token, expires_at = verifier.issue_challenge(
                invoice_id=invoice_id,
                tenant_id=principal.tenant_id,
            )
            return jsonify({
                "challenge_token": token,
                "expires_at": expires_at,
                "invoice_id": invoice_id,
            }), 201
        except BadRequest as exc:
            return jsonify({"error": exc.description}), 400
        except Exception:
            logger.exception("Challenge issuance failed.")
            return jsonify({"error": "Challenge issuance failed."}), 500

    @bp.post("/prove")
    def prove():
        principal = principal_for("can_prove")
        if not isinstance(principal, Principal):
            return principal
        try:
            body = body_json()
            if set(body) != {"invoice_id", "challenge_token"}:
                return jsonify({"error": "Expected invoice_id and challenge_token."}), 400
            invoice_id = body["invoice_id"]
            challenge_token = body["challenge_token"]
            if (
                not valid_identifier(invoice_id, 128)
                or not isinstance(challenge_token, str)
                or len(challenge_token) > 256
                or not challenge_token.isascii()
            ):
                return jsonify({"error": "Invalid invoice_id or challenge_token."}), 400
            invoice = load_invoice(invoice_id, principal.tenant_id)
            if not isinstance(invoice, InvoiceData) or invoice.invoice_id != invoice_id:
                return jsonify({"error": "Invoice not found."}), 404
            if len(invoice.line_items) > MAX_API_LINE_ITEMS:
                return jsonify({"error": "Invoice exceeds the API line-item limit."}), 413
            proof = prover.prove(
                invoice,
                tenant_id=principal.tenant_id,
                challenge_token=challenge_token,
            )
            return jsonify({"proof": json.loads(proof.to_json())}), 201
        except BadRequest as exc:
            return jsonify({"error": exc.description}), 400
        except Exception:
            logger.exception("Proof generation failed.")
            return jsonify({"error": "Proof generation failed."}), 500

    @bp.post("/verify")
    def verify():
        principal = principal_for("can_verify")
        if not isinstance(principal, Principal):
            return principal
        try:
            body = body_json()
            if set(body) != {"proof"} or not isinstance(body.get("proof"), dict):
                return jsonify({"error": "Expected a proof object."}), 400
            proof = InvoiceProof.from_json(json.dumps(body["proof"], separators=(",", ":")))
            if len(proof.line_item_proofs) > MAX_API_LINE_ITEMS:
                return jsonify({"error": "Proof exceeds the API line-item limit."}), 413
            if (
                not isinstance(proof.invoice_id, str)
                or not valid_identifier(proof.invoice_id, 128)
                or not valid_identifier(proof.tenant_id, 128)
            ):
                return jsonify({"error": "Malformed proof metadata."}), 400
            if proof.tenant_id != principal.tenant_id:
                return jsonify({"error": "Invoice not found."}), 404
        except BadRequest as exc:
            return jsonify({"error": exc.description}), 400
        except (ValueError, TypeError, KeyError):
            return jsonify({"error": "Malformed proof request."}), 400

        try:
            trusted_hash = resolve_invoice_hash(proof.invoice_id, principal.tenant_id)
            if not isinstance(trusted_hash, str):
                return jsonify({"error": "Trusted invoice reference not found."}), 404
            result = verifier.verify_with_invoice_hash(
                proof,
                trusted_hash,
                tenant_id=principal.tenant_id,
            )
            status = 200 if result.is_valid else 422
            return jsonify({
                "is_valid": result.is_valid,
                "invoice_id": result.invoice_id,
                "checks_passed": result.checks_passed,
                "checks_failed": result.checks_failed,
                "cryptographic_proof_valid": result.cryptographic_proof_valid,
                "trusted_reference_verified": result.trusted_reference_verified,
                "invoice_authenticity_verified": result.invoice_authenticity_verified,
                "error_message": "" if result.is_valid else "Proof verification failed.",
            }), status
        except Exception:
            logger.exception("Proof verification request failed.")
            return jsonify({"error": "Proof verification failed."}), 500

    return bp


def _unconfigured_response():
    return jsonify({"error": "Configure create_zkp_blueprint with trusted backend callbacks."}), 503


# Compatibility export that fails closed. Production integrations must use
# create_zkp_blueprint with explicit authentication and trusted data callbacks.
zkp_bp = Blueprint("zkp_unconfigured", __name__)
zkp_bp.add_url_rule("/health", view_func=_unconfigured_response, methods=["GET"])
zkp_bp.add_url_rule("/challenge", view_func=_unconfigured_response, methods=["POST"])
zkp_bp.add_url_rule("/prove", view_func=_unconfigured_response, methods=["POST"])
zkp_bp.add_url_rule("/verify", view_func=_unconfigured_response, methods=["POST"])
