import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest

from src.native_zkp import NativeInvoiceProof


def test_native_envelope_round_trip():
    proof = NativeInvoiceProof(b"proof", 2000, 2000, 2400, 2)
    assert NativeInvoiceProof.from_json(proof.to_json()) == proof


def test_native_envelope_rejects_wrong_version():
    with pytest.raises(ValueError):
        NativeInvoiceProof.from_json('{"version":"legacy"}')


def test_native_envelope_rejects_noncanonical_base64():
    raw = '{"item_count":2,"proof_b64":"YR==","subtotal":2000,"tax_rate_bps":2000,"total":2400,"version":"ledgerguard-native-groth16-v1"}'
    with pytest.raises(ValueError, match="noncanonical"):
        NativeInvoiceProof.from_json(raw)
