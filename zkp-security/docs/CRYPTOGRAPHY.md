# Cryptographic Statements and Limitations

## Parameters and encodings

The implementation uses the SEC2 secp256k1 field prime `p`, prime group order
`n`, and generator `G`. A second generator `H` is derived from the fixed
LedgerGuard seed using custom try-and-increment hashing. Every received
compressed point must have a canonical `x < p`, valid prefix/parity, and lie on
the curve; the point at infinity is rejected as proof input. Every proof scalar
must be the canonical integer in `[0,n)`.

Pedersen openings use a nonzero blinding `r`:

`C(v,r) = vG + rH`.

The range-prover bit blindings are randomized so their weighted sum equals the
blinding of the externally bound commitment. This is necessary: a separately
generated range proof is not evidence about another commitment.

## Invoice statement

The versioned canonical serialization contains invoice ID, ordered line items,
tax rate, subtotal, tax, total, and currency. The proof reference is
HMAC-SHA256 over a domain-separated SHA3-256 digest of that complete
serialization. Its key is derived with HKDF for the `invoice-reference`
purpose. The keyed reference avoids publishing a directly guessable unkeyed
digest; the host backend must persist and retrieve it as trusted invoice data.

The verifier distinguishes:

- **Cryptographic proof validity**: the protocol statements validate.
- **Trusted reference verification**: the supplied reference equals the one in
  the proof.
- **Invoice authenticity**: not established by this module alone. It depends
  on the authenticated backend record and host authorization policy.

Changing the invoice ID, tenant, currency, keyed reference, or challenge
changes the proof context and therefore the domain tags of the proof
transcripts. The verifier recomputes that context from the claimed invoice ID
and requires each relevant proof to use the resulting exact domain tag. This
binds the ID as a public statement but does not authenticate it.

## Value bounds

With `ZKP_RANGE_BITS = b`, where `16 <= b <= 64`:

- Every line-item amount, subtotal, and tax is proved in `[0, 2^b)`.
- `InvoiceData` additionally enforces subtotal at most `2^b - 1`.
- There are at most 1000 line items, so their unbounded integer sum is at most
  `1000 * (2^b - 1)`, which is less than the secp256k1 order for `b <= 64`.
- Total is proved in `[0, 2^(b+1))`, which is also below the group order.
- Tax rate is a public integer in `[0,10000]` basis points.

These bounds, plus the total and tax range proofs, prevent a false integer
relation from passing solely due to reduction modulo `n`. Inputs must be
nonnegative Python integers (booleans are rejected).

## Subtotal and total

For line-item amounts `a_i`, the prover gives commitments `C_i` and a range
proof for each exact commitment. The verifier checks byte-for-byte that the
range proof aggregate equals `C_i`, checks each context tag includes the item
index, and verifies:

`C_subtotal = Σ C_i`.

It also verifies the range proof for `C_subtotal`. The linear relation proof
checks:

`C_total = C_subtotal + C_tax`.

The total commitment is range-proved with one extra bit to accommodate the
sum of two bounded values.

## Tax and rounding

The public tax rate `R` is in basis points. The private amounts are subtotal
`S`, tax `T`, and remainder `q`. Half-up integer rounding is exactly:

`T = (S * R + 5000) // 10000`.

The prover commits to `q` with the blinding dictated by the subtotal and tax
commitments. The tax verifier checks the Pedersen equation:

`R*C_S + 5000*G - 10000*C_T = C_q`.

This is a linear commitment relation because `R` is public; no multiplication
of two secret witnesses is required. The proof also establishes `0 <= q <
10000`:

1. A 14-bit OR range proof establishes `0 <= q < 16384`.
2. A second 14-bit range proof establishes `0 <= q_dual < 16384`.
3. A Schnorr proof on base `H` establishes
   `C_q + C_q_dual - 9999*G = rho*H`.
4. Pedersen binding therefore gives `q + q_dual = 9999`; with both values
   nonnegative, `q <= 9999`.

Because `S`, `T`, and `q` are bounded well below `n`, the commitment equation
cannot hide a different integer relation through modular wraparound. Combined
with the linear total relation and bounded total, verification checks both tax
calculation and final total.

## Fiat-Shamir, nonces, and parsers

Schnorr and OR proofs use SHA3-256 Fiat-Shamir challenges over length-prefixed
inputs and domain tags. Billing tags include the proof context and item
position. Fresh proof nonces and Pedersen blindings use Python's `secrets`
module and rejection sampling. Timestamp tokens use HMAC-SHA256 with a
key-version identifier and bind the proof context.

Serializers reject unexpected/missing fields, malformed base64 and malformed
integer encodings. Verifiers reject noncanonical scalars, noncanonical point
encodings, off-curve points, and identity points.

## Security limitations

These are custom protocols implemented with pure Python big integers and
custom elliptic-curve arithmetic. The implementation is not constant-time,
has not had an independent cryptographic review, and has no formal proof or
certification. The H derivation and Fiat-Shamir implementation have not been
independently analyzed. Passing tests is not evidence of cryptographic
soundness.

The tax relation itself is linear when the rate is public. For a different
statement with secret-by-secret multiplication, this implementation is not
sufficient; use a reviewed arithmetic-circuit ZKP system. Before production,
evaluate an independently reviewed ecosystem such as arkworks/Halo2,
Circom/snarkjs, or a suitable audited Bulletproofs implementation.
