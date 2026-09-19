# hookverify

Verify a webhook signature without hand-rolling the check for the fourth
time. Every service that receives webhooks ends up with its own
twenty-line HMAC verifier, and at least one of those copies gets a
detail wrong: `==` instead of a constant-time compare, hex where the
sender sent base64, or — the one that actually costs money — checking
Stripe's `v1` signature and never looking at `t`, which leaves a
captured request replayable forever. This does the three common schemes
in one place, correctly, with an exit code you can script on.

## Usage

```bash
# GitHub: X-Hub-Signature-256, HMAC-SHA256 over the raw body
printf 'Hello, World!' | hookverify github \
  --secret "It's a Secret to Everybody" \
  --signature 'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17'
# -> result: VALID                                      (exit 0)

# Stripe: t=<unix>,v1=<hex>, HMAC-SHA256 over "{t}.{body}", with a replay window
printf '{"id":"evt_test_webhook","object":"event"}' | hookverify stripe \
  --secret whsec_test_secret \
  --signature 't=1719849600,v1=88ce695ef1c916d5ef010b385ff02b2a5cdd948a249e3a6459aac03f4154244d' \
  --tolerance 300 --now 1719849610
# -> result: VALID                                      (exit 0)

# Generic: any header, any prefix, hex or base64 (this one is Shopify-shaped)
printf '{"order_id":1234}' | hookverify generic \
  --secret shpss_generic_secret --header X-Shopify-Hmac-Sha256 --encoding base64 \
  --signature 'qhABbY7I/iJKAkxKUsJ+LtrEqiKlAtgaIJFyvb8Uh/s='
# -> result: VALID                                      (exit 0)

# And the inverse, to test your own endpoint with a signature known to be right:
printf 'Hello, World!' | hookverify sign github --secret "It's a Secret to Everybody"
# -> sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17
```

The body comes from stdin by default, and that is the path meant for
real use: signatures are computed over **raw bytes**, so anything that
parses and re-serializes the JSON first will produce a digest that never
matches, no matter how correct the rest of your code is. `--payload
'<string>'` and `--payload-file <path>` are there for one-off checks.
Note that `echo` appends a newline and will change the digest — use
`printf` or `echo -n`.

Exit codes: **0** valid, **1** signature mismatch, **2** malformed
signature header, **3** Stripe signature correct but outside the
tolerance window. Three and one are deliberately different: a replayed
event is a correctly-signed request, and collapsing it into "invalid"
loses the only fact that explains what is happening. Two is different
again because a garbled header is your own plumbing, not an attack, and
reporting it as "bad signature" sends people hunting for a secret
mismatch that doesn't exist.

## The constant-time compare, specifically

The digest comparison goes through `subtle::ConstantTimeEq`, never `==`.
A normal `==` on `&[u8]` or `String` returns as soon as it finds a
differing byte, so how long the comparison takes depends on how many
leading bytes the attacker guessed right — enough, against a remote
endpoint and with enough samples, to walk a forged signature out one
byte at a time. The length check in front of it is *not* constant-time,
on purpose: an HMAC-SHA256 digest is always 32 bytes, so "wrong length"
leaks nothing that wasn't already public. Stripe mode folds over every
`v1=` in the header rather than `any()`-ing, so a secret rotation with
two candidate signatures doesn't leak which one matched through timing
either.

## Status: built and verified against HMAC digests computed independently by `openssl`

- **39 unit tests** (`cargo test --lib`), all passing, across four areas:
  - *The HMAC itself* is pinned to **RFC 4231 test case 1** (key = 20 ×
    `0x0b`, data `Hi There` →
    `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7`),
    an IETF-published vector, so the primitive is checkable outside this
    repo. The hand-rolled hex and base64 codecs round-trip, reject odd
    lengths / non-alphabet bytes / over-padding as `None` rather than
    panicking, and the base64 encoder is checked against `openssl`'s own
    base64 output for a real digest.
  - *GitHub mode* uses **GitHub's own documented example** — payload
    `Hello, World!`, secret `It's a Secret to Everybody` — whose digest
    in GitHub's docs is
    `757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17`.
    Independently confirmed here:
    `printf 'Hello, World!' | openssl dgst -sha256 -hmac "It's a Secret to Everybody"`
    → `SHA2-256(stdin)= 757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17`,
    byte-identical to what this tool computes.
  - *Stripe mode* uses a vector built exactly the way Stripe documents
    the construction (`signed_payload = t + "." + body`):
    `printf '1719849600.{"id":"evt_test_webhook","object":"event"}' | openssl dgst -sha256 -hmac 'whsec_test_secret'`
    → `SHA2-256(stdin)= 88ce695ef1c916d5ef010b385ff02b2a5cdd948a249e3a6459aac03f4154244d`,
    again matching this tool exactly.
  - *Generic mode* uses one digest in both encodings —
    `aa10016d8ec8fe224a024c4a52c27e2edac4aa22a502d81a209172bdbf1487fb`
    and `qhABbY7I/iJKAkxKUsJ+LtrEqiKlAtgaIJFyvb8Uh/s=` for body
    `{"order_id":1234}` under `shpss_generic_secret` — both taken from
    `openssl dgst -sha256 -hmac ...` (with and without `-binary | base64`).
- **Negative tests are the real content, and were run live through the
  CLI, not only asserted in-process:**
  - *Wrong secret rejected*: the same `Hello, World!` body and the same
    valid signature, verified with `--secret wrong-secret`, printed
    `INVALID — signature does not match` and **exited 1**. The digest the
    tool computed for the wrong secret,
    `067a93552fcc479b3b2bb775fdd484b3a14aff50258794160564599b69bb9acf`,
    is exactly what `openssl dgst -sha256 -hmac "wrong-secret"` gives for
    that body — so the rejection is a genuine cryptographic mismatch, not
    an incidental parse failure.
  - *Tampered body rejected*: one byte changed (`Hello, World!` →
    `Hello, World?`), correct secret, original signature →
    `INVALID`, **exit 1**, with the tool computing
    `319468fd7ae6faec323482b683bcff145fe8b1fc66e17a0bc724cf6d0de2f22f`
    for the tampered body — matching openssl, and bearing no resemblance
    to the original digest.
  - *Stripe timestamp outside the tolerance window rejected — the whole
    point*: the **cryptographically correct** `t=1719849600,v1=88ce695e…`
    header, evaluated at `--now 1719850200` (600s later) with
    `--tolerance 300`, printed `REJECTED — signature is correct but 600s
    old (tolerance 300s); treat as a replay` and **exited 3**. The same
    header at the same `--now` with `--tolerance 900` printed `VALID`
    (exit 0), which proves the rejection came from the replay window and
    not from a digest that happened to be wrong. A far-future `t` is
    rejected symmetrically.
  - *The classic hand-rolled Stripe bug*: a `v1` computed over the body
    **alone** (`f1b27e09364fc7362c461d1314a4853fc2827219e604dfd604e46e40e5fb7b2f`),
    forgetting the `"{t}."` prefix, is rejected — `INVALID`, exit 1.
  - *A replayed capture with `t` rewritten to "now"* is rejected as a
    mismatch, because `t` is inside the signed bytes: an attacker cannot
    slide an old signature into the current window.
  - *Malformed ≠ invalid*: a `sha256=` prefix stripped by a proxy, a
    `sha1=` value from the deprecated header, truncated or non-hex
    digests, a base64 signature handed to hex mode, a `Stripe-Signature`
    with no `t=` or no `v1=` — all report `MALFORMED` with the reason and
    **exit 2**, and the output suppresses the "constant-time compare"
    line in that case, because no comparison actually happened.
  - *A Stripe header carrying only `v0=`* (the test-mode scheme) is
    **not** silently accepted as verified; a `v0` alongside a real `v1`
    is ignored rather than fatal.

**Not done / deliberately deferred**: signature schemes that aren't
HMAC-SHA256 — Slack's `v0=` (same HMAC but its own `v0:{ts}:{body}`
basestring, close enough that it's a natural v2), Twilio's
HMAC-SHA1-over-URL-plus-sorted-params, and anything asymmetric
(Ed25519-signed Discord/Svix-style webhooks), which needs a public key
rather than a shared secret. There is also no HTTP listener: this
verifies a body and a header value you already have, it does not receive
webhooks itself.
