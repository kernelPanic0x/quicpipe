# quicpipe wire protocol — version 1

This document is the contract for `quicpipe/v1`. The ALPN string is the
version: an incompatible change bumps it and nothing else in this document is
negotiated. Wire values (enum tags, close codes) are frozen; names are not.

**Status: pre-release.** `v1` is the only version that exists and the wire is
still being stabilised, so an incompatible change is made *in place* rather
than bumping the ALPN. From the first release onward, the frozen-values rule
above applies: any change to a tag, a close code, a frame shape or the
integrity predicate is a new version.

The protocol is platform-neutral. It talks about bytes, offsets, cancellations
and consumers — never about Unix signals, file descriptors or paths. A Windows
outlet and a Unix inlet speak the same protocol, and either side may resume a
transfer the other started.

## Rendezvous

Before any QUIC connection exists, both sides exchange a
`HandshakePayload` over the magic-wormhole channel:

| field              | meaning                                                       |
|--------------------|---------------------------------------------------------------|
| `public_key`      | the sender's iroh public key; the peer must match it           |
| `relay_url`       | optional relay the peer can be reached through                 |
| `direct_addresses`| optional hints for a direct path                               |
| `size`            | total source bytes when known — advisory only                  |

`size` drives the progress bar and ETA. It never decides whether a transfer
succeeded. The checksum does.

## Streams

Every connection carries exactly two streams:

1. **Control** — bidirectional, opened by the outlet (the dialer).
   Length-delimited frames (`max_frame_length = 64 KiB`), each payload a
   wincode-encoded enum.
2. **Data** — unidirectional, opened by the inlet, carrying raw source bytes
   with no framing at all. It ends with FIN when the source is exhausted, or
   with RESET when the inlet aborts.

The data stream carries no framing at all — QUIC already delivers it in order
and intact, so per-chunk offsets and lengths would only duplicate what the
transport guarantees. **End of stream is announced twice, on purpose:**
`End` on the control stream states how many bytes the source produced, and the
data stream's FIN states that no more are coming. Neither is trusted to arrive
first, and the length in `End` is what turns "have I got everything" into a
check the outlet can make against its own cursor instead of a fact about stream
ordering.

## Control frames

Inlet → outlet:

| tag | frame             | meaning                                                        |
|-----|-------------------|----------------------------------------------------------------|
| 0   | `End(SourceEnd)`  | the source ended: its exact `total` and its XXH3-64 `checksum`; sent once per connection when the source is exhausted |
| 1   | `Cancel`          | this side is ending the transfer at the user's request          |
| 2   | `Fatal(String)`   | unrecoverable error (source read failure, protocol violation, resume outside the replay window) |

Outlet → inlet:

| tag | frame             | meaning                                                        |
|-----|-------------------|----------------------------------------------------------------|
| 0   | `Written(u64)`    | every byte below this offset is handed to the destination       |
| 1   | `Cancel`          | this side is ending the transfer at the user's request          |
| 2   | `ConsumerGone`    | the outlet's downstream consumer exited (broken output)         |
| 3   | `Bye`             | every byte was written **and verified**; clean goodbye          |

`Written` is both the ack and the resume request. The first frame the outlet
sends on a new connection is `Written(cursor)`, where `cursor` is exactly the
number of bytes already handed to the destination. That single frame is the
whole resume handshake.

## Resume contract

Resume rests on one thing: the outlet's cursor must be exact. So before it
dials again, the outlet **drains its writer to a barrier**, and only then
reports `Written(n)`. At the moment that frame is sent:

- every byte below `n` is on the destination,
- no byte at or above `n` has been written, and
- nothing is left in the writer's queue that could be written later.

Without that barrier the cursor is a snapshot of a moving value, and a replay
from it duplicates whatever the queue still held — so the barrier is a
precondition of the handshake, not an optimisation.

On a new connection the inlet:

1. reads `Written(n)` as the resume point — the greeting is the first frame;
2. rebuilds `[n, EOF)` from its replay window;
3. acks everything below `n` (freeing window memory);
4. opens the data stream and writes the rebuilt bytes, then the rest of the
   source;
5. when the source is exhausted, sends `End` and FINs the data stream.

If `n` is no longer reproducible (outside the replay window), the inlet sends
`Fatal` and does not invent bytes: a resume is never a guess.

Reconnect happens after a transport loss, and after a `DONE` close that arrived
without `Bye` — that combination is a teardown overtaking a frame, not a
verdict. `CANCELLED`, `CONSUMER_GONE` and `FATAL` are final: the peer has made
a decision, and redialling would contradict it.

## Integrity contract

The inlet announces `End { total, checksum }` when the source ends. The outlet
drains every queued byte to the OS, then holds the transfer to two independent
checks:

- the cursor equals `total`, so a truncated or overlong stream fails even if
  its digest happened to collide;
- the XXH3-64 digest of exactly those bytes equals `checksum`.

Exit zero is impossible without both. `Bye` is sent only after they hold *and*
after the destination has been committed (flushed and closed): "written and
verified" must never be announced ahead of the flush that makes it true. A
receiver must never treat an earlier ack or a bare stream close as success.

### Checksum algorithm

The digest is **XXH3-64**: `xxhash-rust`'s `xxh3`, 64-bit output, default seed
`0`, as in `xxhash_rust::xxh3::Xxh3` / `xxh3_64`. It is *not* the older
`XXH64`, and not the 32-bit or 128-bit XXH3 variants — those are different
functions, and a peer that implemented one of them would never verify a single
transfer. This is the one place where "just any 64-bit hash" is not an
implementation detail: an interoperating v1 peer must use exactly this
function, this width and this seed.

- **Input.** Exactly the source bytes, in order, with nothing mixed in: no
  length prefix, no chunk boundaries, no byte offsets, no connection or resume
  salt. The inlet hashes what its source produces; the outlet hashes what it
  hands to the destination. Same bytes in, same digest, whoever computes it.
- **Streaming.** The digest is incremental, and streaming it equals hashing
  the concatenation one-shot. That is what lets both sides hash as they go
  instead of buffering the transfer: the inlet hashes on read, the outlet on
  write, and the value is comparable at the end.
- **Scope.** One digest per *source*, over `[0, EOF)` — not per chunk, not per
  connection. Bytes replayed after a reconnect are hashed exactly once by each
  side in stream order, so a duplicate, an omission or a bad resume offset
  shows up as a mismatch rather than being smoothed over.
- **Wire form.** `End` (tag 0) carrying the raw 64-bit value in wincode's
  default little-endian encoding, inside a length-delimited control frame. The
  frame is sent once per connection when the source is exhausted; the value is
  the digest of the whole source, not of the bytes sent on that connection.
- **Verdict.** Exact equality of the two `u64`s, checked only after the
  outlet's drain barrier has fixed the final cursor. No truncation, no
  comparison of a prefix, no tolerance, no "probably fine": a missing
  `End` is a failure, never a reason to skip verification.
- **Cheap by design.** XXH3-64 runs far faster than the transport carries
  bytes (hundreds of MB/s here), so integrity never becomes the bottleneck.
- **Not a MAC.** XXH3 detects accident, not malice: roughly 2^-64 chance of an
  undetected accidental change, and a peer that misreports its own bytes can
  misreport their digest too. Authentication in v1 comes from the wormhole
  rendezvous and iroh's key pinning, never from this value.

`Bye` has a choreography, for the same reason `Cancel` does: the outlet does
not close the connection until the inlet has closed back. An acknowledgement
from the peer's *transport* only proves that the frame reached its QUIC stack,
not that its session loop has read it; closing on that evidence discards a
still-unread `Bye` and turns a verified transfer into a reported failure. So
the outlet waits after sending `Bye`, and the inlet closes with `DONE` as soon
as it has seen `Bye`. The outlet closes as a backstop only if the inlet never
answers.

For the case where the connection dies *with* the goodbye, the outlet stays
reachable for a bounded while after a verified transfer and re-answers any
inlet that comes back: the digest is final and nothing can be written any more,
so repeating `Bye` is always truthful. A lost goodbye therefore costs one
reconnect, exactly like any other transport loss, instead of being fatal.

This is what makes resume safe across arbitrary reconnects without per-chunk
offsets: the end-to-end hash sees any duplication, omission or bad offset,
even one the transport could not detect across two different connections.

## Close codes

The QUIC `CONNECTION_CLOSE` code corroborates a *failure*, because a close
frame can be lost together with stream data and a peer that decided to stop
must not be redialled. It can never corroborate success: `DONE` is only
believed together with `Bye`, and a `DONE` that arrives alone means the
teardown overtook the frame — reconnect, do not conclude.

One trap this rule exists for: a QUIC connection that is merely *dropped* —
every handle gone — is closed with code `0` and an **empty reason**, which is
indistinguishable from a deliberate `DONE`. Every intentional close in this
protocol passes a non-empty reason, so the two can be told apart; but the
structural defence is that neither is a verdict by itself.

| code | name            | meaning                                         |
|------|-----------------|-------------------------------------------------|
| 0    | `DONE`          | complete and verified                           |
| 1    | `CANCELLED`     | ended at the user's request                     |
| 2    | `CONSUMER_GONE` | the outlet's output consumer exited             |
| 3    | `FATAL`         | unrecoverable error; reason string says why     |

Any other application code is not a verdict this version understands, and is
reported as a failed transfer rather than treated as success.

`DONE` corroborates `Bye`; it is not success on its own. An inlet that
observes the close without having received `Bye` must report a failure. The
outlet applies the symmetric rule towards `End`. This keeps "exit zero"
tied to evidence that both sides actually completed, rather than to a close
code that a transport teardown could produce by accident.

The corroboration runs both ways and is what makes the goodbye ordered: the
outlet's `DONE` means "verified", and the inlet's `DONE` close means "I have
read your `Bye`". A side must therefore never treat an in-band frame it has not
read yet as missing just because the transport noticed the teardown first.

## Deliberately not in v1

- **Source identity.** A changed source between reconnects is caught only by
  the final checksum, after replaying. If that becomes a problem, a future
  version can carry an identity/size in the handshake.
- **Feature negotiation.** ALPN is the only version marker; there are no
  capability bits. The hash algorithm is not negotiated either: v1 means
  XXH3-64, and choosing another one is an ALPN bump, not an option.
- **Strong integrity.** The checksum is a corruption detector; it is not a
  signature over the payload and does not survive a hostile peer.
- **Compression or sparse files.** Bytes are bytes.
- **Out-of-band error detail.** `Fatal` exists only inlet → outlet; outlet
  failures travel as the close reason (capped at 256 bytes).

## Local termination policy (not wire format)

The protocol says "cancelled" and "consumer gone". How a host expresses that is
local policy: on Unix the process dies by `SIGINT`/`SIGTERM`/`SIGPIPE`; on
Windows it exits with the conventional code (`130`, `143`, `141`). Neither
choice is visible to the peer, which only sees `Cancel`, `ConsumerGone` and the
close codes above.
