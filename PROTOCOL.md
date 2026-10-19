# quicpipe wire protocol — version 1

This document is the contract for `quicpipe/v1`. The ALPN string is the
version: an incompatible change bumps it and nothing else in this document is
negotiated. Wire values (enum tags, close codes) are frozen; names are not.

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

The data stream's FIN is the primary end-of-stream signal; there is no `EOF`
frame. QUIC already delivers the stream in order and intact, so per-chunk
offsets and lengths would only duplicate what the transport guarantees.

## Control frames

Inlet → outlet:

| tag | frame             | meaning                                                        |
|-----|-------------------|----------------------------------------------------------------|
| 0   | `Checksum(u64)`   | XXH3-64 digest of the whole source; sent once, when it ends     |
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

The outlet drains its writer to a barrier before reconnecting, so its cursor
is a true prefix of the source: no byte has been written twice, and none past
the cursor has been written at all.

On a new connection the inlet:

1. reads `Written(n)` as the resume point;
2. rebuilds `[n, EOF)` from its replay window;
3. acks everything below `n` (freeing window memory);
4. opens the data stream and writes the rebuilt bytes, then the rest of the
   source.

If `n` is no longer reproducible (outside the replay window), the inlet sends
`Fatal` and does not invent bytes. Reconnect is attempted only after a
transport loss; an application close (`DONE`, `CANCELLED`, `CONSUMER_GONE`,
`FATAL`) is final.

## Integrity contract

The inlet announces `Checksum` when the source ends. The outlet drains every
queued byte to the OS, then compares the digest of exactly what it handed to
the destination with the announced value. A mismatch, or a missing checksum,
fails the transfer: exit zero is impossible without a verified digest.

This is what makes resume safe across arbitrary reconnects without per-chunk
offsets: the end-to-end hash sees any duplication, omission or bad offset,
even one the transport could not detect across two different connections.

## Close codes

The QUIC `CONNECTION_CLOSE` reason carries the same verdict as the in-band
frames, because a close frame can be lost together with stream data.

| code | name            | meaning                                         |
|------|-----------------|-------------------------------------------------|
| 0    | `DONE`          | complete and verified                           |
| 1    | `CANCELLED`     | ended at the user's request                     |
| 2    | `CONSUMER_GONE` | the outlet's output consumer exited             |
| 3    | `FATAL`         | unrecoverable error; reason string says why     |

Any other application code is not a verdict this version understands, and is
reported as a failed transfer rather than treated as success.

## Deliberately not in v1

- **Source identity.** A changed source between reconnects is caught only by
  the final checksum, after replaying. If that becomes a problem, a future
  version can carry an identity/size in the handshake.
- **Feature negotiation.** ALPN is the only version marker; there are no
  capability bits.
- **Compression or sparse files.** Bytes are bytes.
- **Out-of-band error detail.** `Fatal` exists only inlet → outlet; outlet
  failures travel as the close reason (capped at 256 bytes).

## Local termination policy (not wire format)

The protocol says "cancelled" and "consumer gone". How a host expresses that is
local policy: on Unix the process dies by `SIGINT`/`SIGTERM`/`SIGPIPE`; on
Windows it exits with the conventional code (`130`, `143`, `141`). Neither
choice is visible to the peer, which only sees `Cancel`, `ConsumerGone` and the
close codes above.
