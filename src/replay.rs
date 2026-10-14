//! The replay window: bytes we have sent but not yet had acknowledged.
//!
//! This is the whole of "resume", and it is deliberately unaware of where the
//! bytes came from. Nothing here seeks, re-reads, or knows what stdin is.
//!
//! The invariant that makes it safe:
//!
//! ```text
//! base <= acknowledged <= the outlet's written offset = the resume request
//! ```
//!
//! `base` advances only on an ack, and the outlet only ever asks to resume from
//! a value it previously reported as written, so a well-behaved outlet cannot
//! ask for a byte that is no longer buffered. Asking anyway means the outlet
//! lost its place, and the honest answer is an error, not a guess.

use std::collections::VecDeque;

use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutOfRange {
    /// The outlet wants bytes we have already released.
    Gone { requested: u64, oldest: u64 },
    /// The outlet claims to have written more than we ever sent.
    Ahead { requested: u64, sent: u64 },
}

impl std::fmt::Display for OutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutOfRange::Gone { requested, oldest } => write!(
                f,
                "cannot resume at byte {requested}: only bytes from {oldest} onwards are still \
                 buffered, so the {} bytes below that were already released and cannot be replayed",
                oldest - requested
            ),
            OutOfRange::Ahead { requested, sent } => write!(
                f,
                "cannot resume at byte {requested}: only {sent} bytes were ever sent"
            ),
        }
    }
}

impl std::error::Error for OutOfRange {}

#[derive(Debug)]
pub struct Window {
    chunks: VecDeque<(u64, Bytes)>,
    base: u64,
    head: u64,
    limit: u64,
}

impl Window {
    pub fn new(limit: u64) -> Self {
        Self {
            chunks: VecDeque::new(),
            base: 0,
            head: 0,
            limit,
        }
    }

    /// Stamps the next absolute offset onto a chunk and keeps it for replay.
    pub fn push(&mut self, payload: Bytes) -> (u64, Bytes) {
        let offset = self.head;
        self.head += payload.len() as u64;
        self.chunks.push_back((offset, payload.clone()));
        (offset, payload)
    }

    /// Records that the outlet has written everything below `up_to`.
    ///
    /// Stale (lower) values are ignored: an ack can race a reconnect, and it
    /// must never be able to move `base` backwards.
    pub fn ack(&mut self, up_to: u64) {
        if up_to <= self.base {
            return;
        }
        self.base = up_to.min(self.head);
        while let Some((offset, chunk)) = self.chunks.front() {
            if offset + chunk.len() as u64 <= self.base {
                self.chunks.pop_front();
            } else {
                break;
            }
        }
    }

    /// Unacknowledged bytes. This is the memory bound, and the thing whose limit
    /// stops the reader — which is what gives a stdin source its backpressure.
    pub fn unacked(&self) -> u64 {
        self.head - self.base
    }

    pub fn is_full(&self) -> bool {
        self.unacked() >= self.limit
    }

    /// Everything from `from` onwards, with the first chunk clipped so the replay
    /// begins exactly at `from`.
    pub fn replay_from(&self, from: u64) -> Result<Vec<(u64, Bytes)>, OutOfRange> {
        if from > self.head {
            return Err(OutOfRange::Ahead {
                requested: from,
                sent: self.head,
            });
        }
        if from < self.base {
            return Err(OutOfRange::Gone {
                requested: from,
                oldest: self.base,
            });
        }
        Ok(self
            .chunks
            .iter()
            .filter_map(|(offset, chunk)| {
                let end = offset + chunk.len() as u64;
                if from <= *offset {
                    Some((*offset, chunk.clone()))
                } else if from < end {
                    Some((from, chunk.slice(usize::try_from(from - offset).expect("within chunk")..)))
                } else {
                    None
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]

    use super::*;

    fn window(chunks: &[&'static [u8]]) -> Window {
        let mut w = Window::new(u64::MAX);
        for c in chunks {
            w.push(Bytes::from_static(c));
        }
        w
    }

    #[test]
    fn resume_clips_the_first_partial_chunk() {
        let w = window(&[b"aaaa", b"bbbb", b"cccc"]);
        assert_eq!(
            w.replay_from(6).unwrap(),
            vec![
                (6, Bytes::from_static(b"bb")),
                (8, Bytes::from_static(b"cccc")),
            ]
        );
        assert_eq!(w.replay_from(12).unwrap(), [] as [(u64, bytes::Bytes); 0]);
    }

    #[test]
    fn a_resume_below_the_window_is_an_error_not_a_guess() {
        let mut w = window(&[b"aaaa", b"bbbb"]);
        w.ack(4);
        assert_eq!(
            w.replay_from(0),
            Err(OutOfRange::Gone {
                requested: 0,
                oldest: 4
            })
        );
    }

    #[test]
    fn a_resume_past_the_head_is_an_error() {
        let w = window(&[b"aaaa"]);
        assert_eq!(
            w.replay_from(5),
            Err(OutOfRange::Ahead {
                requested: 5,
                sent: 4
            })
        );
    }

    #[test]
    fn stale_acks_never_move_the_base_backwards() {
        let mut w = window(&[b"aaaa", b"bbbb"]);
        w.ack(8);
        w.ack(4);
        assert_eq!(w.base, 8);
    }

    #[test]
    fn filling_the_window_is_what_stops_the_reader() {
        let mut w = Window::new(8);
        w.push(Bytes::from_static(b"aaaa"));
        assert!(!w.is_full());
        w.push(Bytes::from_static(b"bbbb"));
        assert!(w.is_full());
        w.ack(4);
        assert!(!w.is_full());
    }

    /// The property the design rests on: replay from any offset the outlet could
    /// legitimately have written must reconstruct the stream byte for byte, with
    /// no gap and no duplication.
    #[test]
    fn replay_from_any_written_offset_is_byte_exact() {
        let original: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        for written in [0u64, 1, 63, 64, 65, 2048, 4095, 4096] {
            let mut w = Window::new(u64::MAX);
            for c in original.chunks(64) {
                w.push(Bytes::copy_from_slice(c));
            }
            w.ack(written);

            let mut offset = written;
            let mut got = original[..written as usize].to_vec();
            for (chunk_offset, payload) in w.replay_from(written).unwrap() {
                // This is the outlet's rule, inlined: never write a byte twice.
                assert!(chunk_offset + payload.len() as u64 > offset);
                let skip = (offset.saturating_sub(chunk_offset)).min(payload.len() as u64) as usize;
                let fresh = payload.slice(skip..);
                assert_eq!(chunk_offset + skip as u64, offset);
                offset += fresh.len() as u64;
                got.extend_from_slice(&fresh);
            }
            assert_eq!(got, original, "resuming at {written}");
        }
    }
}

#[cfg(test)]
mod replay_properties {
    #![allow(
        clippy::pedantic,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::shadow_reuse
    )]

    use super::*;
    use proptest::prelude::*;

    // The core corruption invariant, property-tested: for any sequence of
    // chunk sizes and any (possibly stale, possibly ahead) ack schedule,
    // replaying from any cursor the window still holds must reproduce the
    // exact source prefix, and replaying from anything else must be refused
    // with the precise reason. There is no third outcome.
    proptest! {
        #[test]
        fn replay_always_reconstructs_the_exact_prefix(
            sizes in prop::collection::vec(1usize..256, 1..100),
            acks in prop::collection::vec(0u64..100_000, 1..50),
            cursors in prop::collection::vec(0u64..100_000, 1..50),
        ) {
            let mut w = Window::new(1 << 20);
            let mut stream: Vec<u8> = Vec::new();
            for (i, size) in sizes.into_iter().enumerate() {
                let payload: Vec<u8> = (0..size).map(|b| (b + i) as u8).collect();
                let (offset, _chunk) = w.push(Bytes::from(payload.clone()));
                prop_assert_eq!(offset, stream.len() as u64);
                stream.extend_from_slice(&payload);

                // Apply one ack, possibly stale or ahead — acks must never
                // move the base backwards or above what was sent.
                let ack = acks[i % acks.len()];
                let base_before = stream.len() as u64;
                w.ack(ack);
                prop_assert!(w.unacked() <= base_before);

                // Replay from every cursor the window still holds: the result
                // must be the exact source bytes from that cursor.
                for &from in &cursors {
                    match w.replay_from(from) {
                        Ok(frames) => {
                            let mut rebuilt = Vec::new();
                            let mut expected_off = from;
                            for (off, ch) in &frames {
                                prop_assert_eq!(*off, expected_off);
                                rebuilt.extend_from_slice(ch);
                                expected_off += ch.len() as u64;
                            }
                            let end = rebuilt.len() as u64 + from;
                            let upto = end.min(stream.len() as u64);
                            prop_assert_eq!(&stream[from as usize..upto as usize], &rebuilt[..]);
                        }
                        Err(OutOfRange::Gone { requested, oldest }) => {
                            prop_assert_eq!(requested, from);
                            prop_assert!(from < oldest);
                        }
                        Err(OutOfRange::Ahead { requested, sent }) => {
                            prop_assert_eq!(requested, from);
                            prop_assert!(from > sent);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn offsets_are_sequential_and_absolute() {
        let mut w = Window::new(1024);
        let (o1, _) = w.push(Bytes::from_static(b"abc"));
        let (o2, _) = w.push(Bytes::from_static(b"de"));
        assert_eq!((o1, o2), (0, 3));
    }

    #[test]
    fn stale_ack_never_moves_base_backwards() {
        let mut w = Window::new(1024);
        w.push(Bytes::from_static(b"abcdef"));
        w.ack(6);
        assert_eq!(w.unacked(), 0);
        w.ack(3); // stale
        assert_eq!(w.unacked(), 0);
        assert!(w.replay_from(3).is_err()); // still gone
    }

    #[test]
    fn ack_beyond_sent_is_clamped() {
        let mut w = Window::new(1024);
        w.push(Bytes::from_static(b"abc"));
        w.ack(100); // ahead of what was sent
        assert_eq!(w.unacked(), 0);
        assert_eq!(w.head, 3);
    }

    #[test]
    fn replay_from_mid_chunk_clips_exactly() {
        let mut w = Window::new(1024);
        w.push(Bytes::from_static(b"abcdef"));
        w.push(Bytes::from_static(b"ghij"));
        let frames = w.replay_from(2).expect("in window");
        let mut rebuilt = Vec::new();
        for (i, (off, ch)) in frames.iter().enumerate() {
            assert_eq!(*off, if i == 0 { 2 } else { 6 });
            rebuilt.extend_from_slice(ch);
        }
        assert_eq!(rebuilt, b"cdefghij");
    }

    #[test]
    fn window_full_reflects_limit() {
        let mut w = Window::new(4);
        w.push(Bytes::from_static(b"abc"));
        assert!(!w.is_full());
        w.push(Bytes::from_static(b"d"));
        assert!(w.is_full());
        w.ack(2);
        assert!(!w.is_full()); // unacked = 2 < 4
    }
}
