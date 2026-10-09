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
                    Some((from, chunk.slice((from - offset) as usize..)))
                } else {
                    None
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
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
        assert!(w.replay_from(12).unwrap().is_empty());
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
