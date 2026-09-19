//! TCP write fragmentation and TLS handshake-record splitting.
//! Source: `transport/internet/finalmask/fragment/conn.go`.

use std::{io, time::Duration};

use rand::{CryptoRng, Rng};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{SampleRange, invalid};

#[derive(Clone, Debug)]
pub struct Config {
    /// `(0, 1)` means split the first TLS handshake record only. With `from == 0`
    /// and any other `to`, every write is split; otherwise use an inclusive range
    /// of one-based write-call numbers, just like the Go wrapper.
    pub packets_from: u64,
    pub packets_to: u64,
    pub lengths: Vec<SampleRange>,
    pub delays_ms: Vec<SampleRange>,
    /// Zero is unlimited; a positive sampled value includes the last segment.
    pub max_split: SampleRange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteSegment {
    pub bytes: Vec<u8>,
    pub delay_after: Duration,
}

pub struct Fragmenter {
    config: Config,
    writes: u64,
}

impl Fragmenter {
    pub fn new(config: Config) -> io::Result<Self> {
        if config.lengths.is_empty() || config.delays_ms.is_empty() {
            return Err(invalid("fragment lengths and delays must not be empty"));
        }
        if config.lengths.last().unwrap().lower() == 0 {
            return Err(invalid("final fragment length must be positive"));
        }
        if config.packets_from > 0 && config.packets_from > config.packets_to {
            return Err(invalid("fragment packet range is reversed"));
        }
        Ok(Self { config, writes: 0 })
    }

    pub fn write_count(&self) -> u64 {
        self.writes
    }

    /// Plan exactly one caller write. TLS records may add bytes to the wire;
    /// their concatenated record payload remains unchanged. Execute all returned
    /// writes in order and honor each delay, including the final delay.
    pub fn plan<R: Rng + CryptoRng + ?Sized>(
        &mut self,
        input: &[u8],
        rng: &mut R,
    ) -> Vec<WriteSegment> {
        self.writes = self.writes.wrapping_add(1);
        let plain = || {
            vec![WriteSegment {
                bytes: input.to_vec(),
                delay_after: Duration::ZERO,
            }]
        };
        let tls = self.config.packets_from == 0 && self.config.packets_to == 1;
        let (data, record_end) = if tls {
            if self.writes != 1 || input.len() <= 5 || input[0] != 22 {
                return plain();
            }
            let end = 5 + usize::from(u16::from_be_bytes([input[3], input[4]]));
            if input.len() < end {
                return plain();
            }
            (&input[5..end], end)
        } else {
            if self.config.packets_from != 0
                && (self.writes < self.config.packets_from || self.writes > self.config.packets_to)
            {
                return plain();
            }
            (input, input.len())
        };
        let merge_tls =
            tls && self.config.delays_ms.len() == 1 && self.config.delays_ms[0].upper() == 0;
        let max_split = self.config.max_split.sample(rng);
        let mut segments = Vec::new();
        let mut merged = Vec::new();
        let mut from: usize = 0;
        let mut index = 0;
        loop {
            let length = self.config.lengths[index.min(self.config.lengths.len() - 1)].sample(rng);
            let length = usize::try_from(length).unwrap_or(usize::MAX);
            let to = if max_split > 0 && index as u64 + 1 >= max_split {
                data.len()
            } else {
                from.saturating_add(length).min(data.len())
            };
            let mut bytes = Vec::new();
            if tls {
                bytes.extend_from_slice(&input[..3]);
                bytes.extend_from_slice(&((to - from) as u16).to_be_bytes());
            }
            bytes.extend_from_slice(&data[from..to]);
            if merge_tls {
                merged.extend_from_slice(&bytes);
            } else {
                let delay = self.config.delays_ms[index.min(self.config.delays_ms.len() - 1)];
                segments.push(WriteSegment {
                    bytes,
                    delay_after: Duration::from_millis(delay.sample(rng)),
                });
            }
            from = to;
            index += 1;
            if from == data.len() {
                break;
            }
        }
        if merge_tls {
            segments.push(WriteSegment {
                bytes: merged,
                delay_after: Duration::ZERO,
            });
        }
        if tls && input.len() > record_end {
            segments.push(WriteSegment {
                bytes: input[record_end..].to_vec(),
                delay_after: Duration::ZERO,
            });
        }
        segments
    }

    /// An explicit async writer adapter. Call once per original write so packet
    /// selection counts are preserved. An I/O failure leaves this write counted.
    pub async fn write<W: AsyncWrite + Unpin, R: Rng + CryptoRng + ?Sized>(
        &mut self,
        writer: &mut W,
        input: &[u8],
        rng: &mut R,
    ) -> io::Result<usize> {
        for segment in self.plan(input, rng) {
            writer.write_all(&segment.bytes).await?;
            if !segment.delay_after.is_zero() {
                tokio::time::sleep(segment.delay_after).await;
            }
        }
        Ok(input.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn config() -> Config {
        Config {
            packets_from: 0,
            packets_to: 0,
            lengths: vec![SampleRange::fixed(2), SampleRange::fixed(3)],
            delays_ms: vec![SampleRange::fixed(0)],
            max_split: SampleRange::fixed(0),
        }
    }

    #[test]
    fn plain_lengths_clamp_and_packet_selection_counts_calls() {
        let mut c = config();
        c.packets_from = 2;
        c.packets_to = 2;
        let mut f = Fragmenter::new(c).unwrap();
        let mut rng = StdRng::seed_from_u64(1);
        assert_eq!(f.plan(b"ignored", &mut rng).len(), 1);
        let got = f.plan(b"abcdefghij", &mut rng);
        assert_eq!(
            got.iter().map(|s| s.bytes.as_slice()).collect::<Vec<_>>(),
            vec![b"ab".as_slice(), b"cde", b"fgh", b"ij"]
        );
        assert_eq!(f.plan(b"ignored", &mut rng).len(), 1);
    }

    #[test]
    fn tls_records_have_source_derived_headers_and_preserve_trailing_record() {
        let mut c = config();
        c.packets_to = 1;
        let mut f = Fragmenter::new(c).unwrap();
        let mut rng = StdRng::seed_from_u64(2);
        let input = [22, 3, 3, 0, 7, 1, 2, 3, 4, 5, 6, 7, 23, 3, 3, 0, 1, 99];
        let got = f.plan(&input, &mut rng);
        assert_eq!(
            got[0].bytes,
            [
                22, 3, 3, 0, 2, 1, 2, 22, 3, 3, 0, 3, 3, 4, 5, 22, 3, 3, 0, 2, 6, 7
            ]
        );
        assert_eq!(got[1].bytes, [23, 3, 3, 0, 1, 99]);
        assert_eq!(f.plan(&input, &mut rng)[0].bytes, input);
    }

    #[test]
    fn tls_partial_records_and_non_handshake_writes_are_unchanged() {
        let mut rng = StdRng::seed_from_u64(3);
        for input in [vec![22, 3, 3, 0, 7, 1, 2], vec![23, 3, 3, 0, 1, 9], vec![]] {
            let mut c = config();
            c.packets_to = 1;
            assert_eq!(
                Fragmenter::new(c).unwrap().plan(&input, &mut rng)[0].bytes,
                input
            );
        }
    }

    #[test]
    fn split_limit_includes_last_fragment_and_delays_follow_final_write() {
        let mut c = config();
        c.max_split = SampleRange::fixed(2);
        c.delays_ms = vec![SampleRange::fixed(1), SampleRange::fixed(4)];
        let got = Fragmenter::new(c)
            .unwrap()
            .plan(b"abcdefgh", &mut StdRng::seed_from_u64(4));
        assert_eq!(got[0].bytes, b"ab");
        assert_eq!(got[1].bytes, b"cdefgh");
        assert_eq!(got[1].delay_after, Duration::from_millis(4));
    }

    #[test]
    fn zero_prefix_segment_terminates_but_zero_tail_is_rejected() {
        let mut c = config();
        c.lengths.insert(0, SampleRange::fixed(0));
        let got = Fragmenter::new(c.clone())
            .unwrap()
            .plan(b"abc", &mut StdRng::seed_from_u64(1));
        assert!(got[0].bytes.is_empty());
        assert_eq!(got.len(), 3);
        c.lengths.push(SampleRange::fixed(0));
        assert!(Fragmenter::new(c).is_err());
    }
}
