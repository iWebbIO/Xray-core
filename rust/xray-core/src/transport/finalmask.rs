//! Native finalmask wire transforms and connection helpers.
//!
//! These modules implement individual masks; installing a mask chain on a
//! transport, configuration conversion, and UDP socket ownership belong to the
//! caller. The Go mask manager's maximum UDP wire packet is 4096 bytes.

pub mod custom;
pub mod fragment;
pub mod noise;
pub mod salamander;

use std::io;

use rand::{CryptoRng, Rng, RngCore};

pub const UDP_SIZE: usize = 4096;

/// A nonnegative Go `crypto.RandBetween` range: upper-exclusive unless both
/// endpoints are equal. Reversed endpoints are normalized, as in Go.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleRange {
    pub min: u64,
    pub max: u64,
}

impl SampleRange {
    pub const fn fixed(value: u64) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    pub fn sample<R: Rng + CryptoRng + ?Sized>(self, rng: &mut R) -> u64 {
        let (lo, hi) = (self.min.min(self.max), self.min.max(self.max));
        if hi - lo <= 1 {
            lo
        } else {
            rng.gen_range(lo..hi)
        }
    }

    pub(crate) fn lower(self) -> u64 {
        self.min.min(self.max)
    }
    pub(crate) fn upper(self) -> u64 {
        self.min.max(self.max)
    }
}

/// Matches Go `RandBytesBetween`: inclusive endpoints and byte-modulo mapping.
pub(crate) fn random_bytes<R: RngCore + CryptoRng + ?Sized>(
    out: &mut [u8],
    min: u8,
    max: u8,
    rng: &mut R,
) {
    rng.fill_bytes(out);
    let (lo, hi) = (min.min(max), min.max(max));
    let width = u16::from(hi) - u16::from(lo) + 1;
    if width < 256 {
        for byte in out {
            *byte = lo + (u16::from(*byte) % width) as u8;
        }
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn integer_ranges_are_upper_exclusive_and_bytes_are_inclusive() {
        let mut rng = StdRng::seed_from_u64(42);
        assert_eq!(SampleRange { min: 1, max: 2 }.sample(&mut rng), 1);
        assert_eq!(SampleRange { min: 2, max: 1 }.sample(&mut rng), 1);
        for _ in 0..100 {
            assert!(SampleRange { min: 3, max: 7 }.sample(&mut rng) < 7);
        }
        let mut bytes = [0; 32];
        random_bytes(&mut bytes, 0x2a, 0x2a, &mut rng);
        assert_eq!(bytes, [0x2a; 32]);
    }
}
