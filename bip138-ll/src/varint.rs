//! Bitcoin CompactSize (varint) encode/decode, copied from the `bitcoin` crate's
//! `VarInt` consensus encoding so the core stays dependency-free. Same wire
//! behavior, including rejection of non-minimal encodings.

use alloc::vec::Vec;

/// Encode a value as a CompactSize varint.
pub fn encode(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    match value {
        0..=0xFC => out.push(value as u8),
        0xFD..=0xFFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x10000..=0xFFFFFFFF => {
            out.push(0xFE);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    out
}

/// Parse a CompactSize varint at the start of `bytes`, returning the value and
/// the number of bytes consumed. Returns `None` on a short buffer or a
/// non-minimal encoding.
pub fn parse(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    match first {
        0xFF => {
            let raw = bytes.get(1..9)?;
            let value = u64::from_le_bytes(raw.try_into().expect("8 bytes"));
            (value >= 0x100000000).then_some((value, 9))
        }
        0xFE => {
            let raw = bytes.get(1..5)?;
            let value = u32::from_le_bytes(raw.try_into().expect("4 bytes")) as u64;
            (value >= 0x10000).then_some((value, 5))
        }
        0xFD => {
            let raw = bytes.get(1..3)?;
            let value = u16::from_le_bytes(raw.try_into().expect("2 bytes")) as u64;
            (value >= 0xFD).then_some((value, 3))
        }
        n => Some((n as u64, 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn encode_matches_bitcoin_vectors() {
        assert_eq!(encode(10), vec![10u8]);
        assert_eq!(encode(0xFC), vec![0xFCu8]);
        assert_eq!(encode(0xFD), vec![0xFDu8, 0xFD, 0]);
        assert_eq!(encode(0xFFF), vec![0xFDu8, 0xFF, 0xF]);
        assert_eq!(encode(0xF0F0F0F), vec![0xFEu8, 0xF, 0xF, 0xF, 0xF]);
        assert_eq!(
            encode(0xF0F0F0F0F0E0),
            vec![0xFFu8, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0, 0]
        );
    }

    #[test]
    fn parse_round_trips_and_reports_length() {
        for value in [
            0u64,
            1,
            0xFC,
            0xFD,
            0xFFFF,
            0x10000,
            0xFFFFFFFF,
            0x100000000,
            u64::MAX,
        ] {
            let encoded = encode(value);
            assert_eq!(parse(&encoded), Some((value, encoded.len())));
        }
    }

    #[test]
    fn parse_rejects_non_minimal() {
        assert_eq!(parse(&[0xFD, 0xFC, 0]), None);
        assert_eq!(parse(&[0xFE, 0xFF, 0xFF, 0, 0]), None);
        assert_eq!(parse(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]), None);
    }

    #[test]
    fn parse_rejects_short() {
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[0xFD, 0]), None);
        assert_eq!(parse(&[0xFE, 0, 0]), None);
    }
}
