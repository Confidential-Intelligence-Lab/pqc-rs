// SPDX-License-Identifier: MIT
//
// Native byte-oriented rANS coding for HAETAE 1.2.0.
// Frequency distributions derived from the reference implementation.

const SCALE_BITS: u32 = 10;
const SCALE: u32 = 1 << SCALE_BITS;
const RANS_BYTE_L: u32 = 1 << 23;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RansError {
    InvalidSymbol,
    InvalidTable,
    OutputTooLong,
    Truncated,
    InvalidState,
}

#[derive(Debug, Clone, Copy)]
pub struct Symbol {
    pub start: u16,
    pub freq: u16,
}

pub fn encode(symbols: &[u16], table: &[Symbol], max_len: usize) -> Result<Vec<u8>, RansError> {
    if table.is_empty() || max_len < 4 {
        return Err(RansError::InvalidTable);
    }

    let mut cursor = 0_u32;
    for symbol in table {
        if symbol.freq == 0 || u32::from(symbol.start) != cursor {
            return Err(RansError::InvalidTable);
        }
        cursor += u32::from(symbol.freq);
    }
    if cursor != SCALE {
        return Err(RansError::InvalidTable);
    }

    let mut state = RANS_BYTE_L;
    let mut emitted = Vec::new();

    for &value in symbols.iter().rev() {
        let entry = table
            .get(usize::from(value))
            .ok_or(RansError::InvalidSymbol)?;

        let freq = u32::from(entry.freq);
        let start = u32::from(entry.start);

        let x_max = ((RANS_BYTE_L >> SCALE_BITS) << 8) * freq;

        while state >= x_max {
            emitted.push(state as u8);
            state >>= 8;
            if emitted.len() > max_len.saturating_sub(4) {
                return Err(RansError::OutputTooLong);
            }
        }

        state = ((state / freq) << SCALE_BITS) + (state % freq) + start;
    }

    let mut output = Vec::with_capacity(emitted.len() + 4);
    output.extend_from_slice(&state.to_le_bytes());
    output.extend(emitted.into_iter().rev());

    if output.len() > max_len {
        return Err(RansError::OutputTooLong);
    }

    Ok(output)
}

pub fn decode(encoded: &[u8], table: &[Symbol], count: usize) -> Result<Vec<u16>, RansError> {
    if encoded.len() < 4 {
        return Err(RansError::Truncated);
    }

    let mut cursor = 0_u32;
    for symbol in table {
        if symbol.freq == 0 || u32::from(symbol.start) != cursor {
            return Err(RansError::InvalidTable);
        }
        cursor += u32::from(symbol.freq);
    }
    if cursor != SCALE {
        return Err(RansError::InvalidTable);
    }

    let mut state = u32::from_le_bytes(encoded[..4].try_into().map_err(|_| RansError::Truncated)?);

    if !(RANS_BYTE_L..(RANS_BYTE_L << 8)).contains(&state) {
        return Err(RansError::InvalidState);
    }

    let mut position = 4;
    let mut result = Vec::with_capacity(count);

    for _ in 0..count {
        let slot = state & (SCALE - 1);
        let index = table
            .iter()
            .position(|symbol| {
                let start = u32::from(symbol.start);
                let end = start + u32::from(symbol.freq);
                start <= slot && slot < end
            })
            .ok_or(RansError::InvalidSymbol)?;

        let entry = table[index];
        result.push(index as u16);

        state = u32::from(entry.freq) * (state >> SCALE_BITS) + slot - u32::from(entry.start);

        while state < RANS_BYTE_L && position < encoded.len() {
            state = (state << 8) | u32::from(encoded[position]);
            position += 1;
        }

        if state < RANS_BYTE_L {
            return Err(RansError::Truncated);
        }
    }

    if state != RANS_BYTE_L || position != encoded.len() {
        return Err(RansError::InvalidState);
    }

    Ok(result)
}

pub const MODE2_H: [Symbol; 13] = [
    Symbol {
        start: 0,
        freq: 382,
    },
    Symbol {
        start: 382,
        freq: 246,
    },
    Symbol {
        start: 628,
        freq: 65,
    },
    Symbol {
        start: 693,
        freq: 7,
    },
    Symbol {
        start: 700,
        freq: 1,
    },
    Symbol {
        start: 701,
        freq: 1,
    },
    Symbol {
        start: 702,
        freq: 1,
    },
    Symbol {
        start: 703,
        freq: 1,
    },
    Symbol {
        start: 704,
        freq: 1,
    },
    Symbol {
        start: 705,
        freq: 1,
    },
    Symbol {
        start: 706,
        freq: 7,
    },
    Symbol {
        start: 713,
        freq: 65,
    },
    Symbol {
        start: 778,
        freq: 246,
    },
];

pub const MODE2_HB_Z1: [Symbol; 13] = [
    Symbol { start: 0, freq: 1 },
    Symbol { start: 1, freq: 1 },
    Symbol { start: 2, freq: 1 },
    Symbol { start: 3, freq: 5 },
    Symbol { start: 8, freq: 58 },
    Symbol {
        start: 66,
        freq: 246,
    },
    Symbol {
        start: 312,
        freq: 398,
    },
    Symbol {
        start: 710,
        freq: 247,
    },
    Symbol {
        start: 957,
        freq: 59,
    },
    Symbol {
        start: 1016,
        freq: 5,
    },
    Symbol {
        start: 1021,
        freq: 1,
    },
    Symbol {
        start: 1022,
        freq: 1,
    },
    Symbol {
        start: 1023,
        freq: 1,
    },
];

pub const MODE3_H: [Symbol; 17] = [
    Symbol {
        start: 0,
        freq: 266,
    },
    Symbol {
        start: 266,
        freq: 213,
    },
    Symbol {
        start: 479,
        freq: 113,
    },
    Symbol {
        start: 592,
        freq: 40,
    },
    Symbol {
        start: 632,
        freq: 9,
    },
    Symbol {
        start: 641,
        freq: 1,
    },
    Symbol {
        start: 642,
        freq: 1,
    },
    Symbol {
        start: 643,
        freq: 1,
    },
    Symbol {
        start: 644,
        freq: 1,
    },
    Symbol {
        start: 645,
        freq: 1,
    },
    Symbol {
        start: 646,
        freq: 1,
    },
    Symbol {
        start: 647,
        freq: 1,
    },
    Symbol {
        start: 648,
        freq: 1,
    },
    Symbol {
        start: 649,
        freq: 9,
    },
    Symbol {
        start: 658,
        freq: 40,
    },
    Symbol {
        start: 698,
        freq: 113,
    },
    Symbol {
        start: 811,
        freq: 213,
    },
];

pub const MODE3_HB_Z1: [Symbol; 17] = [
    Symbol { start: 0, freq: 1 },
    Symbol { start: 1, freq: 1 },
    Symbol { start: 2, freq: 1 },
    Symbol { start: 3, freq: 1 },
    Symbol { start: 4, freq: 8 },
    Symbol {
        start: 12,
        freq: 37,
    },
    Symbol {
        start: 49,
        freq: 112,
    },
    Symbol {
        start: 161,
        freq: 216,
    },
    Symbol {
        start: 377,
        freq: 269,
    },
    Symbol {
        start: 646,
        freq: 216,
    },
    Symbol {
        start: 862,
        freq: 112,
    },
    Symbol {
        start: 974,
        freq: 38,
    },
    Symbol {
        start: 1012,
        freq: 8,
    },
    Symbol {
        start: 1020,
        freq: 1,
    },
    Symbol {
        start: 1021,
        freq: 1,
    },
    Symbol {
        start: 1022,
        freq: 1,
    },
    Symbol {
        start: 1023,
        freq: 1,
    },
];

pub const MODE5_H: [Symbol; 33] = [
    Symbol {
        start: 0,
        freq: 122,
    },
    Symbol {
        start: 122,
        freq: 117,
    },
    Symbol {
        start: 239,
        freq: 102,
    },
    Symbol {
        start: 341,
        freq: 81,
    },
    Symbol {
        start: 422,
        freq: 59,
    },
    Symbol {
        start: 481,
        freq: 39,
    },
    Symbol {
        start: 520,
        freq: 23,
    },
    Symbol {
        start: 543,
        freq: 13,
    },
    Symbol {
        start: 556,
        freq: 6,
    },
    Symbol {
        start: 562,
        freq: 3,
    },
    Symbol {
        start: 565,
        freq: 1,
    },
    Symbol {
        start: 566,
        freq: 1,
    },
    Symbol {
        start: 567,
        freq: 1,
    },
    Symbol {
        start: 568,
        freq: 1,
    },
    Symbol {
        start: 569,
        freq: 1,
    },
    Symbol {
        start: 570,
        freq: 1,
    },
    Symbol {
        start: 571,
        freq: 1,
    },
    Symbol {
        start: 572,
        freq: 1,
    },
    Symbol {
        start: 573,
        freq: 1,
    },
    Symbol {
        start: 574,
        freq: 1,
    },
    Symbol {
        start: 575,
        freq: 1,
    },
    Symbol {
        start: 576,
        freq: 1,
    },
    Symbol {
        start: 577,
        freq: 1,
    },
    Symbol {
        start: 578,
        freq: 1,
    },
    Symbol {
        start: 579,
        freq: 3,
    },
    Symbol {
        start: 582,
        freq: 6,
    },
    Symbol {
        start: 588,
        freq: 13,
    },
    Symbol {
        start: 601,
        freq: 24,
    },
    Symbol {
        start: 625,
        freq: 39,
    },
    Symbol {
        start: 664,
        freq: 59,
    },
    Symbol {
        start: 723,
        freq: 81,
    },
    Symbol {
        start: 804,
        freq: 102,
    },
    Symbol {
        start: 906,
        freq: 118,
    },
];

pub const MODE5_HB_Z1: [Symbol; 19] = [
    Symbol { start: 0, freq: 1 },
    Symbol { start: 1, freq: 1 },
    Symbol { start: 2, freq: 1 },
    Symbol { start: 3, freq: 1 },
    Symbol { start: 4, freq: 2 },
    Symbol { start: 6, freq: 13 },
    Symbol {
        start: 19,
        freq: 48,
    },
    Symbol {
        start: 67,
        freq: 118,
    },
    Symbol {
        start: 185,
        freq: 204,
    },
    Symbol {
        start: 389,
        freq: 245,
    },
    Symbol {
        start: 634,
        freq: 204,
    },
    Symbol {
        start: 838,
        freq: 118,
    },
    Symbol {
        start: 956,
        freq: 48,
    },
    Symbol {
        start: 1004,
        freq: 14,
    },
    Symbol {
        start: 1018,
        freq: 2,
    },
    Symbol {
        start: 1020,
        freq: 1,
    },
    Symbol {
        start: 1021,
        freq: 1,
    },
    Symbol {
        start: 1022,
        freq: 1,
    },
    Symbol {
        start: 1023,
        freq: 1,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distributions_and_roundtrips() {
        let tables: &[&[Symbol]] = &[
            &MODE2_H,
            &MODE2_HB_Z1,
            &MODE3_H,
            &MODE3_HB_Z1,
            &MODE5_H,
            &MODE5_HB_Z1,
        ];

        for table in tables {
            let symbols: Vec<u16> = (0..1024).map(|i| (i % table.len()) as u16).collect();

            let encoded = encode(&symbols, table, 4096).unwrap();
            let decoded = decode(&encoded, table, symbols.len()).unwrap();

            assert_eq!(decoded, symbols);
        }
    }

    #[test]
    fn rejects_invalid_symbols() {
        let symbols = [MODE2_H.len() as u16];
        assert_eq!(
            encode(&symbols, &MODE2_H, 4096),
            Err(RansError::InvalidSymbol)
        );
    }
}

#[cfg(test)]
mod negative_decoder_tests {
    use super::*;

    #[test]
    fn truncated_rans_stream_is_rejected() {
        for length in 0..4 {
            let encoded = vec![0u8; length];

            assert_eq!(
                decode(&encoded, &MODE2_H, 256),
                Err(RansError::Truncated),
                "length={length}"
            );
        }
    }

    #[test]
    fn renormalization_exhaustion_is_rejected() {
        // The initial state is valid, but no renormalization
        // bytes are available for a long symbol sequence.
        let encoded = RANS_BYTE_L.to_le_bytes();

        assert_eq!(decode(&encoded, &MODE2_H, 256), Err(RansError::Truncated));
    }

    #[test]
    fn invalid_terminal_state_is_rejected() {
        // Zero decoded symbols leave the initial state intact.
        // A nonterminal initial state must be rejected.
        let encoded = (RANS_BYTE_L + 1).to_le_bytes();

        assert_eq!(decode(&encoded, &MODE2_H, 0), Err(RansError::InvalidState));
    }

    #[test]
    fn invalid_rans_initial_state_is_rejected() {
        for state in [0u32, RANS_BYTE_L - 1, RANS_BYTE_L << 8] {
            let encoded = state.to_le_bytes();

            assert_eq!(
                decode(&encoded, &MODE2_H, 256),
                Err(RansError::InvalidState),
                "state={state}"
            );
        }
    }
}
