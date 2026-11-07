#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "authenticated_fixtures.rs"]
mod authenticated_fixtures;

use authenticated_fixtures::FIXTURES;
use pqc_haetae::params::ParameterSet;
use pqc_haetae::signature_packing::unpack_signature;

fn parameter_set(mode: u8) -> ParameterSet {
    match mode {
        2 => ParameterSet::Haetae2,
        3 => ParameterSet::Haetae3,
        5 => ParameterSet::Haetae5,
        _ => unreachable!("authenticated fixture mode"),
    }
}

fn layout(mode: u8, signature: &[u8]) -> Option<[(usize, usize); 6]> {
    let (l, base_hb, base_h) = match mode {
        2 => (4, 132, 7),
        3 => (6, 376, 127),
        5 => (7, 501, 358),
        _ => return None,
    };

    let challenge_end = 32;
    let lowbits_end = challenge_end + l * 256;

    let hb_length = base_hb + usize::from(*signature.get(lowbits_end)?);
    let h_length = base_h + usize::from(*signature.get(lowbits_end + 1)?);

    let hb_start = lowbits_end + 2;
    let hb_end = hb_start.checked_add(hb_length)?;
    let h_end = hb_end.checked_add(h_length)?;

    if h_end > signature.len() {
        return None;
    }

    Some([
        (0, challenge_end),
        (challenge_end, lowbits_end),
        (lowbits_end, hb_start),
        (hb_start, hb_end),
        (hb_end, h_end),
        (h_end, signature.len()),
    ])
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let fixture = &FIXTURES[usize::from(data[0]) % FIXTURES.len()];
    let mode = parameter_set(fixture.mode);

    let mut signature = fixture.signature.to_vec();

    let Some(regions) = layout(fixture.mode, &signature) else {
        return;
    };

    let region_index = usize::from(data[1]) % regions.len();
    let (start, end) = regions[region_index];

    if start == end {
        return;
    }

    let offset = u16::from_le_bytes([data[2], data[3]]) as usize;
    let position = start + offset % (end - start);

    // Apply one or more mutations while preserving total length.
    for (i, &value) in data[4..].iter().enumerate() {
        let position = start + (position - start + i) % (end - start);
        signature[position] ^= value;
    }

    let _ = unpack_signature(mode, &signature);
});
