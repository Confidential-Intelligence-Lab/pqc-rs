#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "authenticated_fixtures.rs"]
mod authenticated_fixtures;

use authenticated_fixtures::FIXTURES;
use pqc_haetae::params::ParameterSet;
use pqc_haetae::verification::verify_preformatted;

fn parameter_set(mode: u8) -> ParameterSet {
    match mode {
        2 => ParameterSet::Haetae2,
        3 => ParameterSet::Haetae3,
        5 => ParameterSet::Haetae5,
        _ => unreachable!("authenticated fixture mode"),
    }
}

fuzz_target!(|data: &[u8]| {
    // Header:
    // fixture selector: u8
    // replacement flags: u8
    // public-key length: u16 LE
    // prefix length: u16 LE
    // message length: u16 LE
    //
    // Payload:
    // public-key replacement || prefix replacement ||
    // message replacement || signature replacement

    if data.len() < 8 {
        return;
    }

    let fixture = &FIXTURES[usize::from(data[0]) % FIXTURES.len()];
    let mode = parameter_set(fixture.mode);
    let flags = data[1];

    let pk_len = usize::from(u16::from_le_bytes([data[2], data[3]]));
    let pre_len = usize::from(u16::from_le_bytes([data[4], data[5]]));
    let msg_len = usize::from(u16::from_le_bytes([data[6], data[7]]));

    let mut offset = 8_usize;

    let take = |offset: &mut usize, length: usize| {
        let end = offset.checked_add(length)?;
        let slice = data.get(*offset..end)?;
        *offset = end;
        Some(slice)
    };

    let Some(pk_mutation) = take(&mut offset, pk_len) else {
        return;
    };
    let Some(pre_mutation) = take(&mut offset, pre_len) else {
        return;
    };
    let Some(msg_mutation) = take(&mut offset, msg_len) else {
        return;
    };

    let signature_mutation = &data[offset..];

    let pk = if flags & 1 != 0 {
        pk_mutation
    } else {
        fixture.public_key
    };

    let pre = if flags & 2 != 0 {
        pre_mutation
    } else {
        fixture.pre
    };

    let message = if flags & 4 != 0 {
        msg_mutation
    } else {
        fixture.message
    };

    let signature = if flags & 8 != 0 {
        signature_mutation
    } else {
        fixture.signature
    };

    let _ = verify_preformatted(mode, pk, pre, message, signature);
});
