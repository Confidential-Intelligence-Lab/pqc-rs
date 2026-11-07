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
    if data.is_empty() {
        return;
    }

    let fixture = &FIXTURES[usize::from(data[0]) % FIXTURES.len()];
    let mode = parameter_set(fixture.mode);

    // A one-byte selector followed by the candidate signature.
    // Empty payloads and arbitrary lengths are intentional.
    let candidate = &data[1..];

    let _ = verify_preformatted(
        mode,
        fixture.public_key,
        fixture.pre,
        fixture.message,
        candidate,
    );
});
