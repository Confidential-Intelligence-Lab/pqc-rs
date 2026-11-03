#![cfg(feature = "internal-api")]
// H1.0-D.6i.4: authenticated HAETAE 1.2.0 C-reference fixtures
use pqc_haetae::ntt::inverse_to_mont;

fn parse_vector(text: &str) -> [i32; 256] {
    let values: Vec<i32> = text
        .split_whitespace()
        .map(|value| value.parse::<i32>().expect("invalid fixture coefficient"))
        .collect();

    values
        .try_into()
        .expect("fixture must contain 256 coefficients")
}

#[test]
fn authenticated_reference_extended_inverse_ntt() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "mode2_positive",
            include_str!("fixtures/ntt_extended/mode2_positive.in"),
            include_str!("fixtures/ntt_extended/mode2_positive.out"),
        ),
        (
            "mode2_negative",
            include_str!("fixtures/ntt_extended/mode2_negative.in"),
            include_str!("fixtures/ntt_extended/mode2_negative.out"),
        ),
        (
            "mode2_alternating",
            include_str!("fixtures/ntt_extended/mode2_alternating.in"),
            include_str!("fixtures/ntt_extended/mode2_alternating.out"),
        ),
        (
            "mode2_ascending",
            include_str!("fixtures/ntt_extended/mode2_ascending.in"),
            include_str!("fixtures/ntt_extended/mode2_ascending.out"),
        ),
        (
            "mode2_impulse_0",
            include_str!("fixtures/ntt_extended/mode2_impulse_0.in"),
            include_str!("fixtures/ntt_extended/mode2_impulse_0.out"),
        ),
        (
            "mode2_impulse_127",
            include_str!("fixtures/ntt_extended/mode2_impulse_127.in"),
            include_str!("fixtures/ntt_extended/mode2_impulse_127.out"),
        ),
        (
            "mode2_impulse_255",
            include_str!("fixtures/ntt_extended/mode2_impulse_255.in"),
            include_str!("fixtures/ntt_extended/mode2_impulse_255.out"),
        ),
        (
            "mode3_positive",
            include_str!("fixtures/ntt_extended/mode3_positive.in"),
            include_str!("fixtures/ntt_extended/mode3_positive.out"),
        ),
        (
            "mode3_negative",
            include_str!("fixtures/ntt_extended/mode3_negative.in"),
            include_str!("fixtures/ntt_extended/mode3_negative.out"),
        ),
        (
            "mode3_alternating",
            include_str!("fixtures/ntt_extended/mode3_alternating.in"),
            include_str!("fixtures/ntt_extended/mode3_alternating.out"),
        ),
        (
            "mode3_ascending",
            include_str!("fixtures/ntt_extended/mode3_ascending.in"),
            include_str!("fixtures/ntt_extended/mode3_ascending.out"),
        ),
        (
            "mode3_impulse_0",
            include_str!("fixtures/ntt_extended/mode3_impulse_0.in"),
            include_str!("fixtures/ntt_extended/mode3_impulse_0.out"),
        ),
        (
            "mode3_impulse_127",
            include_str!("fixtures/ntt_extended/mode3_impulse_127.in"),
            include_str!("fixtures/ntt_extended/mode3_impulse_127.out"),
        ),
        (
            "mode3_impulse_255",
            include_str!("fixtures/ntt_extended/mode3_impulse_255.in"),
            include_str!("fixtures/ntt_extended/mode3_impulse_255.out"),
        ),
        (
            "mode5_positive",
            include_str!("fixtures/ntt_extended/mode5_positive.in"),
            include_str!("fixtures/ntt_extended/mode5_positive.out"),
        ),
        (
            "mode5_negative",
            include_str!("fixtures/ntt_extended/mode5_negative.in"),
            include_str!("fixtures/ntt_extended/mode5_negative.out"),
        ),
        (
            "mode5_alternating",
            include_str!("fixtures/ntt_extended/mode5_alternating.in"),
            include_str!("fixtures/ntt_extended/mode5_alternating.out"),
        ),
        (
            "mode5_ascending",
            include_str!("fixtures/ntt_extended/mode5_ascending.in"),
            include_str!("fixtures/ntt_extended/mode5_ascending.out"),
        ),
        (
            "mode5_impulse_0",
            include_str!("fixtures/ntt_extended/mode5_impulse_0.in"),
            include_str!("fixtures/ntt_extended/mode5_impulse_0.out"),
        ),
        (
            "mode5_impulse_127",
            include_str!("fixtures/ntt_extended/mode5_impulse_127.in"),
            include_str!("fixtures/ntt_extended/mode5_impulse_127.out"),
        ),
        (
            "mode5_impulse_255",
            include_str!("fixtures/ntt_extended/mode5_impulse_255.in"),
            include_str!("fixtures/ntt_extended/mode5_impulse_255.out"),
        ),
    ];

    for &(name, input, expected) in cases {
        let mut actual = parse_vector(input);
        let expected = parse_vector(expected);

        assert!(
            actual.iter().all(|&x| i64::from(x).abs() < 64_513),
            "reference input-domain violation: {name}"
        );
        assert!(
            actual.iter().any(|&x| x % 64_513 != 0),
            "degenerate reference input: {name}"
        );

        inverse_to_mont(&mut actual);

        assert_eq!(actual, expected, "reference mismatch: {name}");
    }
}
