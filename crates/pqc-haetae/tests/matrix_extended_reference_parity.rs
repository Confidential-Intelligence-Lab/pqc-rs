use pqc_haetae::params::{ParameterSet, N};
use pqc_haetae::poly::Poly;
use pqc_haetae::polymat::{expand_mat_a, pointwise_montgomery};
use pqc_haetae::polyvec::PolyVecM;
use std::path::Path;

fn parse_section(lines: &[&str], begin: &str, end: &str) -> Vec<i32> {
    let start = lines
        .iter()
        .position(|line| *line == begin)
        .expect("missing section start");

    let finish = lines
        .iter()
        .position(|line| *line == end)
        .expect("missing section end");

    assert!(start < finish);

    lines[start + 1..finish]
        .iter()
        .map(|value| value.parse::<i32>().expect("invalid coefficient"))
        .collect()
}

fn vector_coefficient(pattern: usize, column: usize, i: usize) -> i32 {
    match pattern {
        0 => 0,
        1 => 1,
        2 => i32::from(i == (column * 17) % N),
        3 => {
            if (i + column) & 1 == 0 {
                1
            } else {
                -1
            }
        }
        4 => ((i * 17 + column * 29 + 7) % 7) as i32 - 3,
        _ => panic!("invalid vector pattern"),
    }
}

fn compare<const K: usize, const M: usize>(
    mode: ParameterSet,
    fixture: &Path,
    reference_mode: usize,
) -> usize {
    let content = std::fs::read_to_string(fixture).expect("cannot read authenticated C fixture");

    let lines: Vec<&str> = content.lines().collect();

    assert_eq!(lines[0], format!("MODE {reference_mode}"));
    assert_eq!(lines[1], format!("K {K}"));
    assert_eq!(lines[2], format!("M {M}"));
    assert_eq!(lines[3], format!("N {N}"));

    let seed = std::array::from_fn(|i| i as u8);
    let matrix = expand_mat_a::<K, M>(&seed, mode);

    let expected_matrix = parse_section(&lines, "MATRIX_BEGIN", "MATRIX_END");

    assert_eq!(expected_matrix.len(), K * M * N);

    let mut comparisons = 0;

    for (row, matrix_row) in matrix.iter().enumerate() {
        for (column, polynomial) in matrix_row.as_slice().iter().enumerate() {
            for (coefficient, actual) in polynomial.coeffs.iter().enumerate() {
                let index = (row * M + column) * N + coefficient;

                assert_eq!(
                    *actual, expected_matrix[index],
                    "matrix mismatch mode={reference_mode} \
                     row={row} column={column} coefficient={coefficient}"
                );

                comparisons += 1;
            }
        }
    }

    for pattern in 0..5 {
        let vector = PolyVecM::<M>::new(std::array::from_fn(|column| {
            Poly::new(std::array::from_fn(|i| {
                vector_coefficient(pattern, column, i)
            }))
        }));

        let result = pointwise_montgomery(&matrix, &vector, mode);

        let begin = format!("PRODUCT_{pattern}_BEGIN");
        let end = format!("PRODUCT_{pattern}_END");

        let expected = parse_section(&lines, &begin, &end);

        assert_eq!(expected.len(), K * N);

        for (row, polynomial) in result.as_slice().iter().enumerate() {
            for (coefficient, actual) in polynomial.coeffs.iter().enumerate() {
                let index = row * N + coefficient;

                assert_eq!(
                    *actual, expected[index],
                    "product mismatch mode={reference_mode} \
                     pattern={pattern} row={row} coefficient={coefficient}"
                );

                comparisons += 1;
            }
        }

        println!(
            "HAETAE_REFERENCE_MODE={reference_mode} \
             PATTERN={pattern} PRODUCT_COMPARISONS={} STATUS=PASS",
            K * N
        );
    }

    let expected_total = K * M * N + 5 * K * N;
    assert_eq!(comparisons, expected_total);

    println!(
        "HAETAE_REFERENCE_MODE={reference_mode} \
         EXACT_COMPARISONS={comparisons} STATUS=PASS"
    );

    comparisons
}

#[test]
fn authenticated_extended_matrix_reference_parity() {
    let Ok(directory) = std::env::var("HAETAE_MATRIX_PARITY_DIR") else {
        eprintln!(
            "External fixtures unavailable; \
             set HAETAE_MATRIX_PARITY_DIR to enable differential testing"
        );
        return;
    };

    let root = Path::new(&directory);

    let mode2 = compare::<2, 3>(
        ParameterSet::Haetae2,
        &root.join("matrix_mode2_extended.txt"),
        0,
    );

    let mode3 = compare::<3, 5>(
        ParameterSet::Haetae3,
        &root.join("matrix_mode3_extended.txt"),
        1,
    );

    let mode5 = compare::<4, 6>(
        ParameterSet::Haetae5,
        &root.join("matrix_mode5_extended.txt"),
        2,
    );

    let total = mode2 + mode3 + mode5;

    assert_eq!(total, 23_040);

    println!(
        "HAETAE_EXTENDED_MATRIX_DIFFERENTIAL=PASS \
         TOTAL_EXACT_COMPARISONS={total}"
    );
}
