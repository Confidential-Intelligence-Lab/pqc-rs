#![cfg(feature = "internal-api")]
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

    let matrix_expected = parse_section(&lines, "MATRIX_BEGIN", "MATRIX_END");

    let product_expected = parse_section(&lines, "PRODUCT_BEGIN", "PRODUCT_END");

    assert_eq!(matrix_expected.len(), K * M * N);
    assert_eq!(product_expected.len(), K * N);

    let seed = std::array::from_fn(|i| i as u8);

    let matrix = expand_mat_a::<K, M>(&seed, mode);

    let mut comparisons = 0;

    for (row, matrix_row) in matrix.iter().enumerate() {
        for (column, polynomial) in matrix_row.as_slice().iter().enumerate() {
            for (coefficient, actual) in polynomial.coeffs.iter().enumerate() {
                let index = (row * M + column) * N + coefficient;

                assert_eq!(
                    *actual, matrix_expected[index],
                    "matrix mismatch mode={reference_mode} row={row} \
                     column={column} coefficient={coefficient}"
                );

                comparisons += 1;
            }
        }
    }

    let vector = PolyVecM::<M>::new(std::array::from_fn(|_| Poly::new([1; N])));

    let result = pointwise_montgomery(&matrix, &vector, mode);

    for (row, polynomial) in result.as_slice().iter().enumerate() {
        for (coefficient, actual) in polynomial.coeffs.iter().enumerate() {
            let index = row * N + coefficient;

            assert_eq!(
                *actual, product_expected[index],
                "product mismatch mode={reference_mode} row={row} \
                 coefficient={coefficient}"
            );

            comparisons += 1;
        }
    }

    println!(
        "HAETAE_REFERENCE_MODE={reference_mode} \
         EXACT_COMPARISONS={comparisons} STATUS=PASS"
    );

    comparisons
}

#[test]
fn authenticated_matrix_reference_parity() {
    let Ok(directory) = std::env::var("HAETAE_MATRIX_PARITY_DIR") else {
        eprintln!(
            "External C fixtures unavailable; \
             set HAETAE_MATRIX_PARITY_DIR to enable differential testing"
        );
        return;
    };

    let root = Path::new(&directory);

    let mode2 = compare::<2, 3>(ParameterSet::Haetae2, &root.join("matrix_mode2.txt"), 0);

    let mode3 = compare::<3, 5>(ParameterSet::Haetae3, &root.join("matrix_mode3.txt"), 1);

    let mode5 = compare::<4, 6>(ParameterSet::Haetae5, &root.join("matrix_mode5.txt"), 2);

    let total = mode2 + mode3 + mode5;

    assert_eq!(total, 13_824);

    println!(
        "HAETAE_MATRIX_DIFFERENTIAL=PASS \
         TOTAL_EXACT_COMPARISONS={total}"
    );
}
