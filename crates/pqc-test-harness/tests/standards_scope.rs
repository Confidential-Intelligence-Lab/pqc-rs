use pqc_test_harness::standards_scope::{
    target, EvidenceClass, FIPS_203, HPKE_PQ_DRAFT_05, RFC_9180, RFC_9958,
};

#[test]
fn repository_claim_boundaries_are_explicit() {
    assert_eq!(
        target("fips-203").unwrap().evidence,
        EvidenceClass::VectorValidated
    );
    assert_eq!(
        target("rfc-9958").unwrap().evidence,
        EvidenceClass::GuidanceTraced
    );
    assert_eq!(target("rfc-9180").unwrap().evidence, EvidenceClass::Pending);
    assert_eq!(
        target("draft-ietf-hpke-pq-05").unwrap().evidence,
        EvidenceClass::DraftPinned
    );
}

#[test]
fn no_tracked_target_claims_complete_conformance() {
    for target in [FIPS_203, RFC_9958, RFC_9180, HPKE_PQ_DRAFT_05] {
        assert!(!target.complete_conformance_claim);
    }
}
