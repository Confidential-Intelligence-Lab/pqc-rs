use pqc_slh_dsa::{SlhDsaHashFamily, SlhDsaParameterSet};
use serde::Serialize;

const PARAMETER_SETS: [SlhDsaParameterSet; 12] = [
    SlhDsaParameterSet::Sha2_128s,
    SlhDsaParameterSet::Sha2_128f,
    SlhDsaParameterSet::Sha2_192s,
    SlhDsaParameterSet::Sha2_192f,
    SlhDsaParameterSet::Sha2_256s,
    SlhDsaParameterSet::Sha2_256f,
    SlhDsaParameterSet::Shake128s,
    SlhDsaParameterSet::Shake128f,
    SlhDsaParameterSet::Shake192s,
    SlhDsaParameterSet::Shake192f,
    SlhDsaParameterSet::Shake256s,
    SlhDsaParameterSet::Shake256f,
];

#[derive(Serialize)]
struct MemoryBaseline<'a> {
    parameter_set: &'a str,
    hash_family: &'a str,
    n: usize,
    h: usize,
    d: usize,
    hp: usize,
    a: usize,
    k: usize,
    m: usize,
    keygen_seed_bytes: usize,
    public_key_bytes: usize,
    private_key_bytes: usize,
    signature_bytes: usize,
    fors_tree_height: usize,
    fors_max_active_node_calls: usize,
    xmss_tree_height: usize,
    xmss_max_active_node_calls: usize,
}

fn main() {
    for parameter_set in PARAMETER_SETS {
        let parameters = parameter_set.parameters();

        assert_eq!(
            parameters.h,
            parameters.d * parameters.hp,
            "inconsistent hypertree geometry for {}",
            parameter_set.name()
        );

        let hash_family = match parameters.hash_family {
            SlhDsaHashFamily::Sha2 => "SHA2",
            SlhDsaHashFamily::Shake => "SHAKE",
        };

        let record = MemoryBaseline {
            parameter_set: parameter_set.name(),
            hash_family,
            n: parameters.n,
            h: parameters.h,
            d: parameters.d,
            hp: parameters.hp,
            a: parameters.a,
            k: parameters.k,
            m: parameters.m,
            keygen_seed_bytes: parameters.keygen_seed_bytes,
            public_key_bytes: parameters.public_key_bytes,
            private_key_bytes: parameters.private_key_bytes,
            signature_bytes: parameters.signature_bytes,
            fors_tree_height: parameters.a,
            fors_max_active_node_calls: parameters.a + 1,
            xmss_tree_height: parameters.hp,
            xmss_max_active_node_calls: parameters.hp + 1,
        };

        println!(
            "{}",
            serde_json::to_string(&record).expect("memory baseline must serialize")
        );
    }
}
