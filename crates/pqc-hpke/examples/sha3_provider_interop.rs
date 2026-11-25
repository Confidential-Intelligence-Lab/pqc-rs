#[cfg(not(feature = "experimental-hkdf-sha3"))]
fn main() {
    eprintln!("Requires experimental-hkdf-sha3");
    std::process::exit(2);
}

#[cfg(feature = "experimental-hkdf-sha3")]
mod interop {
    use std::io::{self, BufRead};

    use pqc_hpke::hybrid_kem::HybridKem;
    use pqc_hpke::hybrid_setup::{setup_hybrid_base_receiver, setup_hybrid_base_sender};
    use pqc_hpke::setup::{setup_base_receiver, setup_base_sender_with_suite};
    use pqc_hpke::{
        AeadId, HpkeSuite, HpkeSuiteId, KdfId, MlKemHpke, ReceiverContext, SenderContext,
    };
    use rand_core::OsRng;

    const INFO: &[u8] = b"pqc-rs/independent-provider/hpke/v1";

    const AAD: &[u8] = b"independent-provider-aad";

    const MSG1: &[u8] = &[0x21, 0x43, 0x65, 0x87, 0x09];

    const MSG2: &[u8] = b"second authenticated message";

    const EXPORT_CONTEXT: &[u8] = b"independent-provider-export";

    fn decode(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn kdf(s: &str) -> KdfId {
        match s {
            "sha2" => KdfId::HKDF_SHA256,
            "sha3" => KdfId::EXPERIMENTAL_HKDF_SHA3_256,
            _ => panic!("invalid KDF"),
        }
    }

    fn other_kdf(id: KdfId) -> KdfId {
        if id == KdfId::HKDF_SHA256 {
            KdfId::EXPERIMENTAL_HKDF_SHA3_256
        } else {
            KdfId::HKDF_SHA256
        }
    }

    fn keys(kind: &str, ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match kind {
            "pure" => {
                let pair = MlKemHpke::MlKem768.derive_key_pair(ikm).unwrap();

                (pair.private_key_seed.as_bytes().to_vec(), pair.public_key)
            }
            "hybrid" => {
                let pair = HybridKem::MlKem768X25519.derive_key_pair(ikm).unwrap();

                (pair.private_seed.as_bytes().to_vec(), pair.public_key)
            }
            _ => panic!("invalid KEM"),
        }
    }

    fn sender(kind: &str, id: KdfId, pk: &[u8]) -> (Vec<u8>, SenderContext) {
        match kind {
            "pure" => {
                let kem = MlKemHpke::MlKem768;

                let suite = HpkeSuite::new(kem, id, AeadId::AES_256_GCM).unwrap();

                let result =
                    setup_base_sender_with_suite(kem, suite, pk, INFO, &mut OsRng).unwrap();

                (result.encapsulated_key, result.context)
            }
            "hybrid" => {
                let kem = HybridKem::MlKem768X25519;

                let suite = HpkeSuiteId {
                    kem_id: kem.kem_id(),
                    kdf_id: id,
                    aead_id: AeadId::AES_256_GCM,
                };

                let result = setup_hybrid_base_sender(kem, suite, pk, INFO, &mut OsRng).unwrap();

                (result.encapsulated_key, result.context)
            }
            _ => panic!("invalid KEM"),
        }
    }

    fn receiver(kind: &str, id: KdfId, seed: &[u8], enc: &[u8]) -> ReceiverContext {
        match kind {
            "pure" => {
                let kem = MlKemHpke::MlKem768;

                setup_base_receiver(
                    kem,
                    HpkeSuiteId {
                        kem_id: kem.kem_id(),
                        kdf_id: id,
                        aead_id: AeadId::AES_256_GCM,
                    },
                    seed,
                    enc,
                    INFO,
                )
                .unwrap()
            }
            "hybrid" => {
                let kem = HybridKem::MlKem768X25519;

                setup_hybrid_base_receiver(
                    kem,
                    HpkeSuiteId {
                        kem_id: kem.kem_id(),
                        kdf_id: id,
                        aead_id: AeadId::AES_256_GCM,
                    },
                    seed,
                    enc,
                    INFO,
                )
                .unwrap()
            }
            _ => panic!("invalid KEM"),
        }
    }

    pub fn run() {
        let stdin = io::stdin();

        for line in stdin.lock().lines() {
            let line = line.unwrap();

            let fields: Vec<&str> = line.split_ascii_whitespace().collect();

            match fields[0] {
                "keys" => {
                    assert_eq!(fields.len(), 3);

                    let (seed, pk) = keys(fields[1], &decode(fields[2]));

                    println!("{} {}", hex::encode(seed), hex::encode(pk));
                }

                "send" => {
                    assert_eq!(fields.len(), 4);

                    let (enc, mut ctx) = sender(fields[1], kdf(fields[2]), &decode(fields[3]));

                    let exported = ctx.export(EXPORT_CONTEXT, 64).unwrap();

                    let ct1 = ctx.seal(AAD, MSG1).unwrap();
                    let ct2 = ctx.seal(AAD, MSG2).unwrap();

                    assert_eq!(ctx.sequence_number(), 2);

                    println!(
                        "{} {} {} {}",
                        hex::encode(enc),
                        hex::encode(ct1),
                        hex::encode(ct2),
                        hex::encode(exported)
                    );
                }

                "receive" => {
                    assert_eq!(fields.len(), 7);

                    let kind = fields[1];
                    let id = kdf(fields[2]);

                    let seed = decode(fields[3]);
                    let enc = decode(fields[4]);
                    let ct1 = decode(fields[5]);
                    let ct2 = decode(fields[6]);

                    let mut ctx = receiver(kind, id, &seed, &enc);

                    let mut wrong = receiver(kind, other_kdf(id), &seed, &enc);

                    assert!(wrong.open(AAD, &ct1).is_err());
                    assert_eq!(wrong.sequence_number(), 0);

                    assert!(ctx.open(b"wrong aad", &ct1).is_err());

                    let mut tampered = ct1.clone();
                    tampered[0] ^= 1;

                    assert!(ctx.open(AAD, &tampered).is_err());
                    assert_eq!(ctx.sequence_number(), 0);

                    assert_eq!(ctx.open(AAD, &ct1).unwrap(), MSG1);

                    assert_eq!(ctx.open(AAD, &ct2).unwrap(), MSG2);

                    assert_eq!(ctx.sequence_number(), 2);

                    println!(
                        "PASS {}",
                        hex::encode(ctx.export(EXPORT_CONTEXT, 64).unwrap())
                    );
                }

                _ => panic!("invalid operation"),
            }
        }
    }
}

#[cfg(feature = "experimental-hkdf-sha3")]
fn main() {
    interop::run();
}
