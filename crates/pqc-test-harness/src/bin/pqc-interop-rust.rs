use pqc_ml_dsa::{
    keygen::keygen_internal as dsa_keygen, signature::sign_internal as dsa_sign,
    verification::verify_internal as dsa_verify, MlDsaParameterSet,
};
use pqc_ml_kem::{
    ml_kem_decaps::decaps_internal,
    ml_kem_encaps::encaps_internal,
    ml_kem_keygen::{
        ml_kem_1024_keygen_internal, ml_kem_512_keygen_internal, ml_kem_768_keygen_internal,
    },
    MlKemParameterSet,
};
use pqc_slh_dsa::{
    SlhDsa, SlhDsaKeyGenSeed, SlhDsaParameterSet, SlhDsaPreHash, SlhDsaPrivateKey, SlhDsaPublicKey,
    SlhDsaSignature,
};
use serde_json::{json, Value};
use std::io::{self, Read};

fn hex_field(v: &Value, name: &str) -> Result<Vec<u8>, String> {
    let s = v
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {name}"))?;
    hex::decode(s).map_err(|e| format!("invalid {name}: {e}"))
}
fn array32(bytes: Vec<u8>, name: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("{name} must be 32 bytes, got {}", v.len()))
}
fn kem_param(name: &str) -> Result<MlKemParameterSet, String> {
    match name {
        "ML-KEM-512" => Ok(MlKemParameterSet::MlKem512),
        "ML-KEM-768" => Ok(MlKemParameterSet::MlKem768),
        "ML-KEM-1024" => Ok(MlKemParameterSet::MlKem1024),
        _ => Err(format!("unsupported parameter set {name}")),
    }
}
fn dsa_param(name: &str) -> Result<MlDsaParameterSet, String> {
    match name {
        "ML-DSA-44" => Ok(MlDsaParameterSet::MlDsa44),
        "ML-DSA-65" => Ok(MlDsaParameterSet::MlDsa65),
        "ML-DSA-87" => Ok(MlDsaParameterSet::MlDsa87),
        _ => Err(format!("unsupported parameter set {name}")),
    }
}
fn slh_param(name: &str) -> Result<SlhDsaParameterSet, String> {
    match name {
        "SLH-DSA-SHA2-128s" => Ok(SlhDsaParameterSet::Sha2_128s),
        "SLH-DSA-SHA2-128f" => Ok(SlhDsaParameterSet::Sha2_128f),
        "SLH-DSA-SHA2-192s" => Ok(SlhDsaParameterSet::Sha2_192s),
        "SLH-DSA-SHA2-192f" => Ok(SlhDsaParameterSet::Sha2_192f),
        "SLH-DSA-SHA2-256s" => Ok(SlhDsaParameterSet::Sha2_256s),
        "SLH-DSA-SHA2-256f" => Ok(SlhDsaParameterSet::Sha2_256f),
        "SLH-DSA-SHAKE-128s" => Ok(SlhDsaParameterSet::Shake128s),
        "SLH-DSA-SHAKE-128f" => Ok(SlhDsaParameterSet::Shake128f),
        "SLH-DSA-SHAKE-192s" => Ok(SlhDsaParameterSet::Shake192s),
        "SLH-DSA-SHAKE-192f" => Ok(SlhDsaParameterSet::Shake192f),
        "SLH-DSA-SHAKE-256s" => Ok(SlhDsaParameterSet::Shake256s),
        "SLH-DSA-SHAKE-256f" => Ok(SlhDsaParameterSet::Shake256f),
        _ => Err(format!("unsupported parameter set {name}")),
    }
}

fn slh_prehash(name: &str) -> Result<SlhDsaPreHash, String> {
    match name {
        "SHA2-224" => Ok(SlhDsaPreHash::Sha2_224),
        "SHA2-256" => Ok(SlhDsaPreHash::Sha2_256),
        "SHA2-384" => Ok(SlhDsaPreHash::Sha2_384),
        "SHA2-512" => Ok(SlhDsaPreHash::Sha2_512),
        "SHA2-512/224" => Ok(SlhDsaPreHash::Sha2_512_224),
        "SHA2-512/256" => Ok(SlhDsaPreHash::Sha2_512_256),
        "SHA3-224" => Ok(SlhDsaPreHash::Sha3_224),
        "SHA3-256" => Ok(SlhDsaPreHash::Sha3_256),
        "SHA3-384" => Ok(SlhDsaPreHash::Sha3_384),
        "SHA3-512" => Ok(SlhDsaPreHash::Sha3_512),
        "SHAKE-128" => Ok(SlhDsaPreHash::Shake128),
        "SHAKE-256" => Ok(SlhDsaPreHash::Shake256),
        _ => Err(format!("unsupported SLH-DSA prehash {name}")),
    }
}

fn capabilities() -> Value {
    json!([
        {
            "algorithm": "ML-KEM",
            "parameter_sets": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
            "operations": ["kem-keygen", "kem-encaps", "kem-decaps"]
        },
        {
            "algorithm": "ML-DSA",
            "parameter_sets": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
            "operations": ["dsa-keygen", "dsa-sign", "dsa-verify"]
        },
        {
            "algorithm": "SLH-DSA",
            "parameter_sets": [
                "SLH-DSA-SHA2-128s",
                "SLH-DSA-SHA2-128f",
                "SLH-DSA-SHA2-192s",
                "SLH-DSA-SHA2-192f",
                "SLH-DSA-SHA2-256s",
                "SLH-DSA-SHA2-256f",
                "SLH-DSA-SHAKE-128s",
                "SLH-DSA-SHAKE-128f",
                "SLH-DSA-SHAKE-192s",
                "SLH-DSA-SHAKE-192f",
                "SLH-DSA-SHAKE-256s",
                "SLH-DSA-SHAKE-256f"
            ],
            "operations": ["slh-keygen", "slh-sign", "slh-verify", "slh-hash-sign", "slh-hash-verify"]
        }
    ])
}

fn execute(req: &Value) -> Result<Value, String> {
    let op = req
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("missing operation")?;
    let ps = req
        .get("parameter_set")
        .and_then(Value::as_str)
        .ok_or("missing parameter_set")?;
    let null_inputs = Value::Null;
    let inputs = req.get("inputs").unwrap_or(&null_inputs);
    match op {
        "kem-keygen" => {
            let d = array32(hex_field(inputs, "d")?, "d")?;
            let z = array32(hex_field(inputs, "z")?, "z")?;
            let (pk, sk) = match kem_param(ps)? {
                MlKemParameterSet::MlKem512 => {
                    let o = ml_kem_512_keygen_internal(&d, &z).map_err(|e| format!("{e:?}"))?;
                    (o.encapsulation_key.to_vec(), o.decapsulation_key.to_vec())
                }
                MlKemParameterSet::MlKem768 => {
                    let o = ml_kem_768_keygen_internal(&d, &z).map_err(|e| format!("{e:?}"))?;
                    (o.encapsulation_key.to_vec(), o.decapsulation_key.to_vec())
                }
                MlKemParameterSet::MlKem1024 => {
                    let o = ml_kem_1024_keygen_internal(&d, &z).map_err(|e| format!("{e:?}"))?;
                    (o.encapsulation_key.to_vec(), o.decapsulation_key.to_vec())
                }
            };
            Ok(json!({"public_key":hex::encode(pk),"secret_key":hex::encode(sk)}))
        }
        "kem-encaps" => {
            let pk = hex_field(inputs, "public_key")?;
            let m = array32(hex_field(inputs, "m")?, "m")?;
            let o = encaps_internal(kem_param(ps)?, &pk, &m).map_err(|e| format!("{e:?}"))?;
            Ok(
                json!({"ciphertext":hex::encode(o.ciphertext),"shared_secret":hex::encode(o.shared_secret.as_bytes())}),
            )
        }
        "kem-decaps" => {
            let sk = hex_field(inputs, "secret_key")?;
            let ct = hex_field(inputs, "ciphertext")?;
            let o = decaps_internal(kem_param(ps)?, &sk, &ct).map_err(|e| format!("{e:?}"))?;
            Ok(json!({"shared_secret":hex::encode(o.shared_secret.as_bytes())}))
        }
        "dsa-keygen" => {
            let xi = array32(hex_field(inputs, "xi")?, "xi")?;
            let o = dsa_keygen(dsa_param(ps)?, &xi).map_err(|e| format!("{e:?}"))?;
            Ok(
                json!({"public_key":hex::encode(o.public_key()),"secret_key":hex::encode(o.private_key())}),
            )
        }
        "dsa-sign" => {
            let sk = hex_field(inputs, "secret_key")?;
            let msg = hex_field(inputs, "message")?;
            let ctx = hex_field(inputs, "context")?;
            let rnd = array32(hex_field(inputs, "randomness")?, "randomness")?;
            let sig =
                dsa_sign(dsa_param(ps)?, &sk, &msg, &ctx, &rnd).map_err(|e| format!("{e:?}"))?;
            Ok(json!({"signature":hex::encode(sig)}))
        }
        "dsa-verify" => {
            let pk = hex_field(inputs, "public_key")?;
            let msg = hex_field(inputs, "message")?;
            let ctx = hex_field(inputs, "context")?;
            let sig = hex_field(inputs, "signature")?;
            let valid =
                dsa_verify(dsa_param(ps)?, &pk, &msg, &ctx, &sig).map_err(|e| format!("{e:?}"))?;
            Ok(json!({"valid":valid}))
        }
        "slh-keygen" => {
            let parameter_set = slh_param(ps)?;
            let implementation = SlhDsa::new(parameter_set);
            let seed_bytes = hex_field(inputs, "seed")?;
            let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes)
                .map_err(|e| format!("{e:?}"))?;
            let key_pair = implementation
                .keygen_from_seed(&seed)
                .map_err(|e| format!("{e:?}"))?;

            Ok(json!({
                "public_key": hex::encode(key_pair.public_key().as_bytes()),
                "secret_key": hex::encode(key_pair.private_key().as_bytes())
            }))
        }
        "slh-sign" => {
            let parameter_set = slh_param(ps)?;
            let implementation = SlhDsa::new(parameter_set);
            let secret_key_bytes = hex_field(inputs, "secret_key")?;
            let message = hex_field(inputs, "message")?;
            let context = hex_field(inputs, "context")?;

            let secret_key = SlhDsaPrivateKey::from_bytes(parameter_set, &secret_key_bytes)
                .map_err(|e| format!("{e:?}"))?;

            let signature = implementation
                .sign_deterministic(&secret_key, &message, &context)
                .map_err(|e| format!("{e:?}"))?;

            Ok(json!({
                "signature": hex::encode(signature.as_bytes())
            }))
        }
        "slh-hash-sign" => {
            let parameter_set = slh_param(ps)?;
            let implementation = SlhDsa::new(parameter_set);
            let secret_key_bytes = hex_field(inputs, "secret_key")?;
            let message = hex_field(inputs, "message")?;
            let context = hex_field(inputs, "context")?;
            let prehash_name = inputs
                .get("prehash")
                .and_then(Value::as_str)
                .ok_or("missing prehash")?;
            let prehash = slh_prehash(prehash_name)?;

            let secret_key = SlhDsaPrivateKey::from_bytes(parameter_set, &secret_key_bytes)
                .map_err(|e| format!("{e:?}"))?;

            let signature = implementation
                .hash_sign_deterministic(&secret_key, &message, &context, prehash)
                .map_err(|e| format!("{e:?}"))?;

            Ok(json!({
                "signature": hex::encode(signature.as_bytes())
            }))
        }
        "slh-hash-verify" => {
            let parameter_set = slh_param(ps)?;
            let implementation = SlhDsa::new(parameter_set);
            let public_key_bytes = hex_field(inputs, "public_key")?;
            let message = hex_field(inputs, "message")?;
            let context = hex_field(inputs, "context")?;
            let signature_bytes = hex_field(inputs, "signature")?;
            let prehash_name = inputs
                .get("prehash")
                .and_then(Value::as_str)
                .ok_or("missing prehash")?;
            let prehash = slh_prehash(prehash_name)?;

            let public_key = SlhDsaPublicKey::from_bytes(parameter_set, &public_key_bytes)
                .map_err(|e| format!("{e:?}"))?;
            let signature = SlhDsaSignature::from_bytes(parameter_set, &signature_bytes)
                .map_err(|e| format!("{e:?}"))?;

            let valid = implementation
                .hash_verify(&public_key, &message, &context, prehash, &signature)
                .map_err(|e| format!("{e:?}"))?;

            Ok(json!({"valid": valid}))
        }
        "slh-verify" => {
            let parameter_set = slh_param(ps)?;
            let implementation = SlhDsa::new(parameter_set);
            let public_key_bytes = hex_field(inputs, "public_key")?;
            let message = hex_field(inputs, "message")?;
            let context = hex_field(inputs, "context")?;
            let signature_bytes = hex_field(inputs, "signature")?;

            let public_key = SlhDsaPublicKey::from_bytes(parameter_set, &public_key_bytes)
                .map_err(|e| format!("{e:?}"))?;

            let signature = SlhDsaSignature::from_bytes(parameter_set, &signature_bytes)
                .map_err(|e| format!("{e:?}"))?;

            let valid = implementation
                .verify(&public_key, &message, &context, &signature)
                .map_err(|e| format!("{e:?}"))?;

            Ok(json!({"valid": valid}))
        }
        _ => Err(format!("unsupported operation {op}")),
    }
}
fn main() {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s).unwrap();

    let req: Value = match serde_json::from_str(&s) {
        Ok(req) => req,
        Err(error) => {
            println!("{}", json!({"ok": false, "error": format!("{error:?}")}));
            std::process::exit(1);
        }
    };

    if req.get("action").and_then(Value::as_str) == Some("capabilities") {
        println!(
            "{}",
            json!({
                "ok": true,
                "provider": "rust",
                "capabilities": capabilities()
            })
        );
        return;
    }

    let execute_request = req.get("case").unwrap_or(&req);

    match execute(execute_request) {
        Ok(outputs) => println!("{}", json!({"ok": true, "outputs": outputs})),
        Err(error) => {
            println!("{}", json!({"ok": false, "error": error}));
            std::process::exit(1);
        }
    }
}
