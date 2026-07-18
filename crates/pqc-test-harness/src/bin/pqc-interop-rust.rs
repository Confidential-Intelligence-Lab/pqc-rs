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
        _ => Err(format!("unsupported operation {op}")),
    }
}
fn main() {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s).unwrap();
    let result = (|| {
        let req: Value = serde_json::from_str(&s).map_err(|e| format!("{e:?}"))?;
        if req.get("action").and_then(Value::as_str) == Some("capabilities") {
            return Ok(
                json!({"provider":"rust","operations":["kem-keygen","kem-encaps","kem-decaps","dsa-keygen","dsa-sign","dsa-verify"]}),
            );
        }
        execute(&req)
    })();
    match result {
        Ok(outputs) => println!("{}", json!({"ok":true,"outputs":outputs})),
        Err(error) => {
            println!("{}", json!({"ok":false,"error":error}));
            std::process::exit(1)
        }
    }
}
