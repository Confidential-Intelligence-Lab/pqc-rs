use std::io::{self, Read};

use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId, KemId};
use pqc_hpke::kdf::KdfAlgorithm;
use pqc_hpke::key_schedule::{key_schedule, AeadParameters, HpkeMode, KeyScheduleInputs};
use pqc_hpke::setup::{
    setup_base_receiver_from_shared_secret, setup_base_sender_from_shared_secret,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    parameter_set: String,
    shared_secret: String,
    info: String,
    aad: String,
    plaintext: String,
    exporter_context: String,
    exporter_length: usize,
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    key: String,
    base_nonce: String,
    exporter_secret: String,
    key_schedule_context: String,
    ciphertext: String,
    opened: String,
    exported_secret: String,
    sender_sequence: u64,
    receiver_sequence: u64,
}

fn decode(name: &str, value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|error| format!("invalid {name}: {error}"))
}

fn kem_id(parameter_set: &str) -> Result<KemId, String> {
    match parameter_set {
        "ML-KEM-512" => Ok(KemId(0x0040)),
        "ML-KEM-768" => Ok(KemId(0x0041)),
        "ML-KEM-1024" => Ok(KemId(0x0042)),
        other => Err(format!("unsupported parameter set: {other}")),
    }
}

fn execute(request: Request) -> Result<Response, String> {
    let shared_secret = decode("shared_secret", &request.shared_secret)?;
    let info = decode("info", &request.info)?;
    let aad = decode("aad", &request.aad)?;
    let plaintext = decode("plaintext", &request.plaintext)?;
    let exporter_context = decode("exporter_context", &request.exporter_context)?;

    let suite = HpkeSuiteId {
        kem_id: kem_id(&request.parameter_set)?,
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_128_GCM,
    };

    let schedule = key_schedule(
        suite,
        KdfAlgorithm::HkdfSha256,
        AeadParameters::for_id(AeadId::AES_128_GCM).ok_or_else(|| "unsupported AEAD".to_owned())?,
        KeyScheduleInputs {
            mode: HpkeMode::Base,
            shared_secret: &shared_secret,
            info: &info,
            psk: b"",
            psk_id: b"",
        },
    )
    .map_err(|error| format!("key schedule failed: {error:?}"))?;

    let key = hex::encode(schedule.key.as_bytes());
    let base_nonce = hex::encode(&schedule.base_nonce);
    let exporter_secret = hex::encode(schedule.exporter_secret.as_bytes());
    let key_schedule_context = hex::encode(&schedule.key_schedule_context);

    let mut sender = setup_base_sender_from_shared_secret(suite, &shared_secret, &info)
        .map_err(|error| format!("sender setup failed: {error:?}"))?;
    let mut receiver = setup_base_receiver_from_shared_secret(suite, &shared_secret, &info)
        .map_err(|error| format!("receiver setup failed: {error:?}"))?;

    let ciphertext = sender
        .seal(&aad, &plaintext)
        .map_err(|error| format!("seal failed: {error:?}"))?;
    let opened = receiver
        .open(&aad, &ciphertext)
        .map_err(|error| format!("open failed: {error:?}"))?;
    let sender_export = sender
        .export(&exporter_context, request.exporter_length)
        .map_err(|error| format!("sender export failed: {error:?}"))?;
    let receiver_export = receiver
        .export(&exporter_context, request.exporter_length)
        .map_err(|error| format!("receiver export failed: {error:?}"))?;

    if sender_export != receiver_export {
        return Err("sender and receiver exporter outputs differ".to_owned());
    }

    Ok(Response {
        ok: true,
        key,
        base_nonce,
        exporter_secret,
        key_schedule_context,
        ciphertext: hex::encode(ciphertext),
        opened: hex::encode(opened),
        exported_secret: hex::encode(sender_export),
        sender_sequence: sender.sequence_number(),
        receiver_sequence: receiver.sequence_number(),
    })
}

fn main() {
    let mut input = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read request: {error}");
        std::process::exit(2);
    }

    let request: Request = match serde_json::from_str(&input) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("invalid request JSON: {error}");
            std::process::exit(2);
        }
    };

    match execute(request) {
        Ok(response) => println!(
            "{}",
            serde_json::to_string(&response).expect("serialize response")
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
