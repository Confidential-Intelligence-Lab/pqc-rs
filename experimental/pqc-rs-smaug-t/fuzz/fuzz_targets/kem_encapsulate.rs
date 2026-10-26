#![no_main]

use libfuzzer_sys::fuzz_target;
use pqc_rs_smaug_t::{kem, Parameters, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};
use std::sync::OnceLock;

const PREFIX: &[u8; 4] = b"SMTF";

#[derive(Clone)]
struct Fixture {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    ciphertext: Vec<u8>,
    message: Vec<u8>,
    shared_secret: [u8; 32],
}

fn parameters(mode: usize) -> Parameters {
    [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER][mode % 4]
}

fn fixtures() -> &'static [Fixture; 4] {
    static FIXTURES: OnceLock<[Fixture; 4]> = OnceLock::new();

    FIXTURES.get_or_init(|| {
        std::array::from_fn(|mode| {
            let parameters = parameters(mode);
            let seed = [0x42u8; 32];
            let auxiliary = [0xA5u8; 32];

            let (public_key, secret_key) = kem::keypair(&seed, &auxiliary, &parameters).unwrap();

            let message_len = if parameters == TIMER { 16 } else { 32 };
            let message = vec![0x39u8; message_len];

            let (ciphertext, shared_secret) =
                kem::encapsulate_deterministic(&public_key, &message, &parameters).unwrap();

            assert_eq!(
                kem::decapsulate(&ciphertext, &secret_key, &parameters),
                Ok(shared_secret)
            );

            Fixture {
                public_key,
                secret_key,
                ciphertext,
                message,
                shared_secret,
            }
        })
    })
}

fn mutation_descriptor(data: &[u8]) -> Option<(usize, usize, usize, u8, u8)> {
    if data.len() < 10 || &data[..4] != PREFIX {
        return None;
    }

    let mode = usize::from(data[4]) % 4;
    let region = usize::from(data[5]) % 4;
    let offset = usize::from(u16::from_le_bytes([data[6], data[7]]));
    let operation = data[8] % 4;
    let value = data[9];

    Some((mode, region, offset, operation, value))
}

fn mutate(bytes: &mut Vec<u8>, offset: usize, operation: u8, value: u8) {
    match operation {
        0 => {
            if !bytes.is_empty() {
                let index = offset % bytes.len();
                bytes[index] ^= 1u8 << (value % 8);
            }
        }
        1 => {
            if !bytes.is_empty() {
                let index = offset % bytes.len();
                bytes[index] = value;
            }
        }
        2 => {
            if !bytes.is_empty() {
                let index = offset % bytes.len();
                bytes.remove(index);
            }
        }
        _ => {
            let index = offset % (bytes.len() + 1);
            bytes.insert(index, value);
        }
    }
}

#[cfg(not(any(feature = "structured-only", feature = "structured-fields")))]
fn raw(data: &[u8], parameters: &Parameters) {
    let pk_len = 32 + parameters.k * 256 * parameters.q.trailing_zeros() as usize / 8;
    let message_len = if *parameters == TIMER { 16 } else { 32 };

    let split = data.first().copied().unwrap_or(0) as usize;
    let payload = data.get(1..).unwrap_or_default();
    let boundary = split.min(payload.len());
    let (public_key, message) = payload.split_at(boundary);

    let first = kem::encapsulate_deterministic(public_key, message, parameters);
    let second = kem::encapsulate_deterministic(public_key, message, parameters);
    assert_eq!(first, second);

    let mut pk = vec![0u8; pk_len];
    let mut msg = vec![0u8; message_len];

    let pk_copy = public_key.len().min(pk.len());
    let msg_copy = message.len().min(msg.len());
    pk[..pk_copy].copy_from_slice(&public_key[..pk_copy]);
    msg[..msg_copy].copy_from_slice(&message[..msg_copy]);

    let first = kem::encapsulate_deterministic(&pk, &msg, parameters);
    let second = kem::encapsulate_deterministic(&pk, &msg, parameters);
    assert_eq!(first, second);
}

fn structured(data: &[u8]) {
    let (mode, region, offset, operation, value) = mutation_descriptor(data).unwrap();

    let parameters = parameters(mode);
    let fixture = &fixtures()[mode];

    let mut public_key = fixture.public_key.clone();
    let mut message = fixture.message.clone();

    if region % 2 == 0 {
        mutate(&mut public_key, offset, operation, value);
    } else {
        mutate(&mut message, offset, operation, value);
    }

    let first = kem::encapsulate_deterministic(&public_key, &message, &parameters);
    let second = kem::encapsulate_deterministic(&public_key, &message, &parameters);
    assert_eq!(first, second);

    let baseline =
        kem::encapsulate_deterministic(&fixture.public_key, &fixture.message, &parameters);
    assert_eq!(
        baseline,
        Ok((fixture.ciphertext.clone(), fixture.shared_secret))
    );
    assert_eq!(
        kem::decapsulate(&fixture.ciphertext, &fixture.secret_key, &parameters,),
        Ok(fixture.shared_secret)
    );
}

#[cfg(all(feature = "structured-only", feature = "structured-fields"))]
compile_error!("structured-only and structured-fields are mutually exclusive");

fuzz_target!(|data: &[u8]| {
    #[cfg(feature = "structured-fields")]
    {
        let mut descriptor = [0u8; 10];
        descriptor[..4].copy_from_slice(PREFIX);
        let count = data.len().min(6);
        descriptor[4..4 + count].copy_from_slice(&data[..count]);
        structured(&descriptor);
        return;
    }

    #[cfg(feature = "structured-only")]
    {
        let mut descriptor = [0u8; 10];
        descriptor[..4].copy_from_slice(PREFIX);
        let fields = if data.starts_with(PREFIX) {
            &data[4..]
        } else {
            data
        };
        let count = fields.len().min(6);
        descriptor[4..4 + count].copy_from_slice(&fields[..count]);
        structured(&descriptor);
        return;
    }

    #[cfg(not(any(feature = "structured-only", feature = "structured-fields")))]
    if mutation_descriptor(data).is_some() {
        structured(data);
    } else {
        #[cfg(not(any(feature = "structured-only", feature = "structured-fields")))]
        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            raw(data, &parameters);
        }
    }
});
