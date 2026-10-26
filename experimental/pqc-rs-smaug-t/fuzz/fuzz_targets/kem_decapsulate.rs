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
    if data.len() < 2 {
        return;
    }

    let ciphertext_len = parameters.k * 256 * parameters.p.trailing_zeros() as usize / 8
        + 256 * parameters.p_prime.trailing_zeros() as usize / 8;
    let secret_key_len =
        parameters.k * 64 + 64 + parameters.k * 256 * parameters.q.trailing_zeros() as usize / 8;

    let split = usize::from(u16::from_le_bytes([data[0], data[1]]));
    let payload = &data[2..];
    let boundary = split.min(payload.len());
    let (ciphertext, secret_key) = payload.split_at(boundary);

    let first = kem::decapsulate(ciphertext, secret_key, parameters);
    let second = kem::decapsulate(ciphertext, secret_key, parameters);
    assert_eq!(first, second);

    let mut ct = vec![0u8; ciphertext_len];
    let mut sk = vec![0u8; secret_key_len];

    let ct_copy = ciphertext.len().min(ct.len());
    let sk_copy = secret_key.len().min(sk.len());
    ct[..ct_copy].copy_from_slice(&ciphertext[..ct_copy]);
    sk[..sk_copy].copy_from_slice(&secret_key[..sk_copy]);

    let first = kem::decapsulate(&ct, &sk, parameters);
    let second = kem::decapsulate(&ct, &sk, parameters);
    assert_eq!(first, second);
}

fn rejection_secret(secret_key: &[u8], ciphertext: &[u8], parameters: &Parameters) -> [u8; 32] {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Digest, Sha3_256, Shake256,
    };

    let start = parameters.k * 64;
    let t = &secret_key[start..start + 32];

    let ciphertext_hash = Sha3_256::digest(ciphertext);

    let mut shake = Shake256::default();
    Update::update(&mut shake, t);
    Update::update(&mut shake, &ciphertext_hash);

    let mut reader = shake.finalize_xof();
    let mut output = [0u8; 64];
    reader.read(&mut output);

    let mut rejection = [0u8; 32];
    rejection.copy_from_slice(&output[32..]);
    rejection
}

fn structured(data: &[u8]) {
    let (mode, region, offset, operation, value) = mutation_descriptor(data).unwrap();

    let parameters = parameters(mode);
    let fixture = &fixtures()[mode];

    let mut ciphertext = fixture.ciphertext.clone();
    let mut secret_key = fixture.secret_key.clone();

    match region {
        0 => mutate(&mut ciphertext, offset, operation, value),
        1 => {
            let end = parameters.k * 64;
            let mut field = secret_key[..end].to_vec();
            mutate(&mut field, offset, operation, value);
            secret_key.splice(..end, field);
        }
        2 => {
            let start = parameters.k * 64;
            let end = start + 32;
            let mut field = secret_key[start..end].to_vec();
            mutate(&mut field, offset, operation, value);
            secret_key.splice(start..end, field);
        }
        _ => {
            let start = parameters.k * 64 + 32;
            let mut field = secret_key[start..].to_vec();
            mutate(&mut field, offset, operation, value);
            secret_key.splice(start.., field);
        }
    }

    let first = kem::decapsulate(&ciphertext, &secret_key, &parameters);
    let second = kem::decapsulate(&ciphertext, &secret_key, &parameters);
    assert_eq!(first, second);

    if region == 0
        && ciphertext.len() == fixture.ciphertext.len()
        && ciphertext != fixture.ciphertext
    {
        assert_eq!(
            first,
            Ok(rejection_secret(
                &fixture.secret_key,
                &ciphertext,
                &parameters,
            ))
        );
    }

    if region == 2 && secret_key.len() == fixture.secret_key.len() {
        assert_eq!(first, Ok(fixture.shared_secret));

        if secret_key != fixture.secret_key {
            let mut invalid_ciphertext = fixture.ciphertext.clone();
            invalid_ciphertext[0] ^= 1;

            assert_eq!(
                kem::decapsulate(&invalid_ciphertext, &secret_key, &parameters,),
                Ok(rejection_secret(
                    &secret_key,
                    &invalid_ciphertext,
                    &parameters,
                ))
            );
        }
    }

    let baseline = kem::decapsulate(&fixture.ciphertext, &fixture.secret_key, &parameters);
    assert_eq!(baseline, Ok(fixture.shared_secret));
    assert_eq!(
        kem::encapsulate_deterministic(&fixture.public_key, &fixture.message, &parameters,),
        Ok((fixture.ciphertext.clone(), fixture.shared_secret))
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
