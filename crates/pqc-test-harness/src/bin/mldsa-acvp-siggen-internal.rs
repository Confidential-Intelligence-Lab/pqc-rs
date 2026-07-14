use pqc_ml_dsa::params::MlDsaParameterSet;
use pqc_ml_dsa::signature::{sign_internal_message, sign_internal_mu};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, env, fs, path::Path};
type CaseMap<'a> = BTreeMap<(u64, u64), &'a Map<String, Value>>;
type AcvpEnvelope<'a> = (Option<Value>, &'a Map<String, Value>, bool);

fn main() {
    if let Err(e) = run() {
        eprintln!("ML-DSA ACVP internal sigGen failed: {e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), String> {
    let a: Vec<String> = env::args().collect();
    if a.len() != 4 {
        return Err("usage: siggen prompt response expected".to_owned());
    }
    let p = read_json(Path::new(&a[1]))?;
    let e = read_json(Path::new(&a[3]))?;
    let (r, ge, gs, mg, ug, tc) = process(&p)?;
    write_json(Path::new(&a[2]), &r)?;
    let (m, x) = compare(&r, &e)?;
    println!("NIST ACVP ML-DSA sigGen internal response");
    println!("  groups examined: {ge}\n  groups supported: {gs}\n  groups skipped: {}\n  internal message groups: {mg}\n  external mu groups: {ug}\n  tests generated: {tc}\n  matched expected results: {m}\n  mismatches: {x}",ge-gs);
    if x != 0 {
        return Err(format!("{x} mismatches"));
    }
    Ok(())
}
fn process(p: &Value) -> Result<(Value, usize, usize, usize, usize, usize), String> {
    let (ver, set, wrap) = split_envelope(p)?;
    let groups = set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or("missing groups")?;
    let vs = req_u64(set, "vsId")?;
    let mut out = Vec::new();
    let (mut gs, mut mg, mut ug, mut tc) = (0, 0, 0, 0);
    for gv in groups {
        let g = gv.as_object().ok_or("group")?;
        if g.get("testType").and_then(Value::as_str) != Some("AFT")
            || g.get("signatureInterface").and_then(Value::as_str) != Some("internal")
        {
            continue;
        }
        gs += 1;
        let tg = req_u64(g, "tgId")?;
        let ps = parameter_set(req_str(g, "parameterSet")?)?;
        let em = req_bool(g, "externalMu")?;
        let det = req_bool(g, "deterministic")?;
        if em {
            ug += 1
        } else {
            mg += 1
        };
        let mut tests = Vec::new();
        for tv in g.get("tests").and_then(Value::as_array).ok_or("tests")? {
            let t = tv.as_object().ok_or("test")?;
            let id = req_u64(t, "tcId")?;
            let sk = hex_decode(req_str(t, "sk")?)?;
            let rnd = if det {
                [0u8; 32]
            } else {
                fixed::<32>(req_str(t, "rnd")?)?
            };
            let sig = if em {
                let mu = fixed::<64>(req_str(t, "mu")?)?;
                sign_internal_mu(ps, &sk, &mu, &rnd)
            } else {
                let msg = hex_decode(req_str(t, "message")?)?;
                sign_internal_message(ps, &sk, &msg, &rnd)
            }
            .map_err(|e| format!("tgId {tg} tcId {id}: {e:?}"))?;
            tests.push(json!({"tcId":id,"signature":hex_encode(&sig)}));
            tc += 1
        }
        out.push(json!({"tgId":tg,"tests":tests}))
    }
    let seto = json!({"vsId":vs,"testGroups":out});
    let r = if wrap {
        json!([ver.ok_or("version")?, seto])
    } else {
        seto
    };
    Ok((r, groups.len(), gs, mg, ug, tc))
}
fn compare(a: &Value, e: &Value) -> Result<(usize, usize), String> {
    let aa = indexed_cases(a)?;
    let ee = indexed_cases(e)?;
    let (mut m, mut x) = (0, 0);
    for (k, v) in aa {
        let q = ee.get(&k).ok_or("missing expected")?;
        if hex_decode(req_str(v, "signature")?)? == hex_decode(req_str(q, "signature")?)? {
            m += 1
        } else {
            x += 1
        }
    }
    Ok((m, x))
}

fn split_envelope(value: &Value) -> Result<AcvpEnvelope<'_>, String> {
    if let Some(envelope) = value.as_array() {
        if envelope.len() != 2 {
            return Err("invalid ACVP envelope".to_owned());
        }
        Ok((
            Some(envelope[0].clone()),
            envelope[1]
                .as_object()
                .ok_or_else(|| "missing vector set".to_owned())?,
            true,
        ))
    } else {
        Ok((
            None,
            value
                .as_object()
                .ok_or_else(|| "ACVP JSON not object".to_owned())?,
            false,
        ))
    }
}
fn indexed_cases(value: &Value) -> Result<CaseMap<'_>, String> {
    let (_, set, _) = split_envelope(value)?;
    let groups = set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing testGroups".to_owned())?;
    let mut out = BTreeMap::new();
    for gv in groups {
        let g = gv
            .as_object()
            .ok_or_else(|| "group not object".to_owned())?;
        let tg = req_u64(g, "tgId")?;
        for tv in g
            .get("tests")
            .and_then(Value::as_array)
            .ok_or_else(|| "tests missing".to_owned())?
        {
            let t = tv.as_object().ok_or_else(|| "test not object".to_owned())?;
            out.insert((tg, req_u64(t, "tcId")?), t);
        }
    }
    Ok(out)
}
fn parameter_set(s: &str) -> Result<MlDsaParameterSet, String> {
    match s {
        "ML-DSA-44" => Ok(MlDsaParameterSet::MlDsa44),
        "ML-DSA-65" => Ok(MlDsaParameterSet::MlDsa65),
        "ML-DSA-87" => Ok(MlDsaParameterSet::MlDsa87),
        _ => Err(format!("unsupported parameterSet {s}")),
    }
}
fn req_str<'a>(o: &'a Map<String, Value>, f: &str) -> Result<&'a str, String> {
    o.get(f)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {f}"))
}
fn req_u64(o: &Map<String, Value>, f: &str) -> Result<u64, String> {
    o.get(f)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing {f}"))
}
fn req_bool(o: &Map<String, Value>, f: &str) -> Result<bool, String> {
    o.get(f)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing {f}"))
}
fn fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let b = hex_decode(s)?;
    b.try_into()
        .map_err(|v: Vec<u8>| format!("expected {N} bytes, got {}", v.len()))
}
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex length".to_owned());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| Ok((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}
fn nib(v: u8) -> Result<u8, String> {
    match v {
        b'0'..=b'9' => Ok(v - b'0'),
        b'a'..=b'f' => Ok(v - b'a' + 10),
        b'A'..=b'F' => Ok(v - b'A' + 10),
        _ => Err("invalid hex".to_owned()),
    }
}
fn hex_encode(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(char::from(H[usize::from(x >> 4)]));
        s.push(char::from(H[usize::from(x & 15)]));
    }
    s
}
fn read_json(p: &Path) -> Result<Value, String> {
    let d = fs::read(p).map_err(|e| format!("read {}: {e}", p.display()))?;
    serde_json::from_slice(&d).map_err(|e| format!("JSON {}: {e}", p.display()))
}
fn write_json(p: &Path, v: &Value) -> Result<(), String> {
    fs::write(p, serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?)
        .map_err(|e| format!("write {}: {e}", p.display()))
}
