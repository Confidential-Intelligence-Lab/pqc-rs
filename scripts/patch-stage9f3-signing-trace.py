#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-ml-dsa/src/signature.rs")
if not path.exists():
    raise SystemExit("Run from the repository root")

text = path.read_text(encoding="utf-8")

if "pub struct SigningTrace" not in text:
    insertion = text.find("use ")
    if insertion < 0:
        insertion = 0

    tracing = '''use std::cell::Cell;

thread_local! {
    static SIGNING_TRACE: Cell<SigningTrace> =
        const { Cell::new(SigningTrace::new()) };
}

/// Audit counters for one signing operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SigningTrace {
    /// Number of rejection-loop attempts.
    pub attempts: u64,
    /// Rejections caused by the response-vector norm check.
    pub reject_z: u64,
    /// Rejections caused by the low-bits norm check.
    pub reject_r0: u64,
    /// Rejections caused by the secret `t0` product norm check.
    pub reject_ct0: u64,
    /// Rejections caused by excessive hint weight.
    pub reject_hint: u64,
}

impl SigningTrace {
    const fn new() -> Self {
        Self {
            attempts: 0,
            reject_z: 0,
            reject_r0: 0,
            reject_ct0: 0,
            reject_hint: 0,
        }
    }

    /// Total rejected attempts.
    pub const fn total_rejections(self) -> u64 {
        self.reject_z + self.reject_r0 + self.reject_ct0 + self.reject_hint
    }
}

/// Reset the thread-local signing trace.
pub fn clear_signing_trace() {
    SIGNING_TRACE.with(|trace| trace.set(SigningTrace::new()));
}

/// Read the thread-local signing trace.
pub fn signing_trace() -> SigningTrace {
    SIGNING_TRACE.with(Cell::get)
}

fn trace_attempt() {
    SIGNING_TRACE.with(|trace| {
        let mut value = trace.get();
        value.attempts += 1;
        trace.set(value);
    });
}

fn trace_reject_z() {
    SIGNING_TRACE.with(|trace| {
        let mut value = trace.get();
        value.reject_z += 1;
        trace.set(value);
    });
}

fn trace_reject_r0() {
    SIGNING_TRACE.with(|trace| {
        let mut value = trace.get();
        value.reject_r0 += 1;
        trace.set(value);
    });
}

fn trace_reject_ct0() {
    SIGNING_TRACE.with(|trace| {
        let mut value = trace.get();
        value.reject_ct0 += 1;
        trace.set(value);
    });
}

fn trace_reject_hint() {
    SIGNING_TRACE.with(|trace| {
        let mut value = trace.get();
        value.reject_hint += 1;
        trace.set(value);
    });
}

'''
    text = text[:insertion] + tracing + text[insertion:]

start = text.find("fn sign_prepared(")
if start < 0:
    raise SystemExit("Could not find sign_prepared")

body_start = text.find("{", start)
if body_start < 0:
    raise SystemExit("Could not find sign_prepared body")

depth = 0
end = None
for index in range(body_start, len(text)):
    if text[index] == "{":
        depth += 1
    elif text[index] == "}":
        depth -= 1
        if depth == 0:
            end = index + 1
            break

if end is None:
    raise SystemExit("Could not find end of sign_prepared")

body = text[start:end]

if "trace_attempt();" not in body:
    loop_index = body.find("loop {")
    if loop_index < 0:
        raise SystemExit("Could not find rejection loop in sign_prepared")
    loop_insert = loop_index + len("loop {")
    body = body[:loop_insert] + "\n        trace_attempt();" + body[loop_insert:]

if "trace_reject_z();" not in body:
    replacements = [
        "trace_reject_z();",
        "trace_reject_r0();",
        "trace_reject_ct0();",
        "trace_reject_hint();",
    ]

    continue_positions = []
    cursor = 0
    while True:
        position = body.find("continue;", cursor)
        if position < 0:
            break
        continue_positions.append(position)
        cursor = position + len("continue;")

    if len(continue_positions) != 4:
        raise SystemExit(
            f"Expected 4 rejection continues in sign_prepared, found {len(continue_positions)}"
        )

    offset = 0
    for position, statement in zip(continue_positions, replacements):
        actual = position + offset
        insertion_text = f"{statement}\n            "
        body = body[:actual] + insertion_text + body[actual:]
        offset += len(insertion_text)

text = text[:start] + body + text[end:]
path.write_text(text, encoding="utf-8")
print("Instrumented ML-DSA signing rejection loop.")
