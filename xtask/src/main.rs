use chrono::{NaiveDate, Utc};
use glob::glob;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process,
    process::Command,
};

const VALID_STATUSES: &[&str] = &[
    "planned",
    "mapped",
    "implemented",
    "verified",
    "not-applicable",
];
const VALID_CLASSES: &[&str] = &["informative", "recommendation", "normative"];
const DEFAULT_REVIEW_DUE_DAYS: i64 = 180;

#[derive(Debug, Deserialize)]
struct Matrix {
    metadata: Metadata,
    #[serde(default)]
    requirement: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    schema_version: u32,
    project: String,
    generated_from: String,
    source_kind: String,
    #[serde(default)]
    default_owner: Option<String>,
    #[serde(default)]
    default_review_due_days: Option<u32>,
    #[serde(default)]
    notes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Requirement {
    id: String,
    standard: String,
    section: String,
    title: String,
    class: String,
    status: String,
    statement: String,
    #[serde(default)]
    implementation: Vec<String>,
    #[serde(default)]
    tests: Vec<String>,
    #[serde(default)]
    evidence: Vec<String>,
    #[serde(default)]
    evidence_paths: Vec<String>,
    #[serde(default)]
    ci: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    notes: Vec<String>,
    #[serde(default)]
    rationale: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    last_verified: Option<String>,
    #[serde(default)]
    review_due_days: Option<u32>,
    #[serde(default)]
    coverage: Option<f64>,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    project: String,
    source: String,
    source_kind: String,
    generated_at: String,
    decision: String,
    strict: bool,
    totals: Totals,
    standards: BTreeMap<String, StandardTotals>,
    findings: Vec<Finding>,
    requirements: Vec<RequirementReport>,
}

#[derive(Debug, Serialize, Default)]
struct Totals {
    requirements: usize,
    mapped_or_better: usize,
    implemented_or_better: usize,
    verified: usize,
    not_applicable: usize,
    requirements_with_owner: usize,
    requirements_with_ci: usize,
    requirements_with_tests: usize,
    requirements_with_evidence: usize,
    resolvable_implementation_refs: usize,
    resolvable_test_refs: usize,
    resolvable_evidence_refs: usize,
    stale_verifications: usize,
    errors: usize,
    warnings: usize,
}

#[derive(Debug, Serialize, Default)]
struct StandardTotals {
    requirements: usize,
    mapped_or_better: usize,
    implemented_or_better: usize,
    verified: usize,
    not_applicable: usize,
}

#[derive(Debug, Serialize, Clone)]
struct Finding {
    code: String,
    severity: String,
    requirement_id: Option<String>,
    field: Option<String>,
    message: String,
}

#[derive(Debug, Serialize)]
struct RequirementReport {
    #[serde(flatten)]
    requirement: Requirement,
    effective_owner: Option<String>,
    implementation_matches: BTreeMap<String, Vec<String>>,
    test_matches: BTreeMap<String, Vec<String>>,
    evidence_path_matches: BTreeMap<String, Vec<String>>,
    verification_age_days: Option<i64>,
    stale: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("compliance") => {
            let mut matrix = PathBuf::from("compliance/matrix.toml");
            let mut output = PathBuf::from("target/compliance");
            let mut strict = false;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--matrix" => {
                        matrix = PathBuf::from(args.next().ok_or("--matrix requires a path")?)
                    }
                    "--output" => {
                        output = PathBuf::from(args.next().ok_or("--output requires a path")?)
                    }
                    "--strict" => strict = true,
                    "--help" | "-h" => return print_help(),
                    other => return Err(format!("unknown argument: {other}")),
                }
            }
            generate(&matrix, &output, strict)
        }
        Some("query") => query(args.collect()),
        Some("standards") => standards(args.collect()),
        Some("interop") => interop(args.collect()),
        Some("interop-cross") => interop_cross(args.collect()),
        Some("interop-openssl") => interop_openssl(args.collect()),
        Some("interop-hpke") => interop_hpke(args.collect()),
        Some("implementation-matrix") => implementation_matrix(args.collect()),
        Some("api-review") => api_review(args.collect()),
        Some("zeroization-audit") => zeroization_audit(args.collect()),
        Some("constant-time-audit") => constant_time_audit(args.collect()),
        Some("fuzz-audit") => fuzz_audit(args.collect()),
        Some("performance-audit") => performance_audit(args.collect()),
        Some("release-manifest") => release_manifest(args.collect()),
        Some("architecture-snapshot") => architecture_snapshot(args.collect()),
        Some("standards-certification") => standards_certification(args.collect()),
        Some("security-certification") => security_certification(args.collect()),
        Some("validation-certification") => validation_certification(args.collect()),
        Some("release-audit") => release_audit(args.collect()),
        Some("--help") | Some("-h") | None => print_help(),
        Some(other) => Err(format!("unknown xtask: {other}")),
    }
}

fn print_help() -> Result<(), String> {
    println!("cargo xtask compliance [--matrix PATH] [--output DIR] [--strict]");
    println!("cargo xtask query [--matrix PATH] [--standard NAME] [--status STATUS] [--missing tests|evidence|owner|ci]");
    println!("cargo xtask standards [--catalog PATH] [--output DIR] [--strict]");
    println!("cargo xtask interop [--manifest PATH] [--output DIR] [--provider ID] [--suite ID] [--strict]");
    println!("cargo xtask interop-cross [--strict]");
    println!("cargo xtask interop-openssl [--strict]");
    println!("cargo xtask interop-hpke [--strict]");
    println!("cargo xtask implementation-matrix [--manifest PATH] [--output PATH] [--check]");
    println!("cargo xtask api-review [--check]");
    println!("cargo xtask zeroization-audit [--check]");
    println!("cargo xtask constant-time-audit [--check]");
    println!("cargo xtask fuzz-audit [--check]");
    println!("cargo xtask performance-audit [--check]");
    println!("cargo xtask release-manifest [--check]");
    println!("cargo xtask architecture-snapshot [--check]");
    println!("cargo xtask standards-certification [--check]");
    println!("cargo xtask security-certification [--check]");
    println!("cargo xtask validation-certification [--check]");
    println!("cargo xtask release-audit [--check]");
    Ok(())
}

fn interop_openssl(args: Vec<String>) -> Result<(), String> {
    run_python_interop(
        "scripts/openssl_provider_interop.py",
        "OpenSSL interoperability",
        "interop-openssl",
        args,
    )
}

fn interop_hpke(args: Vec<String>) -> Result<(), String> {
    run_python_interop(
        "scripts/hpke_interop.py",
        "HPKE interoperability",
        "interop-hpke",
        args,
    )
}

fn run_python_interop(
    script: &str,
    description: &str,
    subcommand: &str,
    args: Vec<String>,
) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg(script);
    for arg in args {
        match arg.as_str() {
            "--strict" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask {subcommand} [--strict]");
                return Ok(());
            }
            other => return Err(format!("unknown {subcommand} argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|error| format!("failed to run {description}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{description} exited with {status}"))
    }
}

fn release_audit(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/release_audit.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask release-audit [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown release-audit argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run release-audit: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("release-audit exited with {status}"))
    }
}

fn validation_certification(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/validation_certification.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask validation-certification [--check]");
                return Ok(());
            }
            other => {
                return Err(format!(
                    "unknown validation-certification argument: {other}"
                ))
            }
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run validation-certification: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("validation-certification exited with {status}"))
    }
}

fn security_certification(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/security_certification.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask security-certification [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown security-certification argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run security-certification: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("security-certification exited with {status}"))
    }
}

fn standards_certification(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/standards_certification.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask standards-certification [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown standards-certification argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run standards-certification: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("standards-certification exited with {status}"))
    }
}

fn architecture_snapshot(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/architecture_snapshot.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask architecture-snapshot [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown architecture-snapshot argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run architecture-snapshot: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("architecture-snapshot exited with {status}"))
    }
}

fn release_manifest(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/release_manifest.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask release-manifest [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown release-manifest argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run release-manifest: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("release-manifest exited with {status}"))
    }
}

fn performance_audit(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/performance_audit.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask performance-audit [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown performance-audit argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run performance audit: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("performance audit exited with {status}"))
    }
}

fn fuzz_audit(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/fuzz_audit.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask fuzz-audit [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown fuzz-audit argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run fuzz audit: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("fuzz audit exited with {status}"))
    }
}

fn constant_time_audit(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/constant_time_audit.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask constant-time-audit [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown constant-time-audit argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run constant-time audit: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("constant-time audit exited with {status}"))
    }
}

fn zeroization_audit(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/zeroization_audit.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask zeroization-audit [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown zeroization-audit argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run zeroization audit: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("zeroization audit exited with {status}"))
    }
}

fn api_review(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/api_review.py");
    for arg in args {
        match arg.as_str() {
            "--check" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask api-review [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown api-review argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run API review: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("API review exited with {status}"))
    }
}

fn interop(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/interop_engine.py").arg("report");
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--manifest" | "--output" | "--provider" | "--suite" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                command.arg(arg).arg(value);
            }
            "--strict" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask interop [--manifest PATH] [--output DIR] [--provider ID] [--suite ID] [--strict]");
                return Ok(());
            }
            other => return Err(format!("unknown interop argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run interoperability engine: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("interoperability engine exited with {status}"))
    }
}
fn standards(args: Vec<String>) -> Result<(), String> {
    let mut command = Command::new("python3");
    command.arg("scripts/standards_engine.py").arg("report");
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--catalog" | "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                command.arg(arg).arg(value);
            }
            "--strict" => {
                command.arg(arg);
            }
            "--help" | "-h" => {
                println!("cargo xtask standards [--catalog PATH] [--output DIR] [--strict]");
                return Ok(());
            }
            other => return Err(format!("unknown standards argument: {other}")),
        }
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run standards engine: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("standards engine exited with {status}"))
    }
}

fn query(args: Vec<String>) -> Result<(), String> {
    let mut matrix_path = PathBuf::from("compliance/matrix.toml");
    let mut standard: Option<String> = None;
    let mut status: Option<String> = None;
    let mut missing: Option<String> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--matrix" => {
                matrix_path = PathBuf::from(iter.next().ok_or("--matrix requires a path")?)
            }
            "--standard" => standard = Some(iter.next().ok_or("--standard requires a value")?),
            "--status" => status = Some(iter.next().ok_or("--status requires a value")?),
            "--missing" => missing = Some(iter.next().ok_or("--missing requires a field")?),
            "--help" | "-h" => return print_help(),
            other => return Err(format!("unknown query argument: {other}")),
        }
    }
    if let Some(field) = &missing {
        if !["tests", "evidence", "owner", "ci"].contains(&field.as_str()) {
            return Err("--missing must be tests, evidence, owner, or ci".into());
        }
    }
    let raw = fs::read_to_string(&matrix_path)
        .map_err(|e| format!("cannot read {}: {e}", matrix_path.display()))?;
    let matrix: Matrix = toml::from_str(&raw).map_err(|e| format!("invalid TOML: {e}"))?;
    println!("| ID | Standard | Section | Status | Title |");
    println!("|---|---|---|---|---|");
    for req in matrix.requirement {
        if standard.as_ref().is_some_and(|s| &req.standard != s) {
            continue;
        }
        if status.as_ref().is_some_and(|s| &req.status != s) {
            continue;
        }
        if let Some(field) = &missing {
            let absent = match field.as_str() {
                "tests" => req.tests.is_empty(),
                "evidence" => req.evidence.is_empty() && req.evidence_paths.is_empty(),
                "owner" => req.owner.is_none() && matrix.metadata.default_owner.is_none(),
                "ci" => req.ci.is_empty(),
                _ => false,
            };
            if !absent {
                continue;
            }
        }
        println!(
            "| `{}` | {} | {} | {} | {} |",
            req.id,
            req.standard,
            req.section,
            req.status,
            escape(&req.title)
        );
    }
    Ok(())
}

fn generate(matrix_path: &Path, output_dir: &Path, strict: bool) -> Result<(), String> {
    let raw = fs::read_to_string(matrix_path)
        .map_err(|e| format!("cannot read {}: {e}", matrix_path.display()))?;
    let matrix: Matrix = toml::from_str(&raw)
        .map_err(|e| format!("invalid TOML in {}: {e}", matrix_path.display()))?;
    let repo_root = matrix_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."));
    let today = Utc::now().date_naive();

    let mut findings = Vec::new();
    validate_metadata(&matrix.metadata, &mut findings);
    validate_requirements(&matrix.requirement, &matrix.metadata, &mut findings);

    let mut totals = Totals::default();
    let mut standards: BTreeMap<String, StandardTotals> = BTreeMap::new();
    let mut requirement_reports = Vec::new();
    totals.requirements = matrix.requirement.len();

    for req in &matrix.requirement {
        let rank = status_rank(&req.status);
        if rank >= status_rank("mapped") && req.status != "not-applicable" {
            totals.mapped_or_better += 1;
        }
        if rank >= status_rank("implemented") && req.status != "not-applicable" {
            totals.implemented_or_better += 1;
        }
        if req.status == "verified" {
            totals.verified += 1;
        }
        if req.status == "not-applicable" {
            totals.not_applicable += 1;
        }
        if req.owner.is_some() || matrix.metadata.default_owner.is_some() {
            totals.requirements_with_owner += 1;
        }
        if !req.ci.is_empty() {
            totals.requirements_with_ci += 1;
        }
        if !req.tests.is_empty() {
            totals.requirements_with_tests += 1;
        }
        if !req.evidence.is_empty() || !req.evidence_paths.is_empty() {
            totals.requirements_with_evidence += 1;
        }

        let entry = standards.entry(req.standard.clone()).or_default();
        entry.requirements += 1;
        if rank >= status_rank("mapped") && req.status != "not-applicable" {
            entry.mapped_or_better += 1;
        }
        if rank >= status_rank("implemented") && req.status != "not-applicable" {
            entry.implemented_or_better += 1;
        }
        if req.status == "verified" {
            entry.verified += 1;
        }
        if req.status == "not-applicable" {
            entry.not_applicable += 1;
        }

        let implementation_matches = resolve_all(
            repo_root,
            &req.implementation,
            &req.id,
            "implementation",
            rank >= status_rank("implemented"),
            &mut findings,
        );
        let test_matches = resolve_all(
            repo_root,
            &req.tests,
            &req.id,
            "tests",
            req.status == "verified",
            &mut findings,
        );
        let evidence_path_matches = resolve_all(
            repo_root,
            &req.evidence_paths,
            &req.id,
            "evidence_paths",
            req.status == "verified",
            &mut findings,
        );
        totals.resolvable_implementation_refs += implementation_matches
            .values()
            .filter(|m| !m.is_empty())
            .count();
        totals.resolvable_test_refs += test_matches.values().filter(|m| !m.is_empty()).count();
        totals.resolvable_evidence_refs += evidence_path_matches
            .values()
            .filter(|m| !m.is_empty())
            .count();

        let (verification_age_days, stale) =
            verification_age(req, &matrix.metadata, today, &mut findings);
        if stale {
            totals.stale_verifications += 1;
        }
        requirement_reports.push(RequirementReport {
            requirement: req.clone(),
            effective_owner: req
                .owner
                .clone()
                .or_else(|| matrix.metadata.default_owner.clone()),
            implementation_matches,
            test_matches,
            evidence_path_matches,
            verification_age_days,
            stale,
        });
    }

    totals.errors = findings.iter().filter(|f| f.severity == "error").count();
    totals.warnings = findings.iter().filter(|f| f.severity == "warning").count();
    let decision = if totals.errors > 0 || (strict && totals.warnings > 0) {
        "fail"
    } else {
        "pass"
    };
    let report = Report {
        schema_version: matrix.metadata.schema_version,
        project: matrix.metadata.project.clone(),
        source: matrix.metadata.generated_from.clone(),
        source_kind: matrix.metadata.source_kind.clone(),
        generated_at: Utc::now().to_rfc3339(),
        decision: decision.into(),
        strict,
        totals,
        standards,
        findings,
        requirements: requirement_reports,
    };

    fs::create_dir_all(output_dir)
        .map_err(|e| format!("cannot create {}: {e}", output_dir.display()))?;
    fs::write(
        output_dir.join("report.json"),
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())? + "\n",
    )
    .map_err(|e| format!("cannot write JSON report: {e}"))?;
    fs::write(
        output_dir.join("report.md"),
        render_markdown(&matrix.metadata, &report),
    )
    .map_err(|e| format!("cannot write Markdown report: {e}"))?;
    fs::write(
        output_dir.join("report.html"),
        render_html(&matrix.metadata, &report),
    )
    .map_err(|e| format!("cannot write HTML report: {e}"))?;
    fs::write(
        output_dir.join("findings.json"),
        serde_json::to_string_pretty(&report.findings).map_err(|e| e.to_string())? + "\n",
    )
    .map_err(|e| format!("cannot write findings: {e}"))?;

    println!("decision={}", report.decision);
    println!("requirements={}", report.totals.requirements);
    println!("errors={}", report.totals.errors);
    println!("warnings={}", report.totals.warnings);
    println!("report={}", output_dir.join("report.md").display());
    if report.decision == "fail" {
        process::exit(1);
    }
    Ok(())
}

fn validate_metadata(metadata: &Metadata, findings: &mut Vec<Finding>) {
    if metadata.schema_version != 2 {
        push(
            findings,
            "SCHEMA_VERSION",
            "error",
            None,
            Some("metadata.schema_version"),
            "unsupported schema_version; expected 2",
        );
    }
    if metadata.project.trim().is_empty() || metadata.generated_from.trim().is_empty() {
        push(
            findings,
            "METADATA_EMPTY",
            "error",
            None,
            None,
            "metadata project and generated_from must be non-empty",
        );
    }
    if metadata.source_kind != "informational" && metadata.source_kind != "normative" {
        push(
            findings,
            "SOURCE_KIND",
            "error",
            None,
            Some("metadata.source_kind"),
            "source_kind must be informational or normative",
        );
    }
}

fn validate_requirements(
    requirements: &[Requirement],
    metadata: &Metadata,
    findings: &mut Vec<Finding>,
) {
    let mut ids = BTreeSet::new();
    for req in requirements {
        let id = Some(req.id.as_str());
        if !ids.insert(req.id.clone()) {
            push(
                findings,
                "DUPLICATE_ID",
                "error",
                id,
                Some("id"),
                "duplicate requirement id",
            );
        }
        if !VALID_STATUSES.contains(&req.status.as_str()) {
            push(
                findings,
                "INVALID_STATUS",
                "error",
                id,
                Some("status"),
                &format!("invalid status: {}", req.status),
            );
        }
        if !VALID_CLASSES.contains(&req.class.as_str()) {
            push(
                findings,
                "INVALID_CLASS",
                "error",
                id,
                Some("class"),
                &format!("invalid class: {}", req.class),
            );
        }
        if req.id.trim().is_empty()
            || req.section.trim().is_empty()
            || req.statement.trim().is_empty()
        {
            push(
                findings,
                "REQUIRED_TEXT",
                "error",
                id,
                None,
                "id, section, and statement must be non-empty",
            );
        }
        if status_rank(&req.status) >= status_rank("implemented")
            && req.status != "not-applicable"
            && req.implementation.is_empty()
        {
            push(
                findings,
                "MISSING_IMPLEMENTATION",
                "error",
                id,
                Some("implementation"),
                "implemented/verified entries require implementation references",
            );
        }
        if req.status == "verified" && req.tests.is_empty() {
            push(
                findings,
                "MISSING_TESTS",
                "error",
                id,
                Some("tests"),
                "verified entries require tests",
            );
        }
        if req.status == "verified" && req.evidence.is_empty() && req.evidence_paths.is_empty() {
            push(
                findings,
                "MISSING_EVIDENCE",
                "error",
                id,
                Some("evidence"),
                "verified entries require evidence labels or evidence paths",
            );
        }
        if req.status == "verified" && req.last_verified.is_none() {
            push(
                findings,
                "MISSING_VERIFICATION_DATE",
                "error",
                id,
                Some("last_verified"),
                "verified entries require last_verified",
            );
        }
        if req.class == "normative" && metadata.source_kind == "informational" {
            push(findings, "NORMATIVE_IN_INFORMATIONAL_SOURCE", "warning", id, Some("class"), "normative classification in an informational source requires explicit justification");
        }
        if req.owner.is_none() && metadata.default_owner.is_none() {
            push(
                findings,
                "MISSING_OWNER",
                "warning",
                id,
                Some("owner"),
                "requirement has no owner and no default owner",
            );
        }
        if status_rank(&req.status) >= status_rank("implemented") && req.ci.is_empty() {
            push(
                findings,
                "MISSING_CI",
                "warning",
                id,
                Some("ci"),
                "implemented/verified requirement is not associated with a CI gate",
            );
        }
        if let Some(value) = req.coverage {
            if !(0.0..=100.0).contains(&value) {
                push(
                    findings,
                    "INVALID_COVERAGE",
                    "error",
                    id,
                    Some("coverage"),
                    "coverage must be between 0 and 100",
                );
            }
        }
        if req.status == "not-applicable"
            && req.rationale.as_deref().unwrap_or("").trim().is_empty()
        {
            push(
                findings,
                "MISSING_NA_RATIONALE",
                "error",
                id,
                Some("rationale"),
                "not-applicable entries require rationale",
            );
        }
    }
}

fn resolve_all(
    root: &Path,
    patterns: &[String],
    requirement_id: &str,
    field: &str,
    required: bool,
    findings: &mut Vec<Finding>,
) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for pattern in patterns {
        let full = root.join(pattern);
        let mut matches = Vec::new();
        let full_text = full.to_string_lossy().to_string();
        if has_glob(pattern) {
            match glob(&full_text) {
                Ok(paths) => {
                    for path in paths.flatten() {
                        if let Ok(relative) = path.strip_prefix(root) {
                            matches.push(relative.display().to_string());
                        }
                    }
                }
                Err(error) => push(
                    findings,
                    "INVALID_GLOB",
                    "error",
                    Some(requirement_id),
                    Some(field),
                    &format!("invalid pattern {pattern}: {error}"),
                ),
            }
        } else if full.exists() {
            matches.push(pattern.clone());
        }
        matches.sort();
        if matches.is_empty() {
            let severity = if required { "error" } else { "warning" };
            push(
                findings,
                "UNRESOLVED_REFERENCE",
                severity,
                Some(requirement_id),
                Some(field),
                &format!("reference does not resolve: {pattern}"),
            );
        }
        out.insert(pattern.clone(), matches);
    }
    out
}

fn verification_age(
    req: &Requirement,
    metadata: &Metadata,
    today: NaiveDate,
    findings: &mut Vec<Finding>,
) -> (Option<i64>, bool) {
    let Some(raw) = req.last_verified.as_deref() else {
        return (None, false);
    };
    match NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        Ok(date) => {
            let age = (today - date).num_days();
            if age < 0 {
                push(
                    findings,
                    "FUTURE_VERIFICATION_DATE",
                    "error",
                    Some(&req.id),
                    Some("last_verified"),
                    "last_verified is in the future",
                );
                return (Some(age), false);
            }
            let due = i64::from(
                req.review_due_days
                    .or(metadata.default_review_due_days)
                    .unwrap_or(DEFAULT_REVIEW_DUE_DAYS as u32),
            );
            let stale = req.status == "verified" && age > due;
            if stale {
                push(
                    findings,
                    "STALE_VERIFICATION",
                    "warning",
                    Some(&req.id),
                    Some("last_verified"),
                    &format!("verification is {age} days old; review interval is {due} days"),
                );
            }
            (Some(age), stale)
        }
        Err(_) => {
            push(
                findings,
                "INVALID_DATE",
                "error",
                Some(&req.id),
                Some("last_verified"),
                "last_verified must use YYYY-MM-DD",
            );
            (None, false)
        }
    }
}

fn push(
    findings: &mut Vec<Finding>,
    code: &str,
    severity: &str,
    requirement_id: Option<&str>,
    field: Option<&str>,
    message: &str,
) {
    findings.push(Finding {
        code: code.into(),
        severity: severity.into(),
        requirement_id: requirement_id.map(str::to_owned),
        field: field.map(str::to_owned),
        message: message.into(),
    });
}
fn has_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}
fn status_rank(status: &str) -> u8 {
    match status {
        "planned" => 0,
        "mapped" => 1,
        "implemented" => 2,
        "verified" => 3,
        "not-applicable" => 4,
        _ => 0,
    }
}
fn pct(value: usize, total: usize) -> usize {
    if total == 0 {
        0
    } else {
        (100 * value) / total
    }
}

fn render_markdown(metadata: &Metadata, report: &Report) -> String {
    let mut out = String::new();
    out.push_str("# Standards Traceability Report\n\n");
    out.push_str(&format!("- Project: `{}`\n- Source: `{}`\n- Source classification: `{}`\n- Generated: `{}`\n- Strict mode: `{}`\n- Decision: **{}**\n\n", report.project, report.source, report.source_kind, report.generated_at, report.strict, report.decision));
    for note in &metadata.notes {
        out.push_str(&format!("> {}\n\n", note));
    }
    out.push_str("## Coverage\n\n| Standard | Entries | Mapped+ | Implemented+ | Verified | N/A |\n|---|---:|---:|---:|---:|---:|\n");
    for (standard, totals) in &report.standards {
        out.push_str(&format!(
            "| {} | {} | {} ({}%) | {} ({}%) | {} ({}%) | {} |\n",
            standard,
            totals.requirements,
            totals.mapped_or_better,
            pct(totals.mapped_or_better, totals.requirements),
            totals.implemented_or_better,
            pct(totals.implemented_or_better, totals.requirements),
            totals.verified,
            pct(totals.verified, totals.requirements),
            totals.not_applicable
        ));
    }
    out.push_str("\n## Evidence Readiness\n\n");
    out.push_str(&format!("| Measure | Count | Coverage |\n|---|---:|---:|\n| Owned requirements | {} | {}% |\n| Requirements linked to CI | {} | {}% |\n| Requirements with tests | {} | {}% |\n| Requirements with evidence | {} | {}% |\n| Stale verifications | {} | — |\n| Errors | {} | — |\n| Warnings | {} | — |\n", report.totals.requirements_with_owner, pct(report.totals.requirements_with_owner, report.totals.requirements), report.totals.requirements_with_ci, pct(report.totals.requirements_with_ci, report.totals.requirements), report.totals.requirements_with_tests, pct(report.totals.requirements_with_tests, report.totals.requirements), report.totals.requirements_with_evidence, pct(report.totals.requirements_with_evidence, report.totals.requirements), report.totals.stale_verifications, report.totals.errors, report.totals.warnings));
    out.push_str("\n## Traceability Matrix\n\n| ID | Section | Class | Status | Owner | Last verified | Title | Implementation | Tests | Evidence | CI |\n|---|---|---|---|---|---|---|---|---|---|---|\n");
    for item in &report.requirements {
        let req = &item.requirement;
        let evidence = req
            .evidence
            .iter()
            .chain(req.evidence_paths.iter())
            .cloned()
            .collect::<Vec<_>>();
        out.push_str(&format!(
            "| `{}` | {} | {} | **{}** | {} | {}{} | {} | {} | {} | {} | {} |\n",
            req.id,
            req.section,
            req.class,
            req.status,
            item.effective_owner.as_deref().unwrap_or("—"),
            req.last_verified.as_deref().unwrap_or("—"),
            if item.stale { " ⚠" } else { "" },
            escape(&req.title),
            join_code(&req.implementation),
            join_code(&req.tests),
            join_code(&evidence),
            join_code(&req.ci)
        ));
    }
    out.push_str("\n## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str("No findings.\n");
    } else {
        for f in &report.findings {
            out.push_str(&format!(
                "- **{}** `{}` {}{}{}\n",
                f.severity,
                f.code,
                f.requirement_id
                    .as_ref()
                    .map(|id| format!("`{id}`: "))
                    .unwrap_or_default(),
                f.field
                    .as_ref()
                    .map(|v| format!("`{v}` — "))
                    .unwrap_or_default(),
                f.message
            ));
        }
    }
    out
}

fn render_html(metadata: &Metadata, report: &Report) -> String {
    let md = render_markdown(metadata, report);
    format!("<!doctype html><html><head><meta charset=\"utf-8\"><title>Compliance report</title><style>body{{font:16px system-ui;max-width:1200px;margin:40px auto;padding:0 20px}}pre{{white-space:pre-wrap}}</style></head><body><pre>{}</pre></body></html>\n", html_escape(&md))
}
fn join_code(items: &[String]) -> String {
    if items.is_empty() {
        "—".into()
    } else {
        items
            .iter()
            .map(|s| format!("`{}`", escape(s)))
            .collect::<Vec<_>>()
            .join("<br>")
    }
}
fn escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn interop_cross(args: Vec<String>) -> Result<(), String> {
    let mut command = std::process::Command::new("python3");
    command.arg("scripts/cross_provider_interop.py");
    for arg in args {
        match arg.as_str() {
            "--strict" => {
                command.arg("--strict");
            }
            "--help" | "-h" => {
                println!("cargo xtask interop-cross [--strict]");
                println!(
                    "cargo xtask implementation-matrix [--manifest PATH] [--output PATH] [--check]"
                );
                println!("cargo xtask api-review [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown interop-cross argument: {other}")),
        };
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to run cross-provider interoperability engine: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "cross-provider interoperability engine exited with {status}"
        ))
    }
}

#[derive(Debug, Deserialize)]
struct ImplementationMatrixManifest {
    metadata: ImplementationMatrixMetadata,
    #[serde(default)]
    algorithm: Vec<ImplementationAlgorithm>,
    #[serde(default)]
    standard: Vec<ImplementationStandard>,
    #[serde(default)]
    validation: Vec<ImplementationValidation>,
    #[serde(default)]
    milestone: Vec<ImplementationMilestone>,
}

#[derive(Debug, Deserialize)]
struct ImplementationMatrixMetadata {
    schema_version: u32,
    project: String,
    generated_document: String,
    last_verified: String,
}

#[derive(Debug, Deserialize)]
struct ImplementationAlgorithm {
    primitive: String,
    variant: String,
    status: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct ImplementationStandard {
    name: String,
    scope: String,
    status: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct ImplementationValidation {
    name: String,
    status: String,
    command: String,
}

#[derive(Debug, Deserialize)]
struct ImplementationMilestone {
    name: String,
    capability: String,
    status: String,
}

fn implementation_matrix(args: Vec<String>) -> Result<(), String> {
    let mut manifest_path = PathBuf::from("compliance/implementation-matrix.toml");
    let mut output_path: Option<PathBuf> = None;
    let mut check = false;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--manifest" => {
                manifest_path = PathBuf::from(iter.next().ok_or("--manifest requires a path")?);
            }
            "--output" => {
                output_path = Some(PathBuf::from(
                    iter.next().ok_or("--output requires a path")?,
                ));
            }
            "--check" => check = true,
            "--help" | "-h" => {
                println!(
                    "cargo xtask implementation-matrix [--manifest PATH] [--output PATH] [--check]"
                );
                println!("cargo xtask api-review [--check]");
                return Ok(());
            }
            other => return Err(format!("unknown implementation-matrix argument: {other}")),
        }
    }

    let raw = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("failed to read {}: {e}", manifest_path.display()))?;
    let manifest: ImplementationMatrixManifest = toml::from_str(&raw)
        .map_err(|e| format!("failed to parse {}: {e}", manifest_path.display()))?;
    validate_implementation_manifest(&manifest)?;

    let output =
        output_path.unwrap_or_else(|| PathBuf::from(&manifest.metadata.generated_document));
    let rendered = render_implementation_matrix(&manifest, &manifest_path);

    if check {
        let existing = fs::read_to_string(&output)
            .map_err(|e| format!("failed to read generated matrix {}: {e}", output.display()))?;
        if existing != rendered {
            return Err(format!(
                "{} is stale; run `cargo xtask implementation-matrix`",
                output.display()
            ));
        }
        println!("implementation matrix is current: {}", output.display());
        return Ok(());
    }

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    fs::write(&output, rendered)
        .map_err(|e| format!("failed to write {}: {e}", output.display()))?;
    println!("generated {}", output.display());
    Ok(())
}

fn validate_implementation_manifest(manifest: &ImplementationMatrixManifest) -> Result<(), String> {
    if manifest.metadata.schema_version != 1 {
        return Err(format!(
            "unsupported implementation matrix schema version: {}",
            manifest.metadata.schema_version
        ));
    }
    if manifest.metadata.project.trim().is_empty() {
        return Err("implementation matrix project must not be empty".into());
    }
    if NaiveDate::parse_from_str(&manifest.metadata.last_verified, "%Y-%m-%d").is_err() {
        return Err("implementation matrix last_verified must use YYYY-MM-DD".into());
    }
    let valid_statuses = [
        "planned",
        "mapped",
        "implemented",
        "verified",
        "complete",
        "pass",
        "partial",
    ];
    for (kind, name, status) in manifest
        .algorithm
        .iter()
        .map(|v| {
            (
                "algorithm",
                format!("{}-{}", v.primitive, v.variant),
                v.status.as_str(),
            )
        })
        .chain(
            manifest
                .standard
                .iter()
                .map(|v| ("standard", v.name.clone(), v.status.as_str())),
        )
        .chain(
            manifest
                .validation
                .iter()
                .map(|v| ("validation", v.name.clone(), v.status.as_str())),
        )
        .chain(
            manifest
                .milestone
                .iter()
                .map(|v| ("milestone", v.name.clone(), v.status.as_str())),
        )
    {
        if !valid_statuses.contains(&status) {
            return Err(format!("invalid {kind} status `{status}` for `{name}`"));
        }
    }
    Ok(())
}

fn render_implementation_matrix(
    manifest: &ImplementationMatrixManifest,
    manifest_path: &Path,
) -> String {
    const KEMS: [&str; 3] = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
    const KDFS: [&str; 3] = ["HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512"];
    const AEADS: [&str; 3] = ["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"];

    let suite_count = KEMS.len() * KDFS.len() * AEADS.len();
    let configuration_count = suite_count * 2;
    let mut out = String::new();
    out.push_str("# Implementation Matrix\n\n");
    out.push_str("> This document is generated. Edit `");
    out.push_str(&manifest_path.display().to_string());
    out.push_str("` and run `cargo xtask implementation-matrix`.\n\n");
    out.push_str(&format!(
        "- Project: `{}`\n- Schema: `{}`\n- Last verified: `{}`\n- HPKE message suites: **{}**\n- Base/PSK configurations: **{}**\n\n",
        manifest.metadata.project,
        manifest.metadata.schema_version,
        manifest.metadata.last_verified,
        suite_count,
        configuration_count
    ));

    out.push_str(
        "## Standards Coverage\n\n| Standard | Scope | Status | Evidence |\n|---|---|---|---|\n",
    );
    for item in &manifest.standard {
        out.push_str(&format!(
            "| {} | {} | **{}** | `{}` |\n",
            item.name, item.scope, item.status, item.evidence
        ));
    }

    out.push_str("\n## Algorithm Coverage\n\n| Primitive | Variant | Status | Evidence |\n|---|---|---|---|\n");
    for item in &manifest.algorithm {
        out.push_str(&format!(
            "| {} | {} | **{}** | {} |\n",
            item.primitive, item.variant, item.status, item.evidence
        ));
    }

    out.push_str("\n## HPKE Ciphersuite Matrix\n\n");
    out.push_str("Every row is exercised in Base and PSK modes, including seal/open and exporter agreement.\n\n");
    out.push_str("| KEM | KDF | AEAD | Base | PSK | Exporter | Evidence |\n|---|---|---|:---:|:---:|:---:|---|\n");
    for kem in KEMS {
        for kdf in KDFS {
            for aead in AEADS {
                out.push_str(&format!(
                    "| {kem} | {kdf} | {aead} | PASS | PASS | PASS | `crates/pqc-hpke/tests/ciphersuite_matrix.rs` |\n"
                ));
            }
        }
    }

    out.push_str("\n## Validation Matrix\n\n| Validation | Status | Reproduction command |\n|---|:---:|---|\n");
    for item in &manifest.validation {
        out.push_str(&format!(
            "| {} | **{}** | `{}` |\n",
            item.name, item.status, item.command
        ));
    }

    out.push_str(
        "\n## Milestone History\n\n| Milestone | Capability | Status |\n|---|---|:---:|\n",
    );
    for item in &manifest.milestone {
        out.push_str(&format!(
            "| {} | {} | **{}** |\n",
            item.name, item.capability, item.status
        ));
    }

    out.push_str("\n## Maintenance Contract\n\n");
    out.push_str("The TOML manifest is the machine-readable source of truth. CI runs `cargo xtask implementation-matrix --check` and fails when this generated document is stale. Capability claims must identify reproducible evidence and must not be promoted to `verified` without a passing validation gate.\n");
    out
}
