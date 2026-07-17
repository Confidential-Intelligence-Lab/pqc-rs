#!/usr/bin/env python3
"""Standards Engine v2 for pqc-rfc9958-rs.

The engine treats TOML traceability files as the source of truth, normalizes
legacy metadata, discovers standards automatically, and emits stable JSON,
Markdown, generated documentation, and Graphviz dependency graphs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import pathlib
import re
import sys
import tomllib
from dataclasses import dataclass, field
from typing import Any

ENGINE_SCHEMA_VERSION = 2
SUPPORTED_DOCUMENT_SCHEMA_VERSIONS = {1, 2}
STATUS_RANK = {
    "planned": 0,
    "mapped": 1,
    "implemented": 2,
    "verified": 3,
    "not-applicable": 4,
    "deprecated": 5,
}
VALID_CLASSES = {
    "shall", "should", "may", "validation", "informative",
    "recommendation", "normative",
}
VALID_CLASSIFICATIONS = {"informational", "normative", "validation", "guidance"}
PATH_HINT = re.compile(r"(^|/)(src|tests?|docs?|scripts?|compliance|evidence|target)/|\.(md|json|toml|rs|txt|pdf)$")


def load_toml(path: pathlib.Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def relative(root: pathlib.Path, path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def resolve_matches(root: pathlib.Path, pattern: str) -> list[str]:
    candidate = root / pattern
    if any(char in pattern for char in "*?["):
        return sorted(relative(root, pathlib.Path(item)) for item in glob.glob(str(candidate), recursive=True))
    return [pattern] if candidate.exists() else []


def normalized_classification(value: Any) -> str:
    raw = str(value or "unknown").strip().lower()
    aliases = {
        "informative": "informational",
        "information": "informational",
        "recommendation": "guidance",
        "recommended": "guidance",
    }
    return aliases.get(raw, raw)


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "document"


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    document_id: str | None = None
    requirement_id: str | None = None
    field: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "document_id": self.document_id,
            "requirement_id": self.requirement_id,
            "field": self.field,
        }


@dataclass
class DocumentSpec:
    id: str
    title: str
    classification: str
    source: pathlib.Path
    source_display: str
    status: str = "active"
    issuer: str | None = None
    published: str | None = None
    documentation: str | None = None
    origin: str = "discovered"
    catalog_metadata: dict[str, Any] = field(default_factory=dict)


class EngineError(Exception):
    pass


def catalog_documents(root: pathlib.Path, catalog_path: pathlib.Path) -> tuple[dict[pathlib.Path, DocumentSpec], list[Finding]]:
    specs: dict[pathlib.Path, DocumentSpec] = {}
    findings: list[Finding] = []
    if not catalog_path.exists():
        return specs, findings
    try:
        catalog = load_toml(catalog_path)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        findings.append(Finding("error", "CATALOG_PARSE_ERROR", str(exc), field=str(catalog_path)))
        return specs, findings

    seen_ids: set[str] = set()
    for entry in catalog.get("document", []):
        document_id = str(entry.get("id", "")).strip()
        if not document_id:
            findings.append(Finding("error", "EMPTY_DOCUMENT_ID", "Catalog document is missing id"))
            continue
        if document_id in seen_ids:
            findings.append(Finding("error", "DUPLICATE_DOCUMENT", f"Duplicate catalog document id {document_id}", document_id=document_id))
        seen_ids.add(document_id)

        # v1 uses source for the local data file. A1.3 briefly used data for the
        # local file and source for a DOI. Accept both, but normalize internally.
        local_source = entry.get("data") or entry.get("source")
        if not local_source or str(local_source).startswith(("http://", "https://")):
            findings.append(Finding("error", "MISSING_DOCUMENT_SOURCE", "Catalog entry does not identify a local traceability TOML file", document_id=document_id, field="source"))
            continue
        source = (root / str(local_source)).resolve()
        classification = normalized_classification(entry.get("classification") or entry.get("kind"))
        spec = DocumentSpec(
            id=document_id,
            title=str(entry.get("title") or document_id),
            classification=classification,
            source=source,
            source_display=relative(root, source),
            status=str(entry.get("status") or "active"),
            issuer=entry.get("issuer"),
            published=entry.get("published"),
            documentation=entry.get("documentation"),
            origin="catalog",
            catalog_metadata=dict(entry),
        )
        if source in specs:
            findings.append(Finding("error", "DUPLICATE_DOCUMENT_SOURCE", f"Multiple catalog entries reference {spec.source_display}", document_id=document_id))
        specs[source] = spec
    return specs, findings


def infer_document(root: pathlib.Path, path: pathlib.Path, data: dict[str, Any]) -> DocumentSpec:
    meta = data.get("metadata", {})
    document_id = str(
        data.get("standard")
        or meta.get("standard")
        or meta.get("generated_from")
        or path.stem
    ).replace(" ", "")
    title = str(data.get("title") or meta.get("title") or meta.get("generated_from") or document_id)
    classification = normalized_classification(
        data.get("classification") or data.get("kind") or meta.get("classification") or meta.get("source_kind")
    )
    return DocumentSpec(
        id=document_id,
        title=title,
        classification=classification,
        source=path.resolve(),
        source_display=relative(root, path),
        issuer=data.get("issuer") or meta.get("issuer"),
        published=data.get("published") or meta.get("published"),
        origin="discovered",
    )


def discover_documents(root: pathlib.Path, catalog_path: pathlib.Path) -> tuple[list[DocumentSpec], list[Finding]]:
    catalog_specs, findings = catalog_documents(root, catalog_path)
    candidates: set[pathlib.Path] = set(catalog_specs)
    matrix = root / "compliance" / "matrix.toml"
    if matrix.exists():
        candidates.add(matrix.resolve())
    standards_dir = root / "compliance" / "standards"
    if standards_dir.exists():
        candidates.update(path.resolve() for path in standards_dir.glob("*.toml"))

    documents: list[DocumentSpec] = []
    seen_ids: dict[str, pathlib.Path] = {}
    for path in sorted(candidates, key=lambda item: str(item)):
        if not path.exists():
            spec = catalog_specs[path]
            findings.append(Finding("error", "MISSING_DOCUMENT_SOURCE", f"Traceability source does not exist: {spec.source_display}", document_id=spec.id))
            continue
        try:
            data = load_toml(path)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            findings.append(Finding("error", "DOCUMENT_PARSE_ERROR", str(exc), field=relative(root, path)))
            continue
        inferred = infer_document(root, path, data)
        spec = catalog_specs.get(path, inferred)
        # Fill missing/legacy catalog metadata from the document itself.
        if spec.classification == "unknown":
            spec.classification = inferred.classification
        if spec.title == spec.id and inferred.title:
            spec.title = inferred.title
        if spec.id in seen_ids:
            findings.append(Finding("error", "DUPLICATE_DOCUMENT", f"Document id {spec.id} appears in both {relative(root, seen_ids[spec.id])} and {relative(root, path)}", document_id=spec.id))
        else:
            seen_ids[spec.id] = path
        documents.append(spec)
    return documents, findings


def document_payload(data: dict[str, Any], spec: DocumentSpec) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    meta = dict(data.get("metadata", {}))
    if not meta:
        meta = {
            "schema_version": data.get("schema_version", 1),
            "generated_from": data.get("standard", spec.id),
            "source_kind": data.get("classification", spec.classification),
            "notes": data.get("notes", []),
        }
    requirements = data.get("requirement", [])
    return meta, requirements


def validate_document(root: pathlib.Path, spec: DocumentSpec, strict: bool, structural_only: bool) -> dict[str, Any]:
    data = load_toml(spec.source)
    meta, requirements = document_payload(data, spec)
    findings: list[Finding] = []
    schema_version = int(meta.get("schema_version", data.get("schema_version", 1)))
    if schema_version not in SUPPORTED_DOCUMENT_SCHEMA_VERSIONS:
        findings.append(Finding("error", "UNSUPPORTED_SCHEMA_VERSION", f"Unsupported document schema version {schema_version}; supported versions are {sorted(SUPPORTED_DOCUMENT_SCHEMA_VERSIONS)}", document_id=spec.id, field="schema_version"))

    classification = normalized_classification(spec.classification or meta.get("source_kind"))
    if classification not in VALID_CLASSIFICATIONS:
        findings.append(Finding("error" if strict else "warning", "UNKNOWN_CLASSIFICATION", f"Unknown document classification: {classification}", document_id=spec.id, field="classification"))

    rows: list[dict[str, Any]] = []
    local_ids: set[str] = set()
    today = dt.date.today()
    default_owner = meta.get("default_owner")
    default_review_due = int(meta.get("default_review_due_days", 180))

    for raw in requirements:
        req = dict(raw)
        rid = str(req.get("id", "")).strip()
        if not rid:
            findings.append(Finding("error", "EMPTY_REQUIREMENT_ID", "Requirement id must not be empty", document_id=spec.id))
        elif rid in local_ids:
            findings.append(Finding("error", "DUPLICATE_REQUIREMENT_ID", f"Duplicate requirement id {rid}", document_id=spec.id, requirement_id=rid))
        local_ids.add(rid)

        status = str(req.get("status", "")).lower()
        req_class = str(req.get("class", "")).lower()
        if status not in STATUS_RANK:
            findings.append(Finding("error", "INVALID_STATUS", f"Invalid status {status!r}", document_id=spec.id, requirement_id=rid, field="status"))
        if req_class not in VALID_CLASSES:
            findings.append(Finding("error", "INVALID_REQUIREMENT_CLASS", f"Invalid requirement class {req_class!r}", document_id=spec.id, requirement_id=rid, field="class"))

        impl = {pattern: resolve_matches(root, pattern) for pattern in req.get("implementation", [])}
        tests = {pattern: resolve_matches(root, pattern) for pattern in req.get("tests", [])}
        evidence_paths = {pattern: resolve_matches(root, pattern) for pattern in req.get("evidence_paths", [])}
        references = {ref: resolve_matches(root, ref) for ref in req.get("references", []) if PATH_HINT.search(str(ref))}

        rank = STATUS_RANK.get(status, 0)
        if not structural_only and rank >= STATUS_RANK["implemented"] and status not in {"not-applicable", "deprecated"}:
            if not impl or any(not matches for matches in impl.values()):
                findings.append(Finding("error", "IMPLEMENTATION_UNRESOLVED", "Implemented requirement has unresolved implementation references", document_id=spec.id, requirement_id=rid, field="implementation"))
        if not structural_only and status == "verified":
            if not tests or any(not matches for matches in tests.values()):
                findings.append(Finding("error", "TEST_UNRESOLVED", "Verified requirement has unresolved test references", document_id=spec.id, requirement_id=rid, field="tests"))
            if evidence_paths and any(not matches for matches in evidence_paths.values()):
                findings.append(Finding("error", "EVIDENCE_PATH_UNRESOLVED", "Verified requirement has unresolved evidence paths", document_id=spec.id, requirement_id=rid, field="evidence_paths"))
            if not req.get("evidence") and not evidence_paths:
                findings.append(Finding("error", "MISSING_EVIDENCE", "Verified requirement must name evidence or evidence paths", document_id=spec.id, requirement_id=rid, field="evidence"))
            if not req.get("last_verified"):
                findings.append(Finding("error", "MISSING_VERIFICATION_DATE", "Verified requirement must include last_verified", document_id=spec.id, requirement_id=rid, field="last_verified"))
        if not structural_only and any(not matches for matches in references.values()):
            findings.append(Finding("error" if strict else "warning", "REFERENCE_PATH_UNRESOLVED", "Path-like reference does not resolve", document_id=spec.id, requirement_id=rid, field="references"))

        verification_age = None
        stale = False
        if req.get("last_verified"):
            try:
                verified_date = dt.date.fromisoformat(str(req["last_verified"]))
                verification_age = (today - verified_date).days
                due = int(req.get("review_due_days", default_review_due))
                stale = verification_age > due
                if stale:
                    findings.append(Finding("warning", "STALE_VERIFICATION", f"Verification is {verification_age} days old; review is due after {due} days", document_id=spec.id, requirement_id=rid, field="last_verified"))
            except ValueError:
                findings.append(Finding("error", "INVALID_VERIFICATION_DATE", "last_verified must use YYYY-MM-DD", document_id=spec.id, requirement_id=rid, field="last_verified"))

        effective_owner = req.get("owner") or default_owner
        row = {
            **req,
            "id": rid,
            "status": status,
            "class": req_class,
            "effective_owner": effective_owner,
            "implementation_matches": impl,
            "test_matches": tests,
            "evidence_path_matches": evidence_paths,
            "reference_path_matches": references,
            "verification_age_days": verification_age,
            "stale": stale,
        }
        rows.append(row)

    counts = compute_counts(rows, findings)
    decision = "fail" if counts["errors"] or (strict and counts["warnings"]) else "pass"
    return {
        "schema_version": ENGINE_SCHEMA_VERSION,
        "document": {
            "id": spec.id,
            "title": spec.title,
            "classification": classification,
            "source": spec.source_display,
            "status": spec.status,
            "issuer": spec.issuer,
            "published": spec.published,
            "origin": spec.origin,
            "input_schema_version": schema_version,
        },
        "decision": decision,
        "strict": strict,
        "metrics": counts,
        "requirements": rows,
        "findings": [finding.as_dict() for finding in findings],
    }


def compute_counts(rows: list[dict[str, Any]], findings: list[Finding]) -> dict[str, Any]:
    total = len(rows)
    mapped = sum(STATUS_RANK.get(row.get("status", ""), 0) >= 1 for row in rows)
    implemented = sum(STATUS_RANK.get(row.get("status", ""), 0) >= 2 and row.get("status") not in {"not-applicable", "deprecated"} for row in rows)
    verified = sum(row.get("status") == "verified" for row in rows)
    with_tests = sum(bool(row.get("tests")) for row in rows)
    with_evidence = sum(bool(row.get("evidence") or row.get("evidence_paths")) for row in rows)
    with_owner = sum(bool(row.get("effective_owner")) for row in rows)
    with_ci = sum(bool(row.get("ci")) for row in rows)
    ages = [row["verification_age_days"] for row in rows if row.get("verification_age_days") is not None]
    return {
        "requirements": total,
        "mapped_or_better": mapped,
        "implemented_or_better": implemented,
        "verified": verified,
        "not_applicable": sum(row.get("status") == "not-applicable" for row in rows),
        "deprecated": sum(row.get("status") == "deprecated" for row in rows),
        "coverage_percent": round((verified / total * 100.0), 2) if total else 100.0,
        "implementation_coverage_percent": round((implemented / total * 100.0), 2) if total else 100.0,
        "owner_coverage_percent": round((with_owner / total * 100.0), 2) if total else 100.0,
        "ci_coverage_percent": round((with_ci / total * 100.0), 2) if total else 100.0,
        "test_coverage_percent": round((with_tests / total * 100.0), 2) if total else 100.0,
        "evidence_coverage_percent": round((with_evidence / total * 100.0), 2) if total else 100.0,
        "missing_tests": total - with_tests,
        "missing_evidence": total - with_evidence,
        "missing_owner": total - with_owner,
        "missing_ci": total - with_ci,
        "stale_verifications": sum(bool(row.get("stale")) for row in rows),
        "average_verification_age_days": round(sum(ages) / len(ages), 1) if ages else None,
        "errors": sum(finding.severity == "error" for finding in findings),
        "warnings": sum(finding.severity == "warning" for finding in findings),
    }


def markdown_report(result: dict[str, Any]) -> str:
    doc = result["document"]
    m = result["metrics"]
    lines = [
        f"# {doc['id']} Traceability Report", "",
        f"- Classification: `{doc['classification']}`",
        f"- Decision: **{result['decision']}**",
        f"- Requirements: {m['requirements']}",
        f"- Mapped or better: {m['mapped_or_better']}",
        f"- Implemented or better: {m['implemented_or_better']}",
        f"- Verified: {m['verified']}",
        f"- Verification coverage: {m['coverage_percent']}%", "",
        "## Readiness metrics", "",
        "| Metric | Value |", "|---|---:|",
        f"| Owner coverage | {m['owner_coverage_percent']}% |",
        f"| CI coverage | {m['ci_coverage_percent']}% |",
        f"| Test metadata coverage | {m['test_coverage_percent']}% |",
        f"| Evidence metadata coverage | {m['evidence_coverage_percent']}% |",
        f"| Stale verifications | {m['stale_verifications']} |", "",
        "## Requirements", "",
        "| ID | Section | Class | Status | Title | Owner | CI |",
        "|---|---|---|---|---|---|---|",
    ]
    for req in result["requirements"]:
        title = str(req.get("title", "")).replace("|", "\\|")
        owner = str(req.get("effective_owner") or "—").replace("|", "\\|")
        ci = "<br>".join(f"`{value}`" for value in req.get("ci", [])) or "—"
        lines.append(f"| `{req.get('id','')}` | {req.get('section','')} | {req.get('class','')} | **{req.get('status','')}** | {title} | {owner} | {ci} |")
    lines += ["", "## Findings", ""]
    if result["findings"]:
        for finding in result["findings"]:
            target = finding.get("requirement_id") or finding.get("document_id") or ""
            lines.append(f"- **{finding['severity']}** `{finding['code']}` `{target}` — {finding['message']}")
    else:
        lines.append("No findings.")
    return "\n".join(lines) + "\n"


def generated_documentation(result: dict[str, Any]) -> str:
    doc = result["document"]
    lines = [
        f"# {doc['title']}", "",
        "> Generated by `scripts/standards_engine.py`; edit the corresponding TOML source, not this file.", "",
        f"- Identifier: `{doc['id']}`",
        f"- Classification: `{doc['classification']}`",
        f"- Traceability source: `{doc['source']}`",
        f"- Current decision: **{result['decision']}**", "",
        "## Traceability requirements", "",
    ]
    for req in result["requirements"]:
        lines += [
            f"### {req.get('id', '')} — {req.get('title', '')}", "",
            f"**Section:** {req.get('section', '')}  ",
            f"**Class:** `{req.get('class', '')}`  ",
            f"**Status:** `{req.get('status', '')}`  ",
            f"**Owner:** {req.get('effective_owner') or 'Unassigned'}", "",
        ]
        if req.get("statement"):
            lines += [str(req["statement"]), ""]
        if req.get("implementation"):
            lines += ["Implementation: " + ", ".join(f"`{p}`" for p in req["implementation"]), ""]
        if req.get("tests"):
            lines += ["Tests: " + ", ".join(f"`{p}`" for p in req["tests"]), ""]
        if req.get("evidence"):
            lines += ["Evidence: " + "; ".join(str(v) for v in req["evidence"]), ""]
    lines += ["## Claim boundary", "", "This generated documentation records repository traceability. It is not a NIST CAVP, CMVP, or FIPS 140-3 validation certificate.", ""]
    return "\n".join(lines)


def dependency_graph(result: dict[str, Any]) -> str:
    doc_id = result["document"]["id"]
    lines = ["digraph standards_traceability {", "  rankdir=LR;", "  node [shape=box];", f'  "{doc_id}" [shape=folder];']
    for index, req in enumerate(result["requirements"]):
        rid = req.get("id", f"requirement-{index}")
        safe_rid = rid.replace('"', '\\"')
        lines.append(f'  "{doc_id}" -> "{safe_rid}";')
        for field_name, prefix in (("implementation", "impl"), ("tests", "test"), ("evidence_paths", "evidence"), ("ci", "ci")):
            for item_index, value in enumerate(req.get(field_name, [])):
                node = f"{prefix}:{index}:{item_index}"
                label = str(value).replace('"', '\\"')
                shape = "ellipse" if field_name == "ci" else "note"
                lines.append(f'  "{node}" [shape={shape}, label="{label}"];')
                lines.append(f'  "{safe_rid}" -> "{node}";')
    lines.append("}")
    return "\n".join(lines) + "\n"


def aggregate_metrics(results: list[dict[str, Any]], findings: list[Finding]) -> dict[str, Any]:
    keys = ["requirements", "mapped_or_better", "implemented_or_better", "verified", "missing_tests", "missing_evidence", "missing_owner", "missing_ci", "stale_verifications", "errors", "warnings"]
    totals = {key: sum(int(result["metrics"].get(key, 0)) for result in results) for key in keys}
    totals["errors"] += sum(f.severity == "error" for f in findings)
    totals["warnings"] += sum(f.severity == "warning" for f in findings)
    total = totals["requirements"]
    totals["verification_coverage_percent"] = round(totals["verified"] / total * 100.0, 2) if total else 100.0
    totals["implementation_coverage_percent"] = round(totals["implemented_or_better"] / total * 100.0, 2) if total else 100.0
    return totals


def aggregate_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Standards Engine Report", "",
        f"- Engine schema: `{summary['schema_version']}`",
        f"- Decision: **{summary['decision']}**",
        f"- Strict mode: `{summary['strict']}`", "",
        "| Document | Classification | Requirements | Mapped+ | Implemented+ | Verified | Coverage | Decision |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for result in summary["documents"]:
        doc, m = result["document"], result["metrics"]
        lines.append(f"| {doc['id']} | {doc['classification']} | {m['requirements']} | {m['mapped_or_better']} | {m['implemented_or_better']} | {m['verified']} | {m['coverage_percent']}% | **{result['decision']}** |")
    totals = summary["metrics"]
    lines += [
        "", "## Aggregate readiness", "",
        "| Metric | Value |", "|---|---:|",
        f"| Requirements | {totals['requirements']} |",
        f"| Implementation coverage | {totals['implementation_coverage_percent']}% |",
        f"| Verification coverage | {totals['verification_coverage_percent']}% |",
        f"| Missing tests metadata | {totals['missing_tests']} |",
        f"| Missing evidence metadata | {totals['missing_evidence']} |",
        f"| Missing owner | {totals['missing_owner']} |",
        f"| Missing CI | {totals['missing_ci']} |",
        f"| Stale verifications | {totals['stale_verifications']} |",
        "", "## Claim boundary", "",
        "Passing this report means the traceability data and referenced local evidence are internally consistent. It is not a NIST CAVP, CMVP, or FIPS 140-3 validation certificate.", "",
    ]
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    root = pathlib.Path.cwd().resolve()
    catalog = (root / args.catalog).resolve()
    output = (root / args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    docs_output = (root / args.docs_output).resolve()
    graphs_output = output / "graphs"
    docs_output.mkdir(parents=True, exist_ok=True)
    graphs_output.mkdir(parents=True, exist_ok=True)

    specs, discovery_findings = discover_documents(root, catalog)
    results: list[dict[str, Any]] = []
    global_ids: dict[str, str] = {}
    for spec in specs:
        result = validate_document(root, spec, args.strict, args.structural_only)
        for req in result["requirements"]:
            rid = req.get("id", "")
            if rid and rid in global_ids:
                finding = Finding("error", "GLOBAL_DUPLICATE_REQUIREMENT_ID", f"Requirement id already used by {global_ids[rid]}", document_id=spec.id, requirement_id=rid)
                result["findings"].append(finding.as_dict())
                result["metrics"]["errors"] += 1
                result["decision"] = "fail"
            elif rid:
                global_ids[rid] = spec.id
        results.append(result)

        doc_slug = slug(spec.id)
        doc_dir = output / doc_slug
        doc_dir.mkdir(parents=True, exist_ok=True)
        (doc_dir / "report.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        (doc_dir / "report.md").write_text(markdown_report(result))
        (graphs_output / f"{doc_slug}.dot").write_text(dependency_graph(result))
        (docs_output / f"{spec.id}.generated.md").write_text(generated_documentation(result))

    metrics = aggregate_metrics(results, discovery_findings)
    decision = "fail" if metrics["errors"] or (args.strict and metrics["warnings"]) else "pass"
    summary = {
        "schema_version": ENGINE_SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "decision": decision,
        "strict": args.strict,
        "discovery": {
            "catalog": relative(root, catalog),
            "automatic": True,
            "documents": len(results),
        },
        "metrics": metrics,
        "documents": results,
        "findings": [finding.as_dict() for finding in discovery_findings],
    }
    (output / "report.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output / "report.md").write_text(aggregate_markdown(summary))
    (output / "findings.json").write_text(json.dumps({"schema_version": ENGINE_SCHEMA_VERSION, "findings": summary["findings"] + [f for result in results for f in result["findings"]]}, indent=2, sort_keys=True) + "\n")

    print(f"decision={decision}")
    print(f"documents={len(results)}")
    print(f"requirements={metrics['requirements']}")
    print(f"report={relative(root, output / 'report.md')}")
    return 0 if decision == "pass" else 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate standards traceability reports")
    parser.add_argument("command", nargs="?", choices=["validate", "report"], default="report")
    parser.add_argument("--catalog", default="compliance/catalog.toml")
    parser.add_argument("--output", default="target/standards")
    parser.add_argument("--docs-output", default="docs/standards/generated")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--structural-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    raise SystemExit(main())
