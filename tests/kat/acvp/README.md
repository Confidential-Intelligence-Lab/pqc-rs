# NIST ACVP ML-KEM Vectors

Fetch the four required ML-KEM files without cloning the full ACVP repository:

```bash
./scripts/fetch-nist-acvp-ml-kem.sh
```

The script resolves the public repository's current `master` commit and then
downloads the files through that immutable SHA. The resulting
`PROVENANCE.txt` records both the branch and exact commit.

For authenticated GitHub API requests:

```bash
GITHUB_TOKEN=... ./scripts/fetch-nist-acvp-ml-kem.sh
```

Imported files are authoritative source material, but they are not marked as
passed until the implementation reproduces the expected results.
