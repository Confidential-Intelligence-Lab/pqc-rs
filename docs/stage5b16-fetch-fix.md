# Stage 5B-16 Fetch-Script Fix

The original fetch script cloned the complete `usnistgov/ACVP-Server`
repository. That made a four-file import depend on a much larger Git pack
transfer and exposed it to `curl 56`, early-EOF, and `index-pack` failures.

The revised script:

1. resolves the current `master` commit with the GitHub API,
2. downloads only the four required JSON files,
3. addresses the files through the immutable commit SHA,
4. retries transient connection and HTTP failures,
5. validates every download as JSON before installation,
6. records the resolved commit in `PROVENANCE.txt`,
7. generates SHA-256 checksums.

The optional `GITHUB_TOKEN` environment variable can be supplied when GitHub
API rate limits are a concern.
