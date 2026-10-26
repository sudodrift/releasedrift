# Changelog

## Unreleased

First version.

- Finds GitHub release downloads (`releases/download` URLs, `releases/latest` URLs and `gh release download`) in Dockerfiles, shell scripts, Makefiles, YAML (GitHub Actions, Ansible) and install scripts.
- Checks for a SHA-256 pin next to each download: `sha256sum -c`, `shasum -c`, `echo "HASH  file" | sha256sum -c -`, Dockerfile `ADD --checksum`, Ansible `checksum:`, and hashes kept in variables.
- Asks the GitHub API (token optional) whether each release is immutable and which digest each file has, and compares pinned hashes with those digests.
- Keeps the digests in a state file and reports a changed digest until `--accept`.
- Text and JSON output, `--fail-on`, exit codes 0, 1 and 2.
- Example scheduled GitHub Actions workflow in `docs/releasedrift-schedule.yml`.
