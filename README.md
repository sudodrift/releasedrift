# releasedrift

releasedrift reads a source tree, finds every file it downloads from GitHub
releases, and tells you which downloads are not pinned to a SHA-256 and which
release files have changed since you last looked.

It looks in Dockerfiles, shell scripts, Makefiles, GitHub Actions workflows,
Ansible playbooks and install scripts for:

- `https://github.com/OWNER/REPO/releases/download/TAG/ASSET` URLs
- `https://github.com/OWNER/REPO/releases/latest/download/ASSET` URLs
- `gh release download TAG -R OWNER/REPO [-p PATTERN]`

For each one it checks whether a SHA-256 is checked nearby
(`sha256sum -c`, `shasum -a 256 -c`, `echo "HASH  file" | sha256sum -c -`,
`ADD --checksum=sha256:HASH` in a Dockerfile, `checksum: sha256:HASH` in
Ansible, or a variable holding the hash). Then it asks the GitHub API about
each release: is it immutable, and what SHA-256 digest does GitHub report for
each asset? The digests are kept in a state file, so the next run can tell
you if a file was replaced.

It only reads. It never downloads release files, never changes your files,
and works without a GitHub token. It is one static binary.

## Why

On 19 October 2026 a stolen developer account was used to replace the
release files of ovhcloud-cli v0.11.0 to v0.15.0 with binaries that steal
credentials. The tags and version numbers stayed the same. The files were
up for 1 hour 33 minutes and were downloaded about 250 times. OVHcloud says
the main issue was that the repository was not set up for immutable
releases. Their advisory:
https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw

A download that pins the SHA-256 of the file would have failed instead of
running the new binary. The StepSecurity write-up says the swap was in fact
spotted by a user whose CI pinned the hash, and that the checksums file in
the release was replaced too, so checking against it did not help:
https://www.stepsecurity.io/blog/ovhcloud-cli-github-release-swap-glassworm

Two GitHub features make this checkable from the outside:

- Since June 2025 GitHub computes a SHA-256 digest for every uploaded
  release file and shows it in the API
  (https://github.blog/changelog/2025-06-03-releases-now-expose-digests-for-release-assets/).
  Files uploaded before that have no digest.
- Immutable releases lock the tag and the files of a release
  (https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases).
  The API marks them with `"immutable": true`.

releasedrift uses both: it compares your pinned hashes with the digest
GitHub reports, warns about releases that are not immutable, and records
the digests so a later run notices when one changes.

## Install

```sh
go install github.com/sudodrift/releasedrift/cmd/releasedrift@latest
```

or build from a checkout:

```sh
make build        # bin/releasedrift, CGO_ENABLED=0
```

## Usage

```
releasedrift [flags] [DIR]     scan DIR (default: current directory)
releasedrift version

  --state FILE        state file with the digests seen before (default releasedrift.state.json)
  --no-state          do not read or write a state file
  --accept            record changed digests as the new expected values
  --offline           do not call the GitHub API; only look for missing pins
  --format text|json  output format (default text)
  --fail-on LEVEL     exit 1 if a finding is at this level or above: info, low, medium, high (default low)
  --api-url URL       GitHub API base URL (default https://api.github.com)
```

`GITHUB_TOKEN` is optional. Without it GitHub allows 60 API requests an hour
from one address, and releasedrift makes one request per release (not per
file). When the state file already has an ETag and every file used from a
release, the request is conditional and GitHub answers 304 if nothing
changed. If the limit is hit,
releasedrift stops asking, reports what it has, and exits 2.

Exit codes: 0 when no finding is at the `--fail-on` level or above, 1 when
there is one, 2 for errors (bad flags, unreadable state file, API errors,
rate limit).

## Findings

| Rule | Level | Meaning |
|------|-------|---------|
| `digest-changed` | high | GitHub now reports a different digest for a file than on an earlier run (or a digest for a file that had none, which means it was uploaded again). The alert repeats until you run with `--accept`. |
| `pin-mismatch` | high | The SHA-256 pinned next to the download is not the digest GitHub reports. Either the pin is wrong or the file was replaced. |
| `unpinned` | medium | No SHA-256 check near the download. |
| `latest-url` | medium | `releases/latest/download/...` changes with every release, so it cannot be pinned. |
| `release-missing` | medium | No release with that tag (deleted, renamed, private). |
| `asset-missing` | medium | The release exists but the file is not in it. |
| `mutable-release` | low | The release is not immutable. Shown as info when every download from it is pinned and matches. |
| `same-release-checksums` | low | The file is only checked against a checksums file from the same release. Shown as info when the release is immutable. |
| `no-digest` | info | The file has a pinned hash but GitHub has no digest to compare it with (uploaded before June 2025). |
| `unresolved` | info | The URL or command uses a variable, so the release cannot be looked up. |

"Nearby" means 5 lines before to 8 lines after the download. Each hash is
given to the closest download, or to the one whose file name is on the same
line as the hash.

## Example

`examples/sample` is a small folder with real downloads from
[cli/cli](https://github.com/cli/cli/releases/tag/v2.103.2) (immutable
release) and [jqlang/jq](https://github.com/jqlang/jq/releases/tag/jq-1.8.1)
(not immutable). The Makefile has one hash copied from the wrong line on
purpose. This is the output of a real run on 26 October 2026, without a
token and with no state file yet:

```
$ releasedrift examples/sample
releasedrift 0.1.0-dev: 5 files scanned in examples/sample, 9 release downloads found (GitHub API without a token)
Releases checked: 2, API requests: 2

Downloads:
  .github/workflows/tools.yml:7  cli/cli v2.103.2  gh_*_linux_amd64.deb
      not pinned
      release immutable
      gh_2.103.2_linux_amd64.deb sha256:30463d8e1fdce73f178f76b0082b7ab0657b0740b87274890e831def647ca979
  .github/workflows/tools.yml:10  mikefarah/yq (latest)  yq_linux_amd64
      not pinned
  Dockerfile:6  cli/cli v2.103.2  gh_2.103.2_linux_amd64.tar.gz
      pinned sha256 62ccf747115d... (line 5)
      release immutable
      gh_2.103.2_linux_amd64.tar.gz sha256:62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8 pin match
  Dockerfile:10  cli/cli v${GH_VERSION}  gh_${GH_VERSION}_linux_arm64.tar.gz
      not pinned
      not looked up (uses a variable)
  Makefile:4  jqlang/jq jq-1.8.1  jq-linux-amd64
      pinned sha256 020468de7539... (line 5)
      release NOT immutable
      jq-linux-amd64 sha256:020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d pin match
  Makefile:10  jqlang/jq jq-1.8.1  jq-linux-arm64
      pinned sha256 b98e283ff26c... (line 11)
      release NOT immutable
      jq-linux-arm64 sha256:6bc62f25981328edd3cfcfe6fe51b073f2d7e7710d7ef7fcdac28d4e384fc3d4 pin mismatch
  ansible/jq.yml:6  jqlang/jq jq-1.8.1  jq-linux-amd64
      pinned sha256 020468de7539... (line 9)
      release NOT immutable
      jq-linux-amd64 sha256:020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d pin match
  scripts/install-gh.sh:4  cli/cli v2.103.2  gh_2.103.2_checksums.txt
      checked against a checksums file from the same release (line 6)
      release immutable
      gh_2.103.2_checksums.txt sha256:414d6009dc7f9f936d70831af818d1a32aa0ff07a77646861efd207356a36b2d
  scripts/install-gh.sh:5  cli/cli v2.103.2  gh_2.103.2_linux_arm64.tar.gz
      checked against a checksums file from the same release (line 6)
      release immutable
      gh_2.103.2_linux_arm64.tar.gz sha256:4c3e99a50bd8b181a3fe9d69b25dd978bac768148d88f01507c6b4d1ef61a443

Findings:
  HIGH   Makefile:10  [pin-mismatch]
         The pinned SHA-256 b98e283ff26cd747... (line 11) does not match the digest GitHub reports now (6bc62f25981328ed...). Either the pin is wrong or the asset was replaced.
         fix: Do not update the pin blindly. Find out why the file changed (release notes, the project's security advisories) before trusting the new file.
  MEDIUM .github/workflows/tools.yml:7  [unpinned]
         No SHA-256 check was found near this download, so a replaced file would be used without notice.
         fix: Pin the SHA-256 next to the download, for example: echo "HASH  FILE" | sha256sum -c -  (or ADD --checksum=sha256:HASH in a Dockerfile).
  MEDIUM .github/workflows/tools.yml:10  [latest-url]
         The URL uses releases/latest, so it downloads whatever the newest release is. The file changes with every release and cannot be compared with an earlier run.
         fix: Use a versioned URL (releases/download/TAG/ASSET) and pin its SHA-256.
  MEDIUM Dockerfile:10  [unpinned]
         No SHA-256 check was found near this download, so a replaced file would be used without notice.
         fix: Pin the SHA-256 next to the download, for example: echo "HASH  FILE" | sha256sum -c -  (or ADD --checksum=sha256:HASH in a Dockerfile).
  LOW    Makefile:4  [mutable-release]
         This release is not immutable, so its assets can still be deleted and replaced. That is how the ovhcloud-cli assets were swapped (https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw).
         fix: Pin the SHA-256 of each asset you download. If you maintain the project, turn on immutable releases.
  INFO   Dockerfile:10  [unresolved]
         The download uses a variable or omits the repository or tag, so releasedrift cannot tell which release it is and did not look it up.
         fix: Write the owner, repository and tag literally, or check this download by hand.
  INFO   scripts/install-gh.sh:5  [same-release-checksums]
         The file is only checked against a checksums file downloaded from the same release. On a release that is not immutable, anyone who can replace the asset can replace the checksums file next to it as well. This release is immutable, so neither file can be replaced today; the finding matters if you switch to a release that is not.
         fix: Store the expected SHA-256 in this repository instead of fetching it from the release.

Summary: 1 high, 3 medium, 1 low, 2 info
State saved to releasedrift.state.json
$ echo $?
1
```

A second run with the saved state printed the same thing. To show what a
replaced file looks like without replacing one, the state file was then
edited by hand: the stored digest of `jq-linux-amd64` was set to the digest
of another jq file (`jq-linux-armhf`) and the stored ETag was removed. The next real run
(start of the findings):

```
$ releasedrift --fail-on high examples/sample
...
Findings:
  HIGH   Makefile:4  [digest-changed]
         The digest of jq-linux-amd64 changed. It was sha256:ac304e50cf7cd24933d83dc7d0e4f79892a71a92fb02336d4ecaffa8933760bd when first seen on 2026-10-26 and is now sha256:020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d. A release asset that changes after publication may have been swapped, as in the ovhcloud-cli incident (https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw).
         fix: Do not use the file until you know why it changed. Compare with the project's announcements. Once you are sure the new file is good, run again with --accept.
  HIGH   Makefile:10  [pin-mismatch]
...
Summary: 3 high, 3 medium, 1 low, 2 info
```

The state file now has `changed_to` and `changed_at` for that file, and the
alert repeats on every run until `--accept` is used.

## Running it on a schedule

[docs/releasedrift-schedule.yml](docs/releasedrift-schedule.yml) is a GitHub
Actions workflow that runs releasedrift every day with
`--fail-on high`, so the job fails only for a changed digest or a pin that
no longer matches. It keeps the state file in the Actions cache and saves it
even when the check fails. Actions are pinned to commit SHAs and the job
only has `contents: read`.

## JSON output

`--format json` prints one object with `version` (currently 1), `tool`,
`tool_version`, `root`, `files_scanned`, `offline`, `token`,
`api_requests`, `releases_checked`, `refs` (every download found, with its
pin and what the API said) and `findings` (`severity`, `rule`, `file`,
`line`, `release`, `asset`, `message`, `fix`).

## Limits

- It reads files line by line with patterns. A download built from several
  variables, or split in an unusual way, is reported as `unresolved` or not
  found at all.
- A hash near the download counts as a pin when there is a checksum
  command or keyword in the same window. releasedrift does not run your
  scripts, so it cannot prove the check is really applied to that file.
- Files with no digest on GitHub (uploaded before June 2025) can only be
  watched for being uploaded again; a pinned hash for them cannot be
  compared.
- Only github.com release downloads are checked. Container images, package
  managers and other hosts are not.
- The first run has nothing to compare with. A swap that happened before
  the first run is only caught by a pinned hash.

## Development

```sh
make test         # go vet and go test -race
make demo         # offline run on examples/sample
```

The tests use a fake GitHub API (`net/http/httptest`), so they need no
network.

## License

MIT, see [LICENSE](LICENSE).
