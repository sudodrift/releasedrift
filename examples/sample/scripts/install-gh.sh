#!/bin/sh
set -eu
cd "$(mktemp -d)"
curl -fsSLO https://github.com/cli/cli/releases/download/v2.103.2/gh_2.103.2_checksums.txt
curl -fsSLO https://github.com/cli/cli/releases/download/v2.103.2/gh_2.103.2_linux_arm64.tar.gz
sha256sum -c --ignore-missing gh_2.103.2_checksums.txt
tar -xzf gh_2.103.2_linux_arm64.tar.gz
