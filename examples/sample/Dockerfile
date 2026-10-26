FROM debian:13-slim
ARG GH_VERSION=2.103.2

# Pinned: BuildKit checks the SHA-256 before using the file.
ADD --checksum=sha256:62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8 \
    https://github.com/cli/cli/releases/download/v2.103.2/gh_2.103.2_linux_amd64.tar.gz /tmp/gh.tar.gz

# Uses a build argument, so the exact file is not known until build time.
RUN curl -fsSLo /tmp/gh-arm64.tar.gz \
    https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_arm64.tar.gz
