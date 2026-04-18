#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${GITHUB_REPO:?GITHUB_REPO is required}"
: "${BINARY_NAME:?BINARY_NAME is required}"
: "${PLUGIN_NAME:?PLUGIN_NAME is required}"
: "${DIST_DIR:?DIST_DIR is required}"

BASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"

sha_for() {
  cat "${DIST_DIR}/${BINARY_NAME}-${1}.tar.gz.sha256"
}

SHA_LINUX=$(sha_for linux-amd64)
SHA_DARWIN=$(sha_for darwin-amd64)
SHA_DARWIN_ARM=$(sha_for darwin-arm64)
SHA_WINDOWS=$(sha_for windows-amd64)

cat > "${DIST_DIR}/${PLUGIN_NAME}.yaml" <<EOF
apiVersion: krew.googlecontainertools.github.com/v1alpha2
kind: Plugin
metadata:
  name: ${PLUGIN_NAME}
spec:
  version: ${VERSION}
  homepage: https://github.com/${GITHUB_REPO}
  shortDescription: Collect Hubble network flows and generate CiliumNetworkPolicy
  description: |
    Connects to Hubble and collects real network flows between pods,
    then automatically generates CiliumNetworkPolicy with egress/ingress
    rules based on observed traffic. Supports filtering by namespace,
    label, verdict, and follow mode.
  platforms:
    - selector:
        matchLabels:
          os: linux
          arch: amd64
      uri: ${BASE_URL}/${BINARY_NAME}-linux-amd64.tar.gz
      sha256: "${SHA_LINUX}"
      bin: ${BINARY_NAME}

    - selector:
        matchLabels:
          os: darwin
          arch: amd64
      uri: ${BASE_URL}/${BINARY_NAME}-darwin-amd64.tar.gz
      sha256: "${SHA_DARWIN}"
      bin: ${BINARY_NAME}

    - selector:
        matchLabels:
          os: darwin
          arch: arm64
      uri: ${BASE_URL}/${BINARY_NAME}-darwin-arm64.tar.gz
      sha256: "${SHA_DARWIN_ARM}"
      bin: ${BINARY_NAME}

    - selector:
        matchLabels:
          os: windows
          arch: amd64
      uri: ${BASE_URL}/${BINARY_NAME}-windows-amd64.tar.gz
      sha256: "${SHA_WINDOWS}"
      bin: ${BINARY_NAME}.exe
EOF
