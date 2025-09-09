#!/usr/bin/env bash
#
# This script grabs the latest release of Vault, then pins the api and sdk
# packages to the same commit hash, whether or not they've been released.
#
# This is necessary because the latest released versions of each package are
# typically incompatible with each other.
set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo >&2 "==> ERROR: Please install jq before running this script"
  exit 1
fi

go get github.com/hashicorp/vault@latest
release_semver="$(go list -m -json github.com/hashicorp/vault | jq -r .Version)"
release_hash="$(go mod download -json "github.com/hashicorp/vault@${release_semver}" | jq -r .Origin.Hash)"
go get "github.com/hashicorp/vault/api@${release_hash}"
go get "github.com/hashicorp/vault/sdk@${release_hash}"
go mod tidy
