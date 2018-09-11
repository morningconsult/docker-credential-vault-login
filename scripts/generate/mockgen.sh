#!/usr/bin/env bash

set -e

package=${1?Must provide package}
interfaces=${2?Must provide interface names}
outputfile=${3?Must provide an output file}
PROJECT_VENDOR="gitlab.morningconsult.com/mci/docker-credential-vault-login/vendor"

export PATH="${GOPATH//://bin:}/bin:$PATH"

data=$(
cat << EOF
$(mockgen "${package}" "${interfaces}")
EOF
)

mkdir -p $(dirname ${outputfile})

echo "$data" | sed -e "s|${PROJECT_VENDOR}||" | goimports > "${outputfile}"