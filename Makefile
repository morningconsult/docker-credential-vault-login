# Copyright 2019 The Morning Consult, LLC or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#         https://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

BIN_DIR := $(shell pwd)/bin
REPO := github.com/morningconsult/docker-credential-vault-login
SOURCES := $(shell find . -name '*.go')
BINARY_NAME := docker-credential-vault-login
LOCAL_BINARY := bin/local/$(BINARY_NAME)

EXTERNAL_TOOLS := \
	github.com/golang/mock/mockgen \
	golang.org/x/tools/cmd/goimports

.DEFAULT_GOAL := all

all: build

git_chglog_check:
	if [ -z "$(shell which git-chglog)" ]; then \
		go get -u -v github.com/git-chglog/git-chglog/cmd/git-chglog && git-chglog --version; \
	fi
.PHONY: git_chglog_check

changelog: git_chglog_check
	git-chglog --output CHANGELOG.md
.PHONY: changelog

docker: Dockerfile
	@sh -c "$(CURDIR)/scripts/docker-build.sh"
.PHONY: docker

build: $(LOCAL_BINARY)
.PHONY: build

test:
	@go test -v -cover ./...
.PHONY: test

$(LOCAL_BINARY): $(SOURCES)
	@echo "==> Starting binary build..."
	@sh -c "'./scripts/build-binary.sh' '$(shell git describe --tags --abbrev=0)' '$(shell git rev-parse --short HEAD)' '$(REPO)'"
	@echo "==> Done. Binary can be found at ./bin/docker-credential-vault-login"

mocktools:
	@echo $(GOPATH)
	@for tool in  $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		go get -u $$tool; \
	done
.PHONY: mocktools

build_mocks: mocktools
	scripts/build-mocks.sh
.PHONY: build_mocks
