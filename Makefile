
BIN_DIR := $(shell pwd)/bin
REPO=github.com/morningconsult/docker-credential-vault-login
SOURCES := $(shell find . -name '*.go')
VERSION := $(shell cat VERSION)
GITCOMMIT_SHA := $(shell git rev-parse HEAD)
BINARY_NAME=docker-credential-vault-login
LOCAL_BINARY=bin/local/$(BINARY_NAME)
EXTERNAL_TOOLS=\
	github.com/golang/mock/mockgen \
	golang.org/x/tools/cmd/goimports


all: build

update-deps:
	@sh -c "$(CURDIR)/scripts/update-deps.sh"
.PHONY: update-deps

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
	@go test -v -cover  $(go list ./vault-login/... | grep -v testing)
.PHONY: test

$(LOCAL_BINARY): $(SOURCES)
	@echo "==> Starting binary build..."
	@sh -c "'./scripts/build-binary.sh' './bin/local' '$(VERSION)' '$(GITCOMMIT_SHA)' '$(REPO)'"
	@echo "==> Done. Binary can be found at bin/local/docker-credential-vault-login"

mocktools:
	@echo $(GOPATH)
	@for tool in  $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		go get -u $$tool; \
	done
.PHONY: mocktools

build_mocks: mocktools
	PATH=$$PATH:$$$(CURDIR)/scripts/generate scripts/build-mocks.sh
.PHONY: build_mocks
