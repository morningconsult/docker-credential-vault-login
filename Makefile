
BIN_DIR := $(shell pwd)/bin
REPO=gitlab.morningconsult.com/mci/docker-credential-vault-login
SOURCES := $(shell find . -name '*.go')
VERSION := $(shell cat VERSION)
GITCOMMIT_SHA := $(shell git rev-parse HEAD)
BINARY_NAME=docker-credential-vault-login
LOCAL_BINARY=bin/local/$(BINARY_NAME)

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
	@docker run --rm \
	-e TARGET_GOOS=$(TARGET_GOOS) \
	-e TARGET_GOARCH=$(TARGET_GOARCH) \
	-v $(BIN_DIR):/go/src/$(REPO)/bin \
	$(shell docker build -q .)
.PHONY: docker

build: $(LOCAL_BINARY)
.PHONY: build

$(LOCAL_BINARY): $(SOURCES)
	@echo "==> Starting binary build..."
	@sh -c "'./scripts/build_binary.sh' './bin/local' '$(VERSION)' '$(GITCOMMIT_SHA)' '$(REPO)'"
	@echo "==> Done. Binary can be found at bin/local/docker-credential-vault-login"

# sync-version updates the version.go file to match the latest version
# and commit hash of this clone
sync-version:
	@sh -c "'./scripts/sync-version.sh' '$(VERSION)' '$(GITCOMMIT_SHA)'"
.PHONY: sync-version
