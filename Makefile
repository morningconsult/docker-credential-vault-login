

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
	git add CHANGELOG.md
	git commit --amend --no-edit --no-verify
.PHONY: changelog

# sync-version updates the version.go file to match the latest version
# tag (only recognizes tags of the format X.X.X where X is an integer)
sync-version:
	@sh "$(CURDIR)/scripts/sync-version.sh"
.PHONY: sync-version
