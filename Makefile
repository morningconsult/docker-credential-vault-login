

update-deps:
	@sh -c "$(CURDIR)/scripts/update-deps.sh"
.PHONY: update-deps

test:
	@echo "==> Starting test script..."
	@sh -c "$(CURDIR)/scripts/run-tests.sh"
.PHONY: test
