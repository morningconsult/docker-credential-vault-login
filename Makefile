

update-deps:
	@sh -c "$(CURDIR)/scripts/update-deps.sh"
.PHONY: update-deps

test:
	@echo "==> Running unit tests..."
    @sh -c "$(CURDIR)/scripts/run-tests.sh"
.PHONY: test
