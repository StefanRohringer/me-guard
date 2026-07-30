.PHONY: install setup test clean

# === Installation ===
install: setup
	@echo ""
	@echo "✅ Me-Guard installation complete."
	@echo "   Run 'bash scripts/setup.sh' if you haven't already."
	@echo "   See README.md for usage."

setup:
	@bash scripts/setup.sh

# === Testing ===
test:
	@echo "🧪 Running self-test..."
	@TEMP_DIR=$$(mktemp -d); \
	mkdir -p "$$TEMP_DIR/test-skill"; \
	echo "# Test Skill" > "$$TEMP_DIR/test-skill/SKILL.md"; \
	python3 scripts/governance.py scan "$$TEMP_DIR/test-skill"; \
	rm -rf "$$TEMP_DIR"; \
	echo "✅ Self-test passed."

# === Cleanup (DANGER: removes all keys) ===
clean:
	@echo "⚠️  This will DELETE all keys, signatures, and audit logs!"
	@echo "   ~/.me-guard/governance/, ~/.me-guard/skill_catalog/,"
	@echo "   ~/.me-guard/skill_signatures/, ~/.me-guard/rules/"
	@read -p "Type 'yes' to confirm: " CONFIRM; \
	if [ "$$CONFIRM" = "yes" ]; then \
		echo "🧹 Cleaning..."; \
		rm -rf ~/.me-guard/governance; \
		rm -rf ~/.me-guard/skill_catalog; \
		rm -rf ~/.me-guard/skill_signatures; \
		rm -rf ~/.me-guard/rules; \
		rm -rf ~/.me-guard/reports; \
		rm -rf ~/.me-guard/quarantine; \
		echo "✅ Cleaned. Run 'make setup' to start fresh."; \
	else \
		echo "❌ Aborted."; \
	fi

# === Help ===
help:
	@echo "Me-Guard - Make targets:"
	@echo "  make install   - Install Me-Guard (alias for setup)"
	@echo "  make setup     - Run initial setup (CA + structure)"
	@echo "  make test      - Self-test scan on a dummy skill"
	@echo "  make clean     - DELETE all keys and data (careful!)"
	@echo "  make help      - This message"
