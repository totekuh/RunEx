CSC      = mcs
SDK      = 4
CFLAGS   = -sdk:$(SDK) -target:exe -optimize
OUTDIR   = out
EXE      = $(OUTDIR)/RunEx.exe
INVOKE   = $(OUTDIR)/Invoke-RunEx.ps1
TEMPLATE = src/Invoke-RunEx.template.ps1
SOURCES  = src/NativeMethods.cs src/DInvoke.cs src/AccessToken.cs src/WindowStationDACL.cs src/RunEx.cs src/Program.cs

# Test config
SNAPSHOT   = clean
TEST_USER  = _runex_test
TEST_PASS  = T3stP@ss!rx
TOOLDIR    = ~/.winbox/shared/tools

# Unit test config
TEST_SOURCES = tests/unit/TestRunner.cs
TEST_EXE     = $(OUTDIR)/RunExTests.exe
PYTEST       = /home/witchtape/.local/share/pipx/venvs/winbox/bin/python -m pytest

.PHONY: all clean test deploy unit-test e2e-test

all: $(EXE) $(INVOKE)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(EXE): $(SOURCES) | $(OUTDIR)
	$(CSC) $(CFLAGS) -out:$(EXE) $(SOURCES)

$(INVOKE): $(EXE) $(TEMPLATE)
	@{ \
		sed '/^#@@INJECT_BASE64@@$$/q' $(TEMPLATE) | head -n -1; \
		printf '    $$RunExBase64 = "%s"\n' "$$(base64 -w 0 $(EXE))"; \
		sed '1,/^#@@INJECT_BASE64@@$$/d' $(TEMPLATE); \
	} > $(INVOKE)

deploy: $(EXE)
	cp --update $(EXE) $(TOOLDIR)/

test: deploy
	@command -v winbox >/dev/null 2>&1 || { echo "FAIL: winbox not found in PATH"; exit 1; }
	@echo "==> Restoring snapshot '$(SNAPSHOT)'..."
	winbox restore $(SNAPSHOT)
	@echo "==> Creating test user '$(TEST_USER)'..."
	winbox exec 'net user $(TEST_USER) "$(TEST_PASS)" /add'
	@echo "==> Running: RunEx $(TEST_USER) -> whoami"
	@output=$$(winbox exec 'Z:\tools\RunEx.exe $(TEST_USER) "$(TEST_PASS)" -- whoami' 2>&1); \
	echo "    Output: $$output"; \
	echo "$$output" | grep -qi '$(TEST_USER)' \
		&& echo "PASS: whoami returned $(TEST_USER)" \
		|| { echo "FAIL: expected '$(TEST_USER)' in output, got: $$output"; exit 1; }
$(TEST_EXE): $(TEST_SOURCES) $(SOURCES) | $(OUTDIR)
	$(CSC) $(CFLAGS) -main:TestRunner -out:$(TEST_EXE) $(TEST_SOURCES) $(SOURCES)

unit-test: $(TEST_EXE)
	mono $(TEST_EXE)

e2e-test: deploy
	$(PYTEST) tests/e2e/test_runex_e2e.py -m integration -v

clean:
	rm -rf $(OUTDIR)
