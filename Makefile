CSC      = mcs
SDK      = 4
CFLAGS   = -sdk:$(SDK) -target:exe -optimize
OUTDIR   = out
EXE      = $(OUTDIR)/RunEx.exe
INVOKE   = $(OUTDIR)/Invoke-RunEx.ps1
TEMPLATE = src/Invoke-RunEx.template.ps1
SOURCES  = src/NativeMethods.cs src/AccessToken.cs src/WindowStationDACL.cs src/RunEx.cs src/Program.cs

.PHONY: all clean

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

clean:
	rm -rf $(OUTDIR)
