package bpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencharly/plugin-bpf/candy/plugin-bpf/params"
)

// Hermetic verb-dispatch tests: they exercise the SAME dispatch surface the
// provider's Invoke uses (verbReply over the decoded params.BpfInput) and fail
// without it. The lsm file is overridden so the assertions are host-independent.

func writeLsm(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "lsm")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := lsmFile
	lsmFile = p
	t.Cleanup(func() { lsmFile = old })
}

func TestVerbDispatch_LsmGate(t *testing.T) {
	writeLsm(t, "capability,landlock,lockdown,yama,bpf")
	out := verbReply(params.BpfInput{Lsm: true})
	if !strings.Contains(out, "BPF LSM: enabled") {
		t.Fatalf("verb lsm must report enabled (fixture has bpf): %q", out)
	}
}

func TestVerbDispatch_LsmGateDisabled(t *testing.T) {
	writeLsm(t, "capability,landlock,lockdown,yama")
	out := verbReply(params.BpfInput{Lsm: true})
	if strings.Contains(out, "enabled") {
		t.Fatalf("verb lsm must NOT report enabled without bpf: %q", out)
	}
	if !strings.Contains(out, "DISABLED") {
		t.Fatalf("verb lsm must report DISABLED: %q", out)
	}
}

func TestVerbDispatch_StatusReport(t *testing.T) {
	writeLsm(t, "capability,landlock,lockdown,yama,bpf")
	out := verbReply(params.BpfInput{Status: &params.BpfStatusInput{}})
	for _, k := range []string{"BPF kernel feature report", "lsm list", "bpf LSM", "BTF vmlinux"} {
		if !strings.Contains(out, k) {
			t.Fatalf("verb status report missing %q: %s", k, out)
		}
	}
}
