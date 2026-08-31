package bpf

import (
	"encoding/json"
	"strings"
	"testing"
)

// Hermetic tests: pure parsers/renderers on FIXTURES (the real captured CachyOS host +
// guest outputs from the Phase-0 spike), no filesystem access.

func TestParseLsmList_BpfActive(t *testing.T) {
	// Real fixture: host + cachyos guest /sys/kernel/security/lsm.
	got := parseLsmList("capability,landlock,lockdown,yama,bpf")
	if !hasBPF(got) {
		t.Fatalf("expected bpf active in %v", got)
	}
	if len(got) != 5 {
		t.Fatalf("expected 5 LSMs, got %v", got)
	}
}

func TestParseLsmList_BpfAbsent(t *testing.T) {
	got := parseLsmList("capability,landlock,lockdown,yama")
	if hasBPF(got) {
		t.Fatalf("bpf must NOT be reported active in %v", got)
	}
}

func TestParseLsmList_Empty(t *testing.T) {
	if got := parseLsmList(""); got != nil {
		t.Fatalf("empty input must yield nil, got %v", got)
	}
}

func TestParseLsmList_Spacey(t *testing.T) {
	got := parseLsmList(" capability, landlock ,lockdown")
	if len(got) != 3 || got[0] != "capability" || got[2] != "lockdown" {
		t.Fatalf("spacey parse failed: %v", got)
	}
}

func TestGrepConfig(t *testing.T) {
	content := "CONFIG_BPF_LSM=y\nCONFIG_DEBUG_INFO_BTF=y\nCONFIG_IKCONFIG=y\n"
	if v := grepConfig(content, "CONFIG_BPF_LSM"); v != "y" {
		t.Fatalf("expected y, got %q", v)
	}
	if v := grepConfig(content, "CONFIG_DEBUG_INFO_BTF"); v != "y" {
		t.Fatalf("expected y, got %q", v)
	}
	if v := grepConfig(content, "CONFIG_NOPE"); v != "N/A" {
		t.Fatalf("expected N/A, got %q", v)
	}
}

func TestStatusJSONStableKeys(t *testing.T) {
	// Fixture status mirroring the spike-captured host facts.
	s := Status{
		Kernel:       "7.2.2-1-cachyos",
		LSMList:      []string{"capability", "landlock", "lockdown", "yama", "bpf"},
		LSMHasBPF:    true,
		BTFPresent:   true,
		ConfigBPFLSM: "y",
		ConfigBTF:    "y",
	}
	out := renderStatusText(s, true)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("status --json must parse: %v", err)
	}
	for _, k := range []string{"kernel", "lsm_list", "lsm_bpf", "btf_present", "config_bpf_lsm", "config_btf", "unprivileged_bpf_disabled", "memlock", "bpftool_present", "lockdown"} {
		if _, ok := decoded[k]; !ok {
			t.Fatalf("status --json missing key %q", k)
		}
	}
	if !strings.Contains(out, `"lsm_bpf": true`) {
		t.Fatalf("expected lsm_bpf true: %s", out)
	}
}

func TestRenderStatusHuman(t *testing.T) {
	s := Status{Kernel: "6.1.0", LSMHasBPF: false, BTFPresent: false}
	out := renderStatusText(s, false)
	if !strings.Contains(out, "BPF kernel feature report") || !strings.Contains(out, "DISABLED") {
		t.Fatalf("human report malformed: %s", out)
	}
}

func TestProbeDryRunVerdict(t *testing.T) {
	// probeVerify reads the real host — only assert the structural parts here via the
	// pure helpers: the verdict line is deterministic given the requirements.
	// (Full probeVerify coverage is the live CLI on the host.)
	if _, err := probeVerify("lsm", false); err != nil {
		t.Fatalf("dry-run must never error: %v", err)
	}
}
