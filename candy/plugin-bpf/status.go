package bpf

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// status.go owns the READ-ONLY kernel-fact collectors and renderers shared by the CLI
// (command.go) and the verb (provider.go). Every fact has an explicit N/A path — a
// missing file is a reported N/A line, never a hard failure.

const (
	lsmPath      = "/sys/kernel/security/lsm"
	btfPath      = "/sys/kernel/btf/vmlinux"
	lockdownPath = "/sys/kernel/security/lockdown"
)

// Status is the collected readiness report (stable JSON keys via tags).
type Status struct {
	Kernel               string   `json:"kernel"`
	LSMList              []string `json:"lsm_list"`
	LSMHasBPF            bool     `json:"lsm_bpf"`
	BTFPresent           bool     `json:"btf_present"`
	ConfigBPFLSM         string   `json:"config_bpf_lsm"`
	ConfigBTF            string   `json:"config_btf"`
	UnprivilegedDisabled string   `json:"unprivileged_bpf_disabled"`
	Memlock              string   `json:"memlock"`
	BpftoolPresent       bool     `json:"bpftool_present"`
	Lockdown             string   `json:"lockdown"`
}

// kernelVersion reads uname -r.
func kernelVersion() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "N/A"
	}
	return trimCString(u.Release[:])
}

func trimCString(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

// parseLsmList splits the raw /sys/kernel/security/lsm content into the LSM names.
func parseLsmList(content string) []string {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(content, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hasBPF reports whether bpf is in an LSM list.
func hasBPF(list []string) bool {
	for _, l := range list {
		if l == "bpf" {
			return true
		}
	}
	return false
}

func readFile(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// lsmFile is overridable in tests (hermetic verb dispatch tests).
var lsmFile = lsmPath

func readLsm() []string {
	c, ok := readFile(lsmFile)
	if !ok {
		return nil
	}
	return parseLsmList(c)
}

// readKernelConfig greps CONFIG_BPF_LSM / CONFIG_DEBUG_INFO_BTF from /proc/config.gz
// (zcat) or /boot/config-<kernel>.
func readKernelConfig() (bpfLSM, btf string) {
	var content string
	if _, err := os.Stat("/proc/config.gz"); err == nil {
		out, err := exec.Command("zcat", "/proc/config.gz").Output()
		if err == nil {
			content = string(out)
		}
	}
	if content == "" {
		matches, _ := filepath.Glob("/boot/config-" + kernelVersion())
		if len(matches) > 0 {
			if b, err := os.ReadFile(matches[0]); err == nil {
				content = string(b)
			}
		}
	}
	if content == "" {
		return "N/A", "N/A"
	}
	return grepConfig(content, "CONFIG_BPF_LSM"), grepConfig(content, "CONFIG_DEBUG_INFO_BTF")
}

func grepConfig(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"=")
		}
	}
	return "N/A"
}

// memlockLimit extracts the "Max locked memory" line of /proc/self/limits.
func memlockLimit() string {
	b, err := os.ReadFile("/proc/self/limits")
	if err != nil {
		return "N/A"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Max locked memory") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				return fields[3] // soft limit
			}
		}
	}
	return "N/A"
}

func sysctl(path string) string {
	if v, ok := readFile(path); ok {
		return v
	}
	return "N/A"
}

// collectStatus gathers every readiness fact.
func collectStatus() Status {
	lsm := readLsm()
	s := Status{
		Kernel:               kernelVersion(),
		LSMList:              lsm,
		LSMHasBPF:            hasBPF(lsm),
		BTFPresent:           fileExists(btfPath),
		UnprivilegedDisabled: sysctl("/proc/sys/kernel/unprivileged_bpf_disabled"),
		Memlock:              memlockLimit(),
		BpftoolPresent:       bpftoolPresent(),
		Lockdown:             sysctl(lockdownPath),
	}
	s.ConfigBPFLSM, s.ConfigBTF = readKernelConfig()
	return s
}

// bpftoolPresent reports whether bpftool is on PATH.
func bpftoolPresent() bool {
	_, err := exec.LookPath("bpftool")
	return err == nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// renderStatusText renders the report (human or stable JSON). Exit code is ALWAYS 0
// for status — unreadable facts are N/A lines.
func renderStatusText(s Status, asJSON bool) string {
	if asJSON {
		b, _ := json.MarshalIndent(s, "", "  ")
		return string(b) + "\n"
	}
	lsmLine := "N/A"
	if len(s.LSMList) > 0 {
		lsmLine = strings.Join(s.LSMList, ",")
	}
	gate := "DISABLED"
	if s.LSMHasBPF {
		gate = "enabled"
	}
	btf := "absent"
	if s.BTFPresent {
		btf = "present"
	}
	bpftool := "absent"
	if s.BpftoolPresent {
		bpftool = "present"
	}
	return fmt.Sprintf(`BPF kernel feature report
  kernel:                     %s
  lsm list:                   %s
  bpf LSM:                    %s
  BTF vmlinux:                %s
  CONFIG_BPF_LSM:             %s
  CONFIG_DEBUG_INFO_BTF:      %s
  unprivileged_bpf_disabled:  %s
  memlock:                    %s
  bpftool:                    %s
  lockdown:                   %s
`, s.Kernel, lsmLine, gate, btf, s.ConfigBPFLSM, s.ConfigBTF, s.UnprivilegedDisabled, s.Memlock, bpftool, s.Lockdown)
}

// lsmGateText renders the gate verdict. ok=false when bpf is not in the active list.
func lsmGateText(asJSON bool) (bool, string) {
	lsm := readLsm()
	ok := hasBPF(lsm)
	if asJSON {
		j, _ := json.MarshalIndent(map[string]any{"lsm_list": lsm, "lsm_bpf": ok}, "", "  ")
		return ok, string(j) + "\n"
	}
	if ok {
		return true, "BPF LSM: enabled\n"
	}
	return false, "BPF LSM: DISABLED (append bpf to the lsm= kernel cmdline — e.g. lsm=landlock,lockdown,yama,integrity,apparmor,bpf — and reboot)\n"
}

// lsmReportText is the verb variant (no exit-code coupling; matchers decide).
func lsmReportText() string {
	_, text := lsmGateText(false)
	return text
}

// renderConfigText prints the BPF sysctl knobs (read-only).
func renderConfigText() string {
	return fmt.Sprintf("unprivileged_bpf_disabled: %s\nbpf_jit_enable:           %s\n",
		sysctl("/proc/sys/kernel/unprivileged_bpf_disabled"),
		sysctl("/proc/sys/net/core/bpf_jit_enable"))
}

// probeVerify reports the attach requirements for a kind; with attach=true it runs a real
// transient `bpftool feature probe` (requires root + bpftool present).
func probeVerify(kind string, attach bool) (string, error) {
	root := os.Geteuid() == 0
	btf := fileExists(btfPath)
	lsmOK := hasBPF(readLsm())
	bpftool := bpftoolPresent()

	lines := []string{
		fmt.Sprintf("probe kind:           %s", kind),
		fmt.Sprintf("BTF vmlinux:          %v", btf),
		fmt.Sprintf("bpf LSM active:       %v", lsmOK),
		fmt.Sprintf("root/CAP_BPF:          %v", root),
		fmt.Sprintf("bpftool present:      %v", bpftool),
	}
	ready := btf && lsmOK && root && bpftool
	if !attach {
		verdict := "PROBE-DRY-RUN: attach-ready"
		if !ready {
			var missing []string
			if !btf {
				missing = append(missing, "BTF")
			}
			if !lsmOK {
				missing = append(missing, "bpf-LSM")
			}
			if !root {
				missing = append(missing, "root")
			}
			if !bpftool {
				missing = append(missing, "bpftool")
			}
			sort.Strings(missing)
			verdict = "PROBE-DRY-RUN: NOT attach-ready (missing: " + strings.Join(missing, ", ") + ")"
		}
		lines = append(lines, verdict)
		return strings.Join(lines, "\n") + "\n", nil
	}

	if !ready {
		lines = append(lines, "ATTACH: refused (requirements above not met)")
		return strings.Join(lines, "\n") + "\n", fmt.Errorf("bpf probe: attach requirements not met")
	}
	out, err := exec.Command("bpftool", "feature", "probe").CombinedOutput()
	lines = append(lines, "ATTACH: bpftool feature probe output:\n"+strings.TrimSpace(string(out)))
	if err != nil {
		return strings.Join(lines, "\n") + "\n", fmt.Errorf("bpf probe: bpftool feature probe failed: %v", err)
	}
	return strings.Join(lines, "\n") + "\n", nil
}
