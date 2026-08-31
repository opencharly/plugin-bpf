package bpf

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
)

// command.go is the command:bpf leg of this plugin — the `charly bpf …` CLI surface
// (status / lsm / config / probe), parsed with kong and dispatched by cliMain in CLI mode
// (sdk.Main → cliMain). Every subcommand is READ-ONLY against the kernel state; `probe`
// is verify-only unless --attach (root + bpftool) is given. Exit-code contracts:
// status/config always exit 0 (missing facts print N/A lines); lsm exits 0 when bpf is in
// the active LSM list, 1 otherwise; probe exits 0 for a dry-run with all requirements met.

// BpfCmd is the kong command tree.
type BpfCmd struct {
	Status StatusCmd `cmd:"" help:"BPF kernel feature readiness report"`
	Lsm    LsmCmd    `cmd:"" help:"The BPF-LSM gate: is bpf in the active LSM list?"`
	Config ConfigCmd `cmd:"" help:"Read the BPF sysctl knobs (read-only)"`
	Probe  ProbeCmd  `cmd:"" help:"Verify eBPF attach requirements (verify-only by default)"`
}

// StatusCmd prints the full readiness report (human or --json).
type StatusCmd struct {
	JSON bool `long:"json" help:"Emit a stable JSON report"`
}

func (c StatusCmd) Run() error {
	fmt.Print(renderStatusText(collectStatus(), c.JSON))
	return nil
}

// LsmCmd is the gate: exit 0 iff bpf is in the active LSM list.
type LsmCmd struct {
	JSON bool `long:"json" help:"Emit a stable JSON report"`
}

func (c LsmCmd) Run() error {
	ok, text := lsmGateText(c.JSON)
	fmt.Print(text)
	if !ok {
		return fmt.Errorf("bpf: BPF LSM is DISABLED (append bpf to the lsm= kernel cmdline and reboot)")
	}
	return nil
}

// ConfigCmd reads the BPF sysctl knobs (read-only).
type ConfigCmd struct{}

func (c ConfigCmd) Run() error {
	fmt.Print(renderConfigText())
	return nil
}

// ProbeCmd verifies the attach requirements; --attach runs a real transient probe
// (bpftool feature probe) and requires root + bpftool present.
type ProbeCmd struct {
	Kind   string `arg:"" required:"" help:"attach kind to verify: lsm | tracepoint"`
	Attach bool   `long:"attach" help:"run a real attach probe (requires root + bpftool)"`
}

func (c ProbeCmd) Run() error {
	text, err := probeVerify(c.Kind, c.Attach)
	fmt.Print(text)
	return err
}

// cliMain is the CLI-mode entry point (sdk.Main calls it when charly fork/exec'd this
// plugin as a command passthrough). It parses the pass-through tokens against BpfCmd
// and dispatches via kong Run. Returns the process exit code.
func cliMain(args []string) int {
	var grp BpfCmd
	parser, err := kong.New(&grp,
		kong.Name("bpf"),
		kong.Description("charly bpf — generic BPF kernel feature readiness (read-only)"),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, err := parser.Parse(args)
	if err != nil {
		parser.FatalIfErrorf(err)
		return 1
	}
	if err := ctx.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
