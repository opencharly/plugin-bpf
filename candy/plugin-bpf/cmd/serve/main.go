// Command serve is the OUT-OF-PROCESS entrypoint for the bpf plugin: dual-mode sdk.Main
// (serve OR CLI). charly fork/execs this binary in CLI mode for command:bpf dispatch
// (→ CliMain); the serve half backs the out-of-process verb:bpf provider placement. The SAME
// NewProvider()/NewMeta() compile INTO charly in-process when listed in compiled_plugins —
// placement is invisible above the registry.
package main

import (
	bpf "github.com/opencharly/plugin-bpf/candy/plugin-bpf"
	"github.com/opencharly/sdk"
)

func main() { sdk.Main(bpf.NewProvider(), bpf.NewMeta(), bpf.CliMain) }
