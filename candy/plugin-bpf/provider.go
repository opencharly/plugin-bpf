package bpf

import (
	"context"
	"encoding/json"

	"github.com/opencharly/plugin-bpf/candy/plugin-bpf/params"
	"github.com/opencharly/sdk"
	"github.com/opencharly/sdk/kit"
	pb "github.com/opencharly/spec/proto"
	"github.com/opencharly/spec/spec"
)

// provider.go is the out-of-process bpf VERB provider — charly's host dispatches a
// `bpf:` check step to it through the registry (ResolveVerb("bpf") → this grpcProvider
// → Provider.Invoke) with the FULL #Op marshaled as params_json and a CheckEnv snapshot
// as env. The verb reads the kernel state DIRECTLY and read-only (no endpoint resolution
// needed — the BPF/LSM/BTF facts are venue-local): containers share the host kernel, so
// a `bpf:` step in any venue reports the venue's kernel truth with explicit N/A lines
// for anything unreadable. command:bpf (`charly bpf …`) is NOT served over gRPC — it is
// dispatched by charly fork/exec'ing this binary in CLI mode (sdk.Main → cliMain,
// command.go).

type provider struct{ pb.UnimplementedProviderServer }

// Invoke is the gRPC entry point for the ONE gRPC-served capability this plugin
// advertises: verb:bpf.
func (p provider) Invoke(ctx context.Context, req *pb.InvokeRequest) (*pb.InvokeReply, error) {
	return p.invokeVerb(ctx, req)
}

// invokeVerb runs one `bpf:` check operation: decode the full #Op + the typed
// plugin input (params.BpfInput), dispatch lsm / status, render the report text and
// let the SHARED verdict pipeline (sdk.VerbVerdict) evaluate the step's own
// exit_status/stdout matchers — R3, the same matcher implementation the host uses.
func (p provider) invokeVerb(ctx context.Context, req *pb.InvokeRequest) (*pb.InvokeReply, error) {
	var op spec.Op
	if len(req.GetParamsJson()) > 0 {
		if err := json.Unmarshal(req.GetParamsJson(), &op); err != nil {
			return sdk.ResultJSON("fail", "bpf: decode op: "+err.Error())
		}
	}
	var in params.BpfInput
	kit.DecodeInput(op.PluginInput, &in)

	method := "status"
	if in.Lsm {
		method = "lsm"
	}
	return sdk.VerbVerdict("bpf", method, verbReply(in), nil, &op, false)
}

// verbReply is the TESTED dispatch surface: it renders the report for a decoded
// bpf plugin_input (lsm gate or status report). invokeVerb's per-verb branch -
// the code that would fail without the verb path - is exactly this function.
func verbReply(in params.BpfInput) string {
	switch {
	case in.Lsm:
		return lsmReportText()
	case in.Status != nil:
		return renderStatusText(collectStatus(), false)
	default:
		return renderStatusText(collectStatus(), false)
	}
}
