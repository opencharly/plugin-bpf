// Package bpf is the charly GENERIC eBPF/BPF kernel plugin — the one canonical
// surface for BPF kernel-feature readiness on any venue (bare host or VM guest):
// the BPF-LSM gate (`bpf lsm`), the readiness report (`bpf status`), the sysctl
// knobs (`bpf config`) and the verify-only attach-requirements probe (`bpf probe`)
// — plus the `verb:bpf` declarative check steps any candy can bake into its plan
// (`bpf: lsm`). It is an importable dual-placement plugin: the SAME
// NewProvider()/NewMeta()/CliMain compile INTO charly in-process when listed in
// compiled_plugins, or cmd/serve serves them OUT-OF-PROCESS (charly fork/execs the
// binary for command:bpf dispatch; verb:bpf resolves through the gRPC provider
// registry) — placement is invisible above the registry.
//
// Everything reads the kernel state directly and READ-ONLY: /sys/kernel/security/lsm,
// /sys/kernel/btf/vmlinux, /proc/config.gz (or /boot/config-*), the BPF sysctl
// knobs, RLIMIT_MEMLOCK and lockdown. `probe` is verify-only by default; a real
// transient attach probe requires an explicit --attach flag + root + bpftool.
//
// First consumer: plugin-cardwire's status gates on the same BPF-LSM facts (R3 —
// one canonical surface, no per-application ad-hoc copies).
package bpf

import (
	"embed"

	"github.com/opencharly/sdk"
	pb "github.com/opencharly/spec/proto"
)

//go:embed schema/*.cue
var schemaFS embed.FS

// NewProvider returns the bpf verb provider (the Invoke dispatch surface).
func NewProvider() pb.ProviderServer { return &provider{} }

// NewMeta advertises verb:bpf (the BPF-readiness check verb) + the plugin's
// self-contained CUE schema (via sdk.NewMeta → BuildCapabilities). The verb's
// authoring contract lives in the served #BpfInput (schema/bpf.cue), which the
// host splices onto the base and validates every authored `bpf:` step's plugin_input
// against. command:bpf is NOT advertised here: it is dispatched by charly
// fork/exec'ing this binary in CLI mode (cliMain), not resolved through the gRPC
// provider registry (its args are plain CLI tokens parsed by kong). The candy's
// plugin.providers declaration still lists command:bpf (that drives the CLI-grammar
// prescan + the baked `.providers` manifest).
func NewMeta() pb.PluginMetaServer {
	return sdk.NewMeta("2026.243.0001",
		[]sdk.ProvidedCapability{
			{Class: "verb", Word: "bpf", InputDef: "#BpfInput"},
		},
		schemaFS)
}

// CliMain is the plugin's CLI entrypoint (command:bpf dispatch — `charly bpf …`).
func CliMain(args []string) int { return cliMain(args) }
