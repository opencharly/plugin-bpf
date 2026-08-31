// The `bpf` plugin's OWN CUE schema — the typed plugin_input for the `bpf`
// BPF-readiness check verb. It is the SINGLE SOURCE for this plugin's params,
// used two ways:
//
//  1. GENERATE the Go param struct — `cue exp gengotypes` (driven by the cue:gen
//     pipeline, which wraps this with `package params` + `@go(params)`) emits
//     ../params/cue_types_gen.go, so the provider decodes plugin_input into a
//     TYPED struct, never a hand-parsed map.
//  2. VALIDATE authored input AT RUNTIME — the plugin serves this source over the
//     Describe channel; the host splices it onto the base (base ++ plugin) and
//     validates every authored `bpf:` step's plugin_input against #BpfInput.
//
// SELF-CONTAINED: it references NO base def, so it compiles standalone
// (gengotypes + the load-gate compile) AND splices onto the base (base ++ plugin
// is a def-name collision check, not a base-reference resolver).
#BpfInput: {
	// lsm — the scalar-sugar primary: assert bpf is in the active LSM list.
	// The step's own matchers decide pass/fail (e.g. stdout contains "enabled",
	// or exit_status 0).
	lsm?: bool @go(Lsm)

	// status — matcher form over the readiness facts.
	status?: {
		// lsm_bpf — is bpf in the active LSM list.
		lsm_bpf?: bool @go(LSMHasBPF)
		// btf_present — does /sys/kernel/btf/vmlinux exist.
		btf_present?: bool @go(BTFPresent)
		// config_bpf_lsm — is CONFIG_BPF_LSM=y.
		config_bpf_lsm?: bool @go(ConfigBPFLSM)
	}
}