# plugin-bpf

A GENERIC charly plugin for the eBPF/BPF **kernel** surface: readiness detection, the
BPF-LSM gate, BTF/config facts, and a verify-only attach-requirements probe. It is the
one canonical home for "is this kernel BPF-ready" assertions; every eBPF-consuming
workload charly deploys or probes (security LSM tooling, observability agents, GPU
managers like cardwire, kernel-feature gating in checkbeds) reuses it instead of baking
ad-hoc copies.

## Surfaces

- **`charly bpf status [--json]`** — read-only report: kernel, active LSM list
  (`/sys/kernel/security/lsm`) with the bpf presence, BTF (`/sys/kernel/btf/vmlinux`),
  `CONFIG_BPF_LSM` / `CONFIG_DEBUG_INFO_BTF` (from `/proc/config.gz` or `/boot/config-*`),
  `unprivileged_bpf_disabled`, RLIMIT_MEMLOCK, bpftool presence, lockdown.
  Every unreadable fact prints an explicit N/A line; exit 0.
- **`charly bpf lsm`** — THE gate. `BPF LSM: enabled` + exit 0 when `bpf` is in the active
  LSM list; `BPF LSM: DISABLED (…reboot…)` + exit 1 otherwise.
- **`charly bpf config`** — the BPF sysctl knobs, read-only (`unprivileged_bpf_disabled`,
  `bpf_jit_enable`).
- **`charly bpf probe <lsm|tracepoint> [--attach]`** — verify-only by default: reports the
  attach requirements (BTF present, LSM gate, root/CAP_BPF, bpftool) with a
  `PROBE-DRY-RUN` verdict. With `--attach` + root + bpftool it runs `bpftool feature probe`
  (harmless) and reports; otherwise refuses with the missing requirement named.

**Check steps** — `verb:bpf` lets any candy bake a deterministic BPF gate into its plan:

```yaml
- check: the venue kernel enables the bpf LSM
  id: bpf-lsm-gate
  bpf: lsm
  context: [runtime]
  stdout:
    - contains: enabled
```

The authored `plugin_input` is validated at runtime against the self-contained
`#BpfInput` (schema/bpf.cue), spliced by the host.

## Layout

- `candy/plugin-bpf/` — the plugin module (dual-class: `command:bpf` + `verb:bpf`,
  plugin-mcp precedent).
- `cmd/serve/main.go` — the dual-mode sdk.Main entrypoint.

## Verification

- `go test ./...` + `go build ./...` in `candy/plugin-bpf/` (hermetic parser/JSON tests).
- `check-bpf-local` (opencharly/charly) — host-side R10 witness for the `charly bpf`
  dispatch with the deterministic exit-code contracts.
