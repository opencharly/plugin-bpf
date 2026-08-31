## Summary

New generic charly **eBPF/BPF kernel plugin** — the one canonical surface for "is this kernel BPF-ready" assertions on any venue:
- **command:bpf** — `status [--json]` (read-only readiness report: kernel, active LSM list + bpf presence, BTF, CONFIG_BPF_LSM/CONFIG_DEBUG_INFO_BTF, unprivileged_bpf_disabled, memlock, bpftool, lockdown; every unreadable fact = explicit N/A line, exit 0), `lsm` (the BPF-LSM gate: exit 0 when `bpf` is in /sys/kernel/security/lsm, exit 1 + reboot hint otherwise), `config` (BPF sysctl knobs, read-only), `probe <lsm|tracepoint> [--attach]` (verify-only attach-requirements report; real attach = explicit --attach + root + bpftool → `bpftool feature probe`).
- **verb:bpf** — declarative `bpf: lsm` / `bpf: {status: …}` check steps any candy can bake into its plan; self-contained #BpfInput schema (schema/bpf.cue) spliced for runtime validation; shared sdk.VerbVerdict matcher pipeline (R3).

First consumer: plugin-cardwire's status gates on the same BPF-LSM facts (no ad-hoc copies — R3). Mirrors the plugin-mcp dual-class (verb+command) and plugin-udev (command) precedents.

## How tested

```
$ cd candy/plugin-bpf && go mod tidy && go build ./... && go test ./...
ok  github.com/opencharly/plugin-bpf/candy/plugin-bpf  0.003s
?   github.com/opencharly/plugin-bpf/candy/plugin-bpf/cmd/serve  [no test files]
?   github.com/opencharly/plugin-bpf/candy/plugin-bpf/params     [no test files]
```

Live smoke test on the CachyOS host (bpf LSM active):

```
$ bpf status
BPF kernel feature report
  kernel:                     7.1.8-1-cachyos
  lsm list:                   capability,landlock,lockdown,yama,bpf
  bpf LSM:                    enabled
  BTF vmlinux:                present
  CONFIG_BPF_LSM:             y
  CONFIG_DEBUG_INFO_BTF:      y
  unprivileged_bpf_disabled:  2
  memlock:                    unlimited
  bpftool:                    present
  lockdown:                   [none] integrity confidentiality
$ bpf lsm        -> BPF LSM: enabled (exit 0)
$ bpf lsm --json -> {"lsm_bpf": true, "lsm_list": ["capability","landlock","lockdown","yama","bpf"]}
$ bpf probe lsm  -> PROBE-DRY-RUN: NOT attach-ready (missing: root)   # correct: user, not root
```

Hermetic unit tests use the fixture captured in the Phase-0 spike (real host/guest LSM outputs); the disabled-LSM exit-1 path is covered by the bpf-less fixture test (the live host has bpf enabled).

## Rulebook compliance

- **R1**: no anomaly — build/test/smoke all green.
- **R3**: one canonical BPF surface (no per-app duplicates); dual-class mirrors plugin-mcp; matchers via shared sdk.VerbVerdict.
- **R4**: no workarounds — probe is verify-only by default; attach requires explicit --attach + root (documented boundary, bpftool lifecycle stays bpftool's job).
- **R5**: n/a (new capability).
- **R6**: feat/ branch only; no force-push; PR-only landing.
- **R7**: gate = `go build ./...` + `go test ./...` green on the final tree (pasted above); the host-side R10 witness bed (check-bpf-local) lands in the follow-up opencharly/charly PR once this merges.

## Change classification

- Change class: new capability (new external plugin repo, no core changes).
- Verification gate: go build + go test + live CLI smoke (host-side run, read-only).
- Attribution tier: `fully tested and validated` — build+test green on the final committed tree and the changed runtime path (the CLI) executed live with retained output above.

*Assisted-by: pi openrouter/deepseek/deepseek-v4-flash-0731 (fully tested and validated)*
