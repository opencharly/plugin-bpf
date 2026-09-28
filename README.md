# plugin-bpf

BPF/eBPF kernel-feature readiness for OpenCharly — the one canonical surface for
"is this kernel BPF-ready" assertions on any venue (bare host or VM guest).

Every eBPF-consuming workload charly deploys or probes (security LSM tooling,
observability agents, GPU managers like cardwire, kernel-feature gating in check
beds) reuses this plugin instead of baking ad-hoc copies. All reads are
**read-only and direct** — no shelling out.

## What it provides

| Capability | Surface |
|---|---|
| `command:bpf` | `charly bpf status \| lsm \| config \| probe` |
| `verb:bpf` | the declarative `bpf:` check step any candy can bake into its plan |

- **`charly bpf status [--json]`** — read-only report: kernel, active LSM list
  (`/sys/kernel/security/lsm`) with the bpf presence, BTF
  (`/sys/kernel/btf/vmlinux`), `CONFIG_BPF_LSM` / `CONFIG_DEBUG_INFO_BTF`,
  `unprivileged_bpf_disabled`, RLIMIT_MEMLOCK, bpftool presence, lockdown. Every
  unreadable fact prints an explicit N/A line; exit 0.
- **`charly bpf lsm`** — THE gate: `BPF LSM: enabled` + exit 0 when `bpf` is in
  the active LSM list; `BPF LSM: DISABLED (…reboot…)` + exit 1 otherwise.
- **`charly bpf config`** — the BPF sysctl knobs, read-only.
- **`charly bpf probe <lsm|tracepoint> [--attach]`** — verify-only by default,
  with a `PROBE-DRY-RUN` verdict; `--attach` + root + bpftool runs
  `bpftool feature probe`.

## How to use it

Compose the plugin candy in a box or check bed's `candy:` list:

```yaml
- '@github.com/opencharly/plugin-bpf/candy/plugin-bpf:<tag>'
```

Then author the verb in a plan:

```yaml
- check: the venue kernel enables the bpf LSM
  id: bpf-lsm-gate
  bpf: lsm
  context: [runtime]
  stdout:
    - contains: enabled
```

The authored `plugin_input` is validated at runtime against the self-contained
`#BpfInput` (`schema/bpf.cue`), spliced by the host.

## Layout

- `candy/plugin-bpf/` — the plugin module: `plugin.go`, `provider.go`,
  `command.go`, `status.go`, `schema/bpf.cue`, `params/cue_types_gen.go`,
  `cmd/serve/main.go`.
- `candy/plugin-bpf/charly.yml` — the `plugin-bpf:` candy entity and the
  embedded `bpf-skill:` skill entity.
- `charly.yml` — the root project manifest (`discover: candy`), plus the
  `check-bpf-local` R10 witness bed.
- `.github/workflows/tag-on-merge.yml` — CalVer tag + `CHANGELOG/` on merge.

## Related

- Owning skill: `/charly-bpf:bpf` (projected from the embedded `bpf-skill:`
  entity).
- First consumer: `/charly-cardwire:cardwire` — its status gates on the same
  BPF-LSM facts.
- `/charly-internals:plugin` — the plugin/provider model.
- [`opencharly/charly`](https://github.com/opencharly/charly) — the charly CLI.
