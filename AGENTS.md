# AGENTS.md — plugin-bpf

Standalone out-of-tree plugin repo for the generic BPF kernel surface
(`command:bpf` + `verb:bpf`). The plugin is a Go module at `candy/plugin-bpf/`
(module path `github.com/opencharly/plugin-bpf/candy/plugin-bpf`); the root
`charly.yml` declares `discover: candy` (so the repo is a project and its candy
is scanned) and the `check-bpf-local` R10 witness bed.

Canonical files:

- `candy/plugin-bpf/charly.yml` — the `plugin-bpf:` candy entity and the
  embedded `bpf-skill:` skill entity.
- `candy/plugin-bpf/` — the Go source: `plugin.go`, `provider.go`, `command.go`,
  `status.go`, `schema/bpf.cue`, `params/cue_types_gen.go`, `cmd/serve/main.go`.
- `charly.yml` — the root manifest (`discover: candy`) + the `check-bpf-local`
  witness bed.
- `.github/workflows/tag-on-merge.yml` — CalVer tag + `CHANGELOG/` on merge.
- `README.md` — user overview only; never agent guidance.

## Load these skills first (R0)

- `/charly-bpf:bpf` — the `charly bpf` command/verb reference (projected from the
  embedded `bpf-skill:` entity). Load before changing the command tree or verb.
- `/charly-internals:plugin` — the plugin authoring reference: the `plugin:`
  block, the dual-class `command` + `verb` provider model, the per-plugin
  CUE-schema contract. Load before touching the provider or schema.
- `/charly-check:check` — the declarative check-step surface the `bpf:` verb is
  authored through.
- `/charly-internals:git-workflow` — before any git/PR action.

## Build / validate / test

- `go build ./...` in `candy/plugin-bpf/` — compile the plugin module.
- `go test ./...` in `candy/plugin-bpf/` — the plugin's hermetic parser/JSON
  tests.
- `charly box validate` at the repo root — the structural check (the candy +
  `plugin:` block, CUE schema).
- The merge gate is the **org-wide** `charly/pr-validator` (required check
  `validate / validate`, defined in `opencharly/.github`); this repo has **no**
  per-repo candy gate.
- The R10 witness is the `check-bpf-local` bed in the root `charly.yml` — a
  host-side run of `charly bpf status` / `charly bpf lsm` / the `bpf: lsm` verb.

## Modify this repo

- Edit the `plugin-bpf:` candy entity, the Go source, and `schema/bpf.cue`
  **together** — the schema is the single source for the verb's `params/` struct.
- Keep every read read-only and direct (no shelling out).
- Keep the `bpf-skill:` entity in step with any command-tree change — it is the
  projected source for `/charly-bpf:bpf`.

## Landing

- PR-only. Every change lands through a pull request; the org-required
  `charly/pr-validator` validates the diff and body and arms native auto-merge on
  PASS. Direct pushes to `main` are blocked.
- History lives in `CHANGELOG/` (written by `tag-on-merge` at merge time); the PR
  body IS the changelog.
- The authoritative rulebook is the umbrella `AGENTS.md` in
  `opencharly/opencharly` and `charly/AGENTS.md` in the charly repo. Do not
  restate its rules here.
