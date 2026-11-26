# 🚀 Releasing Vaelspire

> **Hard Rule: Documentation MUST be updated *before* cutting any release tag.**

Vaelspire follows Neotales release conventions: every release is built from an annotated git tag on `dev` (`vX.Y.Z` or prereleases `vX.Y.Z-alpha.N` / `-rc.N`), and documentation is never an afterthought.

## Pre-Release Checklist (Required Before `git tag`)

### 1. Update Documentation First (`neotales/vaelspire-site`)
Before creating a tag in `neotales/vaelspire`, update and verify [`neotales/vaelspire-site`](https://github.com/neotales/vaelspire-site):
- [ ] Update affected human guides (`getting-started/`, `guides/`, `enterprise/`) for any new CLI flags, env vars, HTTP routes, or crate APIs.
- [ ] Update `src/content/docs/roadmap.md` (and `ROADMAP.md` in this repo) to reflect completed and upcoming milestones.
- [ ] Update the dense AI agent reference (`src/content/docs/agents/`, `public/llms.txt`, and `public/llms-full.txt`) so agents always see exact post-release signatures and routes.
- [ ] Run `pnpm build` in `vaelspire-site` and confirm zero errors (and strictly **zero cyan** in any theme/asset changes).
- [ ] Commit and push `vaelspire-site` on `dev`.

### 2. Verify All Code & Setup Gates (`neotales/vaelspire`)
- [ ] Update crate versions and changelog notes as appropriate.
- [ ] Update root `README.md` and affected `crates/*/README.md` examples.
- [ ] Run all Rust verification gates on a clean working tree:
  ```bash
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo test --workspace
  ```
- [ ] Run `./scripts/smoke-test.sh` against a live `vaelspire serve` instance.

### 3. Tag & Publish from `dev`
```bash
git switch dev
git pull
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```
