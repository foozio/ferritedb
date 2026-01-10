# Repository Guidelines

## Project Structure & Module Organization
FerriteDB is anchored by `src/main.rs`, which wires the runtime and launches the service. Domain modules live under `crates/`: `crates/core` hosts business logic, `crates/server` exposes Axum routes and middleware, `crates/storage` provides pluggable backends, `crates/rules` evaluates access policies, and `crates/sdk-rs` contains the Rust client. Integration artifacts sit in `tests/`, while database migrations reside in `migrations/`. Operational assets are kept in `scripts/`, packaging recipes in `release/`, and longer-form docs under `docs/`.

## Build, Test, and Development Commands
Use `just dev` for hot-reload development (`cargo watch -x "run -- serve"`). `just build` produces an optimized binary, and `just serve` runs the server once. `just test`, `just test-integration`, and `just test-performance` cover unit, integration, and performance suites. Quality gates include `just lint` (Clippy), `just fmt` (rustfmt), and `just test-coverage` (Tarpaulin HTML in `coverage/`).

## Coding Style & Naming Conventions
Stick to the default Rust 4-space, rustfmt-managed style; run `just fmt` before submitting. Use single-responsibility modules, prefer early returns over deep nesting, and document non-obvious invariants inline. Name modules and files with `snake_case`, types with `CamelCase`, and constants with `SCREAMING_SNAKE_CASE`. Clippy settings in `clippy.toml` tighten complexity thresholds, so `just lint` must pass cleanly.

## Testing Guidelines
Unit tests live next to their modules; integration suites reside in `tests/` and `crates/server/tests/`. Name integration test files after the feature under test (e.g., `auth_tests.rs`). Always run `just test`; include `just test-integration` when touching endpoints or migrations, and `just test-performance` for performance-critical paths. Verify new code preserves coverage before sharing results from `just test-coverage`.

## Commit & Pull Request Guidelines
Commits should be focused and written in the imperative mood (e.g., `Mask password in URI logs`). Reference impacted crates or services when useful. Pull requests need a concise summary, observable impact, and evidence of the commands you ran. Link issues or roadmap items, attach screenshots for admin UI updates, and mention rollout or migration steps whenever schema files in `migrations/` change.

## Security & Configuration Notes
Do not commit secrets; keep overrides in `.env` or `ferritedb.dev.toml`. Run `just audit` and `just security-scan` after dependency upgrades or auth changes. For new endpoints, document required scopes in `docs/` and ensure corresponding migrations are reversible before opening a pull request.

## Versioning & Release Protocol

We strictly adhere to **Semantic Versioning (SemVer)** and use **Conventional Commits** to automate version bumping.

### Core Principles
1.  **Single Source of Truth:** `Cargo.toml` is the master version.
2.  **Conventional Commits:** All commits must follow the `type(scope): description` format.
    *   `feat:` -> Minor version bump.
    *   `fix:` -> Patch version bump.
    *   `BREAKING CHANGE:` footer -> Major version bump.
3.  **Keep a Changelog:** Maintain `CHANGELOG.md` with an `## [Unreleased]` section at the top.

### Release Workflow
When ready to cut a release (e.g., `v0.2.0`):

1.  **Preparation:**
    *   Ensure the `[Unreleased]` section in `CHANGELOG.md` is up-to-date.
    *   Run full test suite: `cargo test --workspace`.
2.  **Versioning:**
    *   Determine the bump type (Major/Minor/Patch) based on unreleased changes.
    *   Update version in `Cargo.toml`.
    *   Move `[Unreleased]` content to `## [vX.Y.Z] - YYYY-MM-DD`.
3.  **Tagging & Publishing:**
    *   Commit changes: `chore(release): Prepare vX.Y.Z`.
    *   Tag the commit: `git tag vX.Y.Z`.
    *   Push: `git push origin main --tags`.

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

---

### Using bv as an AI sidecar

bv is a graph-aware triage engine for Beads projects (.beads/beads.jsonl). Instead of parsing JSONL or hallucinating graph traversal, use robot flags for deterministic, dependency-aware outputs with precomputed metrics (PageRank, betweenness, critical path, cycles, HITS, eigenvector, k-core).

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use [MCP Agent Mail](https://github.com/Dicklesworthstone/mcp_agent_mail).

**⚠️ CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

#### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns everything you need in one call:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command

#### Other Commands

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS (hubs/authorities), eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level` (healthy\|warning\|critical), `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels by: (pagerank × staleness × block_impact) / velocity |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations: `stats`, `histories` (per-bead events/commits/milestones), `commit_index` |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles introduced/resolved |

**Other Commands:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions, cycle breaks |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Self-contained interactive HTML visualization |

#### Scoping & Filtering

bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work (no blockers)
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank scores
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain

#### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl (verify consistency across calls)
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`; contains ref and resolved SHA

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density — always available immediately
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles — check `status` flags

**For large graphs (>500 nodes):** Some metrics may be approximated or skipped. Always check `status`.

#### jq Quick Reference

bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
bv --robot-label-health | jq '.results.labels[] | select(.health_level == "critical")'

**Performance:** Phase 1 instant, Phase 2 async (500ms timeout). Prefer `--robot-plan` over `--robot-insights` when speed matters. Results cached by data hash.

Use bv instead of parsing beads.jsonl—it computes PageRank, critical paths, cycles, and parallel tracks deterministically.

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_viewer](https://github.com/Dicklesworthstone/beads_viewer) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
bd ready              # Show issues ready to work (no blockers)
bd list --status=open # All open issues
bd show <id>          # Full issue details with dependencies
bd create --title="..." --type=task --priority=2
bd update <id> --status=in_progress
bd close <id> --reason="Completed"
bd close <id1> <id2>  # Close multiple issues at once
bd sync               # Commit and push changes
```

### Workflow Pattern

1. **Start**: Run `bd ready` to find actionable work
2. **Claim**: Use `bd update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `bd close <id>`
5. **Sync**: Always run `bd sync` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `bd ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `bd dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
bd sync                 # Commit beads changes
git commit -m "..."     # Commit code
bd sync                 # Commit any new beads changes
git push                # Push to remote
```

### Best Practices

- Check `bd ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `bd create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `bd sync` before ending session

<!-- end-bv-agent-instructions -->
