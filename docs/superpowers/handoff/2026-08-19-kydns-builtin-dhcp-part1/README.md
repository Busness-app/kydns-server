# SDD workspace snapshot — built-in DHCP part 1

This is a committed copy of the subagent-driven-development workspace for
`docs/superpowers/plans/2026-08-19-kydns-builtin-dhcp-part1.md`, so the run can be read without
the git-ignored workspace. All 11 tasks are complete and the branch has been reviewed as a whole. Read `docs/superpowers/plans/2026-08-20-kydns-builtin-dhcp-part1-handoff.md` first —
it is the summary; this directory is the working state behind it.

The live workspace normally lives at `.superpowers/sdd/2026-08-19-kydns-builtin-dhcp-part1/`, which is
git-ignored (`.gitignore:16`). That is why this copy exists.

## Contents

| File | What it is |
|---|---|
| `progress.md` | **The ledger.** Pre-flight conflict scan, every ruling, per-task review outcomes, deferred minors, verified helper names, and the Part 2 amendment list. The authoritative record of the run. |
| `task-N-brief.md` | The requirements handed to each implementer — the task's section of the plan, extracted verbatim. Tasks 1–11. |
| `task-N-report.md` | What each implementer actually did, the commands they ran, and what they found wrong with the brief. Tasks 1–11, all complete. |
| `final-findings.md` | The whole-branch review's findings, written as the brief for the fix wave: 2 Critical, 5 Important, 9 small items, each with its demonstrated failure. |
| `final-fix-report.md` | Both fix waves against those findings, with the RED output and the mutation results. |

**Review diffs are deliberately not here.** They were `git diff` output over commit ranges that are all
pushed on this branch, so they are regenerable and would have added ~110 KB of duplicated history.

## Restoring on another machine

```sh
git clone <repo> && cd kydns-server
git checkout worktree-dhcp-part1
mkdir -p .superpowers/sdd/2026-08-19-kydns-builtin-dhcp-part1
cp docs/superpowers/handoff/2026-08-19-kydns-builtin-dhcp-part1/*.md \
   .superpowers/sdd/2026-08-19-kydns-builtin-dhcp-part1/
rm .superpowers/sdd/2026-08-19-kydns-builtin-dhcp-part1/README.md
```

Then confirm the baseline before doing anything else — the ledger's claims are only true of a green
tree:

```sh
go build ./... && go test ./... -count=1 && go vet ./...
```

Expect 19 packages passing, 0 failures.

`superpowers:subagent-driven-development` resumes from the ledger: tasks with a `Task <N>: complete`
line are done and must not be re-dispatched. As of this snapshot, tasks 1–6 are complete and task 7 is
code-complete with its scoped re-review not yet run.

To regenerate a review package for a range:

```sh
<superpowers>/skills/subagent-driven-development/scripts/review-package \
  docs/superpowers/plans/2026-08-19-kydns-builtin-dhcp-part1.md <BASE> <HEAD>
```

## A caution about this copy

This snapshot is a point-in-time copy, not a live file. If the run continues on the original machine,
the working ledger at `.superpowers/sdd/…` moves ahead of it and this directory goes stale silently.
Whoever continues the work should re-copy it before handing off again, or delete it once the branch
merges — the git history and the handoff document are the durable record.
