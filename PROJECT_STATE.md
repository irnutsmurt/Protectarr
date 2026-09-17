# Project state

Working notes for whoever picks this up next. Current development state only.
Permanent rules live in `CLAUDE.md`; anything in here is expected to go stale.

Last updated: 2026-09-17, end of the v0.8.0 release.

## Where things stand

| | |
|---|---|
| Version | **0.8.0**, released and published |
| Branch | `master`, clean, in sync with `origin/master` |
| Tag | `v0.8.0` -> `2ea1d2e`, pushed |
| CI | `ci/master`, `docker-publish/master`, `docker-publish/v0.8.0` all green |
| Images | `0.8.0`, `0.8`, `latest` all serve 0.8.0 (verified by running the container) |
| Tests | **1090, all passing** |
| Mutation | 105 mutants across six harnesses, 0 survived |

**There is no work in progress.** The tree is clean and the release is
finished. The next session starts from a stable point.

## What v0.8.0 was

The Active Downloads page: a read-only view of what Protectarr currently
believes about each active download, and why. Seven commits:

```
eeabc10  Pin the whole of evaluate() before anything refactors it
00fbc3d  Stop an arr outage writing ownership facts nobody observed
18d61e2  Add core.explain(), and reduce evaluate() to a projection of it
17bc2e0  Publish what the scan believed, atomically, for a view to read
5adcf8a  Add the Active Downloads view
dbf5963  Correct three things the first screenshots showed
5ff231a  Stop the outage dwell depending on a field not existing
2ea1d2e  Release 0.8.0
```

The sequence matters and is worth copying: pin the existing behaviour first,
fix the latent bug the new consumer would have exposed, refactor, publish the
data, then build the view. Each step was independently green.

## Files changed, and why

| File | Why |
|---|---|
| `protectarr/snapshot.py` | **New.** Projects one scan pass into rows for the view. Pure; no I/O. |
| `protectarr/core.py` | Added `explain()` + `_mode_coverage()`; `evaluate()` is now a projection of it. Publishes the snapshot at the end of `scan()`. |
| `protectarr/ownership.py` | Two fixes, both about not asserting unobserved facts on an outage pass. |
| `protectarr/policy.py` | Added `resolve_with_source()`; `resolve()` is now a projection of it. |
| `protectarr/web.py` | `/active` route, the state vocabulary, filters, the Details payload. |
| `protectarr/templates/active.html` | **New.** The page. |
| `protectarr/templates/_details.html` | Renders `r.extra` sections so one dialog serves History and Active. |
| `protectarr/templates/base.html` | Nav entry + icon. |
| `protectarr/static/style.css` | `.dlcards` table/card rules, `.snapage`, `.warnbox`, filter counts. |

## Architectural decisions and invariants

**One decision table, two readers.** `core.explain()` is the table;
`core.evaluate()` is `explain(...).action`. The web layer must never
re-implement the mode branches - that was the whole point of the refactor.
Same pattern in `policy.resolve_with_source()` / `policy.resolve()`.

**The snapshot is presentation state, and non-authoritative.** It is built
complete and published in a single rebind of `state["active"]`. Nothing mutates
a published snapshot in place. A request thread holds either the old one or the
new one, never a half-filled one.

**The page's spine is the torrent list, never `ownership.json`.** Ownership
records outlive their torrents by up to `ownership_prune_minutes` (default 60),
so iterating the store would render up to an hour of ghosts. Iterating torrents
means a stale record has nothing to attach to.

**A failed pass publishes nothing.** The previous snapshot stays and its age
marks it stale. An unreachable qBittorrent must never render as an empty
library - those two states need opposite reactions from an operator.

**Absence of a measurement is not zero.** `absent_for` is `None` whenever a
pass could not verify an absence. That travels untouched to the template, which
says "not being measured" rather than drawing a countdown from zero.

**The ownership store only ever records what a pass observed.** `own.client` is
the signal: it is set only by `_claimed`, which ran because a queue was
actually read. `_unclaimed` carries a previous state forward with no client,
and that is a memory, not an observation.

**"Monitoring" is not an intention.** It means policy covers this torrent, so
if a finding appears Protectarr may act. Most of a healthy library sits there
permanently. No label on this page may imply a queued deletion.

**v0.8.0 is read-only.** No delete, blocklist, re-search, probe trigger,
ownership override or conflict resolution. Adding any of those is a new
decision, not an increment.

## Security and safety requirements

These are not negotiable and several are enforced by tests.

- **Never commit real secrets.** Tests use obviously fake values
  (`test-api-key`), demo data uses RFC 5737 documentation IP ranges. `gitleaks`
  gates CI (`.github/workflows/ci.yml`).
- **A secret the user pastes into a conversation is a runtime value only.** It
  never goes into a test fixture, sample config, script default or comment.
- **Never render a stored secret back to the browser.** Established secret
  fields render blank, blank preserves the stored value, no `********`
  sentinels, no serialising credentials into JS or hidden fields. The API-key
  Reveal/Copy control is for Protectarr's own key and nothing else.
- **Redact credentials in logs.** Protectarr is public and users attach logs to
  GitHub issues. Be careful with new diagnostic logging.
- **Release names are attacker-controlled.** Protectarr exists because someone
  published a torrent designed to deceive, and that person chooses the name,
  category and tags. Anything rendering them must escape in both the markup and
  any JSON payload. Pinned in `tests/test_active_page.py`.
- **Uncertainty fails safe.** An unreadable *arr queue suppresses direct
  deletion for the whole pass. A conflict is never resolved automatically. A
  remediation that could not be verified is terminal and never retried.

## Known issues and unresolved questions

**Deferred, each needs its own approval:**

1. **No membership validation on `auth_method` / `auth_required`.** An
   out-of-range value causes a redirect loop for new sessions. Reported during
   the 0.7.0 recon, never fixed.
2. **No dedupe or validation on the bulk IP and proxy lists.** Same origin.
3. **`dashboard.py`'s Recent Findings card** renders a single bar; flagged as
   odd, on explicit hold.
4. **History's desktop table has a 1366px floor** with long release names and
   scrolls sideways on a 1440 desktop. Active Downloads fixed this for itself
   with `overflow-wrap: anywhere`; History was explicitly out of scope. **This
   is now the obvious next cleanup** - the fix is known and one line.

**Behaviour that looks like a bug and is not:**

- **The orphan dwell spans periods when the *arr was unreachable.** Absent at
  T+60, Sonarr down until T+600, dwell reports 600s of which only ~120 was
  verified. This contradicts a loose reading of "continuous verified absence"
  in the docstring, but it is deliberate and pinned by
  `test_a_failed_queue_read_does_not_advance_the_dwell`, which explicitly
  asserts the clock runs from the first *verified* absence. Do not "fix" it
  without a decision.

**Genuine gap, low priority:**

- **Air-date holds are not visible on Active Downloads.** Whether a replacement
  search is held until a release airs lives in `events.jsonl`, not on the
  intent, so the snapshot cannot read it. In practice unreachable: an intent
  that reached the air-date decision has already had its torrent removed, so it
  has no row on the page.

## Tests

| Suite | What it covers |
|---|---|
| `test_evaluate_matrix.py` | All 240 cells of the safety decision table, as an external literal |
| `test_explain.py` | The reasons `evaluate` discards; proves `evaluate` is a projection |
| `test_snapshot.py` | The projection, publication, staleness, metaDL, paused orphans |
| `test_active_page.py` | Route, state vocabulary, filters, read-only, escaping, dossier payload |
| `test_active_layout.py` | Browser-backed geometry: floor, breakpoint, stacked cards |
| `test_ownership.py` | Outage semantics, including the two fixes in this release |

Run everything:

```bash
venv/bin/python -m unittest discover -s tests          # 1090 tests, ~6 min
```

One suite:

```bash
venv/bin/python -m unittest tests.test_active_page -v
```

Mutation harnesses live in the session scratchpad, not the repo. If they are
gone, the tests still stand on their own; the harnesses only prove the tests
bite. Convention: every patch must change the file, and a **named** test must
fail. A patch matching nothing is reported as a hole, not a pass. A harness
must also purge `__pycache__` and run with `-B`, for the reason recorded under
"Non-obvious implementation discoveries" - without it the results are noise.

## Non-obvious implementation discoveries

Things that cost real time to find and are not visible in the code.

- **`overflow-wrap: anywhere` reduces a cell's min-content contribution;
  `break-word` does not.** `break-word` permits a break during layout but the
  column still demands the whole unbreakable token, so a table cannot shrink
  past it. Measured on History: swapping it in moves the floor by 0px.
- **A `max-width` on that cell does nothing for the floor.** Measured across
  caps from 260px to none, the table floor is 688px in every case and the
  rendered width at a given viewport is identical - table layout was already
  distributing the space. The cap only made the column narrower and the row
  taller. It was removed.
- **Chromium floors `--window-size` at 500px.** Anything narrower needs an
  iframe of the target width inside a >=500px window, served over http so the
  probe is same-origin.
- **PIL is in the system `python3`, not the venv.** Flask is in the venv. The
  screenshot scripts shell out to `python3 -c` for cropping.
- **`re.sub` with a string replacement processes backslash escapes.** The
  stylesheet contains CSS escapes like `\25B8`, which get read as group
  references. Use a function replacement when inlining it.
- **Inline a stylesheet before rendering from `file://`** - there is no server
  behind `/static`.
- **`controls inside `<div inert>` still serialize in FormData`;
  `fieldset disabled` controls do not.** Against whole-section overwrite
  semantics, `disabled` would erase fields on the next save.
- **`docker manifest inspect | sha256sum` is not a reliable digest
  comparison.** Compare `docker image inspect --format '{{.Id}}'` instead.
- **Two mutation harnesses must never run concurrently.** They patch the same
  files. Running two at once left a mutant in `web.py` during this session; it
  survived a full 1090-test run because nothing asserted the clause it
  disabled. Run them sequentially and verify anchors afterwards.
- **A mutation harness must purge `__pycache__` and run its tests with `-B`.**
  CPython validates a `.pyc` against the source's mtime *in whole seconds*
  plus its size. A harness patches and restores a file far faster than that, so
  a restore landing in the same second as the mutant's compile leaves the
  mutant's bytecode looking valid for the original source - and the next mutant
  runs against the previous mutant's code. Found during 0.8.1: the first run of
  the Phase A harness reported eight survivors, every one of them false. After
  adding `PYTHONDONTWRITEBYTECODE=1`, `python -B` and a `__pycache__` purge
  before each subprocess, the same twenty mutants all died.

  **This affects the six historical harnesses too.** Their recorded
  "0 survived" results were produced without that protection and should be
  treated as unverified rather than as evidence. Nothing is known to be wrong
  as a result - a stale mutant makes a harness lie in both directions, so the
  errors are not biased toward false confidence - but the numbers no longer
  mean what they say. Re-running them is cheap and was deliberately not done as
  part of 0.8.1, which was scoped to two safety fixes.

## Next tasks, in priority order

1. **Fix History's 1366px table floor.** The fix is known
   (`overflow-wrap: anywhere` on the release cell), the measurement technique
   exists in `tests/test_active_layout.py`, and it is the last place in the UI
   that scrolls sideways on an ordinary desktop.
2. **Decide on the deferred validation items** (auth method membership, bulk
   list dedupe). Both are small and both were reported and approved-for-later
   during 0.7.0 recon.
3. **Consider a README section for Active Downloads.** Every other major page
   has a screenshot and a paragraph; the flagship feature of 0.8.0 currently
   has neither. Shots already exist in `screenshots/v080/`. This was
   deliberately left out of the release because the brief said no additional
   work.
4. **Operator actions on Active Downloads**, if and only if the displayed state
   has been trusted in real use for a while. This was explicitly deferred.

## Read these first

1. `protectarr/core.py` - `explain()`, `_mode_coverage()`, `evaluate()`, and
   `scan()`'s tail where the snapshot is published. The docstrings carry the
   reasoning.
2. `protectarr/snapshot.py` - short, and its module docstring states the four
   rules the projection follows.
3. `protectarr/ownership.py` - the module docstring explains why ownership is
   durable and what each state means.
4. `tests/test_evaluate_matrix.py` - the safety decision table, readable as a
   table.
5. `README.md` - what the thing is for.
