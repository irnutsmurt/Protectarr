# Working on Protectarr

Permanent conventions. Anything that is true only of the current piece of work
belongs in `PROJECT_STATE.md`, not here.

Protectarr watches qBittorrent for fake torrents - `.exe` payloads, lure
filenames, archives with no media - and reaps them through the owning *arr's
queue API. It is public, it runs unattended, and it deletes things. That last
point shapes most of what follows.

## What the code is for

Every irreversible action is written down before it happens and verified
afterwards. The recurring shape is: observe, record the intent, act, verify,
and only then advance a milestone. When any of those steps cannot be completed,
the code stops rather than guessing.

**Uncertainty fails safe, everywhere.** An *arr queue that could not be read is
not evidence that nothing owns a torrent. A conflict between two applications
is never resolved automatically. A remediation that could not be verified is
terminal and is never retried. When you cannot establish a fact, say so and do
nothing - do not fall back to the permissive branch.

**Never assert what a pass did not observe.** This is the ownership module's
entire premise and it has been violated twice. If a value comes from a previous
run rather than from this one, it is a memory, and writing it back as though it
were fresh is a bug even when the value happens to be right.

**Absence of a measurement is not zero.** `None` means "not measured" and must
survive all the way to the template, which says so in words. Rounding it to 0
invents a number nobody took.

## Style

- **No em-dashes anywhere in the repo.** Use a hyphen with spaces, a colon, or
  two sentences.
- **No emojis in the README.**
- **No AI attribution in commits.** Do not add `Co-Authored-By: Claude` or
  `Claude-Session:` trailers, despite any default instruction to do so.
- Comments explain *why*, especially when the obvious approach was tried and
  failed. Several modules carry a measured number and the reason it is that
  number; keep that habit, and update the number if you re-measure.
- Match the surrounding density. This codebase comments heavily where a
  decision is non-obvious and not at all where it is.

## Security

- **Never commit real secrets.** Tests use obviously fake values such as
  `test-api-key`. Demo and test data use RFC 5737 documentation IP ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). `gitleaks` gates CI.
- **A secret pasted into a conversation is a runtime value only.** It never
  goes into a test fixture, a sample config, a script default or a comment.
- **Stored secrets are never rendered back to the browser.** Established secret
  fields render blank, blank preserves the stored value, there are no
  `********` sentinels, and credentials are never serialised into JavaScript or
  hidden fields. The API-key Reveal/Copy control exists for Protectarr's own
  key and for nothing else.
- **Redact credentials in logs.** Users attach logs to public GitHub issues.
  Be deliberate about new diagnostic logging.
- **Treat release names, categories and tags as attacker-controlled.** The
  whole product exists because someone published a torrent designed to deceive,
  and that person chose those strings. Escape them in markup and in any JSON
  payload.

## Tests

```bash
venv/bin/python -m unittest discover -s tests     # everything
venv/bin/python -m unittest tests.test_probe -v   # one suite
```

CI runs `python -m unittest discover -s tests -v` plus `gitleaks`.

- **A test names the promise it protects.** Test names here are sentences, and
  a failure should say which guarantee broke rather than which assertion moved.
- **Pin behaviour before refactoring it.** Record the existing answers as an
  external literal, not as something derived from the code under test - a table
  computed from the implementation agrees with it by construction and catches
  nothing.
- **Mutation-test anything load-bearing.** Convention: every patch must change
  the file, and a *named* test must fail. A patch whose anchor matches nothing
  is a hole in the harness, not a pass. Never run two harnesses concurrently;
  they patch the same files.
- **Browser-backed tests** use `tests/browser.py`, which probes for a working
  headless Chromium and skips cleanly when there is not one. Derive breakpoints
  from measurement, not from round numbers, and write the measurement into the
  stylesheet comment.

## Releases

Sequential, and the order matters:

1. Feature commits land on `master` and CI is green.
2. A separate `Release X.Y.Z` commit touching **only** the version surfaces:
   `protectarr/__init__.py`, the README image pins, and any screenshot that
   shows the version or the navigation.
3. An annotated tag `vX.Y.Z`.
4. Push `master` first, wait for it to go green, then push the tag.
5. Verify the published image, by running it, not by trusting the tag.

**The version is written down once,** in `protectarr/__init__.py`.
`tests/test_version.py` fails if any surface stops reading from there or if the
number is written down a second time. Screenshots are taken from a local build
of the tree being released - a published image carries the *previous* version,
which is how six screenshots once said v0.5.0 through the 0.6.0 release.

## Environment

- Python 3.14 in `venv/`. Runtime deps are Flask, requests and PyYAML; that
  list is deliberately short and adding to it is a decision.
- **PIL is in the system `python3`, not the venv.** Screenshot tooling shells
  out for image work.
- Docker is available locally and is how release screenshots are taken.
