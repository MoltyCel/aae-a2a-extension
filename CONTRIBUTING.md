# Contributing

Two kinds of contribution are expected here: a **reported cross-run**, and a
**new case** for the cross-run case set. Both go through a pull request.

## License and attribution

By opening a pull request you contribute your change under the
[Apache License 2.0](LICENSE), the license of this repository, and you confirm
you may license it that way.

You keep the authorship of what you contribute. Concretely:

- The commit stays yours. A pull request is merged with a merge commit, so the
  author and the committer of your own commits are not rewritten.
- A case you contribute is credited to you by name in
  [CROSSRUN.md](CROSSRUN.md) and, where the case came out of a run, in the
  credit table of [`crossruns/README.md`](crossruns/README.md).
- A reported run is credited to the participant who ran it, with the commits of
  both sides as recorded in the result file
  ([`crossruns/README.md`](crossruns/README.md)).
- Nobody is named without having asked for it. Say in the pull request how you
  want to be credited — name, handle, a link to your own repository, or not at
  all. Without a word from you, the credit is the pull request author's GitHub
  handle.

There is no contributor license agreement and no copyright assignment.

## Reporting a cross-run

[CROSSRUN.md](CROSSRUN.md) Section 7 is the procedure: publish your result file
in your own repository if you can, then add it under
[`crossruns/`](crossruns/) as `<YYYY-MM-DD>-<participant>-<role>.json` together
with one row in the credit table. A failing case is worth reporting; say which
side you think is wrong.

## Contributing a case

A case is an entry in `tests/vectors/crossrun/cases.json`, a row in the table of
[CROSSRUN.md](CROSSRUN.md) Section 4, and the fixed bytes in
`tests/vectors/crossrun/pinned/` that let a third party check the case without
running our code.

What a case needs:

1. **The next free `XR-` number.** A new case is added, existing numbers are
   not reused, and a reported run stays valid for the case set at its own
   `cases_commit` (Section 7.1).
2. **The expectation, derived from the profile.** Name the section of
   [`spec/aae-a2a-extension-v1.md`](spec/aae-a2a-extension-v1.md) the expected
   outcome follows from. Where a case presents the same AAE more than once,
   state *authorization* and *admission* apart, as XR-20 and XR-24 do.
3. **A counterexample where one applies.** A case that asserts two values are
   equal is worth little without the neighbouring case where they differ.
4. **A test.** `make test` must pass, and the pinned bundle must rebuild to the
   same bytes, with `MANIFEST.sha256` updated.
5. **A row in CROSSRUN.md** Section 4, with the `request_digest` of the request
   part (spec Section 8.5).

CI runs the tests, the demo, the reference-against-reference cross-run, the
pinned bundle against a fixed clock, and `crossrun check` over every reported
run. It must be green before a merge.

## Anything else

A finding about the specification or the reference implementation does not need
a pull request. Open an issue and say what you observed and what you expected.
Keys in this repository are public test keys and are not secrets; do not report
them as a leak.
