# Reported cross-runs

One JSON file per run, in the format of [TEMPLATE.json](TEMPLATE.json) and
[CROSSRUN.md](../CROSSRUN.md#result-file). CI validates every file here with
`python -m aae_a2a.crossrun check`.

File name: `<YYYY-MM-DD>-<participant>-<role>.json`, where role is `client`
(your client against the reference supplier), `server` (the reference buyer
against your server), `both` or `offline` (an offline receiver run,
[CROSSRUN.md](../CROSSRUN.md) Section 6.1).

## Credit

Each run is credited to the participant who ran it, with the commits of both
sides as recorded in the result file. A run with failures is listed as well;
the failure is a finding about one of the two sides, not about the participant.

A run holds for the cases it ran ([CROSSRUN.md](../CROSSRUN.md), Section 7.1).
The column *Cases* names the commit of this repository whose `cases.json` the
run used, its `cases_commit`; a later re-run against newer cases gets a row of
its own.

| Date | Participant | Role | Cases (commit) | Client (commit) | Server (commit) | Result | File |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
