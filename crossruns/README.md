# Reported cross-runs

One JSON file per run, in the format of [TEMPLATE.json](TEMPLATE.json) and
[CROSSRUN.md](../CROSSRUN.md#result-file). CI validates every file here with
`python -m aae_a2a.crossrun check`.

File name: `<YYYY-MM-DD>-<participant>-<role>.json`, where role is `client`
(your client against the reference supplier), `server` (the reference buyer
against your server) or `both`.

## Credit

Each run is credited to the participant who ran it, with the commits of both
sides as recorded in the result file. A run with failures is listed as well;
the failure is a finding about one of the two sides, not about the participant.

| Date | Participant | Role | Client (commit) | Server (commit) | Result | File |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
