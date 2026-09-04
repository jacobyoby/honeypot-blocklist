# Changelog

Notable changes to the published blocklist and its methodology. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Dates are UTC.

Methodology changes affect who appears on the list, so they are treated as
breaking and called out explicitly.

## [Unreleased] — compiled validation shadow

### Added

- A dependency-free Go validator now gates the four publication files and
  preserves the frozen Python validator's stdout and exit-code contract on the
  current corpus. Sanitized in-memory fixtures cover positive and negative
  paths without retaining captured data.
- CI now pins action revisions, compiles native and Linux amd64 targets, runs
  race tests, reports the dependency tree, checks known Go vulnerabilities,
  and rejects secret-like tracked material.

### Changed

- The compiled gate deliberately closes six malformed-input gaps while the
  valid corpus remains byte-for-byte untouched: boolean counters, incomplete
  entry objects, duplicate headed/headerless CSV rows, CSV `asn` drift, and
  malformed ASN identifiers are rejected; every headerless MISP field must
  also match the headed CSV.
- Python remains only as a current-corpus parity oracle during the seven-day
  shadow window. Removing it and its CI runtime is a separately recorded
  cutover gate, not implied by this foundation change.

## [2026-08-30] — claims re-measured: the feed is now SSH-led

### Changed

- Re-measured overlap/novelty against the live 231-entry feed (was 153 on
  2026-08-24) and refreshed the README figures. Novelty vs. the major
  aggregates fell 64.7% → 52.4%; blocklist.de overlap rose 9.8% → 32.5%.
- Re-measured protocol composition from the sensor over the current 30-day
  window: SSH is now the largest single protocol (95 published IPs), telnet
  second (74). This inverts the 2026-07-22 picture (telnet 126, SSH 33), so the
  README's "treat this as a telnet list, not an SSH list" guidance is rewritten
  as an SSH-led list that also carries a large telnet/IoT population.
- No change to who is on the list or to the tier criteria — this is a claims
  refresh, not a methodology change. Triggered by `validate.py`'s claim-drift
  warning (51% size drift) and tracked in issue #9.

## [2026-08-24] — the front-page claims are now guarded too

### Added

- `validate.py` warns when README's overlap/novelty claims were measured
  against a feed size materially different from the one being published. Those
  figures are percentages *of* the feed, so once it moves far enough they
  describe a different list.

  The tolerance is 10%, calibrated against the incident rather than chosen for
  looking reasonable: the README actually went stale between a 181-entry and a
  153-entry feed, which is 15.5% drift. A 20% tolerance would have sat silent
  through the only event this check exists to catch.

  Hermetic — no network in CI. `scripts/overlap.py` makes 9 external fetches and
  stays a manual/scheduled run; this check only notices when it is overdue.

## [2026-08-24] — the validator can now stop a bad publish

### Added

- `validate.py` enforces the README's own inclusion thresholds. A credential-tier
  entry below 50 attempts, or a scanner-tier entry below `meta.scanner_min_events`
  (1000), now fails the publish. Previously `meta.inclusion_criteria` promised a
  floor that nothing checked — a generator bug emitting a public resolver with
  `attempts: 1` would have passed CI and reached consumers' firewalls.
- Strict CSV row width on `blocklist.csv`. `DictReader` silently tolerates a
  shifted row (missing keys become `None`, extras land under a `None` key), so a
  column shift from one unquoted comma passed every downstream check with every
  value one place to the left. Checked with a plain reader before parsing.
- Formula-injection rejection on every published cell of `blocklist.csv` and
  `blocklist.misp.csv`. A cell beginning `=`, `+`, `-` or `@` executes when the
  feed is opened in Excel, LibreOffice or Sheets. Leading tab/CR/LF — the
  documented bypass, since the spreadsheet strips them before evaluating — is
  rejected too.

### Changed

- `blocklist.misp.csv` is now **required**, not optional. README and
  `meta.formats.csv_headerless` both publish it as the MISP/OpenCTI feed URL, but
  the validator guarded the entire block behind an existence check, so a run that
  never wrote it passed clean while those consumers went offline.

### Contract

- **The feed is IPv4-only, stated explicitly for the first time.** A global IPv6
  address now fails validation. This was already true of the data (0 of 154
  entries) but was never a promise: the published `ipset`/`iptables` recipes
  create `family inet` sets, which *reject* a v6 address rather than blocking it,
  so a v6 row would have left consumers unprotected inside a feed they trust.
  Relaxing this requires updating the consumer recipes in the same change.

All five checks were fault-injected in both directions before shipping: each
rejects its defect, and an untouched copy of the live feed still validates clean.

## [2026-07-22] — composition measured

### Added

- **Documented what this list actually consists of: telnet, not SSH.** By
  distinct published IPs — telnet 126, ssh 33, mysql 26, ftp 6. SSH generates
  the most *events* (109,896 vs 86,431 over 30 days) but from ~4× fewer hosts:
  a handful of bruteforcers hammering hard, versus the many-compromised-devices
  pattern of an IoT botnet. Since the list is per-IP, telnet dominates it.

  Confirmed independently against other operators' honeypot feeds: 45.3%
  overlap with dataplane.org's telnet list against 9.4% with their SSH list.
  That ratio also explains the previously odd 1.7% DShield overlap — DShield is
  SSH-focused, so low overlap was expected once the composition is known.

  This matters to consumers choosing a blocklist, and nothing previously told
  them. The README now says plainly that anyone hunting SSH bruteforcers is
  better served by dataplane's sshpwauth or DShield.

- **`scripts/overlap.py` now measures two groups**: aggregates (is this list
  redundant?) and peers (do other honeypot operators see the same attackers?).
  The peer comparison is the like-for-like one and is what surfaced the
  composition finding.

  Peer feeds are queried for **measurement only**. dataplane.org is
  non-commercial and prohibits redistribution; none of its data enters this
  CC0 feed, which remains entirely original sensor output.

  Note the protocol table above is derived from the sensor database and is not
  reproducible from the published feed alone; the overlap figures are.

## [2026-07-22] — overlap measured

### Fixed

- **Corrected the novelty claim.** The README said "~20-25% overlap" with the
  big aggregates, measured once informally against the retired 114-entry list.
  Measured properly against the live 181-entry feed, actual overlap is
  **36.5%** — so 63.5% of entries are novel, not the ~75-80% previously
  implied. The claim was overstating the feed's uniqueness by roughly 12
  points. Per-list breakdown is now in the README, and the measurement is
  reproducible via `scripts/overlap.py` rather than asserted.

  Two thirds novel is still a real result, and the README now also states the
  honest ceiling: this is a small, single-vantage-point feed and belongs
  alongside the large lists, not instead of them.

## [2026-07-22] — later same day

### Fixed — **data correctness**

- **`first_seen` was bookkeeping, not observation, and 74 of 181 entries had
  `first_seen` after `last_seen`.** Credential-tier `first_seen` was taken from
  the ban ledger's "first banned" timestamp — often written in a batch long
  after the IP's last actual attack — while `last_seen` was the last observed
  attack. The giveaway was dozens of unrelated IPs sharing a `first_seen` to
  the same second.

  Both fields now describe observed attack activity inside the window, so
  `first_seen <= last_seen` always holds. The ban date is still published, as
  the new **`first_banned`** field, which is explicitly bookkeeping: it may
  predate the window or fall after `last_seen`, and is `null` for scanner-tier
  entries.

  Found by the new validator, not by inspection.

### Added

- **`validate.py` and CI.** Runs on every push — including the automated
  hourly syncs — plus daily on a schedule. Checks that the three formats name
  the same set, every address parses and is globally routable, tiers and
  counts match the metadata, scanner entries carry `bans: 0`, and
  `first_seen <= last_seen`. A bad generator run can no longer quietly publish
  garbage to a list other people firewall on.

### Changed — **breaking, methodology**

The snapshot in this repo had been generated by the pre-v1 selector and was two
days stale. It is now regenerated from the same pipeline that publishes
<https://jacobrakai.org/feed/>, so the two no longer disagree.

What changed between the old snapshot and this one:

| | previous snapshot | now |
|---|---|---|
| entries | 114 | 181 (176 credential, 5 scanner) |
| recency window | 45 days | 30 days |
| schema | `score` 0–100 | `tier` (`credential` / `scanner`) |
| scanners | excluded entirely | benign surveys excluded; abusive ones published as their own tier |

- **The 0–100 score is gone.** It blended persistence, intensity, protocol
  breadth, credential diversity and an interactive-compromise bonus into one
  number that was never calibrated against anything, so consumers had no
  defensible way to pick a cutoff. Two explicit tiers with published thresholds
  replace it. Anything keying on `score` must move to `tier`.
- **Window narrowed 45 → 30 days**, making entries decay off faster.
- **Added the `scanner` tier** for sustained credential-less abuse (1000+
  in-window connection events). These never crossed the credential threshold
  and so were invisible to the old selector.
- The `bans` field is `0` for every scanner-tier entry by construction — see
  README. It does **not** mean unenforced.

### Fixed

- The README documented the retired 45-day/scored methodology and advertised an
  entry count that no longer matched the data files shipped beside it.
- Upstream, scanner-tier IPs had been published as abusers since 2026-07-21
  while the sensor's own firewall only enforced the credential tier — one had
  been probing unblocked for 27 days. Both tiers are now enforced, which makes
  the README's claim that these are blocked addresses true.

## [2026-07-20]

- Initial public release: 114 IPs, 45-day window, 0–100 recency-decayed score,
  research scanners excluded. Published as v1 beta.
