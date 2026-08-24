# TODO

Open work on the published blocklist. The generator itself lives on the sensor
host (`~/honeypot-stats`) and has its own TODO.

## High

- [x] **Harden `validate.py` — it can't stop a bad publish** (Codex review
      2026-07-23; current published data verified clean, this is guardrail work).
      The validator is the only gate between the loam generator and consumers'
      firewalls, and it under-checks:
  - [x] Enforce the README's inclusion thresholds (min attempts/bans per tier).
        Today a bug emitting `8.8.8.8` credential-tier with `attempts: 1` passes
        CI and firewall-blocks a public resolver. *(High)*
  - [x] Reject global IPv6 (or add an explicit v6 contract) — the documented
        ipset/iptables flow is IPv4-only, so a v6 row breaks consumers' loaders.
  - [x] Reject CSV formula-injection cells (`=`,`+`,`-`,`@` leading) — a
        `=HYPERLINK(...)` in `first_banned` passes today.
  - [x] Enforce strict CSV row width (DictReader silently accepts shifted cells
        from an unquoted comma).
  - [x] Require `blocklist.misp.csv` to exist (STILL OPEN, confirmed
        2026-08-23: `validate.py:261` guards the whole block behind
        `if os.path.exists(mpath)`, so a run that never wrote it passes.
        One-line fix.) Currently optional despite being
        the documented MISP/OpenCTI feed).
  - [x] Parse timestamps as real dates (`2026-99-99` passes string compare).
        *Done: `bad_ts()` parses with `strptime`; shape regex alone let
        `2026-99-99` and `2026-02-30` through. Also pairs `bans` with
        `first_banned`, and cross-checks json/csv field VALUES — a
        CSV-only corruption previously passed CI clean.*
  - [ ] `scripts/overlap.py`: measure the local checkout, not the deployed feed,
        so novelty claims aren't computed from stale data.
  - Full findings: Codex review, 2026-07-23. Generator-side (can it emit a bad
    row at all?) is aardvark's `~/honeypot-stats` on loam — flagged on the bus.

- [x] ~~**Automate the snapshot.**~~ Done 2026-08-23: the repo now receives
      hourly `Feed snapshot <ts> (N IPs)` commits, latest
      2026-08-23T23:00:01Z. The hand-updated-once state this described is
      over; the sensor job commits and pushes.

- [x] ~~**Say how stale a snapshot is, in the files themselves.**~~ Done
      2026-08-23: `blocklist.txt` carries
      `# Updated : 2026-08-23T23:00:01Z (refreshed hourly)` in its header,
      so a raw.githubusercontent consumer can see the snapshot's age.

## Medium

- [x] ~~**Announce the schema break.**~~ Done 2026-08-23: CHANGELOG lines
      94-107 carry the migration table and the explicit "Anything keying on
      `score` must move to `tier`". README no longer mentions `score`, and
      `v1.0.0` (score schema) and `v2.0.0` (tier schema) are both on origin,
      so a stargazer pinned to the old format has a tag to hold.

- [x] ~~**Tag releases.**~~ Done 2026-07-22: `v1.0.0` on the initial score
      schema, `v2.0.0` on the tier schema. Both confirmed on origin
      2026-08-23 (`git ls-remote --tags`); the "local until pushed" caveat
      this note carried is no longer true.

- [x] ~~**Publish the overlap measurement.**~~ Done 2026-07-22. The old
      "~20–25% overlap" claim was wrong: actual overlap against the live
      181-entry feed is **36.5%** (so 63.5% novel, not the ~75–80% implied).
      Method published as `scripts/overlap.py` and the table is in the README.
      Re-run it periodically — the number will drift as the aggregates catch up.

## Low

- [ ] Add a `configs/` example for nftables — currently only ipset/iptables and
      nginx are covered.

- [ ] Consider `.netset`/CIDR output for consumers that expect FireHOL-style
      formats.

- [ ] Decide whether scanner-tier entries belong in the default `blocklist.txt`
      at all, or whether that file should stay credential-only with the scanner
      tier available separately. Mixing them means a consumer who trusts
      "honeypot-confirmed credential attacker" gets volume-based entries too —
      documented, but easy to miss.
