# TODO

Open work on the published blocklist. The generator itself lives on the sensor
host (`~/honeypot-stats`) and has its own TODO.

## High

- [ ] **Harden `validate.py` — it can't stop a bad publish** (Codex review
      2026-07-23; current published data verified clean, this is guardrail work).
      The validator is the only gate between the loam generator and consumers'
      firewalls, and it under-checks:
  - [ ] Enforce the README's inclusion thresholds (min attempts/bans per tier).
        Today a bug emitting `8.8.8.8` credential-tier with `attempts: 1` passes
        CI and firewall-blocks a public resolver. *(High)*
  - [ ] Reject global IPv6 (or add an explicit v6 contract) — the documented
        ipset/iptables flow is IPv4-only, so a v6 row breaks consumers' loaders.
  - [ ] Reject CSV formula-injection cells (`=`,`+`,`-`,`@` leading) — a
        `=HYPERLINK(...)` in `first_banned` passes today.
  - [ ] Enforce strict CSV row width (DictReader silently accepts shifted cells
        from an unquoted comma).
  - [ ] Require `blocklist.misp.csv` to exist (currently optional despite being
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

- [ ] **Automate the snapshot.** This repo went two days stale and
      methodologically obsolete because nothing syncs it — it was updated by
      hand once, at initial release. Either add an hourly job on the sensor
      that commits `blocklist.{txt,json,csv}` and pushes, or strip the data
      files entirely and leave a pointer to <https://jacobrakai.org/feed/>.
      Until one of those happens, assume this repo is stale.

- [ ] **Say how stale a snapshot is, in the files themselves.** Consumers
      pulling `raw.githubusercontent.com` have no way to tell they're getting a
      snapshot rather than the live feed. The `updated` timestamp is in the
      header, but nothing warns that the repo copy lags the canonical one.

## Medium

- [ ] **Announce the schema break.** `score` → `tier` (see CHANGELOG
      2026-07-22) will silently break anyone who pinned to the JSON. The repo
      has stargazers; a release note or a tagged `v1` for the old format would
      give them something to pin to.

- [x] ~~**Tag releases.**~~ Done 2026-07-22: `v1.0.0` on the initial score
      schema, `v2.0.0` on the tier schema. Both are local until pushed.

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
