# TODO

Open work on the published blocklist. The generator itself lives on the sensor
host (`~/honeypot-stats`) and has its own TODO.

## High

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

- [ ] **Tag releases.** There is no tag for the 2026-07-20 initial format, so
      "the old schema" is not fetchable. Tag retroactively before the history
      grows.

- [ ] **Publish the overlap measurement.** The README claims ~20–25% overlap
      with FireHOL/Spamhaus. That was measured once, informally, against the
      114-entry list. Re-measure against the current 181 and publish the method,
      or soften the claim.

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
