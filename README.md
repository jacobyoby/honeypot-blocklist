# jacobrakai.org honeypot blocklist

[![Validate blocklist](https://github.com/jacobyoby/honeypot-blocklist/actions/workflows/validate.yml/badge.svg?branch=main)](https://github.com/jacobyoby/honeypot-blocklist/actions/workflows/validate.yml)

A small, **honeypot-confirmed** IP blocklist. Every address here attacked a
self-operated [Cowrie](https://github.com/cowrie/cowrie)/Heralding sensor
directly — SSH, FTP, telnet, MySQL, VNC — and ages off automatically once it
goes quiet.

- **435 IPs** · 382 credential-tier · 53 scanner-tier · updated `2026-09-10T23:00:01Z`
- Formats: [`blocklist.txt`](blocklist.txt) (fail2ban/iptables drop-in) · [`blocklist.json`](blocklist.json) · [`blocklist.csv`](blocklist.csv) · [`blocklist.misp.csv`](blocklist.misp.csv) (header-less, for MISP/OpenCTI positional ingestion)
- **Canonical source: <https://jacobrakai.org/feed/>** — regenerated hourly.
  This repo is a periodic snapshot; pull the URL if you want current data.

## Why another blocklist?

Because this one is **original sensor data**, not a re-aggregation. Every IP here
hit *my* honeypot directly.

**46.7% of the current list appears on no major public blocklist.** Re-measured
2026-09-08 with `scripts/overlap.py` against the live 413-entry feed (previous
measurements: 2026-08-30, 231 entries, 52.4% novel; 2026-08-24, 153 entries,
64.7% novel; 2026-07-22, 181 entries, 63.5% novel):

| List | 2026-09-08 | 2026-08-30 | 2026-08-24 | 2026-07-22 |
|---|---|---|---|---|
| firehol_level1 | 8.2% | 14.3% | 22.2% | 13.8% |
| spamhaus_drop | 8.2% | 14.3% | 22.2% | 13.3% |
| firehol_level3 | 4.6% | 10.4% | 17.6% | 19.9% |
| blocklist_de | 44.6% | 32.5% | 9.8% | 14.4% |
| dshield | 1.0% | 1.3% | 0.0% | 1.7% |
| **any of the above** | **53.3%** | **47.6%** | **35.3%** | **36.5%** |

So just over half are attackers the big aggregates haven't listed. That's
the point of a live sensor — and it's also the honest ceiling on this feed's
value: it is small and it is one vantage point, so treat it as a supplement to
the large lists, not a replacement. The novelty figure moves as both the feed
and the aggregates change, so trust the measurement date above, not the number
alone.

Reproduce it yourself: [`scripts/overlap.py`](scripts/overlap.py).

## What's actually in it — SSH now leads

Worth knowing before you use this, because it determines whether the list is
relevant to you. Distinct published IPs by the protocol they attacked, measured
2026-08-30 against the current 30-day observation window:

| Protocol | 2026-08-30 | 2026-07-22 |
|---|---|---|
| **ssh** | **95** | 33 |
| telnet | 74 | 126 |
| vnc | 35 | — |
| mysql | 22 | 26 |
| ftp | 11 | 6 |
| http | 4 | — |

(An IP that attacked several protocols is counted once per protocol, so the
column sums to more than the 231 published addresses.)

**The composition has flipped since mid-July.** On 2026-07-22 telnet dominated
(126 addresses, ~4× SSH's 33) — the IoT-botnet signature of many compromised
devices each doing modest volume. As of 2026-08-30 SSH is the largest single
protocol (95 addresses) and telnet has dropped to second (74): over that window
the sensor's attacker population shifted from telnet/IoT sweeps toward SSH
bruteforce. The window rolls, so check the measurement date before relying on
the mix.

Comparing against other operators' honeypot feeds confirms the shift — overlap
with dataplane.org's SSH feed has risen to **51.6%**, now well above the **11.6%**
overlap with their telnet feed. On 2026-08-24 the ratio pointed the other way
(5.2% SSH vs 33.3% telnet):

| Peer honeypot feed | 2026-09-08 | 2026-08-30 | 2026-08-24 | 2026-07-22 |
|---|---|---|---|---|
| dataplane sshpwauth (SSH) | 51.6% | 35.5% | 5.2% | 9.4% |
| dataplane telnetlogin (telnet) | 11.6% | 22.1% | 33.3% | 45.3% |
| greensnow | 39.0% | 26.4% | 6.5% | 3.3% |
| dataplane vncrfb (VNC) | 10.9% | 14.3% | 12.4% | 1.7% |
| **any of the above** | **75.5%** | **72.7%** | **52.9%** | — |

**So: this is currently an SSH-led list that also carries a large telnet/IoT
population.** If you are here for SSH bruteforcers, the feed now covers them
well; if you are here only for telnet/IoT botnets, that tier is still
substantial but is no longer the majority.

*(Peer feeds are queried for measurement only. dataplane.org is non-commercial
and prohibits redistribution — none of their data is in this feed, which
remains entirely original sensor output.)*

## How an IP gets on the list

Two tiers. Both require real attack activity within the last 30 days;
dormant entries decay off on their own.

**`credential`** — connected to a decoy service and submitted login credentials
repeatedly. Honeypot-confirmed, never inferred.

**`scanner`** — submitted *no* credentials at all, but probed at abusive,
sustained volume against a single quiet host. This tier exists because
high-volume protocol scanners (pure VNC screen-scrapers, say) never submit
credentials and so never reach the credential bar, despite being the noisiest
traffic the sensor sees. The floors are **50 credential attempts** for
credential tier and **1 000 connection events** (in-window) for scanner tier;
both are published in the `blocklist.txt` header and `blocklist.json` meta and
enforced by the compiled validator in CI.

### Always excluded

- Private, reserved, loopback, link-local, CGNAT and multicast ranges.
- **Known benign internet-survey scanners** — Censys, Shodan, Rapid7 Sonar,
  Shadowserver, BinaryEdge. This filter matters most for the scanner tier,
  which benign surveys would otherwise land in by definition.
- Any IP that *did* submit credentials but isn't confirmed yet is held out of
  the scanner tier rather than published as credential-less.

## Fields

`ip`, `tier`, `bans`, `attempts`, `first_seen`, `last_seen`, `first_banned`, `asn`.

**This feed is IPv4-only.** Every address published is a global IPv4 address,
and the compiled `blocklist-validator` refuses to publish anything else. This
is a contract, not an accident of the data: the `ipset`/`iptables` recipes below create `family inet`
sets, which reject an IPv6 address rather than blocking it — a v6 entry would
land in a feed you already trust and silently leave you unprotected. If the
sensors ever observe v6 worth publishing, it will arrive as a deliberate change
with the consumer recipes updated alongside it, not as a surprise row.

`attempts` is lifetime credential attempts for credential-tier entries, and
in-window connection events for scanner-tier ones. `bans` counts credential-tier
ban cycles; it is always `0` for scanner-tier entries because their ban cycles
are tracked separately.

> `attempts` for a listed address may keep rising after `first_banned`. That is
> expected, not a bookkeeping error — do not read `first_banned` as "traffic
> stopped".

`first_seen` and `last_seen` are both *observations* — attack activity inside
the current window — so `first_seen <= last_seen` always holds. `first_banned`
is *bookkeeping*: when the address was first ban-listed. It may predate the
window or fall after `last_seen`, and is `null` for scanner-tier entries. Don't
use it to reason about recency.

## Schema version

`meta.schema_version` is `MAJOR.MINOR`, currently **1.0**.

Column order is load-bearing: `blocklist.misp.csv` is header-less and MISP and
OpenCTI address its columns *positionally*, so a reordered feed does not fail
for them — it silently lands every field in the wrong place. The version is how
a consumer notices before that happens.

- **MINOR** bump — a column was appended. Existing readers keep working.
- **MAJOR** bump — a column was renamed, removed, or reordered. Pin on MAJOR and
  refuse a feed whose MAJOR you do not recognise, rather than parsing it anyway.

The compiled validator fails CI on an unrecognised MAJOR and warns on MINOR
drift. During its shadow period, CI also requires exact stdout and exit-code
parity with the frozen Python validator on the current publication corpus.

Repository validation is read-only:

```sh
go run ./cmd/blocklist-validator .
make check
```

## Publication path

The blocklist moves from sensor to consumer through four stages:

1. **Sensor generates** — the Cowrie/Heralding sensor records attack events and
   the generator emits updated `blocklist.txt`, `blocklist.json`, `blocklist.csv`,
   and `blocklist.misp.csv` files.
2. **Commit** — the generated files are committed to this repository (hourly
   snapshots are pushed without human review; structural changes go through PRs).
3. **CI validates** — GitHub Actions runs `make check`, which compiles and runs
   the Go validator against the committed publication files, checks format
   parity with the frozen Python oracle, rejects secret-like material, enforces
   the compiled-language-only rule, and runs the Go vulnerability scanner.
   **CI is the gate between the generator and every consumer.** If it fails, the
   committed files are not safe to consume.
4. **Live** — if CI passes, the files are served at
   `https://jacobrakai.org/feed/` (mirrored from
   `raw.githubusercontent.com`). Consumers pulling the canonical URL always get
   the latest CI-validated snapshot.

### If the CI badge is red

The build badge at the top of this README reflects the latest validation run.
**If it is red, do not update your firewall rules.** Instead:

- Check the open issue labelled
  [`ci-failure`](https://github.com/jacobyoby/honeypot-blocklist/issues?q=label%3Aci-failure) —
  it contains the failing commit SHA, the workflow run link, and the validator
  output.
- Keep using your last known-good blocklist until the issue is closed and the
  badge turns green. CI automatically closes the issue when validation passes
  again.

### Sensor-side validation

The sensor-side generator does **not** run the full publication validator before
committing. Validation is CI-only: the Go validator (`cmd/blocklist-validator`)
and the Python parity oracle (`validate.py`) run against the committed files
during `make check` in GitHub Actions. The `scripts/overlap.py` script is an
analysis tool for measuring feed novelty against public blocklists, not a
pre-commit gate. This means a bad generator push will land in the repo but will
be caught by CI before consumers pull it — and the failure-alert step above
ensures it is visible immediately rather than silently waiting for someone to
notice.

## Usage

See [`configs/fail2ban-example.md`](configs/fail2ban-example.md). Point your
refresh at `https://jacobrakai.org/feed/blocklist.txt` rather than at this repo,
and refresh hourly. The recipes use an **atomic swap** pattern — each refresh
*replaces* the ipset/nftables set rather than appending, so IPs that have aged
off the feed are automatically removed.

### MISP

`blocklist.txt` works as a **freetext** feed with no configuration — it is bare
one-IP-per-line, the same shape MISP already ingests from blocklist.de.

To keep the per-IP metadata, use the header-less CSV as a **csv** feed with
`value: 1`, `delimiter: ,`:

```
https://jacobrakai.org/feed/blocklist.misp.csv
```

Use that URL rather than `blocklist.csv`: MISP's CSV parser skips only
`#`-prefixed lines, so the normal file's header row would be ingested as a data
row and produce a junk attribute on every refresh.

### OpenCTI

Point a CSV Feed ingester at `blocklist.misp.csv` with a CSV Mapper. OpenCTI
addresses columns by letter index and skips the first line, so the header-less
variant is the correct target there too.

### Column contract

`ip, tier, bans, attempts, first_seen, last_seen, first_banned, asn`

Both MISP and OpenCTI map columns **positionally**, not by name. This order is
therefore permanent — new columns are only ever appended on the right, never
inserted or reordered. The compiled validator enforces both the order and exact
value equality with the headed CSV in CI.

## False positives / delisting

IPs are dynamic and get reassigned. If your address is here in error, email
**jacob@jacobrakai.org** — entries also expire automatically as attacks stop.

## License

[CC0-1.0](LICENSE) — public domain, **provided as-is, no warranty**. Verify before blocking.

## Support

[Donate / Support Jacobrakai Foundation — JACOBRAKAI FOUNDATION 501(c)(3)](https://donate.stripe.com/eVq4gy97DanS9h60phfrW00)

**JACOBRAKAI FOUNDATION** (Jacobrakai Foundation) is a 501(c)(3) public charity. EIN 33-3382083 · effective Feb 11, 2025. No Letter 947 PDF URL is available to publish.
