# jacobrakai.org honeypot blocklist

A small, **honeypot-confirmed** IP blocklist. Every address here attacked a
self-operated [Cowrie](https://github.com/cowrie/cowrie)/Heralding sensor
directly — SSH, FTP, telnet, MySQL, VNC — and ages off automatically once it
goes quiet.

- **155 IPs** · 130 credential-tier · 25 scanner-tier · updated `2026-08-25T19:00:01Z`
- Formats: [`blocklist.txt`](blocklist.txt) (fail2ban/iptables drop-in) · [`blocklist.json`](blocklist.json) · [`blocklist.csv`](blocklist.csv)
- **Canonical source: <https://jacobrakai.org/feed/>** — regenerated hourly.
  This repo is a periodic snapshot; pull the URL if you want current data.

## Why another blocklist?

Because this one is **original sensor data**, not a re-aggregation. Every IP here
hit *my* honeypot directly.

**64.7% of the current list appears on no major public blocklist.** Re-measured
2026-08-24 with `scripts/overlap.py` against the live 153-entry feed (previous
measurement 2026-07-22, 181 entries, 63.5% novel — the headline has held):

| List | Overlap | 2026-07-22 |
|---|---|---|
| firehol_level1 | 22.2% | 13.8% |
| spamhaus_drop | 22.2% | 13.3% |
| firehol_level3 | 17.6% | 19.9% |
| blocklist_de | 9.8% | 14.4% |
| dshield | 0.0% | 1.7% |
| **any of the above** | **35.3%** | **36.5%** |

So roughly two thirds are attackers the big aggregates haven't listed. That's
the point of a live sensor — and it's also the honest ceiling on this feed's
value: it is small and it is one vantage point, so treat it as a supplement to
the large lists, not a replacement.

Reproduce it yourself: [`scripts/overlap.py`](scripts/overlap.py).

## What's actually in it — mostly telnet, not SSH

Worth knowing before you use this, because it determines whether the list is
relevant to you. Measured 2026-07-22, distinct published IPs by the protocol
they attacked:

| Protocol | IPs |
|---|---|
| **telnet** | **126** |
| ssh | 33 |
| mysql | 26 |
| ftp | 6 |

Despite SSH producing the *most events* (109,896 vs telnet's 86,431 over 30
days), telnet contributes ~4× more distinct addresses. That is the IoT-botnet
signature: many compromised devices each doing modest volume, versus a handful
of SSH bruteforcers hammering hard. Because the list is per-IP, telnet
dominates it.

Comparing against other operators' honeypot feeds confirms it — overlap with
dataplane.org's telnet feed is **33.3%**, against just **5.2%** for their SSH
feed. The ratio is what matters and it has held across both measurements
(~5x then, ~6x now):

| Peer honeypot feed | Overlap | 2026-07-22 |
|---|---|---|
| dataplane telnetlogin (telnet) | 33.3% | 45.3% |
| dataplane vncrfb (VNC) | 12.4% | 1.7% |
| greensnow | 6.5% | 3.3% |
| dataplane sshpwauth (SSH) | 5.2% | 9.4% |
| **any of the above** | **52.9%** | — |

The one real mover is VNC: **1.7% to 12.4%**, a 7x rise in a month. The
telnet-dominant conclusion below is unchanged, but VNC is no longer a rounding
error in this feed's composition.

**So: treat this as a telnet/IoT-botnet list that also catches SSH, not an SSH
list.** If you are looking specifically for SSH bruteforcers, dataplane's
sshpwauth or DShield cover that population far better than this does.

*(Peer feeds are queried for measurement only. dataplane.org is non-commercial
and prohibits redistribution — none of their data is in this feed, which
remains entirely original sensor output.)*

## How an IP gets on the list

Two tiers. Both require real attack activity **within the last 30 days**;
dormant entries decay off on their own.

**`credential`** — connected to a decoy service and submitted login credentials
**50+ times**. Honeypot-confirmed, never inferred.

**`scanner`** — submitted *no* credentials at all, but probed at abusive volume:
**1000+ connection events** inside the window, roughly 33+/day sustained against
a single quiet host. This tier exists because high-volume protocol scanners
(pure VNC screen-scrapers, say) never submit credentials and so never reach the
credential bar, despite being the noisiest traffic the sensor sees. The
threshold sits inside a real gap in the measured distribution: the casual tail
tops out around 600 events, the scanner cluster starts near 1,350.

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
and `validate.py` refuses to publish anything else. This is a contract, not an
accident of the data: the `ipset`/`iptables` recipes below create `family inet`
sets, which reject an IPv6 address rather than blocking it — a v6 entry would
land in a feed you already trust and silently leave you unprotected. If the
sensors ever observe v6 worth publishing, it will arrive as a deliberate change
with the consumer recipes updated alongside it, not as a surprise row.

`attempts` is lifetime credential attempts for credential-tier entries, and
in-window connection events for scanner-tier ones. `bans` counts credential-tier
ban cycles; it is always `0` for scanner-tier entries because their ban cycles
are tracked separately — **both tiers are ban-listed and filtered at the host;
the sensors themselves deliberately remain reachable.**

> **Enforcement note (2026-08-06).** Ban rules live in the host's `INPUT` chain.
> The sensors run in containers whose published ports traverse `DOCKER-USER`,
> so listed addresses still reach the sensors. That gap was measured and then
> kept **on purpose**: 96.7% of this sensor's telnet credential volume
> originates from already-listed addresses, so filtering at the sensor would
> suppress the very collection this feed is built from. A honeypot that drops
> the addresses it exists to observe stops observing. Host services are
> filtered; the sensors are not.
>
> Consequently `attempts` for a listed address keeps rising after
> `first_banned`. That is by design, not a bookkeeping error — do not read
> `first_banned` as "traffic stopped".

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

`validate.py` fails CI on an unrecognised MAJOR and warns on MINOR drift.

## Usage

See [`configs/fail2ban-example.md`](configs/fail2ban-example.md). Point your
refresh at `https://jacobrakai.org/feed/blocklist.txt` rather than at this repo,
and refresh hourly.

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

`ip, tier, bans, attempts, first_seen, last_seen, first_banned`

Both MISP and OpenCTI map columns **positionally**, not by name. This order is
therefore permanent — new columns are only ever appended on the right, never
inserted or reordered. `validate.py` enforces it in CI.

## False positives / delisting

IPs are dynamic and get reassigned. If your address is here in error, email
**jacob@jacobrakai.org** — entries also expire automatically as attacks stop.

## License

[CC0-1.0](LICENSE) — public domain, **provided as-is, no warranty**. Verify before blocking.
