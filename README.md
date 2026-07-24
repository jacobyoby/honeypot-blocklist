# jacobrakai.org honeypot blocklist

A small, **honeypot-confirmed** IP blocklist. Every address here attacked a
self-operated [Cowrie](https://github.com/cowrie/cowrie)/Heralding sensor
directly — SSH, FTP, telnet, MySQL, VNC — and ages off automatically once it
goes quiet.

- **179 IPs** · 174 credential-tier · 5 scanner-tier · updated `2026-07-24T11:00:01Z`
- Formats: [`blocklist.txt`](blocklist.txt) (fail2ban/iptables drop-in) · [`blocklist.json`](blocklist.json) · [`blocklist.csv`](blocklist.csv)
- **Canonical source: <https://jacobrakai.org/feed/>** — regenerated hourly.
  This repo is a periodic snapshot; pull the URL if you want current data.

## Why another blocklist?

Because this one is **original sensor data**, not a re-aggregation. Every IP here
hit *my* honeypot directly.

**63.5% of the current list appears on no major public blocklist.** Measured
2026-07-22 against the live 181-entry feed:

| List | Overlap |
|---|---|
| firehol_level3 | 19.9% |
| blocklist_de | 14.4% |
| firehol_level1 | 13.8% |
| spamhaus_drop | 13.3% |
| dshield | 1.7% |
| **any of the above** | **36.5%** |

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
dataplane.org's telnet feed is **45.3%**, against just **9.4%** for their SSH
feed:

| Peer honeypot feed | Overlap |
|---|---|
| dataplane telnetlogin (telnet) | 45.3% |
| dataplane sshpwauth (SSH) | 9.4% |
| greensnow | 3.3% |
| dataplane vncrfb (VNC) | 1.7% |

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

`ip`, `tier`, `bans`, `attempts`, `first_seen`, `last_seen`, `first_banned`.

`attempts` is lifetime credential attempts for credential-tier entries, and
in-window connection events for scanner-tier ones. `bans` counts credential-tier
ban cycles; it is always `0` for scanner-tier entries because their ban cycles
are tracked separately — **both tiers are firewalled on the sensor.**

`first_seen` and `last_seen` are both *observations* — attack activity inside
the current window — so `first_seen <= last_seen` always holds. `first_banned`
is *bookkeeping*: when the address was first firewalled. It may predate the
window or fall after `last_seen`, and is `null` for scanner-tier entries. Don't
use it to reason about recency.

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
