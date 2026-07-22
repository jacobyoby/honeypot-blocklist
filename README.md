# jacobrakai.org honeypot blocklist

A small, **honeypot-confirmed** IP blocklist. Every address here attacked a
self-operated [Cowrie](https://github.com/cowrie/cowrie)/Heralding sensor
directly — SSH, FTP, telnet, MySQL, VNC — and ages off automatically once it
goes quiet.

- **181 IPs** · 176 credential-tier · 5 scanner-tier · updated `2026-07-22T18:18:54Z`
- Formats: [`blocklist.txt`](blocklist.txt) (fail2ban/iptables drop-in) · [`blocklist.json`](blocklist.json) · [`blocklist.csv`](blocklist.csv)
- **Canonical source: <https://jacobrakai.org/feed/>** — regenerated hourly.
  This repo is a periodic snapshot; pull the URL if you want current data.

## Why another blocklist?

Because this one is **original sensor data**, not a re-aggregation. Every IP here
hit *my* honeypot directly. Only ~20-25% overlap the big aggregates (FireHOL, Spamhaus) —
the rest are fresh attackers not yet on them. That's the point of a live sensor.

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

## False positives / delisting

IPs are dynamic and get reassigned. If your address is here in error, email
**jacob@jacobrakai.org** — entries also expire automatically as attacks stop.

## License

[CC0-1.0](LICENSE) — public domain, **provided as-is, no warranty**. Verify before blocking.
