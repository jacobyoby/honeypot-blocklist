# jacobrakai.org honeypot blocklist  ·  **BETA**

A small, **honeypot-confirmed** IP blocklist — addresses caught actively brute-forcing
SSH/Telnet against a self-operated [Cowrie](https://github.com/cowrie/cowrie)/Heralding
sensor, then **recency-scored** so stale entries fall off automatically.

- **114 IPs** · **20 of them broke in and ran shell commands** (interactive compromise) · updated `2026-07-21T00:18:41Z`
- Formats: [`blocklist.txt`](blocklist.txt) (fail2ban/iptables drop-in) · [`blocklist.json`](blocklist.json) (scored) · [`blocklist.csv`](blocklist.csv)
- Live mirror: **https://jacobrakai.org/feed/**

## Why another blocklist?
Because this one is **original sensor data**, not a re-aggregation. Every IP here
hit *my* honeypot directly. Only ~20-25% overlap the big aggregates (FireHOL, Spamhaus) —
the rest are fresh attackers not yet on them. That's the point of a live sensor.

## How an IP gets on the list
1. **Confirmed** — crossed 50 credential attempts against the honeypot (not inferred).
2. **Recent** — attacked within the last 45 days (dormant IPs decay off).
3. **Not a scanner** — known research scanners (Censys/Shodan/Rapid7/…) are excluded.
4. **Scored 0-100** — a recency-decayed blend of persistence (distinct active days),
   attempt intensity, protocol breadth, credential diversity, and an
   **interactive-compromise bonus** for IPs that actually ran commands.

## Building in public
This is **v1 (beta)** — the scoring is being refined openly. Known roadmap: windowed/decayed
features, graded interactive scoring, ASN/subnet handling, and **prospective calibration**
(scoring buckets validated against future re-attack rate). Methodology writeup coming.

## Usage
See [`configs/fail2ban-example.md`](configs/fail2ban-example.md). Refresh hourly.

## False positives / delisting
IPs are dynamic and get reassigned. If your address is here in error, email
**jacob@jacobrakai.org** — entries also expire automatically as attacks stop.

## License
[CC0-1.0](LICENSE) — public domain, **provided as-is, no warranty**. Verify before blocking.
