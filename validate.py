#!/usr/bin/env python3
"""
Validate the published blocklist files.

This runs in CI on every push, including the hourly automated feed commits.
The point is that a bad generator run cannot quietly publish garbage to a list
other people firewall on: a private range, an unparseable address, or the three
formats disagreeing about who is on the list.

Exit non-zero on any failure. Usage: python3 validate.py [directory]
"""

import csv
import datetime
import ipaddress
import re
import json
import os
import sys

VALID_TIERS = {"credential", "scanner"}

# The README's own inclusion thresholds, enforced rather than merely advertised.
# meta.inclusion_criteria states 'credential' = 50+ credential attempts and
# 'scanner' = 1000+ connection events in-window. A generator that drops below
# either publishes addresses the documented criteria do not justify, and the
# only person who finds out is a consumer firewalling on it.
# scanner's floor is read from meta.scanner_min_events when present so the
# published criteria and the check cannot drift apart silently.
TIER_MIN_ATTEMPTS = {"credential": 50, "scanner": 1000}

# IPv6 contract, decided 2026-08-24 rather than left implicit.
# The feed is IPv4-only. Nothing upstream has ever emitted a v6 address (0 of
# 154 at time of writing), and every consumer surface assumes v4: the ipset and
# iptables recipes create `family inet` sets, which REJECT a v6 address rather
# than blocking it. Publishing a global v6 entry would therefore not be caught
# by anyone -- it would land in a feed people already trust and be silently
# dropped or error out at import.
# So this is a hard error, not a warning: a v6 address reaching here means the
# generator changed, and that change needs a designed v6 contract (a separate
# file, or a family column) BEFORE it ships. Loosen this deliberately, with the
# consumer recipes updated in the same change.
ALLOWED_IP_VERSIONS = {4}

# README publishes statistical claims -- novelty vs aggregates, overlap with
# peer honeypot feeds -- that justify this feed existing at all. They are
# measured by scripts/overlap.py against the live feed, which makes 9 external
# fetches and cannot run in hourly CI.
# The failure this guards is not a wrong number, it is an UNNOTICED one: the
# 2026-07-22 measurement sat on the front page for a month while the feed moved
# from 181 entries to 153 and dataplane VNC overlap went 1.7% -> 12.4%.
# So: the README states the size it was measured against, and this check warns
# once the live feed has drifted far enough from that size for the published
# claims to be describing a different list. Cheap, hermetic, no network.
MEASURED_AT = re.compile(r"measured\s+(\d{4}-\d{2}-\d{2}).{0,120}?([\d,]+)-entry feed",
                         re.IGNORECASE | re.DOTALL)
# Drift tolerated before the published claims stop describing the live list.
# CALIBRATED AGAINST THE ACTUAL INCIDENT, not chosen for looking reasonable:
# the README went stale between a 181-entry and a 153-entry feed, which is
# 15.5% drift. A 20% tolerance -- my first instinct -- would have sat silent
# through the only event this check exists to catch, while dataplane VNC
# overlap moved 1.7% -> 12.4% underneath it.
# 10% fires on that case with margin and still tolerates the feed's ordinary
# hourly breathing (it has moved 153-154 in a day). Tightening further would
# alarm on normal churn, which is how a warning becomes wallpaper.
CLAIM_DRIFT_TOLERANCE = 0.10

# Cells whose first character makes a spreadsheet treat the value as a formula.
# The feed is a CSV that people open in Excel/LibreOffice/Sheets; a cell
# beginning =, +, - or @ is executed on open. Nothing legitimate in this feed
# starts with one (IPs are digits, timestamps are digits, tiers are words,
# counters are non-negative, ASNs are 'ASnnnn'), so any occurrence is either
# corruption or an injection attempt and must stop the publish.
FORMULA_PREFIXES = ("=", "+", "-", "@")
# Leading control characters are the documented bypass: a cell starting with a
# tab, CR or LF is stripped by the spreadsheet before the formula test.
FORMULA_CONTROL = ("\t", "\r", "\n")

# Timestamps are published as ISO-8601 UTC with a literal Z, e.g.
# 2026-07-13T02:34:54Z. A shape regex alone is NOT enough: "2026-99-99T25:61:00Z"
# matches it and also passes the string comparisons used for ordering, which is
# the formatting-vs-validity gap flagged in the 2026-07-23 review. Parse it.
ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# The schema consumers are coding against right now. It is NOT in REQUIRED_META
# yet: the generator on loam does not emit it, and promoting it today would fail
# every hourly commit until that ships. Sequence is warn -> generator emits ->
# require. Bump MINOR when a column is appended (consumers keep working), MAJOR
# when one is renamed, removed or reordered (they do not).
SCHEMA_VERSION = "1.0"
SEMVER = re.compile(r"^\d+\.\d+$")


def bad_ts(value):
    """Return a reason string if value is not a real ISO-8601 UTC instant."""
    if not ISO_UTC.match(value):
        return "is not ISO-8601 UTC (expected YYYY-MM-DDTHH:MM:SSZ)"
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        return f"is not a real date/time ({exc})"
    return None
REQUIRED_META = {
    "name", "description", "maintainer", "homepage", "contact",
    "inclusion_criteria", "window_days", "count", "count_by_tier",
    "updated", "license",
}
REQUIRED_ENTRY = {"ip", "tier", "bans", "attempts", "first_seen", "last_seen"}

# The published CSV column contract, in order. MISP feeds address columns by
# position and OpenCTI CSV Mappers by letter index, and neither reads a header,
# so this order is permanent: append on the right, never insert or reorder.
# Keep in sync with CSV_COLUMNS in gen_feed.py.
CSV_COLUMNS = ["ip", "tier", "bans", "attempts", "first_seen", "last_seen",
               "first_banned", "asn"]

errors = []
warnings = []


def err(msg):
    errors.append(msg)


def warn(msg):
    warnings.append(msg)


def check_ip(raw, where):
    """Return a parsed address, or None after recording why it is unusable."""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        err(f"{where}: unparseable IP {raw!r}")
        return None
    # The whole value of the list is that it names real, routable attackers.
    # A private or reserved address here means a bogon filter regressed, and
    # would have consumers blocking their own infrastructure.
    if not addr.is_global or addr.is_multicast or addr.is_reserved:
        err(f"{where}: non-global address published: {addr}")
        return None
    if addr.version not in ALLOWED_IP_VERSIONS:
        err(f"{where}: IPv{addr.version} address {addr} published, but this "
            f"feed's contract is IPv{'/'.join(str(v) for v in sorted(ALLOWED_IP_VERSIONS))}"
            f"-only. The ipset/iptables recipes create `family inet` sets, "
            f"which reject a v6 address instead of blocking it -- consumers "
            f"would silently not be protected. Design the v6 contract and "
            f"update the recipes before relaxing ALLOWED_IP_VERSIONS.")
        return None
    return addr


def check_cell(value, where):
    """Record an error if a published cell would execute in a spreadsheet."""
    if value is None:
        return
    text = str(value)
    if not text:
        return
    stripped = text.lstrip("".join(FORMULA_CONTROL))
    if text[0] in FORMULA_CONTROL:
        err(f"{where}: cell {text!r} begins with a control character; a "
            f"spreadsheet strips it and then evaluates what follows")
        return
    if stripped.startswith(FORMULA_PREFIXES):
        err(f"{where}: cell {text!r} begins with a formula character "
            f"({stripped[0]!r}); this feed is opened in spreadsheets and the "
            f"cell would be executed. Nothing legitimate in this feed starts "
            f"with one.")


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    jpath = os.path.join(d, "blocklist.json")
    tpath = os.path.join(d, "blocklist.txt")
    cpath = os.path.join(d, "blocklist.csv")

    for p in (jpath, tpath, cpath):
        if not os.path.exists(p):
            err(f"missing required file: {p}")
    if errors:
        report()

    # ---- JSON: the authoritative structure ----
    with open(jpath) as f:
        data = json.load(f)

    if not isinstance(data, dict) or "meta" not in data or "ips" not in data:
        err("blocklist.json must be an object with 'meta' and 'ips'")
        report()

    meta, entries = data["meta"], data["ips"]

    # ---- schema_version: the field that lets a consumer refuse a feed ----
    # Column order is load-bearing for MISP/OpenCTI, which address positionally.
    # Without a version there is no way for a consumer to notice the contract
    # changed under it -- it just silently reads the wrong column.
    sv = meta.get("schema_version")
    if sv is None:
        warn(f"meta.schema_version is absent; consumers cannot detect a "
             f"contract change. Generator should emit {SCHEMA_VERSION!r}.")
    elif not isinstance(sv, str) or not SEMVER.match(sv):
        err(f"meta.schema_version={sv!r} is not MAJOR.MINOR")
    elif sv.split(".")[0] != SCHEMA_VERSION.split(".")[0]:
        err(f"meta.schema_version={sv!r} has a different MAJOR than the "
            f"{SCHEMA_VERSION!r} this validator knows. A MAJOR bump means "
            f"columns were renamed, removed or reordered -- update "
            f"CSV_COLUMNS and SCHEMA_VERSION together, deliberately.")
    elif sv != SCHEMA_VERSION:
        warn(f"meta.schema_version={sv!r}, validator knows {SCHEMA_VERSION!r} "
             f"(MINOR drift: a column was appended). Confirm CSV_COLUMNS "
             f"matches what the generator now writes.")

    missing = REQUIRED_META - set(meta)
    if missing:
        err(f"meta is missing keys: {sorted(missing)}")

    if not entries:
        err("blocklist.json contains no entries")
        report()

    json_ips = set()
    recidivists = []
    by_tier = {}
    for i, e in enumerate(entries):
        where = f"blocklist.json[{i}]"
        missing = REQUIRED_ENTRY - set(e)
        if missing:
            err(f"{where}: missing fields {sorted(missing)}")
            continue
        addr = check_ip(e["ip"], where)
        if addr is None:
            continue
        if str(addr) in json_ips:
            err(f"{where}: duplicate entry for {addr}")
        json_ips.add(str(addr))

        if e["tier"] not in VALID_TIERS:
            err(f"{where}: unknown tier {e['tier']!r}")
        by_tier[e["tier"]] = by_tier.get(e["tier"], 0) + 1

        for field in ("bans", "attempts"):
            if not isinstance(e[field], int) or e[field] < 0:
                err(f"{where}: {field} must be a non-negative int, got {e[field]!r}")
        # Documented invariant: scanner-tier entries never carry ban cycles,
        # because those are tracked in a separate table upstream.
        if e["tier"] == "scanner" and e["bans"] != 0:
            err(f"{where}: scanner-tier entry has bans={e['bans']}, expected 0")
        # The README advertises a floor per tier; enforce it here so the
        # published criteria describe the published data rather than an
        # intention. scanner's floor comes from meta when the generator states
        # it, so the two cannot drift.
        floor = TIER_MIN_ATTEMPTS.get(e["tier"])
        if e["tier"] == "scanner":
            declared = meta.get("scanner_min_events")
            if isinstance(declared, int) and declared > 0:
                floor = declared
        if floor is not None and isinstance(e["attempts"], int) and e["attempts"] < floor:
            err(f"{where}: {e['tier']}-tier entry has attempts={e['attempts']}, "
                f"below the documented inclusion threshold of {floor}. "
                f"meta.inclusion_criteria promises this floor to every "
                f"consumer -- publishing under it lists an address the stated "
                f"criteria do not justify.")
        # An empty timestamp slips through silently: the ordering check below is
        # guarded on both fields being truthy, so "" passes every check. A
        # consumer parsing first_seen for an age cutoff gets a ValueError, not a
        # skip. Nothing currently trips this -- that is the point of asserting
        # it before a generator change does.
        for field in ("first_seen", "last_seen"):
            if not e[field]:
                err(f"{where}: {field} is empty")
            else:
                reason = bad_ts(e[field])
                if reason:
                    err(f"{where}: {field}={e[field]!r} {reason}")
        if e["first_seen"] and e["last_seen"] and e["first_seen"] > e["last_seen"]:
            err(f"{where}: first_seen {e['first_seen']} is after last_seen {e['last_seen']}")
        # first_banned pairs with the ban counter: an entry never banned has
        # nothing to stamp, one that was banned must say when. Empty
        # first_banned on scanner-tier rows is correct, not missing data.
        if e["bans"] == 0 and e.get("first_banned"):
            err(f"{where}: bans=0 but first_banned={e['first_banned']!r}")
        if e["bans"] > 0 and not e.get("first_banned"):
            err(f"{where}: bans={e['bans']} but first_banned is empty")
        if e.get("first_banned"):
            reason = bad_ts(e["first_banned"])
            if reason:
                err(f"{where}: first_banned={e['first_banned']!r} {reason}")
        # NOT an error: first_banned routinely predates first_seen, because the
        # columns count different lifetimes -- first_banned is all-time ban
        # history, first_seen is the current observation window. README says so.
        # Warn only, so a generator change that inverts far more than usual shows.
        if e.get("first_banned") and e["first_seen"] and e["first_banned"] < e["first_seen"]:
            recidivists.append(str(addr))

    if recidivists:
        warn(f"{len(recidivists)} of {len(entries)} entries have first_banned "
             f"before first_seen (expected: see the column contract in "
             f"README.md). Sample: {recidivists[:3]}")

    # ---- meta counts must describe the payload ----
    if meta.get("count") != len(entries):
        err(f"meta.count={meta.get('count')} but {len(entries)} entries present")
    if meta.get("count_by_tier") != by_tier:
        err(f"meta.count_by_tier={meta.get('count_by_tier')} but actual is {by_tier}")

    # ---- TXT: comment header + one IP per line ----
    txt_ips = set()
    with open(tpath) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if check_ip(line, f"blocklist.txt:{n}"):
                if line in txt_ips:
                    err(f"blocklist.txt:{n}: duplicate {line}")
                txt_ips.add(line)

    # ---- CSV: header + rows ----
    csv_ips = set()
    csv_rows = {}
    # Row width first, with a plain reader: DictReader silently tolerates a
    # short or long row (missing keys become None, extras land under a None
    # key), so a generator that shifts a column past the header count passes
    # every downstream check while every value sits one place to the left.
    with open(cpath, newline="") as f:
        for n, raw in enumerate(csv.reader(f), 1):
            if not raw:
                continue
            if len(raw) != len(CSV_COLUMNS):
                err(f"blocklist.csv:{n}: {len(raw)} columns, expected "
                    f"{len(CSV_COLUMNS)} ({','.join(CSV_COLUMNS)}). "
                    f"DictReader would have accepted this silently.")
            if n > 1:
                for col, cell in zip(CSV_COLUMNS, raw):
                    check_cell(cell, f"blocklist.csv:{n}.{col}")

    with open(cpath, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != CSV_COLUMNS:
            err(f"blocklist.csv header {reader.fieldnames} does not match the "
                f"published column contract {CSV_COLUMNS}. Column order is "
                f"load-bearing for MISP/OpenCTI; append only, never reorder.")
        else:
            for n, row in enumerate(reader, 2):
                if check_ip(row["ip"], f"blocklist.csv:{n}"):
                    csv_ips.add(row["ip"])
                if row.get("tier") not in VALID_TIERS:
                    err(f"blocklist.csv:{n}: unknown tier {row.get('tier')!r}")
                # The JSON is authoritative, but the CSV is what most consumers
                # actually parse -- so it needs the same field checks, not just
                # an IP/tier glance. Without this a generator that emits a good
                # JSON and a bad CSV passes CI clean.
                where = f"blocklist.csv:{n}"
                for field in ("first_seen", "last_seen"):
                    if not row.get(field):
                        err(f"{where}: {field} is empty")
                    else:
                        reason = bad_ts(row[field])
                        if reason:
                            err(f"{where}: {field}={row[field]!r} {reason}")
                if row.get("first_banned"):
                    reason = bad_ts(row["first_banned"])
                    if reason:
                        err(f"{where}: first_banned={row['first_banned']!r} {reason}")
                csv_rows[row["ip"]] = row

    # ---- header-less CSV for MISP / OpenCTI ----
    # These consumers address columns positionally and never read a header, so
    # two things must hold: the file must not start with a header row (MISP
    # would import it as a junk attribute), and the column order must match
    # blocklist.csv exactly or every field lands in the wrong place silently.
    mpath = os.path.join(d, "blocklist.misp.csv")
    misp_ips = set()
    if os.path.exists(mpath):
        with open(mpath, newline="") as f:
            rows = list(csv.reader(f))
        if rows and rows[0] and rows[0][0].strip().lower() == "ip":
            err("blocklist.misp.csv starts with a header row; MISP would "
                "ingest it as data. It must be header-less.")
        for n, row in enumerate(rows, 1):
            if not row:
                continue
            if len(row) != len(CSV_COLUMNS):
                err(f"blocklist.misp.csv:{n}: {len(row)} columns, "
                    f"expected {len(CSV_COLUMNS)} ({','.join(CSV_COLUMNS)})")
                continue
            for col, cell in zip(CSV_COLUMNS, row):
                check_cell(cell, f"blocklist.misp.csv:{n}.{col}")
            if check_ip(row[0], f"blocklist.misp.csv:{n}"):
                misp_ips.add(row[0])
            if row[1] not in VALID_TIERS:
                err(f"blocklist.misp.csv:{n}: unknown tier {row[1]!r}")
        if misp_ips != json_ips:
            err(f"blocklist.misp.csv names a different set than blocklist.json "
                f"({len(misp_ips)} vs {len(json_ips)})")
    else:
        # Required, not optional: README and meta.formats both publish
        # blocklist.misp.csv as THE feed URL for MISP and OpenCTI. A publish
        # without it takes those consumers offline while the other three
        # formats look healthy, and a warning is exactly the signal that gets
        # scrolled past in a green CI run.
        err("blocklist.misp.csv is missing. It is the documented MISP/OpenCTI "
            "feed (README.md and meta.formats.csv_headerless both point at "
            "it); publishing without it silently breaks those consumers.")

    # ---- the three formats must name the same set ----
    if json_ips != txt_ips:
        only_j, only_t = sorted(json_ips - txt_ips), sorted(txt_ips - json_ips)
        err(f"json/txt disagree: {len(only_j)} only in json {only_j[:3]}, "
            f"{len(only_t)} only in txt {only_t[:3]}")
    if json_ips != csv_ips:
        only_j, only_c = sorted(json_ips - csv_ips), sorted(csv_ips - json_ips)
        err(f"json/csv disagree: {len(only_j)} only in json {only_j[:3]}, "
            f"{len(only_c)} only in csv {only_c[:3]}")

    # ---- the formats must agree on VALUES, not just on membership ----
    # Matching IP sets says the same addresses are listed; it says nothing about
    # whether they carry the same dates and counters. A CSV-only corruption used
    # to pass every check above.
    shared = ("tier", "bans", "attempts", "first_seen", "last_seen",
              "first_banned")
    mismatches = []
    for e in entries:
        row = csv_rows.get(e["ip"])
        if row is None:
            continue
        for field in shared:
            j, c = e.get(field), row.get(field)
            j = "" if j is None else str(j)
            c = "" if c is None else str(c)
            if j != c:
                mismatches.append(f"{e['ip']}.{field}: json={j!r} csv={c!r}")
    if mismatches:
        err(f"json and csv disagree on {len(mismatches)} field value(s): "
            f"{mismatches[:3]}")

    # ---- README should not advertise a count it no longer ships ----
    rpath = os.path.join(d, "README.md")
    if os.path.exists(rpath):
        readme = open(rpath).read()
        if f"**{len(entries)} IPs**" not in readme:
            warn(f"README does not state the current count (**{len(entries)} IPs**) — "
                 "it drifted out of date once before")

        # ---- published statistical claims must still describe this feed ----
        m = MEASURED_AT.search(readme)
        if not m:
            warn("README does not record the date and feed size its overlap/"
                 "novelty claims were measured against, so nothing can tell "
                 "whether they still describe the published list. Expected a "
                 "phrase like 'measured 2026-08-24 ... against the live "
                 "153-entry feed'.")
        else:
            when, size = m.group(1), int(m.group(2).replace(",", ""))
            drift = abs(len(entries) - size) / size if size else 1.0
            if drift > CLAIM_DRIFT_TOLERANCE:
                warn(f"README's overlap/novelty claims were measured {when} "
                     f"against {size} entries; the feed is now {len(entries)} "
                     f"({drift:.0%} drift, tolerance {CLAIM_DRIFT_TOLERANCE:.0%}). "
                     f"Those figures are percentages OF the feed, so they now "
                     f"describe a different list. Re-run "
                     f"scripts/overlap.py and update README.")

    report()


def report():
    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")
    if errors:
        print(f"\n{len(errors)} error(s)")
        sys.exit(1)
    print(f"OK — {len(warnings)} warning(s)")
    sys.exit(0)


if __name__ == "__main__":
    main()
