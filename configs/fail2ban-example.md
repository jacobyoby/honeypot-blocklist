# Use with fail2ban / iptables / nftables

## ipset + iptables (recommended)

### One-time setup
```bash
ipset create jrk-blocklist hash:ip -exist
iptables -I INPUT -m set --match-set jrk-blocklist src -j DROP
```

### Refresh (cron, hourly)

Each refresh **replaces** the set rather than appending to it, so IPs that have
aged off the feed are automatically removed. The `swap` is atomic — there is
no gap where the firewall has no rules.

```bash
ipset create jrk-blocklist-new hash:ip -exist
curl -s https://jacobrakai.org/feed/blocklist.txt | grep -vE '^#' | while read ip; do ipset add jrk-blocklist-new "$ip" -exist; done
ipset swap jrk-blocklist-new jrk-blocklist
ipset destroy jrk-blocklist-new
```

## nftables

### One-time setup
```bash
nft add set inet filter jrk-blocklist { type ipv4_addr \; flags interval \; }
nft add rule inet filter input ip saddr @jrk-blocklist drop
```

### Refresh (cron, hourly)

Same replace-not-append pattern: flush and repopulate.

```bash
nft flush set inet filter jrk-blocklist
curl -s https://jacobrakai.org/feed/blocklist.txt | grep -vE '^#' | while read ip; do nft add element inet filter jrk-blocklist { "$ip" }; done
```

## fail2ban action

Drop `jrk-ipset.conf` into `/etc/fail2ban/action.d/` to let fail2ban manage
the same ipset. This is complementary to the cron refresh above — fail2ban
adds IPs it catches in real time, while the cron job replaces the bulk list.

```ini
# /etc/fail2ban/action.d/jrk-ipset.conf
[Definition]

actionstart = ipset create jrk-blocklist hash:ip -exist
              iptables -I INPUT -m set --match-set jrk-blocklist src -j DROP

actionstop  = iptables -D INPUT -m set --match-set jrk-blocklist src -j DROP
              ipset destroy jrk-blocklist

actionban   = ipset add jrk-blocklist <ip> -exist

actionunban = ipset del jrk-blocklist <ip> -exist
```

Pair it with a jail (e.g. SSH) in `/etc/fail2ban/jail.local`:

```ini
[sshd]
enabled  = true
banaction = jrk-ipset
```

## nginx deny

```bash
curl -s https://jacobrakai.org/feed/blocklist.txt | grep -vE '^#' | sed 's/^/deny /; s/$/;/' > /etc/nginx/jrk-blocklist.conf
# include /etc/nginx/jrk-blocklist.conf; inside your http/server block
nginx -s reload
```

Refresh on a cron (hourly is plenty).
