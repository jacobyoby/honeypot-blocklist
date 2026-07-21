# Use with fail2ban / iptables

## ipset + iptables (recommended)
```bash
ipset create jrk-blocklist hash:ip -exist
curl -s https://jacobrakai.org/feed/blocklist.txt | grep -vE '^#' | while read ip; do ipset add jrk-blocklist "$ip" -exist; done
iptables -I INPUT -m set --match-set jrk-blocklist src -j DROP
```

## nginx deny
```bash
curl -s https://jacobrakai.org/feed/blocklist.txt | grep -vE '^#' | sed 's/^/deny /; s/$/;/' > /etc/nginx/jrk-blocklist.conf
# include /etc/nginx/jrk-blocklist.conf; inside your http/server block
```
Refresh on a cron (hourly is plenty).
