# Threat-intelligence sources for the DNS block-list

The block-list in this repo is meant to be **populated from credible, maintained
threat-intelligence feeds** — not hand-curated. A static list goes stale within
hours. Below are the reputable public sources this project recommends, what they
cover, and how to consume them.

> ⚠️ Never paste live malicious domains into version control as "examples". Pull
> them at deploy time from the feeds below (see `scripts/build-blocklist.*`) or
> rely on the Azure-managed threat-intel list already wired into the policy
> (`AzureManagedDomainListThreatIntel`, rule 110 = Block).

## Recommended feeds

| Source | Coverage | Free feed | Notes |
|--------|----------|-----------|-------|
| **abuse.ch — URLhaus** | Malware distribution URLs/domains | https://urlhaus.abuse.ch/downloads/hostfile/ | Hostfile format, easy to parse |
| **abuse.ch — ThreatFox** | IOC / payload delivery + C2 domains | https://threatfox.abuse.ch/downloads/hostfile/ | Community IOC database |
| **abuse.ch — Feodo Tracker** | Botnet C2 (Emotet, Dridex, TrickBot) | https://feodotracker.abuse.ch/downloads/ipblocklist.txt | Mostly IPs; pair with URLhaus for domains |
| **Spamhaus** | Botnet C2, DGA, compromised hosts | https://www.spamhaus.com/data/ | DNSBL / RPZ; some tiers commercial |
| **OpenPhish** | Phishing domains | https://openphish.com/feed.txt | Free community feed |
| **SANS ISC / DShield** | Aggregated C2 / suspicious domains | https://isc.sans.edu/feeds.html | Good for hunting/RPZ |
| **HaGeZi DNS blocklists** | Malware/phishing (FP-minimized) | https://github.com/hagezi/dns-blocklists | Curated, low false positives |
| **PeterDaveHello/threat-hostlist** | Aggregated malware/phishing/botnet | https://github.com/PeterDaveHello/threat-hostlist | Community aggregate |

## How this maps to the Azure DNS Security Policy

- **Rule 110 (Block, `AzureManagedDomainListThreatIntel`)** — Microsoft's own
  managed threat-intel feed. Zero maintenance; enabled by default.
- **Rule 100 (Block, custom `blocklist_domains`)** — your organization-specific
  additions. Populate via `scripts/build-blocklist.*` from the feeds above.

## Licensing / usage

Respect each provider's terms. abuse.ch feeds are free for non-commercial and
most commercial use with attribution; Spamhaus has free and paid tiers;
OpenPhish community feed is free with restrictions. Review before production use.

## Operational guidance

1. Pull feeds on a schedule (e.g., hourly) in CI, not once at build time.
2. De-duplicate and normalize to trailing-dot FQDNs.
3. Stage changes and monitor for **false positives** before enforcing.
4. Keep an allow-list override so critical business domains can't be blocked by
   a bad feed entry.
