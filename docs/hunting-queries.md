# DNS exfiltration hunting queries (KQL)

Run these in the Log Analytics workspace that receives the DNS Security Policy
logs (`DnsResponse` category). They surface classic DNS information-leakage
patterns.

## 1. Queries that were blocked by policy

```kql
DNSQueryLogs
| where TimeGenerated > ago(24h)
| where ResponseCode == "Blocked" or Result == "Blocked"
| summarize Count = count() by QueryName, SourceIpAddress
| order by Count desc
```

## 2. Suspiciously long / high-entropy subdomains (tunneling signal)

```kql
DNSQueryLogs
| where TimeGenerated > ago(24h)
| extend Label = tostring(split(QueryName, ".")[0])
| where strlen(Label) > 40
| project TimeGenerated, SourceIpAddress, QueryName, strlen(Label)
| order by strlen_Label desc
```

## 3. Unusual record types often used for exfiltration (TXT / NULL)

```kql
DNSQueryLogs
| where TimeGenerated > ago(24h)
| where QueryType in ("TXT", "NULL", "CNAME")
| summarize Count = count() by SourceIpAddress, QueryType
| order by Count desc
```

## 4. High query volume to a single domain (beaconing / exfil)

```kql
DNSQueryLogs
| where TimeGenerated > ago(1h)
| summarize Count = count() by ParentDomain = strcat_array(array_slice(split(QueryName, "."), -2, -1), "."), SourceIpAddress
| where Count > 500
| order by Count desc
```

> Note: exact table/column names depend on the schema version streamed to your
> workspace. Adjust `DNSQueryLogs` / column names to match your environment.

---

## Alternative schema: `AzureDiagnostics` (`DnsSecurityPolicy` category)

The queries above target the resource-specific `DNSQueryLogs` table. Depending
on how you configure the diagnostic setting, DNS Security Policy events may
instead land in the legacy **`AzureDiagnostics`** table under
`Category == "DnsSecurityPolicy"`, with columns `Action`, `DestinationDomain`,
`SourceIP`, and `RuleName`. The following queries (adapted from
[learn.cloudpartner.fi](https://learn.cloudpartner.fi/posts/azure-dns-security-policy-with-threat-intelligence-protecting-the-first-step-of-every-cyberattack))
use that schema — pick whichever matches your workspace.

### A. Daily blocked-query trend (attack-campaign detection)

```kql
AzureDiagnostics
| where Category == "DnsSecurityPolicy"
| where Action == "Block"
| summarize BlockedCount = count() by bin(TimeGenerated, 1d)
| render timechart
```

### B. Top 10 malicious domains blocked

```kql
AzureDiagnostics
| where Category == "DnsSecurityPolicy"
| where Action == "Block"
| summarize Count = count() by DestinationDomain
| order by Count desc
| take 10
```

### C. Identify potentially compromised resources (many distinct blocked domains)

```kql
AzureDiagnostics
| where Category == "DnsSecurityPolicy"
| where Action == "Block"
| summarize DistinctBlockedDomains = dcount(DestinationDomain), BlockedCount = count() by SourceIP
| where DistinctBlockedDomains > 5
| order by BlockedCount desc
```

### D. DNS tunneling detection (high volume to one domain)

```kql
AzureDiagnostics
| where Category == "DnsSecurityPolicy"
| summarize QueryCount = count() by SourceIP, DestinationDomain, bin(TimeGenerated, 1m)
| where QueryCount > 50   // >50 queries/min to the same domain
| project TimeGenerated, SourceIP, DestinationDomain, QueryCount
| order by QueryCount desc
```

### E. Sentinel analytics rule — high-volume source (auto-response candidate)

```kql
AzureDiagnostics
| where Category == "DnsSecurityPolicy"
| where TimeGenerated > ago(5m)
| summarize QueryCount = count() by SourceIP, bin(TimeGenerated, 5m)
| where QueryCount > 200
| extend AlertSeverity = "High"
| project TimeGenerated, SourceIP, QueryCount, AlertSeverity
```

Wire this to a Sentinel playbook (Logic App) to isolate the VM (NSG change),
open a ticket, notify the SOC, and snapshot the disk for forensics.
