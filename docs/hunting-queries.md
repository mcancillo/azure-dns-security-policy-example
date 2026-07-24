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
