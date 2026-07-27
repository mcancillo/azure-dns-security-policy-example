# How DNS Security Policies mitigate real-world attacks

DNS is the first step of almost every cyberattack — *"over 90% of the cases, an
attack starts with a DNS query."* Because nearly every internet transaction
begins with a DNS lookup, that single query is often the entry point for
compromise, and most organizations have little visibility into it.

This page maps the **attack scenarios and examples** from
[*Azure DNS Security Policy with Threat Intelligence*](https://learn.cloudpartner.fi/posts/azure-dns-security-policy-with-threat-intelligence-protecting-the-first-step-of-every-cyberattack)
(learn.cloudpartner.fi) onto **how a DNS Security Policy mitigates them** and
**which rule/resource in this repo** implements the control.

> Repo rule model (see [`terraform/dns-security-policy.tf`](../terraform/dns-security-policy.tf)),
> evaluated by priority — **lowest number wins**:
>
> | Priority | Action | Target |
> |----------|--------|--------|
> | 100 | Block | Known-bad / exfil domains (`blocklist_domains` + generated feed) |
> | 110 | Block | Microsoft-managed threat-intelligence list |
> | 200 | Allow | Approved business FQDNs |
> | 210 | Allow | Required Azure platform FQDNs |
> | 400 | Block | Default-deny catch-all (`.`) |

---

## How DNS is used in attacks → how the policy stops it

### 1. Initial access / Command-and-Control (C2)

**Attack (from article):** a compromised VM resolves an attacker domain
(`pennywise.it`) via a public resolver, gets the attacker IP, and opens a C2
channel — silently, with no firewall alert.

```
Compromised VM → DNS query: pennywise.it → Public resolver → Attacker IP
              → VM connects to C2 → Data exfiltration begins
```

**Mitigation:** the query never resolves.
- **Rule 110 (Block threat-intel)** catches the domain if Microsoft's MSRC feed
  knows it; **Rule 100 (Block)** catches it from your custom/feed block-list.
- **Rule 400 (default-deny)** blocks it even if it is brand-new and unknown —
  the attacker domain isn't on any allow-list, so C2 setup fails at the DNS
  layer, before any connection.
- The block is **logged**, generating a security signal instead of silence.

### 2. Malware delivery / DNS tunneling

**Attack (from article):** data is base64-encoded into a subdomain and smuggled
out as normal-looking DNS queries:

```
Normal:  www.cloudnoso.com            → returns IP
Tunneled: aGVsbG8gd29ybGQ.pennywise.it → attacker's DNS server decodes the label
```

**Mitigation:**
- The **parent domain** (`pennywise.it`) is blocked by **Rule 100/110**, and
  **CNAME-chain inspection** (below) prevents indirection evasion — so *every*
  `*.pennywise.it` tunneling query fails.
- **Rule 400 default-deny** blocks tunneling to any *unapproved* parent domain.
- **Detection:** logging surfaces the behavioral signal (long/high-entropy
  labels, `TXT`/`NULL` records, high query volume) — see the tunneling KQL in
  [`hunting-queries.md`](./hunting-queries.md).

### 3. Network disruption / DDoS

**Attack (from article):** the 2016 Mirai botnet DDoS against DNS provider Dyn
took Twitter, Netflix, Reddit and GitHub offline — not by downing the sites, but
by making their names unresolvable.

**Mitigation / scope note:** a DNS Security Policy governs **outbound
resolution from your VNet**, so it stops your workloads being *used* as part of
botnet C2/DDoS infrastructure (Rules 100/110/400) and gives visibility into
anomalous outbound volume. Protecting your *inbound* authoritative/public
endpoints from volumetric attack is the job of **Azure DDoS Protection** — a
complementary layer (see *Defense in depth* below).

### 4. Data theft / DNS poisoning & phishing

**Attack (from article):** a poisoned cache returns a fake IP for `bank.com`,
redirecting users to an attacker site for credential theft.

**Mitigation:**
- Blocking the attacker's landing/phishing domains (**Rule 100/110**, plus
  phishing feeds like OpenPhish — see [`intel/sources.md`](../intel/sources.md))
  stops resolution to the malicious destination.
- **Default-deny (Rule 400)** prevents resolution to unknown phishing infra.
- Forcing all DNS through the **inspected Azure-provided path** (NSG denies
  external resolvers — [`terraform/network.tf`](../terraform/network.tf)) reduces
  exposure to untrusted/poisonable resolvers.

---

## Key policy capabilities that do the mitigating

| Capability | What it does | Where in this repo |
|------------|--------------|--------------------|
| **Priority traffic rules (Allow/Block/Alert)** | Deterministic per-domain decisions; lowest priority number wins | `dns-security-policy.tf` rules 100–400 |
| **Microsoft MSRC Threat-Intelligence feed** | Continuously updated managed list of known-malicious domains; zero maintenance | Rule 110 (`AzureManagedDomainListThreatIntel`) |
| **Custom domain lists** | Org-specific allow/block/category lists | `dl-allow`, `dl-platform`, `dl-block`, `dl-all` + [`intel/`](../intel/) |
| **CNAME-chain inspection** | Blocking `pennywise.it` also blocks anything resolving to it via CNAME (`cloudnoso.com → cdn.cloudnoso.com → pennywise.it`) | Native to the policy |
| **VNet linkage (public + private DNS)** | All DNS from linked VNets is filtered | `azapi_resource.vnet_link` |
| **Comprehensive logging** | Source, destination, action, timestamp, rule → Log Analytics / Storage / Event Hubs | `monitoring.tf` diagnostic setting |
| **DNS firewall (FQDN network rule)** | Azure Firewall DNS proxy resolves & pins known-bad FQDNs, then denies **all** ports/protocols to them — closes non-HTTP paths the app rules miss | `firewall.tf` `nrc-dns-firewall-block-fqdns` |

---

## Real-world protection scenarios (from the article)

| Scenario | Without policy | With DNS Security Policy | Repo control |
|----------|----------------|--------------------------|--------------|
| **Block C2** | VM resolves `pennywise.it` → C2 → ransomware | Query blocked → alert → IR → VM isolated | Rules 110/100/400 + Sentinel alert |
| **Insider threat** | VM resolves `unauthorized-storage.com` → upload → data loss | **Alert** on unapproved category → SOC investigates → access revoked | Add an **Alert** rule over a `high-risk`/`unapproved` list |
| **DNS tunneling** | Container sends `base64data.pennywise.it` → decoded & stolen | Attacker domain in TI feed → all queries blocked → container isolated | Rules 110/100 + tunneling detection KQL |
| **Compliance / audit (SOC 2 / ISO 27001)** | No DNS visibility | Every query logged → KQL → reports; Sentinel + Power BI | `monitoring.tf` + [`hunting-queries.md`](./hunting-queries.md) |

> **Insider-threat note:** the article uses **Alert** (permit-but-monitor) for
> unapproved SaaS so security can investigate before blocking. This repo runs a
> stricter **default-deny**; to reproduce the alert-first behavior, add an
> `Alert` rule referencing a "high-risk/unapproved" domain list *above* rule 400.
> Example category lists are in
> [`intel/domain-lists-examples.md`](../intel/domain-lists-examples.md).

---

## Important behavioral rules to remember

From the article's "Important Considerations" — these directly affect mitigation:

- ⚠️ **Priority wins:** blocked at 100 but allowed at 200 → **blocked** (lower
  number wins). This is why the repo blocks known-bad (100/110) *before* allows
  (200/210).
- ⚠️ **DNS hierarchy:** if you **allow** `contoso.com`, then `sub.contoso.com` is
  also allowed even if a lower-priority rule blocks it. Keep allow-lists
  **narrow and specific** to avoid opening exfil channels under allowed parents.
- ⚠️ **Wildcard caution:** blocking `.` (all) can break required Azure services —
  which is why the repo pairs default-deny (Rule 400) with an explicit
  **platform allow-list** (Rule 210).
- ⚠️ **CNAME-chain inspection:** blocking a domain also blocks anything that
  CNAMEs to it — defeats a common evasion technique.

---

## Rollout guidance (article best practices)

1. **Start in Alert-only mode** for 1–2 weeks to learn traffic patterns, then
   switch to **Block** (especially for the threat-intel rule).
2. **Layer rules** by priority (block TI → block high-risk → alert suspicious →
   allow approved → catch-all log).
3. **Test in non-production** VNets first; watch for false positives.
4. **Maintain an allow-list** for business-critical services to prevent
   accidental blocking.
5. **Audit rules quarterly** (promote alert→block, prune stale lists).
6. **Integrate Sentinel** playbooks for automated isolation of noisy sources.

---

## Defense in depth

A DNS Security Policy is **one layer**. The article's model, aligned to this
repo's design:

| Layer | Service | In this repo |
|-------|---------|--------------|
| Identity | Microsoft Entra ID | (out of scope) |
| Network | NSG / Azure Firewall / ASG | `network.tf`, `firewall.tf` |
| **DNS** | **DNS Security Policy + Threat Intel** | `dns-security-policy.tf` |
| Application | WAF / DDoS Protection | (recommended add-on) |
| Data | Encryption / Key Vault | (out of scope) |
| Monitoring | Sentinel / Defender for Cloud | `monitoring.tf` |

**Bottom line:** over 90% of attacks begin with a DNS query — the policy stops
them *at the door*, before a connection to malicious infrastructure is ever
established, and logs everything for detection and compliance.

*Source: examples and scenarios adapted from
[learn.cloudpartner.fi](https://learn.cloudpartner.fi/posts/azure-dns-security-policy-with-threat-intelligence-protecting-the-first-step-of-every-cyberattack).*
