# Example domain lists (categories)

These are **illustrative** domain-list categories drawn from the scenarios in
[learn.cloudpartner.fi](https://learn.cloudpartner.fi/posts/azure-dns-security-policy-with-threat-intelligence-protecting-the-first-step-of-every-cyberattack).
Use them as templates for the custom domain lists referenced by rules in
[`terraform/dns-security-policy.tf`](../terraform/dns-security-policy.tf).

> All example bad/attacker domains below are the article's illustrative
> placeholders (`pennywise.it`, `cloudnoso.com`). They are **not** verified live
> indicators — treat them as documentation examples, not an operational feed.
> For real indicators, use the credible sources in [`sources.md`](./sources.md)
> and the automation in [`../scripts/`](../scripts/).

---

## `approved-external-services` — Allow (maps to repo Rule 200)

Explicit allow-list for business-critical SaaS so default-deny never blocks
them. Keep entries **narrow** (DNS hierarchy means allowing a parent also allows
all its subdomains).

```
api.salesforce.com
*.office365.com
*.azure.com
*.microsoft.com
trusted-partner-api.com
```

## `azure-platform-required` — Allow (maps to repo Rule 210)

Endpoints Azure resources need to function; pairs with the default-deny so the
wildcard block doesn't break the platform.

```
*.blob.core.windows.net
*.azure-automation.net
management.azure.com
login.microsoftonline.com
*.monitor.azure.com
```

## `high-risk-categories` — Alert or Block

Categories to monitor or deny (gambling, torrents, unapproved cloud storage,
newly-registered / rare TLDs). Use **Alert** first to catch insider-threat
patterns (e.g., unauthorized data upload) before enforcing **Block**.

```
# unapproved cloud storage (example placeholders)
unauthorized-storage.com
*.rare-file-share.example
# rare / abused TLDs (evaluate before blocking)
*.zip
*.mov
```

## `internal-blocklist` — Block (maps to repo Rule 100)

Org-specific known-bad indicators layered on top of the Microsoft-managed
threat-intelligence feed (Rule 110). The article's example attacker/C2 domains:

```
pennywise.it
cloudnoso.com
```

CNAME-chain inspection means blocking `pennywise.it` also blocks any domain that
resolves to it (e.g., `cloudnoso.com → cdn.cloudnoso.com → pennywise.it`).

---

## How these map to policy rules

| List | Action | Repo rule | Purpose |
|------|--------|-----------|---------|
| `internal-blocklist` | Block | 100 | Custom known-bad / exfil |
| *Microsoft MSRC feed* | Block | 110 | Managed threat intel |
| `high-risk-categories` | Alert→Block | *(add above 400)* | Insider threat / risky categories |
| `approved-external-services` | Allow | 200 | Business SaaS |
| `azure-platform-required` | Allow | 210 | Keep Azure working |
| `.` (all) | Block | 400 | Default-deny catch-all |

See [`../docs/how-dns-security-policy-mitigates-attacks.md`](../docs/how-dns-security-policy-mitigates-attacks.md)
for the full attack→mitigation mapping.
