#!/usr/bin/env bash
# Build a DNS block-list for the Azure DNS Security Policy from CREDIBLE live
# threat-intel feeds. Emits a plain, newline-delimited list of trailing-dot
# FQDNs that Terraform reads (terraform/blocklist.generated.txt) and unions
# with var.blocklist_domains.
#
# Sources (see intel/sources.md): abuse.ch URLhaus + ThreatFox host files.
# Usage:  ./scripts/build-blocklist.sh > terraform/blocklist.generated.txt
#
# Notes:
#  - Requires curl. Respect each feed's terms of use.
#  - Output is normalized to lowercase, trailing-dot FQDNs, de-duplicated.
#  - Review for false positives before applying. The allow-list stays authoritative.
set -euo pipefail

FEEDS=(
  "https://urlhaus.abuse.ch/downloads/hostfile/"
  "https://threatfox.abuse.ch/downloads/hostfile/"
)

# Cap to keep the domain list a manageable size for the policy.
MAX_DOMAINS="${MAX_DOMAINS:-500}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

for url in "${FEEDS[@]}"; do
  # Hostfile lines look like: "127.0.0.1 malicious.example"
  curl -fsSL "$url" \
    | grep -viE '^\s*#' \
    | awk '{print $2}' \
    | grep -viE '^(localhost|)$' \
    >> "$tmp" || echo "warn: failed to fetch $url" >&2
done

echo "# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) from abuse.ch URLhaus + ThreatFox."
echo "# Do not edit by hand; regenerate with scripts/build-blocklist.sh."
echo "# One trailing-dot FQDN per line; read by Terraform and unioned with blocklist_domains."
tr 'A-Z' 'a-z' < "$tmp" \
  | sed -E 's/\.*$/./' \
  | sort -u \
  | head -n "$MAX_DOMAINS"
