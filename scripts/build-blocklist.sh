#!/usr/bin/env bash
# Build a DNS block-list for the Azure DNS Security Policy from CREDIBLE live
# threat-intel feeds, and emit it as an HCL fragment for terraform.tfvars.
#
# Sources (see intel/sources.md): abuse.ch URLhaus + ThreatFox host files.
# Usage:  ./scripts/build-blocklist.sh > generated-blocklist.auto.tfvars
#
# Notes:
#  - Requires curl. Respect each feed's terms of use.
#  - Output is normalized to lowercase, trailing-dot FQDNs, de-duplicated.
#  - Review for false positives before applying. Keep the allow-list authoritative.
set -euo pipefail

FEEDS=(
  "https://urlhaus.abuse.ch/downloads/hostfile/"
  "https://threatfox.abuse.ch/downloads/hostfile/"
)

# Optional cap to keep the domain list a manageable size for the policy.
MAX_DOMAINS="${MAX_DOMAINS:-500}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

for url in "${FEEDS[@]}"; do
  # Hostfile lines look like: "127.0.0.1 malicious.example"
  curl -fsSL "$url" \
    | grep -viE '^\s*#' \
    | awk '{print $2}' \
    | grep -viE '^(localhost|)$' \
    >> "$tmp" || echo "war: failed to fetch $url" >&2
done

mapfile -t domains < <(
  tr 'A-Z' 'a-z' < "$tmp" \
    | sed -E 's/\.*$/./' \
    | sort -u \
    | head -n "$MAX_DOMAINS"
)

echo "# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) from abuse.ch URLhaus + ThreatFox."
echo "# Do not edit by hand; regenerate with scripts/build-blocklist.sh."
echo "blocklist_domains = ["
for d in "${domains[@]}"; do
  printf '  "%s",\n' "$d"
done
echo "]"
