<#
.SYNOPSIS
  Build a DNS block-list for the Azure DNS Security Policy from credible live
  threat-intel feeds (abuse.ch URLhaus + ThreatFox) and emit an HCL fragment
  for terraform.tfvars.

.EXAMPLE
  ./scripts/build-blocklist.ps1 -MaxDomains 500 | Out-File generated-blocklist.auto.tfvars -Encoding utf8

.NOTES
  See intel/sources.md. Respect each feed's terms of use. Review for false
  positives before applying; keep the allow-list authoritative.
#>
[CmdletBinding()]
param(
  [int]$MaxDomains = 500
)

$ErrorActionPreference = 'Stop'

$feeds = @(
  'https://urlhaus.abuse.ch/downloads/hostfile/',
  'https://threatfox.abuse.ch/downloads/hostfile/'
)

$domains = New-Object System.Collections.Generic.HashSet[string]

foreach ($url in $feeds) {
  try {
    $content = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
  } catch {
    Write-Warning "Failed to fetch $url : $_"
    continue
  }
  foreach ($line in $content -split "`n") {
    $line = $line.Trim()
    if ($line -eq '' -or $line.StartsWith('#')) { continue }
    # Hostfile format: "127.0.0.1 malicious.example"
    $parts = $line -split '\s+'
    if ($parts.Count -lt 2) { continue }
    $d = $parts[1].ToLower().TrimEnd('.')
    if ($d -eq '' -or $d -eq 'localhost') { continue }
    [void]$domains.Add("$d.")
  }
}

$selected = $domains | Sort-Object | Select-Object -First $MaxDomains

$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
"# Generated $now from abuse.ch URLhaus + ThreatFox."
"# Do not edit by hand; regenerate with scripts/build-blocklist.ps1."
"blocklist_domains = ["
foreach ($d in $selected) { "  `"$d`"," }
"]"
