# Diagnostic prototype. Capture only; never changes firewall, proxy, certificates or DNS.
[CmdletBinding()]
param(
 [string]$CaptureInterface,
 [string[]]$RemoteIP = @(),
 [ValidateRange(10,300)][int]$Seconds = 90,
 [switch]$Consent
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows only.' }
$dumpcap = Join-Path $env:ProgramFiles 'Wireshark\dumpcap.exe'
if (-not (Test-Path -LiteralPath $dumpcap -PathType Leaf)) {
 throw 'Wireshark/dumpcap is not present in the standard location. Nothing installed or changed. See README.fa.md.'
}
if (-not $CaptureInterface) {
 & $dumpcap -D
 if ($LASTEXITCODE -ne 0) { throw 'Interface listing failed. Check Wireshark/Npcap setup; do not disable firewall.' }
 Write-Host 'Listing only. No capture started. See README.fa.md before continuing.'
 return
}
if (-not $Consent) { throw 'Capture may contain private data. Read README.fa.md, then pass -Consent explicitly.' }
$destinations = @('level3.blizzard.com','us.version.battle.net')
$source = 'explicit_IPs_provided_by_operator_not_independently_hostname_verified'
$cacheEvidence = @()
if ($RemoteIP.Count -eq 0) {
 $source = 'existing_Windows_DNS_cache_snapshot_not_socket_hostname_proof'
 # Cache inspection only. No Resolve-DnsName, nslookup or external lookup.
 $cacheEvidence = @(Get-DnsClientCache | Where-Object {
  $_.Entry -in $destinations -and $_.Type -in @(1,28)
 } | Select-Object Entry,Type,Data)
 $RemoteIP = @($cacheEvidence | ForEach-Object { [string]$_.Data })
}
$addresses = @()
foreach ($text in $RemoteIP) {
 $parsed = $null
 if (-not [System.Net.IPAddress]::TryParse($text,[ref]$parsed)) { throw 'Invalid IP address; no capture started.' }
 if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $parsed.ScopeId -ne 0) { throw 'Scoped IPv6 is not supported.' }
 $addresses += $parsed.ToString()
}
$addresses = @($addresses | Sort-Object -Unique)
if ($addresses.Count -lt 1 -or $addresses.Count -gt 64) {
 throw 'No usable direct A/AAAA cache entries, or more than 64 IPs. No fallback lookup and no broad capture. Use observed destination IPs with -RemoteIP; see README.'
}
# All IP protocols and ports for this bounded IP set, not just 80/443.
# Shared-IP traffic from other programs may also be present.
$filter = '(' + (($addresses | ForEach-Object { 'host ' + $_ }) -join ' or ') + ')'
$root = Join-Path $env:LOCALAPPDATA 'TwoDestinationEvidence'
$run = Join-Path $root ([guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $run -Force
$pcap = Join-Path $run 'traffic.PRIVATE.pcapng'
$meta = [ordered]@{
 schema='two-destination-capture-1'; started_utc=[DateTime]::UtcNow.ToString('o');
 destinations=$destinations; ip_source=$source; selected_ips=$addresses;
 dns_cache_snapshot=$cacheEvidence; interface=$CaptureInterface; capture_filter=$filter;
 duration_limit_seconds=$Seconds; size_limit_kB=65536;
 process_attribution_verified=$false; coverage_verified=$false;
 tls_decryption_performed=$false; absence_of_fingerprinting_verified=$false;
 firewall_changed=$false; dns_configuration_changed=$false; certificates_changed=$false;
 status='capture_requested'
}
$metadata = Join-Path $run 'metadata.PRIVATE.json'
$meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metadata -Encoding UTF8
Write-Host ('Private capture directory: ' + $run)
Write-Host 'Observe normal download activity now. Stop with Ctrl+C if needed. Do not disable your firewall.'
Write-Host 'Automatic stop: duration OR size limit, whichever comes first. Do not share raw capture publicly.'
& $dumpcap -i $CaptureInterface -p -s 0 -f $filter -a ('duration:' + $Seconds) -a 'filesize:65536' -w $pcap
$code = $LASTEXITCODE
$meta['ended_utc'] = [DateTime]::UtcNow.ToString('o')
$meta['dumpcap_exit_code'] = $code
if ($code -eq 0 -and (Test-Path -LiteralPath $pcap)) {
 $meta['status'] = 'capture_command_completed_coverage_unverified'
 $meta['capture_bytes'] = (Get-Item -LiteralPath $pcap).Length
 $meta['capture_sha256'] = (Get-FileHash -LiteralPath $pcap -Algorithm SHA256).Hash.ToLowerInvariant()
} else { $meta['status'] = 'failed_or_interrupted_do_not_treat_as_complete' }
$meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metadata -Encoding UTF8
if ($code -ne 0) { throw ('Capture failed/interrupted, exit=' + $code + '. Retained files may be incomplete.') }
Write-Host 'Capture finished. No privacy verdict was made. Read README.fa.md for local inspection.'
