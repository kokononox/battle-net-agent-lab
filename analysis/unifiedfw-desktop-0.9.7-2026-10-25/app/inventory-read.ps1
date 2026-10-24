# Fixed, READ-ONLY child. No rule/journal mutations, no UOpenPrivateFile creation.
param([Parameter(Mandatory=$true)][string]$Request,[Parameter(Mandatory=$true)][string]$Output)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lab/session-core.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lab/native.ps1')
. (Join-Path $PSScriptRoot 'live-inventory.ps1')
UAssertPath $Request;UAssertPath $Output
if((Get-Item -LiteralPath $Request).Length -gt 1048576){throw 'inventory_request_size'}
$j=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request))
if($j.owner -cnotmatch '^[a-f0-9]{32}$' -or @($j.programs).Count -lt 1 -or @($j.programs).Count -gt 32){throw 'inventory_request_scope'}
foreach($p in $j.programs){if($p.id -cnotmatch '^[a-f0-9]{24}$' -or $p.path -cnotmatch '^[A-Za-z]:\\' -or [IO.Path]::GetExtension([string]$p.path) -ine '.exe'){throw 'inventory_program'}}
$result=Get-MonitorInventory ([string]$j.owner) $j.programs
$text=ConvertTo-Json -InputObject $result -Depth 20
if([Text.Encoding]::UTF8.GetByteCount($text) -gt 4194304){throw 'inventory_output_size'}
$tmp=$Output+'.next-'+[guid]::NewGuid().ToString('N')
try{
 [IO.File]::WriteAllText($tmp,$text,(New-Object Text.UTF8Encoding($false)))
 if([IO.File]::Exists($Output)){[IO.File]::Replace($tmp,$Output,[NullString]::Value)}else{[IO.File]::Move($tmp,$Output)}
}finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
