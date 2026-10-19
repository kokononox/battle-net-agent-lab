param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Core.ps1')
$script:checks=0
function Check($Value) { if(-not $Value){throw ('test_check_'+($script:checks+1))};$script:checks++ }
function Reject([scriptblock]$Code) { $bad=$false;try { & $Code | Out-Null } catch {$bad=$true};Check $bad }
$dir=Join-Path ([IO.Path]::GetTempPath()) ('sstp-tool-test-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($dir)
$receipt=[ordered]@{schema='sstp-allowlist-tool-test-1';passed=$false;checks=0;error_code=$null;powershell_version=$PSVersionTable.PSVersion.ToString();live_windows_tested=$false;network_changed=$false;ready_for_user_apply=$false}
try {
 $path=Join-Path $dir 'allowlist.json'
 foreach($f in @('Core.ps1','SstpAllowlist.ps1','Test-Tool.ps1')) {
  $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $f),[ref]$tokens,[ref]$errors)
  Check ($errors.Count -eq 0)
 }
 $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Core.ps1'))
 Check ($source -notmatch '(?i)(Set|New|Remove|Enable|Disable)-NetFirewall|rasdial|rasphone|Register-ScheduledTask|Start-Process|Invoke-Expression')
 $c=EditAllowlistFile $path Init
 Check ($c.domains.Count -eq 1 -and $c.domains[0] -ceq 'level3.blizzard.com')
 Reject {EditAllowlistFile $path Init}
 $c=EditAllowlistFile $path Add 'EXAMPLE.COM.';Check ($c.domains.Count -eq 2)
 $c=EditAllowlistFile $path Add 'example.com';Check ($c.domains.Count -eq 2)
 $c=EditAllowlistFile $path Add '192.0.2.10';Check ($c.ip_addresses.Count -eq 1)
 $c=EditAllowlistFile $path Remove 'example.com';Check ($c.domains.Count -eq 1)
 $c=EditAllowlistFile $path Remove '192.0.2.10';Check ($c.ip_addresses.Count -eq 0)
 $before=[IO.File]::ReadAllText($path)
 Reject {EditAllowlistFile $path Remove 'level3.blizzard.com'}
 Check ([IO.File]::ReadAllText($path) -ceq $before)
 foreach($bad in @('https://example.com','*.example.com','0.0.0.0/0','::/0','127.0.0.1')) {Reject {EditAllowlistFile $path Add $bad}}
 $hold=[IO.File]::Open(($path+'.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
 try {Reject {EditAllowlistFile $path Add 'example.org'}} finally {$hold.Dispose()}
 Check ([IO.File]::ReadAllText($path) -ceq $before)
 $profiles=@('Domain','Private','Public'|ForEach-Object{[pscustomobject]@{name=$_;enabled='True';default_outbound='Block'}})
 $rules=@(
  [pscustomobject]@{name='legacy';group='SSTP Kill Switch';action='Allow';source_type='Local'},
  [pscustomobject]@{name='other';group='';action='Allow';source_type='Local'},
  [pscustomobject]@{name='domain';group='SSTP Kill Switch';action='Allow';source_type='GroupPolicy'},
  [pscustomobject]@{name='block';group='';action='Block';source_type='Local'}
 )
 $p=NewCompatibilityPlan $c $profiles $rules
 Check ($p.legacy_group_candidates.Count -eq 1)
 Check ($p.other_outbound_allow_candidates.Count -eq 2)
 Check ($p.existing_outbound_blocks_to_review.Count -eq 1)
 Check ($p.profile_blockers.Count -eq 0)
 Check (-not $p.apply_available -and -not $p.ready_for_user_apply -and -not $p.network_changed)
 Check (-not $p.legacy_group_is_ownership_proof -and -not $p.vpn_connection_managed -and -not $p.dns_queried -and -not $p.resident_component_created)
 $profiles[0].enabled='False';$profiles[1].default_outbound='NotConfigured'
 $p=NewCompatibilityPlan $c $profiles $rules;Check ($p.profile_blockers.Count -eq 2)
 Reject {NewCompatibilityPlan $c @($profiles[0],$profiles[0],$profiles[2]) $rules}
 Reject {NewCompatibilityPlan $c $profiles @($rules[0],$rules[0])}
 Reject {NewCompatibilityPlan $c $profiles @([pscustomobject]@{name='x';group='';action='Permit';source_type='Local'})}
 $badPath=Join-Path $dir 'bad.json';[IO.File]::WriteAllText($badPath,'{"schema":"unknown"}')
 Reject {ReadAllowlistConfig $badPath}
 [IO.File]::WriteAllText($badPath,('x'*65537));Reject {ReadAllowlistConfig $badPath}
 Reject {ReadAllowlistConfig (Join-Path $dir 'missing.json')}
 Reject {ReadAllowlistConfig (Join-Path $dir 'not-json.txt')}
 Check (@([IO.Directory]::GetFiles($dir,'.sstp-config-*.tmp')).Count -eq 0)
 $receipt.passed=$true
} catch {
 $receipt.error_code='tool_test_failed'
 if($_.Exception.Message -cmatch '^(test|tool|policy)_[a-z_0-9]{1,80}$'){$receipt.error_code=$_.Exception.Message}
} finally {
 $receipt.checks=$script:checks
 [IO.Directory]::Delete($dir,$true)
 if($OutputPath){[IO.File]::WriteAllText($OutputPath,($receipt|ConvertTo-Json -Depth 4),(New-Object Text.UTF8Encoding($false)))}
}
$receipt | ConvertTo-Json -Depth 4
if(-not $receipt.passed){exit 1}
