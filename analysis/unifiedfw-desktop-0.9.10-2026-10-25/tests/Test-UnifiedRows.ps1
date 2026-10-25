param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$checks=0
function Check([bool]$b,[string]$n){if(-not $b){throw ('test_failed: '+$n)};$script:checks++}
. (Join-Path $Root 'app/workspace-model.ps1')
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui.ps1'),[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Confirmation-DisplayText'},$true);. ([scriptblock]::Create($f.Extent.Text))
$a=New-IPDraftRow @('a') '8.8.8.8' 'TCP' 443 '' 'id1'
$b=New-IPDraftRow @('a') '1.1.1.1' 'TCP' 443 '' 'id2'
$n=[pscustomobject]@{entries=@([pscustomobject]@{entry_id='id1';status='active_verified'});orphan_rules=@()}
$x=@(Get-BlacklistDisplayRows @($a,$b) @($a) $n)
Check ($x.Count -eq 2) 'one-unified-list'
Check ($x[0].local_state -ceq 'saved' -and $x[0].native_state -ceq 'active_verified') 'saved-and-active-distinct-fields'
Check ($x[1].local_state -ceq 'draft' -and $x[1].native_state -ceq 'unknown') 'draft-never-inherits-active'
$x=@(Get-BlacklistDisplayRows @($b) @($a) $n)
Check ($x.Count -eq 2 -and $x[1].local_state -ceq 'pending_removal') 'deleted-draft-saved-row-still-visible'
Check ($x[1].view_only -and $x[1].native_state -ceq 'active_verified') 'draft-delete-does-not-imply-native-delete'
$x=@(Get-BlacklistDisplayRows @($a) @($a) $null)
Check ($x[0].native_state -ceq 'unknown') 'unchecked-not-active'
$n.orphan_rules=@([pscustomobject]@{program_id='a';program='C:\Apps\Game.exe';remote_addresses=@('9.9.9.9/32');protocol='TCP';port=443;name='old-rule'})
$x=@(Get-BlacklistDisplayRows @() @() $n)
Check ($x.Count -eq 1 -and $x[0].local_state -ceq 'active_only' -and $x[0].view_only) 'active-orphan-visible-not-added-to-draft'
Check ($x[0].row.target -ceq '9.9.9.9/32') 'orphan-destination-preserved'
foreach($token in @('RESET WINDOWS HOSTS','RESTORE HOSTS BACKUP','I ACCEPT LAB NETWORK CHANGES','ENABLE BLOCKED CONNECTION LOGGING')){
 $text=Confirmation-DisplayText ("KEEP SAFETY WARNING`r`nبرای ادامه دقیقاً تایپ کنید:`r`n"+$token) $token
 Check ($text.Contains('KEEP SAFETY WARNING') -and -not $text.Contains($token)) 'click-prompt-preserves-warning-removes-token'
 Check (-not $text.Contains('دقیقاً تایپ')) 'no-type-instruction'
}
$r=@{passed=$true;assertions=$checks;Windows_GUI_executed=$false;suite='single-blacklist-status-and-click-confirmation';environment='PowerShell 7.4.6 Linux, production pure functions'}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/unified-rows-tests.json'),(ConvertTo-Json $r));$r|ConvertTo-Json -Compress
