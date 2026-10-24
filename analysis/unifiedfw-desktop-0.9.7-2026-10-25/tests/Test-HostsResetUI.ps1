param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui-hosts-reset.ps1'),[ref]$tokens,[ref]$errors)
Check (@($errors).Count -eq 0) 'module-parsed'
foreach($name in @('Confirm-HostsResetPlan','Set-HostsResetControls')){
 $f=$ast.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -ceq $name},$true)
 Check ($null -ne $f) ('production-helper-extracted-'+$name);Invoke-Expression $f.Extent.Text
}
$script:consent=$false;$script:called=@();$script:captured=$null
function ConfirmText([string]$Title,[string]$Explanation,[string]$Expected){$script:captured=@{title=$Title;explanation=$Explanation;token=$Expected};return $script:consent}
function BeginOp([string]$Action,$Payload){$script:called+=,@{action=$Action;payload=$Payload}}
$reset=[pscustomobject]@{operation='reset';backup_id=$null;expected_sha256=('a'*64);plan_digest=('b'*64)}
Confirm-HostsResetPlan $reset
Check ($script:called.Count -eq 0) 'cancel-no-write-request'
Check ($script:captured.token -ceq 'RESET WINDOWS HOSTS') 'reset-specific-consent-token'
Check ($script:captured.explanation.Contains('NO FIREWALL RESET')) 'scope-warning-shown'
$script:consent=$true;Confirm-HostsResetPlan $reset
Check ($script:called.Count -eq 1) 'one-reset-request-only'
Check ($script:called[0].action -ceq 'hosts_reset_apply') 'reset-dispatches-only-hosts-adapter'
Check ($script:called[0].payload.expected_sha256 -ceq ('a'*64) -and $script:called[0].payload.plan_digest -ceq ('b'*64)) 'preview-bound-payload'
Check ($script:called[0].payload.confirmation -ceq 'RESET WINDOWS HOSTS') 'reset-confirmation-forwarded'
$restore=[pscustomobject]@{operation='restore';backup_id=('c'*32);expected_sha256=('d'*64);plan_digest=('e'*64)}
Confirm-HostsResetPlan $restore
Check ($script:called.Count -eq 2 -and $script:called[1].action -ceq 'hosts_reset_restore_apply') 'restore-separate-request'
Check ($script:called[1].payload.backup_id -ceq ('c'*32)) 'selected-backup-bound'
Check ($script:captured.token -ceq 'RESTORE HOSTS BACKUP') 'restore-specific-consent'
Check ($script:called[1].payload.confirmation -ceq 'RESTORE HOSTS BACKUP') 'restore-confirmation-forwarded'
$hostsResetDefault=[pscustomobject]@{Enabled=$true};$hostsResetReload=[pscustomobject]@{Enabled=$true};$hostsResetRestore=[pscustomobject]@{Enabled=$true};$hostsResetFolder=[pscustomobject]@{Enabled=$true};$hostsResetGrid=[pscustomobject]@{Enabled=$true}
Set-HostsResetControls $true
foreach($v in @($hostsResetDefault,$hostsResetReload,$hostsResetRestore,$hostsResetFolder,$hostsResetGrid)){Check (-not $v.Enabled) 'busy-disables-new-controls'}
Set-HostsResetControls $false
foreach($v in @($hostsResetDefault,$hostsResetReload,$hostsResetRestore,$hostsResetFolder,$hostsResetGrid)){Check $v.Enabled 'completion-reenables-new-controls'}
$result=@{suite='hosts-reset-ui';passed=$true;assertions=$script:checks;production_confirmation_and_busy_helpers_executed_with_mocks=$true;Windows_GUI_executed=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/hosts-reset-ui-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
