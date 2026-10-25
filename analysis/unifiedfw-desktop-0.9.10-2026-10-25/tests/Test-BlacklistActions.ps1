param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$checks=0
function Check([bool]$b,[string]$n){if(-not $b){throw ('test_failed: '+$n)};$script:checks++}
. (Join-Path $Root 'app/workspace-model.ps1')
$script:calls=@();$script:edits=@();$script:bindCalls=0;$script:rangeSeed=$null
function TryOp([scriptblock]$Body){& $Body}
function BeginOp([string]$Action,$Payload){$script:calls+=,@{action=$Action;payload=$Payload}}
function Edit-IPDraft($Old=$null){$script:edits+=,$Old}
function Draft-Selection($Grid){return $Grid.SelectedRows[0].Tag}
function Register-DraftPrograms {$script:bindCalls++}
function Open-RangeBuilder($Seed=$null){$script:rangeSeed=$Seed}
function Render-Drafts {}
function AssertSaved {}
function Generation {return 4}
$script:ipGeneration=4;$script:ipDirty=$false;$script:blacklistInventory='old';$script:state=[pscustomobject]@{config=[pscustomobject]@{legacy_imports=@()}}
$r=New-IPDraftRow @('program-a') '8.8.8.8' 'TCP' 443 'C:\Apps\Game.exe' 'row1';$other=New-IPDraftRow @('program-b') '1.1.1.1' 'UDP' 53 '' 'row2';$script:ipDraft=@($r,$other)
$ipDraftGrid=[pscustomobject]@{SelectedRows=@([pscustomobject]@{Tag=$r})};$restore=[pscustomobject]@{};$restore|Add-Member ScriptMethod PerformClick {$script:calls+=,@{action='restore-button';payload=@{}}}
function Invoke-Click([string]$File,[string]$Variable){
 $tokens=$null;$errors=$null;$a=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $File),[ref]$tokens,[ref]$errors)
 $node=$a.Find({param($n)$n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Value -ceq 'Add_Click' -and $n.Expression -is [Management.Automation.Language.VariableExpressionAst] -and $n.Expression.VariablePath.UserPath -ceq $Variable},$true)
 if($null -eq $node){throw ('missing_click_'+$Variable)};& $node.Arguments[0].ScriptBlock.GetScriptBlock()
}
Invoke-Click 'app/ui-workspace.ps1' 'ipNew';Check ($script:edits.Count -eq 1 -and $null -eq $script:edits[0]) 'add-button-opens-new-draft'
Invoke-Click 'app/ui-workspace.ps1' 'ipEdit';Check ($script:edits.Count -eq 2 -and $script:edits[1].id -ceq 'row1') 'edit-uses-selected-row'
Invoke-Click 'app/ui-workspace.ps1' 'ipBind';Check ($script:bindCalls -eq 1) 'bind-button-dispatches'
Invoke-Click 'app/ui-workspace.ps1' 'rangeAdd';Check ($script:rangeSeed.program_ids[0] -ceq 'program-a' -and $script:rangeSeed.ips[0] -ceq '8.8.8.8') 'range-uses-selected-row-exe-not-global-checks'
Invoke-Click 'app/ui-workspace.ps1' 'ipSave';Check ($script:calls[-1].action -ceq 'workspace_blacklist_save' -and $script:calls[-1].payload.generation -eq 4 -and $script:calls[-1].payload.rows.Count -eq 2) 'save-dispatches-complete-draft-not-native-apply'
Invoke-Click 'app/ui-workspace.ps1' 'ipCheckNative';Check ($script:calls[-1].action -ceq 'workspace_blacklist_inventory' -and $null -eq $script:blacklistInventory) 'check-clears-stale-snapshot-and-reads'
Invoke-Click 'app/ui-workspace.ps1' 'ipRestore';Check ($script:calls[-1].action -ceq 'restore-button') 'restore-uses-explicit-original-confirmation-handler'
Invoke-Click 'app/ui.ps1' 'apply';Check ($script:calls[-1].action -ceq 'native_prepare') 'apply-opens-preview-not-blind-native-write'
Invoke-Click 'app/ui-workspace.ps1' 'ipDelete';Check ($script:ipDirty -and $script:ipDraft.Count -eq 1 -and $script:ipDraft[0].id -ceq 'row2') 'delete-only-selected-draft-no-native-delete'
$result=@{suite='blacklist-production-click-dispatch';passed=$true;assertions=$checks;production_click_handlers_executed_with_mock_dialog_backend=$true;Windows_GUI_executed=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/blacklist-actions-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
