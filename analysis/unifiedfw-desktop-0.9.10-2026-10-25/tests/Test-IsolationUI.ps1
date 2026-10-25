param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Assert($b,$m){$script:checks++;if(-not $b){throw $m}}
. (Join-Path $Root 'app/policy-mode-model.ps1')
$script:calls=@();$script:consent=$false;$script:job=$null;$script:saveChecks=0;$script:whiteEdits=@()
function TryOp([scriptblock]$b){& $b}
function AssertSaved{$script:saveChecks++}
function Generation{7}
function BeginOp($Action,$Payload){$script:calls+=,@{action=$Action;payload=$Payload}}
function ConfirmText($Title,$Text,$Expected){$script:lastConfirmation=$Text;return $script:consent}
function Open-WhiteRange([bool]$Edit=$false){$script:whiteEdits+=,$Edit}
function Load-Function($File,$Name){$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $File),[ref]$t,[ref]$e);$n=$ast.Find({param($x)$x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -ceq $Name},$true);. ([scriptblock]::Create('function script:'+ $Name+$n.Extent.Text.Substring(('function '+$Name).Length)))}
function Click($Variable){$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui-isolation.ps1'),[ref]$t,[ref]$e);$n=$ast.Find({param($x)$x -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $x.Member.Value -ceq 'Add_Click' -and $x.Expression -is [Management.Automation.Language.VariableExpressionAst] -and $x.Expression.VariablePath.UserPath -ceq $Variable},$true);& $n.Arguments[0].ScriptBlock.GetScriptBlock()}
Click 'isoApply';Assert ($script:saveChecks -eq 1) 'must save before prepare';Assert ($script:calls[-1].action -ceq 'isolation_prepare') 'apply begins read-only preparation';Assert ($script:calls[-1].payload.generation -eq 7) 'current generation'
Click 'isoStatus';Assert ($script:calls[-1].action -ceq 'isolation_status') 'status action'
$count=$script:calls.Count;Click 'isoRestore';Assert ($script:calls.Count -eq $count) 'restore cancel no backend';$script:consent=$true;Click 'isoRestore';Assert ($script:calls[-1].action -ceq 'isolation_restore') 'restore consent';Assert ($script:calls[-1].payload.confirmation -ceq 'RESTORE ISOLATION') 'internal token preserved no typing'
Click 'whiteAdd';Click 'whiteEdit';Assert ($script:whiteEdits.Count -eq 2 -and -not $script:whiteEdits[0] -and $script:whiteEdits[1]) 'white add/edit wired'
Load-Function 'app/ui-isolation.ps1' 'Confirm-IsolationPlan'
$plan=[pscustomobject]@{generation=7;review_digest=('a'*64);review=[pscustomobject]@{connection='vpn';vpn='synthetic';quarantine_allow_count=0;whitelist=@();overlaps=@();no_leak_certified=$false}}
$script:consent=$false;$count=$script:calls.Count;Confirm-IsolationPlan $plan;Assert ($script:calls.Count -eq $count) 'cancel native apply';$script:consent=$true;Confirm-IsolationPlan $plan;Assert ($script:calls[-1].action -ceq 'isolation_apply') 'explicit native apply';Assert ($script:calls[-1].payload.review_digest -ceq ('a'*64)) 'fresh review token';Assert ($script:lastConfirmation -match 'SYSTEM' -and $script:lastConfirmation -match 'DHCP') 'scope and control exceptions warned'
Load-Function 'app/ui-isolation.ps1' 'Accept-IsolationResult'
$status=[pscustomobject]@{Text=''};$tabs=[pscustomobject]@{SelectedTab=''};$policyTab='policy'
Accept-IsolationResult ([pscustomobject]@{isolation_status=[pscustomobject]@{phase='armed';health='baseline_only';configuration_verified=$true;settings_match_active=$false}})
Assert ($tabs.SelectedTab -ceq 'policy') 'result keeps policy';Assert ($status.Text -match 'یکسان نیست') 'saved not applied warning'
# Ensure range conversion replaces only on accepted preview, not when opening/canceling dialog.
$workspace=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-workspace.ps1'))
Assert ($workspace -match 'range_replace_id=\$replace') 'replacement metadata retained';Assert ($workspace -match "DialogResult='Retry'") 'edit exposes range conversion';Assert ($workspace -match 'Merge-IPDraft \$kept \$new') 'accepted conversion removes old row not duplicate'
$result=@{suite='isolation-whitelist-production-click-handlers';assertions=$script:checks;passed=$true;Windows_GUI_executed=$false};[IO.File]::WriteAllText((Join-Path $Root 'evidence/isolation-ui-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
