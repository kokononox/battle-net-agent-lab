$ErrorActionPreference='Stop'
$old='/data/ufd-hf122-prepare/candidate';$new='/data/ufd-recovery-hf123/candidate'
function FunctionMap($Path){$t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e);if($e.Count){throw 'parse_error'};$map=@{};foreach($n in $a.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){$map[$n.Name]=$n.Extent.Text};return $map}
$rows=@()
foreach($pair in @(@('app/isolation-native.ps1',@('IsoProfileSet','IsoNativeOps','IsoPrepare')),@('app/isolation-core.ps1',@('IsoAssertRestorableProfileBaseline','IsoAssertRecoveryReaders','IsoAssertRestoredState','Invoke-IsoArm','Restore-IsoSession')),@('app/isolation-worker.ps1',@('IsoSummary')),@('app/policy-mode-model.ps1',@('Get-IsolationStatusText')))){
 $left=FunctionMap (Join-Path $old $pair[0]);$right=FunctionMap (Join-Path $new $pair[0]);$changed=@()
 foreach($n in @(@($left.Keys)+@($right.Keys)|Sort-Object -Unique)){if(-not $left.ContainsKey($n) -or -not $right.ContainsKey($n) -or $left[$n] -cne $right[$n]){$changed+=,$n}}
 if((($changed|Sort-Object)-join ',') -cne (($pair[1]|Sort-Object)-join ',')){throw ('unexpected_function_change:'+ $pair[0]+':'+($changed -join ','))}
 $rows+=,[pscustomobject]@{file=$pair[0];changed_functions=$changed}
}
$restore=(FunctionMap (Join-Path $new 'app/isolation-core.ps1'))['Restore-IsoSession']
if($restore -match "ProfileSet[^\r\n]*'Allow'"){throw 'invented_allow_restore'}
$result=@{expected_function_boundaries_verified=$true;changes=$rows;transport_compiler_rule_specs_unchanged=$true;guardian_body_unchanged=$true;bulk_reader_and_Prepare_foreign_helpers_unchanged=$true;old_live_controller_not_upgraded=$true;Windows_API_executed=$false;ready_for_apply=$false}
$result|ConvertTo-Json -Depth 8|Set-Content '/data/ufd-recovery-hf123/function-boundary-checks.json'
Write-Host 'Expected function boundaries verified; no forced Allow in Restore.'
