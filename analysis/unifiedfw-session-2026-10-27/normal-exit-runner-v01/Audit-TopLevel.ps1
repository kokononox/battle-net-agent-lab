$ErrorActionPreference='Stop'
$root='/data/ufd-normal-exit-runner-v01/package/NORMAL-EXIT-REVIEW-01'
$result=@(foreach($file in Get-ChildItem $root -Filter '*.ps1'){
 $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$t,[ref]$e)
 if($e.Count){throw 'parse'}
 $calls=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true))
 $top=@(foreach($call in $calls){$p=$call.Parent;$inFunction=$false;while($p){if($p -is [Management.Automation.Language.FunctionDefinitionAst]){$inFunction=$true;break};$p=$p.Parent};if(-not $inFunction){$call.GetCommandName()}})
 $setters=@(foreach($call in $calls){if($call.GetCommandName() -match '^(Set-NetFirewallProfile|New-NetFirewallRule|Set-NetFirewallRule|Remove-NetFirewallRule|Enable-NetFirewallRule|Disable-NetFirewallRule)$'){[pscustomobject]@{name=$call.GetCommandName();line=$call.Extent.StartLineNumber}}})
 [pscustomobject]@{file=$file.Name;top_level_command_names=$top;policy_mutator_definition_calls=$setters}
})
$result|ConvertTo-Json -Depth 8|Set-Content '/data/ufd-normal-exit-runner-v01/top-level-audit.json'
$result|ForEach-Object{Write-Host ($_.file+': top-level='+($_.top_level_command_names -join ',')+'; mutator calls anywhere='+$_.policy_mutator_definition_calls.Count)}
