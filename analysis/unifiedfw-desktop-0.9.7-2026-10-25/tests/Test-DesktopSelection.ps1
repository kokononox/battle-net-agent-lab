param([string]$Root=(Join-Path $PSScriptRoot '..'))
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse'}
foreach($name in @('CheckedIds','Counts')){
 $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 . ([scriptblock]::Create($node.Extent.Text))
}
$script:state=[pscustomobject]@{config=[pscustomobject]@{programs=@([pscustomobject]@{id='A'},[pscustomobject]@{id='B'},[pscustomobject]@{id='C'})}}
$programGrid=[pscustomobject]@{IsCurrentCellDirty=$false;Rows=@([pscustomobject]@{Tag='A'},[pscustomobject]@{Tag='C'})}
$programGrid|Add-Member ScriptMethod EndEdit {$true}
$counts=[pscustomobject]@{Text=''}
$script:checks=@{A=$true;B=$true;stale=$true}
$ids=CheckedIds
if($ids.Count -ne 2 -or $ids[0] -cne 'A' -or $ids[1] -cne 'B'){throw 'stable id snapshot'}
Counts
if($counts.Text -notmatch 'کل: 3' -or $counts.Text -notmatch 'تیک‌خورده: 2' -or $counts.Text -notmatch 'فیلتر: 1'){throw ('hidden count: '+$counts.Text)}
$script:checks=@{};$ids=CheckedIds;if($ids.Count -ne 0){throw 'empty snapshot'};Counts
if($counts.Text -notmatch 'تیک‌خورده: 0'){throw 'empty count'}
$script:checks=@{C=$true};$programGrid.Rows=@([pscustomobject]@{Tag='C'},[pscustomobject]@{Tag='A'});$ids=CheckedIds
if($ids.Count -ne 1 -or $ids[0] -cne 'C'){throw 'sorted id snapshot'}
@{passed=$true;cases=4;environment='PowerShell 7 Linux; extracted pure functions with fake grid';native_WinForms_executed=$false}|ConvertTo-Json -Compress
