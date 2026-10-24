param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$checks=0
function Check([bool]$b,[string]$n){if(-not $b){throw ('test_failed: '+$n)};$script:checks++}
function Reject($Action,[string]$Name){$failed=$false;try{& $Action}catch{$failed=$true};Check $failed $Name}
. (Join-Path $Root 'app/workspace-model.ps1')
$a=New-IPDraftRow @() '::ffff:8.232.70.12' '' 0 'C:\Apps\Game.exe' 'a'
$b=New-IPDraftRow @() '127.0.0.1' 'TCP' 53473 'C:\Apps\Other.exe' 'b'
$c=New-IPDraftRow @('unchanged') '8.8.8.8' 'UDP' 53 '' 'c'
$programs=@([pscustomobject]@{id='game';path='c:\apps\GAME.EXE'},[pscustomobject]@{id='other';path='C:\Apps\Other.exe'},[pscustomobject]@{id='unrelated';path='C:\Apps\Else.exe'})
$before=ConvertTo-Json @($a,$b,$c) -Depth 8
$x=Bind-ObservedIPDrafts @($a,$b,$c) @('a','b') $programs
Check ($x.Count -eq 3) 'row-count-preserved'
Check ($x[0].program_ids.Count -eq 1 -and $x[0].program_ids[0] -ceq 'game') 'case-insensitive-exact-path'
Check ($x[1].program_ids[0] -ceq 'other') 'each-row-bound-to-own-exe'
Check ($x[2].program_ids[0] -ceq 'unchanged') 'unselected-unchanged'
Check ($x[0].target -ceq $a.target -and $x[1].target -ceq '127.0.0.1') 'no-address-rewrite'
Check ($x[0].port -eq 0 -and $x[0].protocol -ceq '') 'no-dns-transport-guess'
Check ($x[1].port -eq 53473 -and $x[1].protocol -ceq 'TCP') 'observed-transport-preserved'
Check ($before -ceq (ConvertTo-Json @($a,$b,$c) -Depth 8)) 'input-unmodified'
Reject {Bind-ObservedIPDrafts @($a,$b) @('a','b') @($programs[0])} 'missing-second-exe-atomic-reject'
Reject {Bind-ObservedIPDrafts @($a) @('a') @($programs[0],$programs[0])} 'ambiguous-path-rejected'
Reject {Bind-ObservedIPDrafts @($a) @('missing') $programs} 'stale-row-rejected'
Reject {Bind-ObservedIPDrafts @($a) @() $programs} 'empty-selection-rejected'
Reject {Bind-ObservedIPDrafts @($c) @('c') $programs} 'manual-row-needs-explicit-edit'
$ui=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-workspace.ps1'))
Check (-not $ui.Contains('@(CheckedIds)')) 'no-nested-checked-id-array'
Check ($ui.Contains('draft_bind_ids=@($ids)')) 'async-binds-only-explicit-selection'
Check ($ui.Contains("if($"+'protocol.SelectedIndex -eq 0 -or $number.Value -lt 1')) 'no-zero-port-in-range'
@{passed=$true;assertions=$checks;environment='PowerShell 7 Linux; production pure binding model';Windows_GUI_executed=$false}|ConvertTo-Json|Set-Content (Join-Path $Root 'evidence/draft-binding-tests.json')
Write-Output ('PASS '+$checks)
