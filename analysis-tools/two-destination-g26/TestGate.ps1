$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$cases=@(
 @{name='clear_components';reg=0;outside=0;bits=0;complete=$true;expected=$false},
 @{name='unclassified_task';reg=1;outside=0;bits=0;complete=$true;expected=$true},
 @{name='external_target';reg=0;outside=1;bits=0;complete=$true;expected=$true},
 @{name='new_bits_definition';reg=0;outside=0;bits=1;complete=$true;expected=$true},
 @{name='modified_bits_definition';reg=0;outside=0;bits=2;complete=$true;expected=$true},
 @{name='incomplete_bits_history';reg=0;outside=0;bits=0;complete=$false;expected=$true},
 @{name='invalid_negative_count';reg=-1;outside=0;bits=0;complete=$true;expected=$true}
)
$r=@();foreach($c in $cases){$got=Test-RecoveryRefusal $c.reg $c.outside $c.bits $c.complete;$r+=@{name=$c.name;passed=($got -eq $c.expected);expected_refused=$c.expected;actual_refused=$got}}
$ok=@($r | Where-Object {-not $_.passed}).Count -eq 0
New-Item -ItemType Directory -Force output | Out-Null
@{all_passed=$ok;case_count=$r.Count;level='in_memory_same_decision_function_used_by_recovery';cases=$r} | ConvertTo-Json -Depth 6 | Set-Content output/g19-gate-tests.json -Encoding UTF8
if(-not $ok){throw 'recovery_gate_unit_tests_failed'}
