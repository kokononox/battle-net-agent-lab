
param([string]$Root)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'src/Ranges.ps1')
$cases=ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $Root 'evidence/random-inputs.json')))
$out=@();foreach($c in $cases){$out+=,[pscustomobject]@{bits=$c.bits;allowed=@($c.allowed);blocked_cidrs=@(IntervalsToCidrs (ComplementAddresses @($c.allowed) $c.bits))}}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/random-output.json'),(ConvertTo-Json -InputObject $out -Depth 8))
