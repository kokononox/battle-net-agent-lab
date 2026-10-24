param([string]$Root=(Join-Path $PSScriptRoot '..'))
$ErrorActionPreference='Stop'
$out=@()
foreach($file in @(Get-ChildItem -LiteralPath (Join-Path $Root 'src') -Filter '*.ps1')+@(Get-ChildItem -LiteralPath (Join-Path $Root 'tests') -Filter '*.ps1')){
 $tokens=$null;$errors=$null
 $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
 if(@($errors).Count -gt 0){throw ('parse_failed: '+$file.Name+': '+($errors.Message -join '; '))}
 $out+=,[pscustomobject]@{file=$file.Name;passed=$true}
}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/parser-tests.json'),(ConvertTo-Json -InputObject $out))
[pscustomobject]@{parsed=$out.Count;passed=$true}|ConvertTo-Json -Compress
