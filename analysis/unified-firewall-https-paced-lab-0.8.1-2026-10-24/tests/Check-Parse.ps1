param([string]$Root=(Join-Path $PSScriptRoot '..'))
$ErrorActionPreference='Stop'
$result=@()
foreach($f in @(Get-ChildItem (Join-Path $Root 'app') -Filter '*.ps1')+@(Get-ChildItem (Join-Path $Root 'tests') -Filter '*.ps1')+@(Get-ChildItem (Join-Path $Root 'experimental') -Filter '*.ps1')+@(Get-ChildItem (Join-Path $Root 'lab') -Filter '*.ps1')){
 $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tokens,[ref]$errors)
 if(@($errors).Count -gt 0){throw ('parse_failed: '+$f.Name+': '+($errors.Message -join '; '))}
 $result+=,[pscustomobject]@{file=$f.Name;passed=$true}
}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/parser-tests.json'),(ConvertTo-Json -InputObject $result))
[pscustomobject]@{parsed=$result.Count;passed=$true;windows_gui_executed=$false}|ConvertTo-Json -Compress
