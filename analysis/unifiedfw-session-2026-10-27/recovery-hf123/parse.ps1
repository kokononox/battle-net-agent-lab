param([string]$Root)
$ErrorActionPreference='Stop';$rows=@(Get-ChildItem $Root -Filter '*.ps1' -Recurse|ForEach-Object{
 $tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors)
 [pscustomobject]@{file=$_.FullName.Substring($Root.Length+1);passed=($errors.Count -eq 0);errors=@($errors|ForEach-Object{$_.Message})}
})
$rows|ConvertTo-Json -Depth 5|Set-Content '/data/ufd-recovery-hf123/parse-results.json'
@{files=$rows.Count;passed=@($rows|Where-Object{$_.passed}).Count}|ConvertTo-Json -Compress
if(@($rows|Where-Object{-not $_.passed}).Count){exit 1}
