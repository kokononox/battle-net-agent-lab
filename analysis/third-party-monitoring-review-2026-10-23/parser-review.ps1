$ErrorActionPreference='Stop'
$root='/data/wlab-third-party-monitoring-review'
$results=@()
foreach($dir in @('NORMAL','AGGRESSIVE')) {
 foreach($f in Get-ChildItem (Join-Path $root $dir) -Filter *.ps1 -Recurse) {
  $tokens=$null;$parseErrors=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tokens,[ref]$parseErrors)
  $results += [pscustomobject]@{file=$f.FullName.Substring($root.Length+1);errors=@($parseErrors | ForEach-Object { [pscustomobject]@{line=$_.Extent.StartLineNumber;id=$_.ErrorId} })}
 }
}
$readonlyResult='not tested'
try { $pid=12345; $readonlyResult='unexpected assignment succeeded' }
catch { $readonlyResult=$_.FullyQualifiedErrorId }
[pscustomobject]@{mode='Parser only; supplied scripts were not invoked';pidAssignmentOwnMinimalTest=$readonlyResult;files=$results} | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $root 'parser-review.json')
Write-Output "Readonly PID minimal test: $readonlyResult"
$results | Where-Object {$_.errors.Count -gt 0} | ForEach-Object {Write-Output ($_.file+': '+($_.errors | ConvertTo-Json -Compress))}
