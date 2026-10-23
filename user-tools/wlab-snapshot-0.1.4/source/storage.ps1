# Output follows the selected executable's local drive letter, never launcher/CWD.
# Keep cache and the cross-version capture lock in LocalAppData.
function Get-WLabGameOutputRoot([string]$gamePath){
if([string]::IsNullOrWhiteSpace($gamePath) -or $gamePath -notmatch '^([A-Za-z]):[\\/]'){
throw 'Selected Wow.exe must have an absolute local drive path. No fallback output drive is used.'
}
return ($Matches[1].ToUpperInvariant()+':\WLabSnapshot')
}
function Get-WLabOutputFreeBytes([string]$runPath){
if($runPath -notmatch '^([A-Za-z]):[\\/]'){throw 'Output path has no local drive letter.'}
$drive=Get-PSDrive -Name $Matches[1] -ErrorAction Stop
if($null -eq $drive.Free){throw 'Cannot determine output drive free space.'}
return [long]$drive.Free
}
