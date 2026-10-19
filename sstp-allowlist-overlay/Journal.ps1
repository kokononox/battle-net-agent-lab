Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function JournalHash([string]$Text) {
 $sha=[Security.Cryptography.SHA256]::Create()
 try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}
function AssertJournalPath([string]$Path) {
 if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\') -or $Path -match '(^|[\\/])\.\.([\\/]|$)') { throw 'journal_path' }
 $full=[IO.Path]::GetFullPath($Path)
 if ($full.Substring(2).Contains(':')) { throw 'journal_path' }
 $item=$full
 while ($item) {
  if (Test-Path -LiteralPath $item) {
   if ((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'journal_reparse' }
  }
  $parent=[IO.Path]::GetDirectoryName($item)
  if ($parent -eq $item) { break };$item=$parent
 }
 return $full
}
function AssertJournalAcl([string]$Root) {
 $acl=Get-Acl -LiteralPath $Root
 if (-not $acl.AreAccessRulesProtected) { throw 'journal_acl_inheritance' }
 $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { throw 'journal_acl_owner' }
 $seen=@{}
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
  $sid=$rule.IdentityReference.Value
  if ($sid -notin @('S-1-5-18','S-1-5-32-544') -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.IsInherited) { throw 'journal_acl_rule' }
  if (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -eq 0 -or ($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -eq 0 -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw 'journal_acl_children' }
  $seen[$sid]=$true
 }
 if ($seen.Count -ne 2) { throw 'journal_acl_missing' }
}
function InitializeJournalRoot([string]$Root) {
 $Root=AssertJournalPath $Root
 if (Test-Path -LiteralPath $Root) { AssertJournalAcl $Root;return $Root }
 $parent=[IO.Path]::GetDirectoryName($Root)
 if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'journal_parent_missing' }
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false)
 $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
 $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
 $acl.SetOwner($admins)
 foreach($sid in @($admins,$system)) {
  $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $acl.AddAccessRule($rule)
 }
 # Windows PowerShell 5.1 uses the ACL-taking overload: no intentionally world-readable creation window.
 [IO.Directory]::CreateDirectory($Root,$acl) | Out-Null
 AssertJournalAcl $Root
 return $Root
}
function OpenJournalLock([string]$Root) {
 $Root=AssertJournalPath $Root;AssertJournalAcl $Root
 $path=AssertJournalPath (Join-Path $Root 'journal.lock')
 return New-Object IO.FileStream($path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function ReadJournalFile([string]$Path) {
 $Path=AssertJournalPath $Path
 if (-not [IO.File]::Exists($Path)) { return $null }
 if ((Get-Item -LiteralPath $Path).Length -gt 1048576) { throw 'journal_size' }
 $e=[IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8) | ConvertFrom-Json
 if ((($e.PSObject.Properties.Name | Sort-Object) -join ',') -ne 'payload,schema,sha256' -or $e.schema -ne 'sstp-journal-envelope-1' -or $e.payload -isnot [string] -or $e.sha256 -cne (JournalHash $e.payload)) { throw 'journal_integrity' }
 $p=$e.payload | ConvertFrom-Json
 if ((($p.PSObject.Properties.Name | Sort-Object) -join ',') -ne 'revision,schema,state' -or $p.schema -ne 'sstp-journal-1' -or $p.revision -isnot [int] -or $p.revision -lt 0 -or $null -eq $p.state) { throw 'journal_schema' }
 return $p
}
function ReadJournalUnlocked([string]$Root) {
 $primary=Join-Path $Root 'journal.json';$backup=Join-Path $Root 'journal.bak'
 $bad=$false
 try { $p=ReadJournalFile $primary } catch { $bad=$true;$p=$null }
 if ($null -ne $p) { return [pscustomobject]@{status='valid';record=$p} }
 try { $b=ReadJournalFile $backup } catch { $b=$null;$bad=$true }
 if ($null -ne $b) { return [pscustomobject]@{status='recovery_required';record=$b} }
 if ($bad) { throw 'journal_unrecoverable' }
 return [pscustomobject]@{status='absent';record=$null}
}
function ReadJournal([string]$Root) {
 $lock=OpenJournalLock $Root
 try { return ReadJournalUnlocked $Root } finally { $lock.Dispose() }
}
function WriteJournal([string]$Root,[int]$ExpectedRevision,$State) {
 $lock=OpenJournalLock $Root;$tmp=$null
 try {
  $current=ReadJournalUnlocked $Root
  if ($current.status -eq 'recovery_required') { throw 'journal_recovery_required' }
  $revision=-1
  if ($current.status -eq 'valid') { $revision=[int]$current.record.revision }
  if ($ExpectedRevision -ne $revision -or $revision -eq [int]::MaxValue) { throw 'journal_revision_conflict' }
  if ($null -eq $State) { throw 'journal_empty_state' }
  $payload=ConvertTo-Json -InputObject ([ordered]@{schema='sstp-journal-1';revision=($revision+1);state=$State}) -Depth 32 -Compress
  $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject ([ordered]@{schema='sstp-journal-envelope-1';payload=$payload;sha256=(JournalHash $payload)}) -Compress))
  if ($bytes.Length -gt 1048576) { throw 'journal_size' }
  $tmp=Join-Path $Root ('journal.next-'+[guid]::NewGuid().ToString('N'))
  $stream=New-Object IO.FileStream($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
  $primary=AssertJournalPath (Join-Path $Root 'journal.json');$backup=AssertJournalPath (Join-Path $Root 'journal.bak')
  if ([IO.File]::Exists($primary)) { [IO.File]::Replace($tmp,$primary,$backup) } else { [IO.File]::Move($tmp,$primary) }
  $tmp=$null
  $readback=ReadJournalFile $primary
  if ($readback.revision -ne ($revision+1)) { throw 'journal_readback' }
  return $readback
 } finally {
  if ($tmp -and [IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) }
  $lock.Dispose()
 }
}
