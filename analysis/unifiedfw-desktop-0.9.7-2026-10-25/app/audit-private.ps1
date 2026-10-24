# Separate protected audit receipt; unchanged native journal helpers are reused only for ACL-safe files.
function Get-AuditPrivateRoot([bool]$Create){
 $root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'UnifiedFirewallAudit-096';UAssertPath $root
 if(-not [IO.Directory]::Exists($root)){
  if(-not $Create){return $root}
  $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
  $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544');$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18');$acl.SetOwner($admins)
  foreach($sid in @($admins,$system)){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)}
  $dir=New-Object IO.DirectoryInfo($root);$dir.Create($acl)
 }
 UAssertPath $root;$actual=Get-Acl -LiteralPath $root -ErrorAction Stop
 if(-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'unsafe_journal_acl_or_owner'}
 $rules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));$seen=@{}
 foreach($r in $rules){if($r.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18') -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne 'FullControl' -or [string]$r.InheritanceFlags -ne 'ContainerInherit, ObjectInherit' -or [string]$r.PropagationFlags -ne 'None'){throw 'unsafe_journal_access_rule'};$seen[$r.IdentityReference.Value]=$true}
 if($seen.Count -ne 2){throw 'incomplete_journal_acl'}
 # Refuse unsafe pre-existing children; do not silently repair their permissions.
 foreach($child in @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)){
  UAssertPath $child.FullName;if($child.PSIsContainer){throw 'unexpected_journal_subdirectory'}
  $ca=Get-Acl -LiteralPath $child.FullName -ErrorAction Stop
  if($ca.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'unsafe_journal_file_owner'}
  foreach($r in $ca.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($r.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18') -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne 'FullControl'){throw 'unsafe_journal_file_acl'}}
 }
 return $root
}
