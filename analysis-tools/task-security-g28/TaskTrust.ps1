# Read-only HKLM COM binding + exact binary measurement. Never activate the COM handler.
function Get-SvcBinding($TaskXml){
 $stage='task_xml'
 try {
  if([IntPtr]::Size -ne 8){throw 'native_registry_view_required'}
  $doc=[xml]$TaskXml;$ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
  $ids=@($doc.SelectNodes('/t:Task/t:Actions/t:ComHandler/t:ClassId',$ns));if($ids.Count -ne 1){throw 'com_shape_refused'}
  $id=$ids[0].InnerText;if($id -notmatch '^\{[0-9A-Fa-f-]{36}\}$'){throw 'class_id_refused'}
  $stage='registry_binding';$base='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\'+$id
  foreach($key in @('TreatAs','AutoConvertTo','LocalServer32')){if(Test-Path ($base+'\'+$key)){throw 'com_redirect_refused'}}
  foreach($sid in @('S-1-5-18','S-1-5-19','S-1-5-20')){
   foreach($key in @(('Registry::HKEY_USERS\'+$sid+'\Software\Classes\CLSID\'+$id),('Registry::HKEY_USERS\'+$sid+'_Classes\CLSID\'+$id))){if(Test-Path $key){throw 'user_com_overlay_refused'}}
  }
  $values=[ordered]@{}
  foreach($suffix in @('','\InprocServer32')){
   $k=Get-Item ($base+$suffix) -ErrorAction Stop
   try{foreach($name in @($k.GetValueNames() | Sort-Object)){$value=$k.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);if($value -isnot [string] -or $value.Length -gt 16384){throw 'registry_value_refused'};$values[$suffix+'|'+$name]=@([string]$k.GetValueKind($name),$value)}}finally{$k.Close()}
  }
  $stage='system_image';$raw=[string]$values['\InprocServer32|'][1];$path=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($raw).Trim('"'));$prefix=$env:SystemRoot+'\System32\'
  if(-not $path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($path) -ne '.dll'){throw 'system_dll_required'}
  $file=Get-Item -LiteralPath $path;if($file.Length -gt 33554432){throw 'image_size_bound'}
  $d=$file;while($null -ne $d){if(($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'reparse_refused'};if($d -is [IO.FileInfo]){$d=$d.Directory}else{$d=$d.Parent}}
  $stage='image_hash';$stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$h=[Security.Cryptography.SHA256]::Create()
  try{$sha=[BitConverter]::ToString($h.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose();$stream.Dispose()}
  return @{capture_complete=$true;class_id=$id.ToLowerInvariant();image_path=$path.ToLowerInvariant();file_sha256=$sha;binding_hash=(Hash-Bytes ([Text.Encoding]::UTF8.GetBytes(($values | ConvertTo-Json -Compress -Depth 6))))}
 }catch{$m=$_.Exception.Message;if($m -notmatch '^[a-z_]{1,80}$'){$m='svc_binding_not_supported'};return @{capture_complete=$false;error_code=$m;failure_stage=$stage}}
}
function New-SvcTrust($Snapshot){
 $binding=$Snapshot.svc_binding;$trusted=$false
 if($binding.capture_complete){
  $sig=Get-AuthenticodeSignature -LiteralPath $binding.image_path -ErrorAction Stop
  $trusted=([string]$sig.Status -eq 'Valid' -and $null -ne $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)')
 }
 return @{system_identity=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');captured_before_target=(-not (Test-Path (Join-Path $c.root 'launch-attempted.json')));signature_valid_microsoft=$trusted;binding=$binding}
}
