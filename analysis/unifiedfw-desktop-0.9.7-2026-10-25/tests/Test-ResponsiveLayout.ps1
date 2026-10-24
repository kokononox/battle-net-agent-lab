param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui-polish.ps1'),[ref]$tokens,[ref]$errors)
foreach($name in @('Get-NavigationMetrics','Get-DialogExtent')){$f=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true);Check ($null -ne $f) $name;Invoke-Expression $f.Extent.Text}
foreach($w in @(800,980,1240,1920)){
 foreach($h in @(17,22,34)){
  $v=Get-NavigationMetrics $w $h
  Check ($v.sidebar -ge 222 -and $v.sidebar -le 330 -and $v.button -lt $v.sidebar) 'sidebar-contained'
  Check ($v.counts -ge $h+8 -and $v.status -ge $h+12 -and $v.button_height -ge 2*$h+12) 'font-aware-heights'
  Check ($v.rtl -ceq 'Yes' -and $v.alignment -ceq 'MiddleLeft') 'RTL-logical-compensation'
 }
}
foreach($size in @(@(1366,768),@(800,600),@(1920,1080))){
 $e=Get-DialogExtent 1200 1000 $size[0] $size[1]
 Check ($e.width -le $size[0]-24 -and $e.height -le $size[1]-24) 'dialog-within-work-area'
 Check ($e.minimum_width -le $e.width -and $e.minimum_height -le $e.height) 'dialog-minimum-not-overflow'
}
$e=Get-DialogExtent 680 300 1920 1080;Check ($e.width -eq 680 -and $e.height -eq 300) 'small-dialog-not-enlarged-to-main-window-minimum'
. (Join-Path $Root 'app/workspace-model.ps1')
$p=[pscustomobject]@{id='a'*24;path='C:\Games\Wow.exe'};$other=[pscustomobject]@{id='b'*24;path='C:\Other\Wow.exe'}
$row=[pscustomobject]@{program_path=$p.path;protocol='TCP';remote_port=3724;remote_ip='8.8.8.8'};$r2=$row.PSObject.Copy();$r2.remote_ip='1.1.1.1'
$s=Get-ObservedPortRangeSeed @($row,$r2) @($p,$other)
Check ($s.program_ids.Count -eq 1 -and $s.program_ids[0] -ceq $p.id) 'exact-observed-EXE-not-checked-others'
Check ($s.ips.Count -eq 2 -and $s.protocol -ceq 'TCP' -and $s.port -eq 3724) 'observed-IP-set-and-explicit-editable-transport'
$s=Get-ObservedPortRangeSeed @($row,$row) @($p);Check ($s.ips.Count -eq 1) 'deduplicate-observed-IP'
$r2.protocol='UDP';$s=Get-ObservedPortRangeSeed @($row,$r2) @($p);Check ($s.protocol -ceq '') 'mixed-protocol-requires-choice'
$failed=$false;$r2.program_path=$other.path;try{Get-ObservedPortRangeSeed @($row,$r2) @($p,$other)|Out-Null}catch{$failed=$true};Check $failed 'mixed-EXE-selection-refused'
$failed=$false;try{Get-ObservedPortRangeSeed @($row) @($other)|Out-Null}catch{$failed=$true};Check $failed 'unregistered-not-adopted'
$failed=$false;try{Get-ObservedPortRangeSeed @() @($p)|Out-Null}catch{$failed=$true};Check $failed 'no-selection-no-guess'
$source=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-polish.ps1'))
Check ($source.Contains("`$footer.Dock='Bottom'") -and $source.Contains('$main.Controls.Remove($footer)')) 'footer-outside-percent-table'
Check ($source.Contains("`$script:desktopNavigationPanel.AutoScroll=`$true") -and $source.Contains('Sync-DesktopLayout')) 'scrollable-responsive-navigation'
Check ($source.Contains('نمایش کامل پیام')) 'full-status-action'
$result=@{suite='responsive-layout-and-observed-port-seed';passed=$true;assertions=$script:checks;Windows_GUI_executed=$false;Windows_DPI_verified=$false;environment='PowerShell 7 Linux; pure sizing/binding helpers and source integration checks'}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/responsive-layout-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
