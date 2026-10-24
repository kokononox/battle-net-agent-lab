param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
# Actual PowerShell arithmetic/constructor behavior, not an imitation of the reported expression.
$area=[pscustomobject]@{Left=100;Top=200};$caught=$false
try{$null=New-Object Drawing.Point($area.Left+8,$area.Top+8)}catch{$caught=($_.Exception.Message -match 'op_Addition')}
Check $caught 'original-constructor-failure-reproduced'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui-layout.ps1'),[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -ceq 'Set-WindowBoundsForArea'},$true)
Check ($null -ne $f) 'production-geometry-helper-found';Invoke-Expression $f.Extent.Text
function Window([int]$Width,[int]$Height){return [pscustomobject]@{Width=$Width;Height=$Height;MinimumSize=(New-Object Drawing.Size(980,720));Size=(New-Object Drawing.Size($Width,$Height));Location=(New-Object Drawing.Point(40,50))}}
$w=Window 1240 860;$area=New-Object Drawing.Rectangle(0,0,1366,768);Set-WindowBoundsForArea $w $area
Check ($w.Location.X -eq 8 -and $w.Location.Y -eq 8) 'oversized-height-position-correct'
Check ($w.Size.Width -eq 1240 -and $w.Size.Height -eq 752) 'oversized-height-fitted'
Check ($w.MinimumSize.Width -eq 900 -and $w.MinimumSize.Height -eq 620) 'valid-minimum-size'
Check ($w.Location -is [Drawing.Point] -and $w.Size -is [Drawing.Size]) 'real-framework-value-types'
$w=Window 2200 1600;$area=New-Object Drawing.Rectangle(100,200,1920,1080);Set-WindowBoundsForArea $w $area
Check ($w.Location.X -eq 108 -and $w.Location.Y -eq 208) 'nonzero-origin-correct'
Check ($w.Size.Width -eq 1904 -and $w.Size.Height -eq 1064) 'both-dimensions-fitted'
$w=Window 1600 1000;$area=New-Object Drawing.Rectangle(-1280,-900,1280,860);Set-WindowBoundsForArea $w $area
Check ($w.Location.X -eq -1272 -and $w.Location.Y -eq -892) 'negative-monitor-origin-correct'
$w=Window 900 620;$area=New-Object Drawing.Rectangle(0,0,1920,1080);Set-WindowBoundsForArea $w $area
Check ($w.Size.Width -eq 900 -and $w.Size.Height -eq 620 -and $w.Location.X -eq 40 -and $w.Location.Y -eq 50) 'fitting-window-not-moved-or-resized'
$w=Window 1240 860;$area=New-Object Drawing.Rectangle(0,0,800,600);Set-WindowBoundsForArea $w $area
Check ($w.MinimumSize.Width -eq 776 -and $w.MinimumSize.Height -eq 576) 'small-screen-minimum-clamped'
Check ($w.Size.Width -eq 784 -and $w.Size.Height -eq 584) 'small-screen-extent-clamped'
$w=Window 1240 860;$bad=$false;try{Set-WindowBoundsForArea $w ([pscustomobject]@{Width=0;Height=600})}catch{$bad=($_.Exception.Message -ceq 'invalid_window_working_area')}
Check $bad 'invalid-area-rejected'
$source=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-layout.ps1'))
Check ($source.Contains('$form.Add_Shown({Fit-WorkingArea $form})') -and $source.Contains('$livePopup.Add_Shown({Fit-WorkingArea $livePopup})')) 'both-shown-handlers-use-fixed-wrapper'
Check ($source.Contains('Set-WindowBoundsForArea $Window $area')) 'wrapper-calls-tested-helper'
$result=@{suite='startup-layout-constructor-regression';passed=$true;assertions=$script:checks;original_error_reproduced=$true;actual_Drawing_Point_Size_constructors_executed=$true;environment='PowerShell 7 Linux; real arithmetic and Drawing value types; fake window and work-area';Windows_GUI_executed=$false;Windows_51_executed=$false;Windows_DPI_verified=$false;firewall_or_hosts_changed=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/layout-geometry-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
