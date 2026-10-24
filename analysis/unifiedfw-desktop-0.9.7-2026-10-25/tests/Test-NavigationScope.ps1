param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
# Reproduce the actual read-only collection behavior without Windows/WinForms.
$readonly=[Collections.ArrayList]::ReadOnly((New-Object Collections.ArrayList))
$menu=[pscustomobject]@{Controls=$readonly}
$oldFailed=$false;try{$menu.Controls.Add([pscustomobject]@{Text='old fixture'})}catch{$oldFailed=([string]$_.Exception.Message -match 'read.only')}
Check $oldFailed 'original-read-only-Add-reproduced'
$script:desktopNavigationPanel=[pscustomobject]@{Controls=(New-Object Collections.Generic.List[object])}
$script:menuEntries=New-Object Collections.Generic.List[object]
function Button([string]$Caption){
 $button=[pscustomobject]@{Text=$Caption;AutoSize=$true;Size=[Drawing.Size]::Empty;MinimumSize=[Drawing.Size]::Empty;TextAlign='';Tag=$null;RightToLeft=''}
 $button|Add-Member ScriptMethod Add_Click {param($Callback)};return $button
}
function New-VerticalTools {return [pscustomobject]@{Visible=$true;Name='fixture tools'}}
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui-layout.ps1'),[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -ceq 'New-MenuEntry'},$true)
Check ($null -ne $f) 'production-function-extracted';Invoke-Expression $f.Extent.Text
$page=[pscustomobject]@{Text='audit page'}
$tools=New-MenuEntry $page 'audit fixture'
Check ($script:desktopNavigationPanel.Controls.Count -eq 2) 'late-entry-uses-navigation-not-shadowed-menu'
Check ($script:menuEntries.Count -eq 1 -and $script:menuEntries[0].page -eq $page) 'entry-retains-page-binding'
Check ($script:menuEntries[0].button.Tag -eq $page -and $tools -eq $script:menuEntries[0].tools) 'click-target-and-tools-preserved'
Check ($menu.Controls.Count -eq 0) 'readonly-context-collection-not-touched'
# Mimic later dot-sourced scripts and function-local dynamic shadowing.
$menu=[pscustomobject]@{Controls=$readonly};$observedContextMenu=[pscustomobject]@{Controls=$readonly}
function Nested-Registration { $desktopNavigationPanel=[pscustomobject]@{Controls=$readonly};$menu=$desktopNavigationPanel;return (New-MenuEntry $page 'second audit fixture') }
$null=Nested-Registration
Check ($script:desktopNavigationPanel.Controls.Count -eq 4 -and $script:menuEntries.Count -eq 2) 'explicit-script-scope-beats-dynamic-local-shadow'
$removed=$script:desktopNavigationPanel.Controls.Remove($tools)
Check ($removed -and $script:desktopNavigationPanel.Controls.Count -eq 3) 'workspace-removal-targets-mutable-navigation'
foreach($n in @('ui-layout.ps1','ui-workspace.ps1','ui-polish.ps1')){
 $s=[IO.File]::ReadAllText((Join-Path $Root ('app/'+$n)))
 Check ($s -notmatch '\$menu\b') ('no-generic-menu-navigation-reference-'+$n)
 Check ($s.Contains('$script:desktopNavigationPanel')) ('scoped-navigation-reference-'+$n)
}
foreach($n in @('ui-context.ps1','ui-transfer.ps1')){
 $s=[IO.File]::ReadAllText((Join-Path $Root ('app/'+$n)))
 Check ($s -notmatch '\$menu\b' -and $s.Contains('$observedContextMenu')) ('distinct-context-menu-variable-'+$n)
}
$s=[IO.File]::ReadAllText((Join-Path $Root 'app/ui.ps1'))
Check ($s -notmatch '\$menu\b' -and $s.Contains('$observedContextMenuToDispose.Dispose()')) 'cleanup-does-not-reassign-navigation'
$contextIndex=$s.IndexOf("'ui-context.ps1'");$auditIndex=$s.IndexOf("'ui-denials.ps1'")
Check ($contextIndex -gt 0 -and $auditIndex -gt $contextIndex) 'production-late-audit-order-covered'
$result=@{suite='navigation-scope-startup-regression';passed=$true;assertions=$script:checks;original_readonly_exception_reproduced=$true;production_New_MenuEntry_executed_with_fake_controls=$true;Windows_GUI_executed=$false;environment='PowerShell 7 Linux; actual read-only .NET collection and extracted production function with mock controls'}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/navigation-scope-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
