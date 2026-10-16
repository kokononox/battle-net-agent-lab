# Read-only UI Automation, ONLY HWND/PID pairs supplied by native target enumeration.
# No Value/Text patterns, screenshots, input, focus, selection or navigation actions.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$cfg = $env:BNET_LAB_UIA_CONFIG | ConvertFrom-Json
$targets = @($cfg.targets)
$items = New-Object 'System.Collections.Generic.List[object]'
$truncated = $false
$errors = 0
$watch = [Diagnostics.Stopwatch]::StartNew()
$walker = [System.Windows.Automation.TreeWalker]::RawViewWalker
foreach ($target in $targets) {
    if ($watch.ElapsedMilliseconds -gt 3000 -or $items.Count -ge 64) { $truncated=$true; break }
    try {
        $root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr][long]$target.hwnd)
        $stack = New-Object System.Collections.Stack
        $stack.Push(@{element=$root; depth=0})
        while ($stack.Count -gt 0) {
            if ($watch.ElapsedMilliseconds -gt 3000 -or $items.Count -ge 64) { $truncated=$true; break }
            $entry = $stack.Pop()
            try {
                $element = $entry.element
                $current = $element.Current
                # Never enumerate another application's descendants or read its name.
                if ($current.ProcessId -ne [int]$target.pid) { continue }
                $kind = [string]$current.ControlType.ProgrammaticName
                if ($kind.StartsWith('ControlType.')) { $kind=$kind.Substring(12) }
                if ($kind -notin @($cfg.types)) { $kind='Other' }
                $label='not_read'; $markers=@()
                if (-not $current.IsPassword -and -not $current.IsOffscreen -and $kind -in @($cfg.readable_types)) {
                    $raw = [string]$current.Name
                    if ($raw.Length -gt 512) { $raw=$raw.Substring(0,512) }
                    $name = (($raw.Replace('&','').Trim() -replace '\s+',' ')).ToLowerInvariant()
                    $property = $cfg.labels.PSObject.Properties[$name]
                    if ($null -ne $property) { $label=[string]$property.Value } else { $label='unrecognized' }
                    foreach ($marker in @($cfg.markers)) {
                        $pattern='\b'+[regex]::Escape([string]$marker)+'\b'
                        if ($marker -eq 'sign_in') { $pattern='\bsign[ _-]?in\b' }
                        if ([regex]::IsMatch($name,$pattern)) { $markers+=([string]$marker) }
                    }
                    $raw=$null; $name=$null
                }
                $items.Add(@{pid=[int]$target.pid; depth=[int]$entry.depth; control_type=$kind;
                    enabled=[bool]$current.IsEnabled; offscreen=[bool]$current.IsOffscreen;
                    password=[bool]$current.IsPassword; label=$label; markers=@($markers)})
                if ($entry.depth -ge 6) { $truncated=$true; continue }
                $child=$walker.GetFirstChild($element)
                $siblings=0
                while ($null -ne $child) {
                    if ($watch.ElapsedMilliseconds -gt 3000 -or $stack.Count -ge 64 -or $siblings -ge 64) { $truncated=$true; break }
                    $stack.Push(@{element=$child;depth=([int]$entry.depth+1)})
                    $child=$walker.GetNextSibling($child);$siblings++
                }
            } catch { $errors++ }
        }
    } catch { $errors++ }
}
# This is the only stdout payload; no provider strings/error messages leave the helper.
@{status='ok'; elements=@($items.ToArray()); truncated=[bool]$truncated;
    errors=[int]$errors; top_windows_requested=[int]$targets.Count} | ConvertTo-Json -Depth 8 -Compress
