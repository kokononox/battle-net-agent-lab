param(
    [Parameter(Mandatory=$true)][ValidateSet('Init','List','Add','Remove','Plan')][string]$Action,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$Address=''
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Core.ps1')
try {
    if ($Action -in @('Add','Remove') -and [string]::IsNullOrWhiteSpace($Address)) { throw 'tool_address_required' }
    if ($Action -notin @('Add','Remove') -and $Address) { throw 'tool_address_unexpected' }
    $result = switch ($Action) {
        'List' { ReadAllowlistConfig $ConfigPath }
        'Plan' { ReadCompatibilityPlan $ConfigPath }
        default { EditAllowlistFile $ConfigPath $Action $Address }
    }
    ConvertTo-Json -InputObject $result -Depth 8
    exit 0
} catch {
    # Do not print raw provider errors/paths/policy to shared CI logs.
    $code='tool_operation_failed'
    if ($_.Exception.Message -cmatch '^(tool|policy)_[a-z_0-9]{1,80}$') { $code=$_.Exception.Message }
    [Console]::Error.WriteLine($code)
    exit 1
}
