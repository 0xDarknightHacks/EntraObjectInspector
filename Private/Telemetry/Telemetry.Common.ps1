function Get-InspectorTelemetryTimestamp {
    (Get-Date).ToUniversalTime().ToString('o')
}

function Get-InspectorTelemetryMemoryMB {
    try {
        return [math]::Round(
            [System.Diagnostics.Process]::GetCurrentProcess().WorkingSet64 / 1MB,
            2
        )
    }
    catch {
        return $null
    }
}

function Get-InspectorTelemetryEndpointPattern {
    [CmdletBinding()]
    param (
        [string]$Uri
    )

    if ([string]::IsNullOrWhiteSpace($Uri)) {
        return 'Unknown'
    }

    try {
        $parsed = [uri]$Uri
        $path = $parsed.AbsolutePath -replace '/[0-9a-fA-F-]{36}', '/{id}'
        $path = $path -replace '\([^)]*\)', '({key})'
        return $path
    }
    catch {
        return ($Uri -split '\?')[0]
    }
}

function Get-InspectorTelemetryHost {
    [CmdletBinding()]
    param (
        [string]$Uri
    )

    try {
        return ([uri]$Uri).Host
    }
    catch {
        return $null
    }
}

function Add-InspectorGraphTransportTelemetryRecord {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Telemetry,

        [Parameter(Mandatory)]
        [ValidateSet('Single', 'Batch')]
        [string]$TransportKind,

        [ValidateRange(0, 20)]
        [int]$LogicalSubrequestCount = 1
    )

    $currentRuntimeTelemetry =
        Get-Variable `
            -Name 'InspectorCurrentRuntimeTelemetry' `
            -Scope Script `
            -ValueOnly `
            -ErrorAction SilentlyContinue

    if ($null -ne $currentRuntimeTelemetry) {
        $Telemetry = $currentRuntimeTelemetry
    }

    if ($null -eq $Telemetry) {
        return
    }

    $summaryProperty = $Telemetry.PSObject.Properties['GraphTransportSummary']
    if ($null -eq $summaryProperty -or $null -eq $summaryProperty.Value) {
        return
    }

    $summary = $summaryProperty.Value
    $timestamp = Get-InspectorTelemetryTimestamp
    $summary.TotalHttpRequests++

    if ($TransportKind -eq 'Batch') {
        $summary.BatchHttpRequests++
        $summary.BatchSubrequestExecutions += $LogicalSubrequestCount
    }
    else {
        $summary.SingleHttpRequests++
    }

    if (-not $summary.FirstHttpRequestAt) {
        $summary.FirstHttpRequestAt = $timestamp
    }
    $summary.LastHttpRequestAt = $timestamp
}
