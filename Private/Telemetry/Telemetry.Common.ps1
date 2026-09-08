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

function Get-InspectorTelemetryProcessPeakMemoryMB {
    [CmdletBinding()]
    param ()

    try {
        $process = [System.Diagnostics.Process]::GetCurrentProcess()
        $process.Refresh()
        return [math]::Round($process.PeakWorkingSet64 / 1MB, 2)
    }
    catch {
        return $null
    }
}

function Update-InspectorTelemetryMemorySample {
    [CmdletBinding()]
    param (
        [AllowNull()][object]$Telemetry
    )

    if ($null -eq $Telemetry) {
        return
    }

    $memorySummary = $Telemetry.PSObject.Properties['MemorySummary']
    if ($null -eq $memorySummary -or $null -eq $memorySummary.Value) {
        return
    }

    $summary = $memorySummary.Value
    $workingSet = Get-InspectorTelemetryMemoryMB
    $processPeak = Get-InspectorTelemetryProcessPeakMemoryMB
    $timestamp = Get-InspectorTelemetryTimestamp

    if ($null -ne $workingSet) {
        $currentObservedPeak = $summary.PSObject.Properties['RunObservedWorkingSetPeakMB']
        if ($null -eq $currentObservedPeak) {
            $summary | Add-Member -NotePropertyName RunObservedWorkingSetPeakMB -NotePropertyValue $workingSet -Force
        }
        elseif ($null -eq $currentObservedPeak.Value -or $workingSet -gt [double]$currentObservedPeak.Value) {
            $summary.RunObservedWorkingSetPeakMB = $workingSet
        }

        $sampleCount = $summary.PSObject.Properties['MemorySampleCount']
        if ($null -eq $sampleCount) {
            $summary | Add-Member -NotePropertyName MemorySampleCount -NotePropertyValue 1 -Force
        }
        else {
            $summary.MemorySampleCount = [int]$summary.MemorySampleCount + 1
        }
    }

    if ($null -ne $processPeak) {
        $summary | Add-Member -NotePropertyName ProcessPeakWorkingSetEndMB -NotePropertyValue $processPeak -Force
        $summary | Add-Member -NotePropertyName PeakMemoryMB -NotePropertyValue $processPeak -Force
        $summary | Add-Member -NotePropertyName PeakMemorySource -NotePropertyValue 'Process.PeakWorkingSet64' -Force
        $summary | Add-Member -NotePropertyName PeakMemoryScope -NotePropertyValue 'ProcessLifetimeHighWaterMark' -Force
    }

    $summary | Add-Member -NotePropertyName LastMemorySampleAt -NotePropertyValue $timestamp -Force
    $summary | Add-Member -NotePropertyName MemoryTelemetryAvailable -NotePropertyValue ($null -ne $workingSet -or $null -ne $processPeak) -Force
}

function Update-InspectorTelemetryDerivedMetrics {
    [CmdletBinding()]
    param (
        [AllowNull()][object]$Telemetry
    )

    if ($null -eq $Telemetry) {
        return
    }

    $logicalSummary = $Telemetry.PSObject.Properties['GraphRequestSummary']
    $transportSummary = $Telemetry.PSObject.Properties['GraphTransportSummary']
    if ($null -eq $logicalSummary -or $null -eq $logicalSummary.Value -or $null -eq $transportSummary -or $null -eq $transportSummary.Value) {
        return
    }

    $logical = [double](Get-InspectorObjectInsightProperty -InputObject $logicalSummary.Value -Name 'TotalRequests')
    $http = [double](Get-InspectorObjectInsightProperty -InputObject $transportSummary.Value -Name 'TotalHttpRequests')
    $batchHttp = [double](Get-InspectorObjectInsightProperty -InputObject $transportSummary.Value -Name 'BatchHttpRequests')
    $batchLogical = [double](Get-InspectorObjectInsightProperty -InputObject $transportSummary.Value -Name 'BatchSubrequestExecutions')

    $singleHttp = [double](Get-InspectorObjectInsightProperty -InputObject $transportSummary.Value -Name 'SingleHttpRequests')
    $transportExecutions = $singleHttp + $batchLogical

    $transportSummary.Value | Add-Member -NotePropertyName LogicalRequestsPerHttpRequest -NotePropertyValue $(if ($http -gt 0) { [math]::Round($logical / $http, 2) } else { $null }) -Force
    $transportSummary.Value | Add-Member -NotePropertyName TransportExecutionsPerHttpRequest -NotePropertyValue $(if ($http -gt 0) { [math]::Round($transportExecutions / $http, 2) } else { $null }) -Force
    $transportSummary.Value | Add-Member -NotePropertyName AverageBatchSubrequestsPerRequest -NotePropertyValue $(if ($batchHttp -gt 0) { [math]::Round($batchLogical / $batchHttp, 2) } else { $null }) -Force
    $transportSummary.Value | Add-Member -NotePropertyName BatchExecutionSharePercent -NotePropertyValue $(if ($transportExecutions -gt 0) { [math]::Round(($batchLogical / $transportExecutions) * 100.0, 2) } else { $null }) -Force
}

function Complete-InspectorTelemetryMemorySummary {
    [CmdletBinding()]
    param (
        [AllowNull()][object]$Telemetry
    )

    if ($null -eq $Telemetry) { return }
    $memoryProperty = $Telemetry.PSObject.Properties['MemorySummary']
    if ($null -eq $memoryProperty -or $null -eq $memoryProperty.Value) { return }

    Update-InspectorTelemetryMemorySample -Telemetry $Telemetry

    $summary = $memoryProperty.Value
    $memoryEnd = Get-InspectorTelemetryMemoryMB
    $processPeakEnd = Get-InspectorTelemetryProcessPeakMemoryMB
    $processPeakStart = Get-InspectorObjectInsightProperty -InputObject $summary -Name 'ProcessPeakWorkingSetStartMB'
    $workingSetStart = Get-InspectorObjectInsightProperty -InputObject $summary -Name 'ProcessWorkingSetStartMB'

    $summary | Add-Member -NotePropertyName ProcessWorkingSetEndMB -NotePropertyValue $memoryEnd -Force
    $summary | Add-Member -NotePropertyName ProcessPeakWorkingSetEndMB -NotePropertyValue $processPeakEnd -Force

    if ($null -ne $memoryEnd -and $null -ne $workingSetStart) {
        $summary | Add-Member -NotePropertyName ProcessWorkingSetDeltaMB -NotePropertyValue ([math]::Round([double]$memoryEnd - [double]$workingSetStart, 2)) -Force
    }

    if ($null -ne $processPeakEnd) {
        $summary | Add-Member -NotePropertyName PeakMemoryMB -NotePropertyValue $processPeakEnd -Force
    }

    if ($null -eq $processPeakStart -or $null -eq $processPeakEnd) {
        $summary | Add-Member -NotePropertyName RunPeakWorkingSetMB -NotePropertyValue $null -Force
        $summary | Add-Member -NotePropertyName RunPeakMemoryExact -NotePropertyValue $false -Force
        $summary | Add-Member -NotePropertyName RunPeakMemoryStatus -NotePropertyValue 'Unavailable' -Force
    }
    elseif ([double]$processPeakEnd -gt [double]$processPeakStart) {
        # The OS-maintained process high-water mark increased after this run's
        # baseline sample, so the new high-water value was reached during this
        # assessment and is an exact run peak.
        $summary | Add-Member -NotePropertyName RunPeakWorkingSetMB -NotePropertyValue ([double]$processPeakEnd) -Force
        $summary | Add-Member -NotePropertyName RunPeakMemoryExact -NotePropertyValue $true -Force
        $summary | Add-Member -NotePropertyName RunPeakMemoryStatus -NotePropertyValue 'ExactNewProcessHighWaterMark' -Force
    }
    else {
        # A pre-existing process high-water mark was not exceeded. The exact run
        # peak cannot be recovered from the lifetime counter; the sampled value
        # remains an explicitly labelled observed lower bound.
        $summary | Add-Member -NotePropertyName RunPeakWorkingSetMB -NotePropertyValue $null -Force
        $summary | Add-Member -NotePropertyName RunPeakMemoryExact -NotePropertyValue $false -Force
        $summary | Add-Member -NotePropertyName RunPeakMemoryStatus -NotePropertyValue 'PriorProcessHighWaterMarkNotExceeded' -Force
    }
}
