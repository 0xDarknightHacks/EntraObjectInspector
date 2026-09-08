function Start-InspectorTelemetryStage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Telemetry,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $now = Get-InspectorTelemetryTimestamp

    if (-not $Telemetry.StageDurations.Contains($Name)) {
        $Telemetry.StageDurations[$Name] = [PSCustomObject][ordered]@{
            Status                = 'Running'
            StartedAt             = $now
            CompletedAt           = $null
            DurationMs            = 0
            InvocationCount       = 0
            FailedInvocationCount = 0
            AverageDurationMs     = 0
            CurrentStartedAt      = $now
        }
        return
    }

    $stage = $Telemetry.StageDurations[$Name]

    if ($null -eq $stage.PSObject.Properties['InvocationCount']) {
        $stage | Add-Member -NotePropertyName 'InvocationCount' -NotePropertyValue 0 -Force
    }
    if ($null -eq $stage.PSObject.Properties['FailedInvocationCount']) {
        $stage | Add-Member -NotePropertyName 'FailedInvocationCount' -NotePropertyValue 0 -Force
    }
    if ($null -eq $stage.PSObject.Properties['AverageDurationMs']) {
        $stage | Add-Member -NotePropertyName 'AverageDurationMs' -NotePropertyValue 0 -Force
    }
    if ($null -eq $stage.PSObject.Properties['CurrentStartedAt']) {
        $stage | Add-Member -NotePropertyName 'CurrentStartedAt' -NotePropertyValue $null -Force
    }
    if ($null -eq $stage.PSObject.Properties['DurationMs'] -or $null -eq $stage.DurationMs) {
        $stage | Add-Member -NotePropertyName 'DurationMs' -NotePropertyValue 0 -Force
    }
    if ($null -eq $stage.PSObject.Properties['StartedAt'] -or [string]::IsNullOrWhiteSpace([string]$stage.StartedAt)) {
        $stage | Add-Member -NotePropertyName 'StartedAt' -NotePropertyValue $now -Force
    }

    $stage.Status = 'Running'
    $stage.CurrentStartedAt = $now
}
