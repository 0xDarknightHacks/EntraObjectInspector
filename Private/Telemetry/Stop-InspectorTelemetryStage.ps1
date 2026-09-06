function Stop-InspectorTelemetryStage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Telemetry,

        [Parameter(Mandatory)]
        [string]$Name,

        [ValidateSet('Completed', 'Failed', 'NotRun')]
        [string]$Status = 'Completed'
    )

    if (-not $Telemetry.StageDurations.Contains($Name)) {
        $Telemetry.StageDurations[$Name] = [PSCustomObject][ordered]@{
            Status                = 'NotRun'
            StartedAt             = $null
            CompletedAt           = $null
            DurationMs            = 0
            InvocationCount       = 0
            FailedInvocationCount = 0
            CurrentStartedAt      = $null
        }
    }

    $stage = $Telemetry.StageDurations[$Name]
    foreach ($propertyDefinition in @(
        @{ Name = 'InvocationCount'; Value = 0 },
        @{ Name = 'FailedInvocationCount'; Value = 0 },
        @{ Name = 'CurrentStartedAt'; Value = $null },
        @{ Name = 'DurationMs'; Value = 0 }
    )) {
        if ($null -eq $stage.PSObject.Properties[$propertyDefinition.Name]) {
            $stage | Add-Member -NotePropertyName $propertyDefinition.Name -NotePropertyValue $propertyDefinition.Value -Force
        }
    }

    $completedAt = Get-InspectorTelemetryTimestamp
    $currentStartedAt = [string]$stage.CurrentStartedAt
    if ([string]::IsNullOrWhiteSpace($currentStartedAt)) {
        $currentStartedAt = [string]$stage.StartedAt
    }

    if (-not [string]::IsNullOrWhiteSpace($currentStartedAt)) {
        $elapsedMs = [math]::Max(0, [int](([datetime]$completedAt - [datetime]$currentStartedAt).TotalMilliseconds))
        $stage.DurationMs = [int]$stage.DurationMs + $elapsedMs
        $stage.InvocationCount = [int]$stage.InvocationCount + 1
        if ($Status -eq 'Failed') {
            $stage.FailedInvocationCount = [int]$stage.FailedInvocationCount + 1
        }
    }

    $stage.Status = $Status
    $stage.CompletedAt = $completedAt
    $stage.CurrentStartedAt = $null
}
