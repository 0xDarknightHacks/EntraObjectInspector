function Invoke-InspectorPipeline {
    <#
    .SYNOPSIS
        Deprecated compatibility helper for the pre-snapshot tenant pipeline.

    .DESCRIPTION
        This internal helper is retained for compatibility and regression tests.
        It is not used by Invoke-EntraTenantInspection or Invoke-EntraSecurityAssessment.
        The production tenant path is snapshot-first and implements retry/resume
        semantics directly against the freshly collected in-memory snapshot.

        Do not use this helper as the release contract for checkpoint/resume
        behavior. Use Invoke-EntraTenantInspection for supported tenant execution.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$DiscoveredObject,

        [ValidateRange(1, 500)]
        [int]$BatchSize = 25,

        [ValidateRange(0, 600000)]
        [int]$ThrottleDelayMilliseconds = 0,

        [ValidateRange(0, 10)]
        [int]$MaxRetryCount = 2,

        [string]$CheckpointPath,

        [switch]$Resume,

        [switch]$NoProgress
    )

    Write-Verbose 'Invoke-InspectorPipeline is deprecated and is not used by the production snapshot-first tenant orchestration path.'

    $startedAt = (Get-Date).ToUniversalTime().ToString('o')
    $objectInsights = [System.Collections.Generic.List[object]]::new()
    $failedObjects = [System.Collections.Generic.List[object]]::new()
    $logs = [System.Collections.Generic.List[object]]::new()

    $checkpoint =
        if (-not [string]::IsNullOrWhiteSpace($CheckpointPath) -and $Resume) {
            Read-InspectorCheckpointState -Path $CheckpointPath
        }
        else {
            New-InspectorCheckpointState
        }

    $orderedObjects =
        @(
            $DiscoveredObject |
            Where-Object { $null -ne $_ } |
            Sort-Object ObjectType, ObjectId
        )

    $objectsToProcess =
        @(
            $orderedObjects |
            Where-Object {
                $key = [string]$_.ObjectKey
                -not ($Resume -and $key -in @($checkpoint.ProcessedObjectKeys))
            }
        )

    $total = @($objectsToProcess).Count
    $processed = 0

    $logs.Add(
        (New-InspectorStructuredLog `
            -Stage 'Pipeline' `
            -Level 'Information' `
            -Message 'Starting object insight pipeline.' `
            -Data @{
                TotalObjects = $total
                BatchSize = $BatchSize
                Resume = [bool]$Resume
                CheckpointPath = $CheckpointPath
            })
    )

    for ($index = 0; $index -lt $objectsToProcess.Count; $index += $BatchSize) {
        $batch =
            @(
                $objectsToProcess |
                Select-Object `
                    -Skip $index `
                    -First $BatchSize
            )

        foreach ($object in $batch) {
            $processed++

            if (-not $NoProgress) {
                $percent =
                    if ($total -eq 0) {
                        100
                    }
                    else {
                        [math]::Min(
                            100,
                            [int](($processed / [double]$total) * 100)
                        )
                    }

                Write-Progress `
                    -Activity 'Entra Object Inspector tenant pipeline' `
                    -Status "Processing $processed of $total" `
                    -PercentComplete $percent
            }

            $attempt = 0
            $completed = $false
            $lastError = $null

            while (-not $completed -and $attempt -le $MaxRetryCount) {
                $attempt++

                try {
                    if ($ThrottleDelayMilliseconds -gt 0) {
                        Start-Sleep -Milliseconds $ThrottleDelayMilliseconds
                    }

                    $insight =
                        Get-EntraObjectInsight `
                            -Identity $object.InspectionIdentity

                    $insight |
                        Add-Member `
                            -NotePropertyName 'DiscoveryObject' `
                            -NotePropertyValue $object `
                            -Force

                    $objectInsights.Add($insight)

                    Add-InspectorCheckpointObject `
                        -State $checkpoint `
                        -ObjectKey $object.ObjectKey

                    if (-not [string]::IsNullOrWhiteSpace($CheckpointPath)) {
                        Write-InspectorCheckpointState `
                            -Path $CheckpointPath `
                            -State $checkpoint
                    }

                    $logs.Add(
                        (New-InspectorStructuredLog `
                            -Stage 'Pipeline' `
                            -Level 'Information' `
                            -Message 'Processed discovered object.' `
                            -Data @{
                                ObjectKey = $object.ObjectKey
                                ObjectType = $object.ObjectType
                                InspectionIdentity = $object.InspectionIdentity
                                Attempt = $attempt
                                Status = $insight.Status
                            })
                    )

                    $completed = $true
                }
                catch {
                    $lastError = $_

                    $logs.Add(
                        (New-InspectorStructuredLog `
                            -Stage 'Pipeline' `
                            -Level 'Warning' `
                            -Message 'Object processing attempt failed.' `
                            -Data @{
                                ObjectKey = $object.ObjectKey
                                ObjectType = $object.ObjectType
                                InspectionIdentity = $object.InspectionIdentity
                                Attempt = $attempt
                                Error = $_.Exception.Message
                            })
                    )

                    if ($attempt -le $MaxRetryCount -and $ThrottleDelayMilliseconds -gt 0) {
                        Start-Sleep -Milliseconds $ThrottleDelayMilliseconds
                    }
                }
            }

            if (-not $completed) {
                $failed = [PSCustomObject][ordered]@{
                    PSTypeName          = 'EntraObjectInspector.FailedPipelineObject'
                    ObjectKey           = $object.ObjectKey
                    ObjectType          = $object.ObjectType
                    ObjectId            = $object.ObjectId
                    InspectionIdentity  = $object.InspectionIdentity
                    Attempts            = $attempt
                    Error               = $lastError.Exception.Message
                }

                $failedObjects.Add($failed)

                Add-InspectorCheckpointObject `
                    -State $checkpoint `
                    -ObjectKey $object.ObjectKey `
                    -Failed

                if (-not [string]::IsNullOrWhiteSpace($CheckpointPath)) {
                    Write-InspectorCheckpointState `
                        -Path $CheckpointPath `
                        -State $checkpoint
                }
            }
        }
    }

    if (-not $NoProgress) {
        Write-Progress `
            -Activity 'Entra Object Inspector tenant pipeline' `
            -Completed
    }

    $status =
        if (@($failedObjects).Count -gt 0 -and @($objectInsights).Count -gt 0) {
            'Partial'
        }
        elseif (@($failedObjects).Count -gt 0) {
            'Failed'
        }
        else {
            'Success'
        }

    return [PSCustomObject][ordered]@{
        PSTypeName        = 'EntraObjectInspector.PipelineResult'
        SchemaVersion     = '0.6.0'
        StartedAt         = $startedAt
        CompletedAt       = (Get-Date).ToUniversalTime().ToString('o')
        Status            = $status
        BatchSize         = $BatchSize
        ThrottleDelayMs   = $ThrottleDelayMilliseconds
        MaxRetryCount     = $MaxRetryCount
        InputCount        = @($orderedObjects).Count
        SkippedCount      = @($orderedObjects).Count - @($objectsToProcess).Count
        ProcessedCount    = @($objectInsights).Count
        FailedCount       = @($failedObjects).Count
        ObjectInsights    = @($objectInsights)
        FailedObjects     = @($failedObjects)
        Checkpoint        = $checkpoint
        Logs              = @($logs)
    }
}

