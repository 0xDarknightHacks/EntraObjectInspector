function Invoke-EntraTenantInspection {
    <#
    .SYNOPSIS
        Runs tenant-wide discovery and object-insight orchestration.

    .DESCRIPTION
        Builds an in-memory tenant snapshot first, then resolves objects and
        builds relationships offline from that snapshot before running the
        existing normalization, permission intelligence, rule, and observation
        layers.

        Tenant inspection is orchestration only. It does not add scoring, attack paths,
        reporting, MITRE mapping, remediation, or new intelligence.

    .PARAMETER ObjectType
        Object types to discover and inspect.

    .PARAMETER MaxObjectsPerType
        Optional limit per object type for controlled validation runs.
        Use 0 for no explicit limit. If the limit truncates a collected object
        type, the snapshot and tenant result are marked Partial/Truncated and
        cannot be treated as release-eligible complete-tenant evidence.

    .PARAMETER BatchSize
        Number of discovered objects grouped per processing batch.

    .PARAMETER ThrottleDelayMilliseconds
        Optional fixed delay before each object inspection attempt.

    .PARAMETER MaxRetryCount
        Number of retries for object-level offline pipeline exceptions. The
        initial attempt is not counted as a retry, so MaxRetryCount 2 allows up
        to three attempts for a failed object.

    .PARAMETER CheckpointPath
        Optional checkpoint file path used to record object-processing progress.

    .PARAMETER Resume
        Reuses checkpoint progress ordering, but reconstructs the complete final
        ObjectInsight corpus from the newly collected immutable snapshot. Objects
        already recorded as processed are replayed from the current snapshot
        rather than omitted, preventing a resumed run from producing an incomplete
        assessment package or mixing old checkpoint state with new snapshot state.
    #>

    [CmdletBinding()]
    param (
        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string[]]$ObjectType = @(
            'Application',
            'ServicePrincipal',
            'User',
            'Group'
        ),

        [int]$MaxObjectsPerType = 0,

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

    $startedAt = (Get-Date).ToUniversalTime().ToString('o')
    $objectInsights = [System.Collections.Generic.List[object]]::new()
    $failedObjects = [System.Collections.Generic.List[object]]::new()
    $logs = [System.Collections.Generic.List[object]]::new()
    $resultLimitations = [System.Collections.Generic.List[string]]::new()

    $previousRuntimeTelemetryVariable =
        Get-Variable `
            -Name 'InspectorCurrentRuntimeTelemetry' `
            -Scope Script `
            -ErrorAction SilentlyContinue
    $hadPreviousRuntimeTelemetry = $null -ne $previousRuntimeTelemetryVariable
    $previousRuntimeTelemetry =
        if ($hadPreviousRuntimeTelemetry) { $previousRuntimeTelemetryVariable.Value } else { $null }
    $telemetry = if ($hadPreviousRuntimeTelemetry -and $null -ne $previousRuntimeTelemetry) { $previousRuntimeTelemetry } else { New-InspectorRuntimeTelemetry }
    $script:InspectorCurrentRuntimeTelemetry = $telemetry

    try {
    Start-InspectorTelemetryStage -Telemetry $telemetry -Name 'TenantSnapshotCollection'
    $snapshot =
        New-InspectorTenantSnapshot `
            -ObjectType $ObjectType `
            -MaxObjectsPerType $MaxObjectsPerType `
            -RuntimeTelemetry $telemetry
    Stop-InspectorTelemetryStage -Telemetry $telemetry -Name 'TenantSnapshotCollection'

    $graphCollectionCompletedAt = (Get-Date).ToUniversalTime().ToString('o')
    $graphRequestsAtSnapshotCompletion =
        [int](Get-InspectorObjectInsightProperty `
            -InputObject (Get-InspectorObjectInsightProperty -InputObject $telemetry -Name 'GraphRequestSummary') `
            -Name 'TotalRequests')

    $discovery =
        ConvertFrom-InspectorTenantSnapshot `
            -TenantSnapshot $snapshot `
            -ObjectType $ObjectType

    foreach ($limitation in @(Get-InspectorObjectInsightProperty -InputObject $discovery -Name 'Limitations')) {
        if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) {
            $resultLimitations.Add([string]$limitation)
        }
    }

    $orderedObjects =
        @($discovery.DiscoveredObjects | Sort-Object ObjectType, ObjectId)

    $checkpoint =
        if (-not [string]::IsNullOrWhiteSpace($CheckpointPath) -and $Resume) {
            Read-InspectorCheckpointState -Path $CheckpointPath
        }
        else {
            New-InspectorCheckpointState
        }

    $checkpointProcessedKeys = @(
        Get-InspectorObjectInsightProperty -InputObject $checkpoint -Name 'ProcessedObjectKeys'
    )
    $resumeReplayObjectKeys = @(
        if ($Resume) {
            @($orderedObjects | ForEach-Object { [string]$_.ObjectKey }) |
                Where-Object { $_ -in $checkpointProcessedKeys } |
                Select-Object -Unique
        }
    )

    # Resume is intentionally integrity-first. A checkpoint records progress, but
    # the final result must be derived entirely from the newly collected immutable
    # snapshot. Process not-yet-checkpointed objects first, then replay previously
    # processed objects so the returned corpus is complete and single-snapshot.
    $objectsToProcess =
        if ($Resume -and $resumeReplayObjectKeys.Count -gt 0) {
            @(
                $orderedObjects | Where-Object { [string]$_.ObjectKey -notin $resumeReplayObjectKeys }
                $orderedObjects | Where-Object { [string]$_.ObjectKey -in $resumeReplayObjectKeys }
            )
        }
        else {
            @($orderedObjects)
        }

    if ($Resume) {
        $resumeMessage =
            if ($resumeReplayObjectKeys.Count -gt 0) {
                "Resume checkpoint contained $($resumeReplayObjectKeys.Count) processed object(s). They are replayed from the current snapshot after pending objects so the final assessment corpus remains complete and snapshot-consistent."
            }
            else {
                'Resume was requested, but no processed checkpoint objects matched the current snapshot. The complete current snapshot is processed normally.'
            }
        $resultLimitations.Add($resumeMessage)
    }

    $offlineProcessingStartedAt = (Get-Date).ToUniversalTime().ToString('o')
    $total = @($objectsToProcess).Count
    $processed = 0
    $totalRetryAttempts = 0

    for ($index = 0; $index -lt $objectsToProcess.Count; $index += $BatchSize) {
        $batch = @($objectsToProcess | Select-Object -Skip $index -First $BatchSize)

        foreach ($object in $batch) {
            $processed++

            if (-not $NoProgress) {
                $percent = if ($total -eq 0) { 100 } else { [math]::Min(100, [int](($processed / [double]$total) * 100)) }
                Write-Progress -Activity 'Entra Object Inspector offline tenant pipeline' -Status "Processing $processed of $total" -PercentComplete $percent
            }

            $attempt = 0
            $completed = $false
            $lastError = $null

            while (-not $completed -and $attempt -le $MaxRetryCount) {
                $attempt++
                $activeStage = $null

                try {
                    if ($ThrottleDelayMilliseconds -gt 0) {
                        Start-Sleep -Milliseconds $ThrottleDelayMilliseconds
                    }

                    $activeStage = 'OfflineResolution'
                    Start-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage
                    $resolution = Resolve-EntraObjectFromSnapshot -Identity $object.InspectionIdentity -TenantSnapshot $snapshot
                    Stop-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage
                    $activeStage = $null

                    $activeStage = 'OfflineRelationshipBuilding'
                    Start-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage
                    $relationshipCollection = Get-InspectorSnapshotRelationships -Resolution $resolution -TenantSnapshot $snapshot
                    Stop-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage
                    $activeStage = $null

                    $activeStage = 'Normalization'
                    Start-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage
                    $insight = ConvertTo-InspectorObjectInsight -Resolution $resolution -RelationshipCollection $relationshipCollection
                    Stop-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage
                    $activeStage = $null

                    $activeStage = 'PermissionIntelligence'
                    Start-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage
                    $insight = Add-InspectorPermissionIntelligence -ObjectInsight $insight
                    $ruleResults = Invoke-InspectorRules -ObjectInsight $insight
                    $insight.RuleResults = @($ruleResults)
                    $insight.Findings = @($ruleResults)
                    $insight.Summary.FindingCount = @($ruleResults).Count
                    Stop-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage
                    $activeStage = $null

                    $activeStage = 'ObservationEngine'
                    Start-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage
                    $observationResult = Invoke-InspectorObservationEngine -ObjectInsight $insight
                    $insight | Add-Member -NotePropertyName 'ObservationEngine' -NotePropertyValue $observationResult -Force
                    $insight | Add-Member -NotePropertyName 'SecurityObservations' -NotePropertyValue @($observationResult.Observations) -Force
                    $insight.Summary | Add-Member -NotePropertyName 'SecurityObservationCount' -NotePropertyValue @($observationResult.Observations).Count -Force
                    Stop-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage
                    $activeStage = $null

                    $insight | Add-Member -NotePropertyName 'DiscoveryObject' -NotePropertyValue $object -Force
                    Add-InspectorCheckpointObject -State $checkpoint -ObjectKey $object.ObjectKey

                    if (-not [string]::IsNullOrWhiteSpace($CheckpointPath)) {
                        Write-InspectorCheckpointState -Path $CheckpointPath -State $checkpoint
                    }

                    # Commit the completed ObjectInsight only after any requested
                    # checkpoint update succeeds. This prevents a retry triggered by
                    # checkpoint I/O from duplicating a previously-added insight.
                    $objectInsights.Add($insight)
                    $completed = $true
                }
                catch {
                    $lastError = $_
                    if (-not [string]::IsNullOrWhiteSpace([string]$activeStage)) {
                        Stop-InspectorTelemetryStage -Telemetry $telemetry -Name $activeStage -Status 'Failed'
                    }

                    $diagnosticRunLog =
                        Get-Variable `
                            -Name 'InspectorCurrentRunLog' `
                            -Scope Script `
                            -ValueOnly `
                            -ErrorAction SilentlyContinue

                    $willRetry = $attempt -le $MaxRetryCount
                    Write-InspectorDiagnosticEvent `
                        -RunLog $diagnosticRunLog `
                        -Stage 'ObjectProcessing' `
                        -Level $(if ($willRetry) { 'Warning' } else { 'Error' }) `
                        -EventName $(if ($willRetry) { 'ObjectProcessingRetry' } else { 'ObjectProcessingFailed' }) `
                        -Message $(if ($willRetry) { 'Object processing attempt failed and will be retried.' } else { 'Object processing failed after all configured attempts.' }) `
                        -ObjectId $object.ObjectId `
                        -ObjectType $object.ObjectType `
                        -Exception $_ `
                        -Data @{
                            InspectionIdentity = $object.InspectionIdentity
                            Attempt = $attempt
                            MaxRetryCount = $MaxRetryCount
                        }

                    if ($willRetry) {
                        $totalRetryAttempts++
                        continue
                    }
                }
            }

            if (-not $completed) {
                $failedObjects.Add([PSCustomObject][ordered]@{
                    PSTypeName         = 'EntraObjectInspector.FailedPipelineObject'
                    ObjectKey          = $object.ObjectKey
                    ObjectType         = $object.ObjectType
                    ObjectId           = $object.ObjectId
                    InspectionIdentity = $object.InspectionIdentity
                    Attempts           = $attempt
                    Error              = $(if ($null -ne $lastError) { $lastError.Exception.Message } else { 'Object processing failed.' })
                })

                Add-InspectorCheckpointObject -State $checkpoint -ObjectKey $object.ObjectKey -Failed
                if (-not [string]::IsNullOrWhiteSpace($CheckpointPath)) {
                    Write-InspectorCheckpointState -Path $CheckpointPath -State $checkpoint
                }
            }
        }
    }

    if (-not $NoProgress) {
        Write-Progress -Activity 'Entra Object Inspector offline tenant pipeline' -Completed
    }

    $offlineProcessingCompletedAt = (Get-Date).ToUniversalTime().ToString('o')

    $pipeline = [PSCustomObject][ordered]@{
        PSTypeName           = 'EntraObjectInspector.PipelineResult'
        SchemaVersion        = '1.0.0'
        StartedAt            = $offlineProcessingStartedAt
        CompletedAt          = $offlineProcessingCompletedAt
        Status               = if (@($failedObjects).Count -gt 0 -and @($objectInsights).Count -gt 0) { 'Partial' } elseif (@($failedObjects).Count -gt 0) { 'Failed' } else { 'Success' }
        BatchSize            = $BatchSize
        ThrottleDelayMs      = $ThrottleDelayMilliseconds
        MaxRetryCount        = $MaxRetryCount
        InputCount           = @($orderedObjects).Count
        SkippedCount         = 0
        ProcessedCount       = @($objectInsights).Count
        FailedCount          = @($failedObjects).Count
        RetryAttemptCount    = $totalRetryAttempts
        Resume               = [bool]$Resume
        ResumeReplayCount    = $resumeReplayObjectKeys.Count
        ObjectInsights       = @($objectInsights)
        FailedObjects        = @($failedObjects)
        Checkpoint           = $checkpoint
        Logs                 = @($logs)
    }

    $status =
        if ($discovery.Status -eq 'Failed' -or $pipeline.Status -eq 'Failed') { 'Failed' }
        elseif ($discovery.Status -eq 'Partial' -or $pipeline.Status -eq 'Partial') { 'Partial' }
        else { 'Success' }

    $securityObservations =
        @(
            @($objectInsights) |
            ForEach-Object {
                @(
                    Get-InspectorObservationProperty `
                        -InputObject $_ `
                        -Name 'SecurityObservations'
                )
            } |
            Where-Object { $null -ne $_ }
        )

    $completedAt = (Get-Date).ToUniversalTime().ToString('o')
    $graphRequestsAtInspectionCompletion =
        [int](Get-InspectorObjectInsightProperty `
            -InputObject (Get-InspectorObjectInsightProperty -InputObject $telemetry -Name 'GraphRequestSummary') `
            -Name 'TotalRequests')
    $graphCallsAfterSnapshot =
        [math]::Max(0, $graphRequestsAtInspectionCompletion - $graphRequestsAtSnapshotCompletion)
    $telemetry | Add-Member -NotePropertyName GraphRequestsAtSnapshotCompletion -NotePropertyValue $graphRequestsAtSnapshotCompletion -Force
    $telemetry | Add-Member -NotePropertyName GraphRequestsAtInspectionCompletion -NotePropertyValue $graphRequestsAtInspectionCompletion -Force
    $telemetry | Add-Member -NotePropertyName GraphRequestsAtAssessmentCompletion -NotePropertyValue $graphRequestsAtInspectionCompletion -Force
    $telemetry | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue $graphCallsAfterSnapshot -Force
    $telemetry.CompletedAt = $completedAt
    $telemetry.TotalDurationMs = [int](([datetime]$completedAt - [datetime]$telemetry.StartedAt).TotalMilliseconds)
    $memoryEnd = Get-InspectorTelemetryMemoryMB
    $telemetry.MemorySummary.ProcessWorkingSetEndMB = $memoryEnd
    if ($null -ne $memoryEnd -and $null -ne $telemetry.MemorySummary.ProcessWorkingSetStartMB) {
        $telemetry.MemorySummary.ProcessWorkingSetDeltaMB = [math]::Round($memoryEnd - $telemetry.MemorySummary.ProcessWorkingSetStartMB, 2)
        $telemetry.MemorySummary.PeakMemoryMB = [math]::Max($memoryEnd, $telemetry.MemorySummary.ProcessWorkingSetStartMB)
    }
    $telemetry.ObjectProcessingSummary.ObjectsProcessed = $pipeline.ProcessedCount
    $telemetry.ObjectProcessingSummary.ObjectsSucceeded = @($objectInsights | Where-Object Status -eq 'Resolved').Count
    $telemetry.ObjectProcessingSummary.ObjectsFailed = $pipeline.FailedCount
    $telemetry.ObjectProcessingSummary.ObjectsSkipped = $pipeline.SkippedCount
    $telemetry.ObjectProcessingSummary.RetryAttempts = $pipeline.RetryAttemptCount
    $telemetry.ObjectProcessingSummary.ResumeReplayCount = $pipeline.ResumeReplayCount
    $telemetry.RetrySummary.ObjectProcessingRetries = $pipeline.RetryAttemptCount
    $telemetry.ThroughputSummary.ObjectsProcessed = $pipeline.ProcessedCount
    $telemetry.ThroughputSummary.ObjectsPerSecond =
        if ($telemetry.TotalDurationMs -gt 0) {
            [math]::Round($pipeline.ProcessedCount / ($telemetry.TotalDurationMs / 1000.0), 2)
        }
        else {
            $null
        }

    $tenantMetadata =
        Get-InspectorObjectInsightProperty `
            -InputObject $snapshot `
            -Name 'TenantMetadata'

    $scopeInventory =
        Get-InspectorObjectInsightProperty `
            -InputObject $snapshot `
            -Name 'ScopeInventory'

    $assessmentCoverage =
        Get-InspectorObjectInsightProperty `
            -InputObject $snapshot `
            -Name 'AssessmentCoverage'

    $result = [PSCustomObject][ordered]@{
        PSTypeName                      = 'EntraObjectInspector.TenantInspectionResult'
        SchemaVersion                   = '0.7.0'
        StartedAt                       = $startedAt
        CompletedAt                     = $completedAt
        Status                          = $status
        Completeness                    = $(if ($status -eq 'Success') { 'Complete' } else { 'Partial' })
        ObjectTypes                     = @($ObjectType | Sort-Object -Unique)
        SnapshotMode                    = 'InMemory'
        SnapshotSchemaVersion           = $snapshot.SchemaVersion
        SnapshotId                      = $snapshot.SnapshotId
        GraphCollectionCompletedAt      = $graphCollectionCompletedAt
        OfflineProcessingStartedAt      = $offlineProcessingStartedAt
        OfflineProcessingCompletedAt    = $offlineProcessingCompletedAt
        GraphRequestsAtSnapshotCompletion = $graphRequestsAtSnapshotCompletion
        GraphRequestsAtInspectionCompletion = $graphRequestsAtInspectionCompletion
        GraphRequestsAtAssessmentCompletion = $graphRequestsAtInspectionCompletion
        GraphCallsAfterSnapshot         = $graphCallsAfterSnapshot
        Discovery                       = $discovery
        AssessmentCoverage              = $assessmentCoverage
        Pipeline                        = $pipeline
        ObjectInsights                  = @($objectInsights)
        SecurityObservations            = @($securityObservations)
        FailedObjects                   = @($failedObjects)
        Logs                            = @($logs)
        Limitations                     = @($resultLimitations | Select-Object -Unique)
        RuntimeTelemetry                = $telemetry
        Summary                         = [PSCustomObject][ordered]@{
            TenantId                    = Get-InspectorObjectInsightProperty -InputObject $tenantMetadata -Name 'TenantId'
            TenantDisplayName           = Get-InspectorObjectInsightProperty -InputObject $tenantMetadata -Name 'TenantDisplayName'
            TenantMetadata              = $tenantMetadata
            ScopeInventory              = $scopeInventory
            AssessmentCoverage          = $assessmentCoverage
            DiscoveredCount             = $discovery.TotalCount
            ProcessedCount              = $pipeline.ProcessedCount
            FailedCount                 = $pipeline.FailedCount
            SkippedCount                = $pipeline.SkippedCount
            ResumeReplayCount           = $pipeline.ResumeReplayCount
            RetryAttemptCount           = $pipeline.RetryAttemptCount
            ObjectInsightCount          = @($objectInsights).Count
            SecurityObservationCount    = @($securityObservations).Count
            RuntimeTelemetry            = $telemetry
        }
    }

    return $result
    }
    finally {
        if ($hadPreviousRuntimeTelemetry) {
            $script:InspectorCurrentRuntimeTelemetry = $previousRuntimeTelemetry
        }
        else {
            Remove-Variable `
                -Name 'InspectorCurrentRuntimeTelemetry' `
                -Scope Script `
                -ErrorAction SilentlyContinue
        }
    }
}
