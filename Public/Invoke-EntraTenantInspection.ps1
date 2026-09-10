function Invoke-EntraTenantInspection {
    <#
    .SYNOPSIS
        Runs live, targeted, or portable-snapshot object-insight orchestration.

    .DESCRIPTION
        Builds an in-memory tenant snapshot first, or imports a previously saved
        portable snapshot, then resolves objects and builds relationships offline
        before running normalization, permission intelligence, rules, observations,
        optional comparison, and assessment policy.

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

    .PARAMETER SnapshotPath
        Imports a versioned portable tenant snapshot and re-runs analysis offline.
        Graph connection and collection are not required for this path.

    .PARAMETER SaveSnapshotPath
        Saves the collected or imported tenant snapshot in the portable snapshot
        contract for later offline reanalysis or comparison.

    .PARAMETER TargetFile
        CSV or TXT target file. CSV requires Identity and may include ObjectType.
        TXT accepts Identity or ObjectType|Identity per line.

    .PARAMETER Target
        Explicit target entries supplied as Identity or ObjectType|Identity.

    .PARAMETER CompareToSnapshotPath
        Portable previous snapshot to compare with the current snapshot. Comparison
        is offline and requires the same tenant and deterministic collection scope.

    .PARAMETER RulePackPath
        Constrained JSON rule pack evaluated against normalized observations.

    .PARAMETER BaselinePath
        JSON assessment baseline that annotates accepted observations and comparable
        drift records without deleting the underlying observation or evidence.

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

        [string]$SnapshotPath,

        [string]$SaveSnapshotPath,

        [string]$TargetFile,

        [string[]]$Target = @(),

        [string]$CompareToSnapshotPath,

        [string]$RulePackPath,

        [string]$BaselinePath,

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
    $offlineSnapshotMode = -not [string]::IsNullOrWhiteSpace($SnapshotPath)
    if ($offlineSnapshotMode -and (-not [string]::IsNullOrWhiteSpace($TargetFile) -or @($Target).Count -gt 0)) {
        throw '-SnapshotPath cannot be combined with -TargetFile or -Target because the portable snapshot already defines the collected scope.'
    }

    $targetSpecification = @()
    if (-not $offlineSnapshotMode -and (-not [string]::IsNullOrWhiteSpace($TargetFile) -or @($Target).Count -gt 0)) {
        $targetSpecification = @(Import-InspectorTargetSpecification -TargetFile $TargetFile -Target $Target -AllowedObjectType $ObjectType)
    }

    Start-InspectorTelemetryStage -Telemetry $telemetry -Name 'TenantSnapshotCollection'
    if ($offlineSnapshotMode) {
        $snapshot = Import-InspectorTenantSnapshot -Path $SnapshotPath
    }
    else {
        $snapshot = New-InspectorTenantSnapshot -ObjectType $ObjectType -MaxObjectsPerType $MaxObjectsPerType -TargetSpecification $targetSpecification -RuntimeTelemetry $telemetry
    }
    Stop-InspectorTelemetryStage -Telemetry $telemetry -Name 'TenantSnapshotCollection'
    Update-InspectorTelemetryMemorySample -Telemetry $telemetry

    if (-not [string]::IsNullOrWhiteSpace($SaveSnapshotPath)) {
        Export-InspectorTenantSnapshot -TenantSnapshot $snapshot -Path $SaveSnapshotPath -Force | Out-Null
    }

    $collectionScope = Get-InspectorSnapshotProperty -InputObject $snapshot -Name 'CollectionScope'
    $snapshotObjectTypes = @(Get-InspectorSnapshotProperty -InputObject $collectionScope -Name 'ObjectTypes') | Where-Object { $_ -in @('Application','ServicePrincipal','User','Group') }
    $collectionScopeMode = [string](Get-InspectorSnapshotProperty -InputObject $collectionScope -Name 'Mode')
    $resolvedTargets = @(Get-InspectorSnapshotProperty -InputObject $collectionScope -Name 'ResolvedTargets')
    $resolvedObjectKeys = @(Get-InspectorSnapshotProperty -InputObject $collectionScope -Name 'ResolvedObjectKeys')

    # Older callers/tests may reuse a telemetry DTO created before the maturity fields
    # existed. Add the additive profile shapes before assigning them so StrictMode
    # remains compatible with those callers.
    if ($null -eq $telemetry.PSObject.Properties['ExecutionProfile']) {
        $telemetry | Add-Member -NotePropertyName ExecutionProfile -NotePropertyValue ([PSCustomObject][ordered]@{
            Mode = 'Unknown'; SnapshotMode = ''; OfflineSnapshot = $false; Targeted = $false
        }) -Force
    }
    else {
        foreach ($profileProperty in @('Mode','SnapshotMode','OfflineSnapshot','Targeted')) {
            if ($null -eq $telemetry.ExecutionProfile.PSObject.Properties[$profileProperty]) {
                $defaultProfileValue = if ($profileProperty -in @('OfflineSnapshot','Targeted')) { $false } else { '' }
                $telemetry.ExecutionProfile | Add-Member -NotePropertyName $profileProperty -NotePropertyValue $defaultProfileValue -Force
            }
        }
    }
    if ($null -eq $telemetry.PSObject.Properties['ScopeSummary']) {
        $telemetry | Add-Member -NotePropertyName ScopeSummary -NotePropertyValue ([PSCustomObject][ordered]@{
            Mode = ''; ObjectTypes = @(); TargetCount = 0; ResolvedObjectCount = 0; ScopeSignature = ''
        }) -Force
    }
    else {
        $scopeDefaults = [ordered]@{ Mode = ''; ObjectTypes = @(); TargetCount = 0; ResolvedObjectCount = 0; ScopeSignature = '' }
        foreach ($scopeProperty in $scopeDefaults.Keys) {
            if ($null -eq $telemetry.ScopeSummary.PSObject.Properties[$scopeProperty]) {
                $telemetry.ScopeSummary | Add-Member -NotePropertyName $scopeProperty -NotePropertyValue $scopeDefaults[$scopeProperty] -Force
            }
        }
    }
    if ($null -eq $telemetry.PSObject.Properties['ThroughputSummary']) {
        $telemetry | Add-Member -NotePropertyName ThroughputSummary -NotePropertyValue ([PSCustomObject][ordered]@{
            ObjectsProcessed = 0; ObjectsPerSecond = $null; EndToEndObjectsPerSecond = $null; OfflineProcessingDurationMs = $null
        }) -Force
    }
    else {
        foreach ($throughputProperty in @('EndToEndObjectsPerSecond','OfflineProcessingDurationMs')) {
            if ($null -eq $telemetry.ThroughputSummary.PSObject.Properties[$throughputProperty]) {
                $telemetry.ThroughputSummary | Add-Member -NotePropertyName $throughputProperty -NotePropertyValue $null -Force
            }
        }
    }

    $telemetry.ExecutionProfile.Mode = $(if($offlineSnapshotMode){'PortableOffline'}elseif($collectionScopeMode -eq 'Targeted'){'TargetedLive'}else{'TenantWideLive'})
    $telemetry.ExecutionProfile.SnapshotMode = $(if($offlineSnapshotMode){'PortableFile'}elseif($collectionScopeMode -eq 'Targeted'){'TargetedInMemory'}else{'InMemory'})
    $telemetry.ExecutionProfile.OfflineSnapshot = [bool]$offlineSnapshotMode
    $telemetry.ExecutionProfile.Targeted = ($collectionScopeMode -eq 'Targeted')
    $telemetry.ScopeSummary.Mode = $collectionScopeMode
    $telemetry.ScopeSummary.ObjectTypes = @($snapshotObjectTypes | Sort-Object -Unique)
    $telemetry.ScopeSummary.TargetCount = @($resolvedTargets).Count
    $telemetry.ScopeSummary.ResolvedObjectCount = @($resolvedObjectKeys).Count
    $telemetry.ScopeSummary.ScopeSignature = [string](Get-InspectorSnapshotProperty -InputObject $collectionScope -Name 'ScopeSignature')
    $effectiveObjectType = if ($offlineSnapshotMode -and -not $PSBoundParameters.ContainsKey('ObjectType') -and $snapshotObjectTypes.Count -gt 0) { @($snapshotObjectTypes) } else { @($ObjectType) }

    $graphCollectionCompletedAt = (Get-Date).ToUniversalTime().ToString('o')
    $graphRequestsAtSnapshotCompletion =
        if ($offlineSnapshotMode) { 0 }
        else {
            [int](Get-InspectorObjectInsightProperty -InputObject (Get-InspectorObjectInsightProperty -InputObject $telemetry -Name 'GraphRequestSummary') -Name 'TotalRequests')
        }

    $snapshotComparison = $null
    if (-not [string]::IsNullOrWhiteSpace($CompareToSnapshotPath)) {
        $previousSnapshot = Import-InspectorTenantSnapshot -Path $CompareToSnapshotPath
        $snapshotComparison = Compare-InspectorTenantSnapshots -PreviousSnapshot $previousSnapshot -CurrentSnapshot $snapshot
    }

    $discovery =
        ConvertFrom-InspectorTenantSnapshot `
            -TenantSnapshot $snapshot `
            -ObjectType $effectiveObjectType

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
    Start-InspectorTelemetryStage -Telemetry $telemetry -Name 'OfflineProcessing'
    Update-InspectorTelemetryMemorySample -Telemetry $telemetry
    $total = @($objectsToProcess).Count
    $processed = 0
    $totalRetryAttempts = 0

    for ($index = 0; $index -lt $objectsToProcess.Count; $index += $BatchSize) {
        $batch = @($objectsToProcess | Select-Object -Skip $index -First $BatchSize)

        foreach ($object in $batch) {
            $processed++
            if (($processed % 10) -eq 0 -or $processed -eq $total) {
                Update-InspectorTelemetryMemorySample -Telemetry $telemetry
            }

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

    Stop-InspectorTelemetryStage -Telemetry $telemetry -Name 'OfflineProcessing'
    Update-InspectorTelemetryMemorySample -Telemetry $telemetry
    $offlineProcessingStage = $telemetry.StageDurations['OfflineProcessing']
    $offlineProcessingDurationForShare = if ($null -ne $offlineProcessingStage) { [double]$offlineProcessingStage.DurationMs } else { 0.0 }
    if ($offlineProcessingDurationForShare -gt 0) {
        foreach ($offlineChildStageName in @('OfflineResolution','OfflineRelationshipBuilding','Normalization','PermissionIntelligence','ObservationEngine')) {
            if ($telemetry.StageDurations.Contains($offlineChildStageName)) {
                $offlineChildStage = $telemetry.StageDurations[$offlineChildStageName]
                $offlineChildStage | Add-Member -NotePropertyName ShareOfOfflineProcessingPercent -NotePropertyValue ([math]::Round(([double]$offlineChildStage.DurationMs / $offlineProcessingDurationForShare) * 100.0, 2)) -Force
            }
        }
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

    $crossObjectSecurityObservations = @(
        Get-InspectorCrossObjectSecurityObservations -ObjectInsights @($objectInsights)
    )
    $securityObservations = @($securityObservations + $crossObjectSecurityObservations)

    $policyResult = Invoke-InspectorAssessmentPolicy -Observations $securityObservations -SnapshotComparison $snapshotComparison -RulePackPath $RulePackPath -BaselinePath $BaselinePath
    $securityObservations = @($policyResult.Observations)
    $snapshotComparison = $policyResult.SnapshotComparison

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
    Complete-InspectorTelemetryMemorySummary -Telemetry $telemetry
    Update-InspectorTelemetryDerivedMetrics -Telemetry $telemetry
    $telemetry.ObjectProcessingSummary.ObjectsProcessed = $pipeline.ProcessedCount
    $telemetry.ObjectProcessingSummary.ObjectsSucceeded = @($objectInsights | Where-Object Status -eq 'Resolved').Count
    $telemetry.ObjectProcessingSummary.ObjectsFailed = $pipeline.FailedCount
    $telemetry.ObjectProcessingSummary.ObjectsSkipped = $pipeline.SkippedCount
    $telemetry.ObjectProcessingSummary.RetryAttempts = $pipeline.RetryAttemptCount
    $telemetry.ObjectProcessingSummary.ResumeReplayCount = $pipeline.ResumeReplayCount
    $telemetry.RetrySummary.ObjectProcessingRetries = $pipeline.RetryAttemptCount
    $telemetry.ThroughputSummary.ObjectsProcessed = $pipeline.ProcessedCount
    $offlineDurationMs = [double](Get-InspectorObjectInsightProperty -InputObject ($telemetry.StageDurations['OfflineProcessing']) -Name 'DurationMs')
    $telemetry.ThroughputSummary.OfflineProcessingDurationMs = $(if($offlineDurationMs -gt 0){[int]$offlineDurationMs}else{$null})
    $telemetry.ThroughputSummary.ObjectsPerSecond =
        if ($offlineDurationMs -gt 0) {
            [math]::Round($pipeline.ProcessedCount / ($offlineDurationMs / 1000.0), 2)
        }
        else {
            $null
        }
    $telemetry.ThroughputSummary.EndToEndObjectsPerSecond =
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

    $tenantCapabilities =
        Get-InspectorObjectInsightProperty `
            -InputObject $snapshot `
            -Name 'TenantCapabilities'

    $result = [PSCustomObject][ordered]@{
        PSTypeName                      = 'EntraObjectInspector.TenantInspectionResult'
        SchemaVersion                   = '0.7.0'
        StartedAt                       = $startedAt
        CompletedAt                     = $completedAt
        Status                          = $status
        Completeness                    = $(if ($status -eq 'Success') { 'Complete' } else { 'Partial' })
        ObjectTypes                     = @($effectiveObjectType | Sort-Object -Unique)
        SnapshotMode                    = $(if($offlineSnapshotMode){'PortableFile'}elseif(@($targetSpecification).Count -gt 0){'TargetedInMemory'}else{'InMemory'})
        PortableSnapshotPath            = $(if(-not [string]::IsNullOrWhiteSpace($SaveSnapshotPath)){$SaveSnapshotPath}elseif($offlineSnapshotMode){$SnapshotPath}else{''})
        CollectionScope                 = $collectionScope
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
        TenantCapabilities              = $tenantCapabilities
        Pipeline                        = $pipeline
        ObjectInsights                  = @($objectInsights)
        SecurityObservations            = @($securityObservations)
        FailedObjects                   = @($failedObjects)
        Logs                            = @($logs)
        Limitations                     = @($resultLimitations | Select-Object -Unique)
        RuntimeTelemetry                = $telemetry
        SnapshotComparison              = $snapshotComparison
        Changes                         = $(if($null -ne $snapshotComparison){@($snapshotComparison.Changes)}else{@()})
        AssessmentPolicy                = $policyResult
        TenantSnapshot                  = $snapshot
        Summary                         = [PSCustomObject][ordered]@{
            TenantId                    = Get-InspectorObjectInsightProperty -InputObject $tenantMetadata -Name 'TenantId'
            TenantDisplayName           = Get-InspectorObjectInsightProperty -InputObject $tenantMetadata -Name 'TenantDisplayName'
            TenantMetadata              = $tenantMetadata
            ScopeInventory              = $scopeInventory
            TenantCapabilities          = $tenantCapabilities
            AssessmentCoverage          = $assessmentCoverage
            DiscoveredCount             = $discovery.TotalCount
            ProcessedCount              = $pipeline.ProcessedCount
            FailedCount                 = $pipeline.FailedCount
            SkippedCount                = $pipeline.SkippedCount
            ResumeReplayCount           = $pipeline.ResumeReplayCount
            RetryAttemptCount           = $pipeline.RetryAttemptCount
            ObjectInsightCount          = @($objectInsights).Count
            SecurityObservationCount    = @($securityObservations).Count
            ChangeCount                 = $(if($null -ne $snapshotComparison){[int]$snapshotComparison.ChangeCount}else{0})
            AcceptedObservationCount    = [int](Get-InspectorSnapshotProperty -InputObject $policyResult -Name 'AcceptedObservationCount')
            CustomObservationCount      = [int](Get-InspectorSnapshotProperty -InputObject $policyResult -Name 'CustomObservationCount')
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
