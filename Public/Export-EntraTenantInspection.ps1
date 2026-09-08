function Export-EntraTenantInspection {
    <#
    .SYNOPSIS
        Exports an existing tenant inspection result into reviewable artifacts.

    .DESCRIPTION
        Assessment output/export layer.

        This command consumes a completed TenantInspectionResult and optional
        AssessmentIntelligence object, then writes deterministic JSON,
        CSV, and Markdown artifacts. It does not call Microsoft Graph, rerun
        discovery, invoke collectors, or generate new assessment intelligence.

    .PARAMETER InputObject
        TenantInspectionResult returned by Invoke-EntraTenantInspection.

    .PARAMETER AssessmentIntelligence
        Optional AssessmentIntelligence object returned by
        Invoke-EntraAssessmentIntelligence. If omitted, the exporter checks
        InputObject.AssessmentIntelligence.

    .PARAMETER OutputDirectory
        Base output directory. A run-specific child directory is created.

    .PARAMETER AssessmentName
        Human-readable assessment name used in manifest and Markdown.

    .PARAMETER NoCsv
        Suppresses CSV artifacts.

    .PARAMETER NoMarkdown
        Suppresses Markdown summary artifact.

    .PARAMETER Force
        Allows writing into an existing export directory when ExportDirectoryName is specified.
    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            ValueFromPipeline
        )]
        [object]$InputObject,

        [AllowNull()]
        [object]$AssessmentIntelligence,

        [string]$OutputDirectory = '.\EntraObjectInspector-Exports',

        [string]$AssessmentName = 'Entra Object Inspector Assessment',

        [string]$RunId = '',

        [string]$ReportId = '',

        [string]$ExportDirectoryName,

        [switch]$NoCsv,

        [switch]$NoMarkdown,

        [switch]$IncludeFullObjectInsights,

        [switch]$Force
    )

    process {
        $totalExportStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $modelBuildStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $jsonWriteElapsedMs = 0
        $csvWriteElapsedMs = 0
        $markdownWriteElapsedMs = 0
        $manifestFinalizeElapsedMs = 0
        $workingSetSamples = [System.Collections.Generic.List[double]]::new()
        $workingSetStartMB = Get-InspectorExportWorkingSetMB
        if ($null -ne $workingSetStartMB) {
            $workingSetSamples.Add([double]$workingSetStartMB)
        }

        $exportModel =
            ConvertTo-InspectorAssessmentExport `
                -InputObject $InputObject `
                -AssessmentName $AssessmentName `
                -AssessmentIntelligence $AssessmentIntelligence `
                -RunId $RunId `
                -ReportId $ReportId `
                -IncludeFullObjectInsights:$IncludeFullObjectInsights

        $modelBuildStopwatch.Stop()
        $workingSetAfterModelMB = Get-InspectorExportWorkingSetMB
        if ($null -ne $workingSetAfterModelMB) {
            $workingSetSamples.Add([double]$workingSetAfterModelMB)
        }

        $timestamp =
            (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')

        if ([string]::IsNullOrWhiteSpace($ExportDirectoryName)) {
            $safeName =
                ConvertTo-InspectorSafeFileName `
                    -Name $AssessmentName

            $ExportDirectoryName = "$safeName-$timestamp"
        }
        else {
            $ExportDirectoryName =
                ConvertTo-InspectorSafeFileName `
                    -Name $ExportDirectoryName
        }

        $targetDirectory =
            Join-Path `
                -Path $OutputDirectory `
                -ChildPath $ExportDirectoryName

        if ((Test-Path -LiteralPath $targetDirectory) -and -not $Force) {
            throw "Export directory already exists: $targetDirectory. Use -Force or choose another ExportDirectoryName."
        }

        New-Item `
            -ItemType Directory `
            -Path $targetDirectory `
            -Force |
            Out-Null

        $artifactRecords = [System.Collections.Generic.List[object]]::new()

        $manifestPath = Join-Path $targetDirectory 'assessment-manifest.json'
        $summaryPath = Join-Path $targetDirectory 'assessment-summary.json'
        $observationsJsonPath = Join-Path $targetDirectory 'security-observations.json'
        $fullObjectInsightsPath = Join-Path $targetDirectory 'object-insights-full.json'
        $objectIndexPath = Join-Path $targetDirectory 'object-index.json'
        $evidencePath = Join-Path $targetDirectory 'evidence-index.json'
        $failedObjectsPath = Join-Path $targetDirectory 'failed-objects.json'
        $logsPath = Join-Path $targetDirectory 'execution-log.json'
        $intelligencePath = Join-Path $targetDirectory 'assessment-intelligence.json'
        $tenantPosturePath = Join-Path $targetDirectory 'tenant-posture.json'
        $findingsJsonPath = Join-Path $targetDirectory 'assessment-findings.json'
        $recommendationsJsonPath = Join-Path $targetDirectory 'assessment-recommendations.json'
        $correlationsJsonPath = Join-Path $targetDirectory 'assessment-correlations.json'
        $limitationsJsonPath = Join-Path $targetDirectory 'assessment-limitations.json'
        $changesJsonPath = Join-Path $targetDirectory 'snapshot-changes.json'

        $jsonWriteStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        Write-InspectorJsonFile -Path $summaryPath -Value $exportModel.Summary
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-summary.json' -Kind 'json' -Path $summaryPath -RecordCount 1))

        Write-InspectorJsonFile -Path $observationsJsonPath -Value $exportModel.SecurityObservations
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'security-observations.json' -Kind 'json' -Path $observationsJsonPath -RecordCount @($exportModel.SecurityObservations).Count))

        if ($IncludeFullObjectInsights) {
            Write-InspectorJsonFile -Path $fullObjectInsightsPath -Value $exportModel.FullObjectInsights -Depth 80
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'object-insights-full.json' -Kind 'json' -Path $fullObjectInsightsPath -RecordCount @($exportModel.FullObjectInsights).Count))
        }

        Write-InspectorJsonFile -Path $objectIndexPath -Value $exportModel.ObjectIndexRows
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'object-index.json' -Kind 'json' -Path $objectIndexPath -RecordCount @($exportModel.ObjectIndexRows).Count))

        Write-InspectorJsonFile -Path $evidencePath -Value $exportModel.EvidenceRows
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'evidence-index.json' -Kind 'json' -Path $evidencePath -RecordCount @($exportModel.EvidenceRows).Count))

        Write-InspectorJsonFile -Path $failedObjectsPath -Value $exportModel.FailedObjectRows
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'failed-objects.json' -Kind 'json' -Path $failedObjectsPath -RecordCount @($exportModel.FailedObjectRows).Count))

        Write-InspectorJsonFile -Path $logsPath -Value $exportModel.LogRows
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'execution-log.json' -Kind 'json' -Path $logsPath -RecordCount @($exportModel.LogRows).Count))

        Write-InspectorJsonFile -Path $intelligencePath -Value $exportModel.AssessmentIntelligence -Depth 40
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-intelligence.json' -Kind 'json' -Path $intelligencePath -RecordCount $(if ($null -ne $exportModel.AssessmentIntelligence) { 1 } else { 0 })))

        Write-InspectorJsonFile -Path $tenantPosturePath -Value $exportModel.TenantPosture
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'tenant-posture.json' -Kind 'json' -Path $tenantPosturePath -RecordCount $(if ($null -ne $exportModel.TenantPosture) { 1 } else { 0 })))

        Write-InspectorJsonFile -Path $findingsJsonPath -Value $exportModel.AssessmentFindings
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-findings.json' -Kind 'json' -Path $findingsJsonPath -RecordCount @($exportModel.AssessmentFindings).Count))

        Write-InspectorJsonFile -Path $recommendationsJsonPath -Value $exportModel.AssessmentRecommendations
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-recommendations.json' -Kind 'json' -Path $recommendationsJsonPath -RecordCount @($exportModel.AssessmentRecommendations).Count))

        Write-InspectorJsonFile -Path $correlationsJsonPath -Value $exportModel.AssessmentCorrelations
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-correlations.json' -Kind 'json' -Path $correlationsJsonPath -RecordCount @($exportModel.AssessmentCorrelations).Count))

        Write-InspectorJsonFile -Path $limitationsJsonPath -Value $exportModel.AssessmentLimitationRows
        $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-limitations.json' -Kind 'json' -Path $limitationsJsonPath -RecordCount @($exportModel.AssessmentLimitationRows).Count))

        if ($null -ne $exportModel.SnapshotComparison) {
            Write-InspectorJsonFile -Path $changesJsonPath -Value $exportModel.SnapshotChanges -Depth 40
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'snapshot-changes.json' -Kind 'json' -Path $changesJsonPath -RecordCount @($exportModel.SnapshotChanges).Count))
        }

        $jsonWriteStopwatch.Stop()
        $jsonWriteElapsedMs = $jsonWriteStopwatch.ElapsedMilliseconds
        $workingSetAfterJsonMB = Get-InspectorExportWorkingSetMB
        if ($null -ne $workingSetAfterJsonMB) {
            $workingSetSamples.Add([double]$workingSetAfterJsonMB)
        }

        if (-not $NoCsv) {
            $csvWriteStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $observationsCsvPath = Join-Path $targetDirectory 'security-observations.csv'
            $objectIndexCsvPath = Join-Path $targetDirectory 'object-index.csv'
            $evidenceCsvPath = Join-Path $targetDirectory 'evidence-index.csv'
            $failedObjectsCsvPath = Join-Path $targetDirectory 'failed-objects.csv'
            $logsCsvPath = Join-Path $targetDirectory 'execution-log.csv'
            $findingsCsvPath = Join-Path $targetDirectory 'assessment-findings.csv'
            $recommendationsCsvPath = Join-Path $targetDirectory 'assessment-recommendations.csv'
            $correlationsCsvPath = Join-Path $targetDirectory 'assessment-correlations.csv'
            $limitationsCsvPath = Join-Path $targetDirectory 'assessment-limitations.csv'
            $changesCsvPath = Join-Path $targetDirectory 'snapshot-changes.csv'

            Write-InspectorCsvFile -Path $observationsCsvPath -Rows $exportModel.SecurityObservationRows -Header @('ObservationId','Category','Severity','Confidence','BaselineState','Title','Description','AffectedObjectType','AffectedObjectId','AffectedDisplayName','EvidenceIds','MicrosoftReference','WhyItMatters','Limitations','Recommendation','SourceRuleIds','Metadata')
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'security-observations.csv' -Kind 'csv' -Path $observationsCsvPath -RecordCount @($exportModel.SecurityObservationRows).Count))

            Write-InspectorCsvFile -Path $objectIndexCsvPath -Rows $exportModel.ObjectIndexRows -Header @('Input','Status','ResolutionType','DiscoveryObjectType','DiscoveryObjectId','DisplayName','RelationshipStatus','RelationshipCompleteness','SourceObjectCount','RelationshipCount','ArtifactCount','EvidenceCount','DirectEvidenceCount','EvidenceSampleIds','EvidenceTruncated','EvidenceMappingStatus','EvidenceMappingLimitation','RuleResultCount','PermissionInsightCount','SecurityObservationCount','FindingEligibleObservationCount','FindingCount','Limitations')
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'object-index.csv' -Kind 'csv' -Path $objectIndexCsvPath -RecordCount @($exportModel.ObjectIndexRows).Count))

            Write-InspectorCsvFile -Path $evidenceCsvPath -Rows $exportModel.EvidenceRows -Header @('ParentInput','ParentResolutionType','EvidenceId','QueryName','CollectorName','Endpoint','RequiredPermission','CollectionTime','Status','ResultCount','SourceResultCount','Completeness','Limitations','EvidenceScope','SubjectObjectType','SubjectObjectId')
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'evidence-index.csv' -Kind 'csv' -Path $evidenceCsvPath -RecordCount @($exportModel.EvidenceRows).Count))

            Write-InspectorCsvFile -Path $failedObjectsCsvPath -Rows $exportModel.FailedObjectRows -Header @('ObjectKey','ObjectType','ObjectId','InspectionIdentity','Attempts','Error')
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'failed-objects.csv' -Kind 'csv' -Path $failedObjectsCsvPath -RecordCount @($exportModel.FailedObjectRows).Count))

            Write-InspectorCsvFile -Path $logsCsvPath -Rows $exportModel.LogRows -Header @('Timestamp','Stage','Level','Message','Data')
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'execution-log.csv' -Kind 'csv' -Path $logsCsvPath -RecordCount @($exportModel.LogRows).Count))

            Write-InspectorCsvFile -Path $findingsCsvPath -Rows $exportModel.AssessmentFindingRows -Header @('FindingId','Category','Severity','Confidence','ResultState','EvidenceLinkStatus','EvidenceSupportStatus','ContributingObservationCount','DirectEvidenceObservationCount','DerivedEvidenceObservationCount','UnsupportedObservationCount','UniqueEvidenceCount','DirectEvidenceCoveragePercent','Title','Conclusion','WhatHappened','WhyItMatters','RecommendedAction','BaselineState','EvidenceProof','CriterionSummary','SeverityReason','ObservationCount','AffectedObjectCount','ObservationIds','EvidenceIds','MicrosoftReference','Recommendation','RecommendationNotApplicable','Limitations','AffectedObjects','IssueGroups','Metadata')
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-findings.csv' -Kind 'csv' -Path $findingsCsvPath -RecordCount @($exportModel.AssessmentFindingRows).Count))

            Write-InspectorCsvFile -Path $recommendationsCsvPath -Rows $exportModel.AssessmentRecommendationRows -Header @('RecommendationId','Category','Confidence','Title','Action','Rationale','MicrosoftReference','ObservationIds','EvidenceIds','Limitations')
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-recommendations.csv' -Kind 'csv' -Path $recommendationsCsvPath -RecordCount @($exportModel.AssessmentRecommendationRows).Count))

            Write-InspectorCsvFile -Path $correlationsCsvPath -Rows $exportModel.AssessmentCorrelationRows -Header @('CorrelationId','CorrelationType','Confidence','Title','Description','ObservationIds','EvidenceIds','AffectedObjects','Limitations')
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-correlations.csv' -Kind 'csv' -Path $correlationsCsvPath -RecordCount @($exportModel.AssessmentCorrelationRows).Count))

            Write-InspectorCsvFile -Path $limitationsCsvPath -Rows $exportModel.AssessmentLimitationRows -Header @('Limitation')
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-limitations.csv' -Kind 'csv' -Path $limitationsCsvPath -RecordCount @($exportModel.AssessmentLimitationRows).Count))

            if ($null -ne $exportModel.SnapshotComparison) {
                Write-InspectorCsvFile -Path $changesCsvPath -Rows $exportModel.SnapshotChangeRows -Header @('ChangeId','ChangeType','Category','SemanticKey','SubjectObjectType','SubjectObjectId','RelatedObjectId','BaselineState','PreviousEvidenceIds','CurrentEvidenceIds','PreviousValue','CurrentValue')
                $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'snapshot-changes.csv' -Kind 'csv' -Path $changesCsvPath -RecordCount @($exportModel.SnapshotChangeRows).Count))
            }

            $csvWriteStopwatch.Stop()
            $csvWriteElapsedMs = $csvWriteStopwatch.ElapsedMilliseconds
            $workingSetAfterCsvMB = Get-InspectorExportWorkingSetMB
            if ($null -ne $workingSetAfterCsvMB) {
                $workingSetSamples.Add([double]$workingSetAfterCsvMB)
            }
        }

        $markdownPath = Join-Path $targetDirectory 'assessment-summary.md'
        if (-not $NoMarkdown) {
            $artifactRecords.Add((New-InspectorExportArtifactRecord -Name 'assessment-summary.md' -Kind 'markdown' -Path $markdownPath -RecordCount 1))
        }

        $artifactRecords.Insert(0, (New-InspectorExportArtifactRecord -Name 'assessment-manifest.json' -Kind 'json' -Path $manifestPath -RecordCount 1))
        $exportModel.Manifest.Artifacts = @($artifactRecords)

        Write-InspectorJsonFile -Path $manifestPath -Value $exportModel.Manifest

        if (-not $NoMarkdown) {
            $markdownWriteStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            New-InspectorAssessmentMarkdown `
                -ExportModel $exportModel |
                Set-Content `
                    -LiteralPath $markdownPath `
                    -Encoding UTF8 `
                    -Force

            $markdownWriteStopwatch.Stop()
            $markdownWriteElapsedMs = $markdownWriteStopwatch.ElapsedMilliseconds
            $workingSetAfterMarkdownMB = Get-InspectorExportWorkingSetMB
            if ($null -ne $workingSetAfterMarkdownMB) {
                $workingSetSamples.Add([double]$workingSetAfterMarkdownMB)
            }
        }

        $manifestFinalizeStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        # Finalize physical artifact sizes after every requested artifact exists.
        # A few passes allow the manifest's own SizeBytes entry to converge after
        # rewriting the manifest with the refreshed inventory.
        for ($artifactRefreshPass = 0; $artifactRefreshPass -lt 3; $artifactRefreshPass++) {
            Update-InspectorExportArtifactSizes -Manifest $exportModel.Manifest -BasePath $targetDirectory
            Write-InspectorJsonFile -Path $manifestPath -Value $exportModel.Manifest
        }

        $manifestFinalizeStopwatch.Stop()
        $manifestFinalizeElapsedMs = $manifestFinalizeStopwatch.ElapsedMilliseconds
        $workingSetEndMB = Get-InspectorExportWorkingSetMB
        if ($null -ne $workingSetEndMB) {
            $workingSetSamples.Add([double]$workingSetEndMB)
        }
        $totalExportStopwatch.Stop()

        $peakObservedWorkingSetMB =
            if ($workingSetSamples.Count -gt 0) {
                [math]::Round(
                    [double](($workingSetSamples | Measure-Object -Maximum).Maximum),
                    2
                )
            }
            else {
                $null
            }

        $largestArtifacts =
            @(
                $artifactRecords |
                    Sort-Object SizeBytes -Descending |
                    Select-Object -First 5 |
                    ForEach-Object {
                        [PSCustomObject][ordered]@{
                            Name        = $_.Name
                            Kind        = $_.Kind
                            RecordCount = $_.RecordCount
                            SizeBytes   = $_.SizeBytes
                        }
                    }
            )

        $performanceProfile = [PSCustomObject][ordered]@{
            SchemaVersion              = '1.0.0'
            TotalDurationMs            = $totalExportStopwatch.ElapsedMilliseconds
            ModelBuildDurationMs       = $modelBuildStopwatch.ElapsedMilliseconds
            JsonWriteDurationMs        = $jsonWriteElapsedMs
            CsvWriteDurationMs         = $csvWriteElapsedMs
            MarkdownWriteDurationMs    = $markdownWriteElapsedMs
            ManifestFinalizeDurationMs = $manifestFinalizeElapsedMs
            WorkingSetStartMB          = $workingSetStartMB
            WorkingSetAfterModelMB     = $workingSetAfterModelMB
            WorkingSetEndMB            = $workingSetEndMB
            PeakObservedWorkingSetMB   = $peakObservedWorkingSetMB
            LargestArtifacts           = @($largestArtifacts)
        }

        return [PSCustomObject][ordered]@{
            PSTypeName                     = 'EntraObjectInspector.AssessmentExportResult'
            SchemaVersion                  = '0.10.0'
            Status                         = 'Success'
            AssessmentName                 = $AssessmentName
            RunId                          = $exportModel.Manifest.RunId
            ReportId                       = $exportModel.Manifest.ReportId
            ExportDirectory                = $targetDirectory
            ManifestPath                   = $manifestPath
            AssessmentIntelligenceIncluded = $exportModel.Manifest.AssessmentIntelligenceIncluded
            ArtifactCount                  = @($artifactRecords).Count
            Artifacts                      = @($artifactRecords)
            GraphCallsIssued               = 0
            IntelligenceAdded              = $false
            FailedObjectCount              = $exportModel.Manifest.FailedObjectCount
            PackageValidationStatus        = $exportModel.Manifest.PackageValidationStatus
            ReleaseEligible                = $exportModel.Manifest.ReleaseEligible
            PerformanceProfile             = $performanceProfile
        }
    }
}

