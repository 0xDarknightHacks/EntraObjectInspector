function Get-InspectorReportObservationsFromObject {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject
    )

    $rootObservations =
        @(
            Get-InspectorReportProperty `
                -InputObject $InputObject `
                -Name 'SecurityObservations'
        ) |
        Where-Object { $null -ne $_ }

    if ($rootObservations.Count -gt 0) {
        return @($rootObservations)
    }

    $objectInsights =
        @(
            Get-InspectorReportProperty `
                -InputObject $InputObject `
                -Name 'ObjectInsights'
        ) |
        Where-Object { $null -ne $_ }

    return @(
        $objectInsights |
        ForEach-Object {
            @(
                Get-InspectorReportProperty `
                    -InputObject $_ `
                    -Name 'SecurityObservations'
            )
        } |
        Where-Object { $null -ne $_ }
    )
}

function Get-InspectorReportIntelligenceFromObject {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject,

        [AllowNull()]
        [object]$AssessmentIntelligence
    )

    if ($null -ne $AssessmentIntelligence) {
        return $AssessmentIntelligence
    }

    return Get-InspectorReportProperty `
        -InputObject $InputObject `
        -Name 'AssessmentIntelligence'
}

function Get-InspectorReportModelFromDirectory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ExportDirectory,

        [string]$AssessmentName = 'Entra Object Inspector Assessment',

        [string]$ClientName = '',

        [string]$ConsultantName = ''
    )

    if (-not (Test-Path -LiteralPath $ExportDirectory -PathType Container)) {
        throw "Export directory was not found: $ExportDirectory"
    }

    $manifest =
        Read-InspectorReportJsonFile `
            -Path (Join-Path $ExportDirectory 'assessment-manifest.json')

    $summary =
        Read-InspectorReportJsonFile `
            -Path (Join-Path $ExportDirectory 'assessment-summary.json')

    $observations =
        @(
            Read-InspectorReportJsonFile `
                -Path (Join-Path $ExportDirectory 'security-observations.json')
        ) |
        Where-Object { $null -ne $_ }

    $objectIndex =
        @(
            Read-InspectorReportJsonFile `
                -Path (Join-Path $ExportDirectory 'object-index.json')
        ) |
        Where-Object { $null -ne $_ }

    $evidence =
        @(
            Read-InspectorReportJsonFile `
                -Path (Join-Path $ExportDirectory 'evidence-index.json')
        ) |
        Where-Object { $null -ne $_ }

    $evidence =
        @(
            $evidence |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace(
                        [string](Get-InspectorReportProperty -InputObject $_ -Name 'EvidenceId')
                    )
                } |
                Sort-Object EvidenceId -Unique
        )

    $failedObjects =
        @(
            Read-InspectorReportJsonFile `
                -Path (Join-Path $ExportDirectory 'failed-objects.json')
        ) |
        Where-Object { $null -ne $_ }

    $intelligence =
        Read-InspectorReportJsonFile `
            -Path (Join-Path $ExportDirectory 'assessment-intelligence.json')

    $tenantPosture =
        Read-InspectorReportJsonFile `
            -Path (Join-Path $ExportDirectory 'tenant-posture.json')

    $findings =
        @(
            Read-InspectorReportJsonFile `
                -Path (Join-Path $ExportDirectory 'assessment-findings.json')
        ) |
        Where-Object { $null -ne $_ }

    $recommendations =
        @(
            Read-InspectorReportJsonFile `
                -Path (Join-Path $ExportDirectory 'assessment-recommendations.json')
        ) |
        Where-Object { $null -ne $_ }

    $correlations =
        @(
            Read-InspectorReportJsonFile `
                -Path (Join-Path $ExportDirectory 'assessment-correlations.json')
        ) |
        Where-Object { $null -ne $_ }

    $limitations =
        @(
            @(
                Read-InspectorReportJsonFile `
                    -Path (Join-Path $ExportDirectory 'assessment-limitations.json')
            ) |
            Where-Object { $null -ne $_ } |
            ForEach-Object {
                $limitation =
                    Get-InspectorReportProperty `
                        -InputObject $_ `
                        -Name 'Limitation'

                if ($null -ne $limitation) {
                    [string]$limitation
                }
                else {
                    [string]$_
                }
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )

    return ConvertTo-InspectorReportModel `
        -AssessmentName $AssessmentName `
        -Manifest $manifest `
        -Summary $summary `
        -SecurityObservations $observations `
        -ObjectIndex $objectIndex `
        -EvidenceRows $evidence `
        -FailedObjects $failedObjects `
        -AssessmentIntelligence $intelligence `
        -TenantPosture $tenantPosture `
        -AssessmentFindings $findings `
        -AssessmentRecommendations $recommendations `
        -AssessmentCorrelations $correlations `
        -AssessmentLimitations $limitations `
        -ClientName $ClientName `
        -ConsultantName $ConsultantName `
        -SourceKind 'ExportDirectory' `
        -SourcePath $ExportDirectory
}

function Get-InspectorReportFirstValue {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object[]]$InputObjects,

        [string[]]$Names
    )

    foreach ($inputObject in @($InputObjects)) {
        foreach ($name in @($Names)) {
            $value =
                Get-InspectorReportProperty `
                    -InputObject $inputObject `
                    -Name $name

            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                return $value
            }
        }
    }

    return $null
}

function Get-InspectorReportModuleVersion {
    [CmdletBinding()]
    param ()

    $module = Get-Module -Name EntraObjectInspector

    if ($null -ne $module -and $null -ne $module.Version) {
        return [string]$module.Version
    }

    return ''
}

function ConvertTo-InspectorReportObservationGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object[]]$SecurityObservations
    )

    return @(
        @($SecurityObservations) |
        Where-Object { $null -ne $_ } |
        Group-Object {
            $category =
                ConvertTo-InspectorReportString `
                    (Get-InspectorReportProperty -InputObject $_ -Name 'Category')

            $severity =
                ConvertTo-InspectorReportString `
                    (Get-InspectorReportProperty -InputObject $_ -Name 'Severity')

            $confidence =
                ConvertTo-InspectorReportString `
                    (Get-InspectorReportProperty -InputObject $_ -Name 'Confidence')

            $title =
                ConvertTo-InspectorReportString `
                    (Get-InspectorReportProperty -InputObject $_ -Name 'Title')

            "$category|$severity|$confidence|$title"
        } |
        ForEach-Object {
            $first = @($_.Group)[0]

            [PSCustomObject][ordered]@{
                Category     = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $first -Name 'Category')
                Severity     = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $first -Name 'Severity')
                Confidence   = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $first -Name 'Confidence')
                Title        = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $first -Name 'Title')
                Count        = @($_.Group).Count
                WhyItMatters = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $first -Name 'WhyItMatters')
                Recommendation = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $first -Name 'Recommendation')
                Observations = @($_.Group)
                ObservationIds = @(
                    @($_.Group) |
                    ForEach-Object {
                        Get-InspectorReportProperty `
                            -InputObject $_ `
                            -Name 'ObservationId'
                    } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                    Select-Object -Unique
                )
                AffectedObjects = @(
                    @($_.Group) |
                    ForEach-Object {
                        Get-InspectorReportObservationDisplayName -Observation $_
                    } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                    Select-Object -Unique
                )
            }
        } |
        Sort-Object {
            Get-InspectorReportSeverityOrder -Severity $_.Severity
        }, Category, Title
    )
}

function Test-InspectorReportPackageConsistency {
    [CmdletBinding()]
    param (
        [AllowNull()][object]$Summary,
        [object[]]$SecurityObservations = @(),
        [object[]]$EvidenceRows = @(),
        [object[]]$AssessmentFindings = @(),
        [object[]]$FailedObjects = @(),
        [AllowNull()][object]$Manifest,
        [string]$SourcePath = ''
    )

    $errors = [System.Collections.Generic.List[object]]::new()
    $warnings = [System.Collections.Generic.List[object]]::new()
    $seenErrorIds = @{}
    $seenWarningIds = @{}

    function Add-PackageValidationError {
        param (
            [string]$ErrorId,
            [string]$Message,
            [string]$AffectedInvariant
        )

        if ($seenErrorIds.ContainsKey($ErrorId)) {
            return
        }

        $seenErrorIds[$ErrorId] = $true
        $errors.Add(
            [PSCustomObject][ordered]@{
                ErrorId = $ErrorId
                Message = $Message
                AffectedInvariant = $AffectedInvariant
            }
        )
    }

    function Add-PackageValidationWarning {
        param (
            [string]$WarningId,
            [string]$Message,
            [string]$AffectedInvariant
        )

        if ($seenWarningIds.ContainsKey($WarningId)) {
            return
        }

        $seenWarningIds[$WarningId] = $true
        $warnings.Add(
            [PSCustomObject][ordered]@{
                WarningId = $WarningId
                Message = $Message
                AffectedInvariant = $AffectedInvariant
            }
        )
    }

    $manifestHasValidationEnvelope =
        $null -ne $Manifest -and
        (
            $null -ne $Manifest.PSObject.Properties['PackageValidationStatus'] -or
            $null -ne $Manifest.PSObject.Properties['ReleaseEligible']
        )
    $summaryHasValidationEnvelope =
        $null -ne $Summary -and
        (
            $null -ne $Summary.PSObject.Properties['PackageValidationStatus'] -or
            $null -ne $Summary.PSObject.Properties['ReleaseEligible']
        )
    $manifestSchemaVersion = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $Manifest -Name 'SchemaVersion')
    $summarySchemaVersion = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $Summary -Name 'SchemaVersion')
    $manifestHasCurrentSchema = $manifestSchemaVersion -eq '0.10.0'
    $summaryHasCurrentSchema = $summarySchemaVersion -eq '0.10.0'
    $isCurrentPackageEnvelope =
        $manifestHasValidationEnvelope -or
        $summaryHasValidationEnvelope -or
        $manifestHasCurrentSchema -or
        $summaryHasCurrentSchema

    $isCurrentPackageSchema = $manifestHasCurrentSchema -or $summaryHasCurrentSchema

    $raw = Get-InspectorReportProperty -InputObject $Summary -Name 'RawObservationCount'
    $deduped = Get-InspectorReportProperty -InputObject $Summary -Name 'DeduplicatedObservationCount'
    $duplicate = Get-InspectorReportProperty -InputObject $Summary -Name 'DuplicateObservationCount'
    $scopeInventory = Get-InspectorReportProperty -InputObject $Summary -Name 'ScopeInventory'
    if ($null -eq $scopeInventory) {
        $scopeInventory = Get-InspectorReportProperty -InputObject $Manifest -Name 'ScopeInventory'
    }

    $scopeHasCollectionCompleteness =
        $null -ne $scopeInventory -and
        $null -ne $scopeInventory.PSObject.Properties['CollectionCompleteness']
    $scopeCollectionCompleteness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $scopeInventory -Name 'CollectionCompleteness')
    $truncatedCollections = @(Get-InspectorReportProperty -InputObject $scopeInventory -Name 'TruncatedCollections') |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    $scopeIsComplete =
        (
            $null -ne $scopeInventory -and
            $scopeHasCollectionCompleteness -and
            $scopeCollectionCompleteness -eq 'Complete' -and
            (@($truncatedCollections).Count -eq 0)
        )

    if ($isCurrentPackageSchema -and $null -eq $scopeInventory) {
        Add-PackageValidationError -ErrorId 'PKG-SCOPE-MISSING-001' -Message 'Current assessment package is missing ScopeInventory.' -AffectedInvariant 'current assessment packages include a non-null ScopeInventory envelope'
    }

    if (-not $scopeIsComplete -and ($isCurrentPackageSchema -or $null -ne $scopeInventory)) {
        Add-PackageValidationError -ErrorId 'PKG-SCOPE-INCOMPLETE-001' -Message 'Assessment scope completeness is not Complete; release eligibility cannot be established.' -AffectedInvariant 'ScopeInventory.CollectionCompleteness == Complete for current release-eligible assessment packages'
    }

    if ($null -ne $raw -and $null -ne $deduped -and $null -ne $duplicate -and ([int]$raw -ne ([int]$deduped + [int]$duplicate))) {
        Add-PackageValidationError -ErrorId 'PKG-COUNT-OBSERVATION-001' -Message 'RawObservationCount does not equal DeduplicatedObservationCount plus DuplicateObservationCount.' -AffectedInvariant 'RawObservationCount == DeduplicatedObservationCount + DuplicateObservationCount'
    }

    if ($null -ne $deduped -and [int]$deduped -ne @($SecurityObservations).Count) {
        Add-PackageValidationError -ErrorId 'PKG-COUNT-OBSERVATION-002' -Message 'Security observation record count does not match DeduplicatedObservationCount.' -AffectedInvariant 'security-observations records == DeduplicatedObservationCount'
    }

    $categorySummary = @(Get-InspectorReportProperty -InputObject $Summary -Name 'CategorySummary')
    if ($null -ne $deduped -and @($categorySummary).Count -gt 0) {
        $categoryTotal = @($categorySummary | ForEach-Object { Get-InspectorReportProperty -InputObject $_ -Name 'Count' } | Measure-Object -Sum).Sum
        if ([int]$categoryTotal -ne [int]$deduped) {
            Add-PackageValidationError -ErrorId 'PKG-COUNT-CATEGORY-001' -Message 'Category summary count does not match DeduplicatedObservationCount.' -AffectedInvariant 'sum(CategorySummary.Count) == DeduplicatedObservationCount'
        }
    }

    $severitySummary = @(Get-InspectorReportProperty -InputObject $Summary -Name 'SeveritySummary')
    if ($null -ne $deduped -and @($severitySummary).Count -gt 0) {
        $severityTotal = @($severitySummary | ForEach-Object { Get-InspectorReportProperty -InputObject $_ -Name 'Count' } | Measure-Object -Sum).Sum
        if ([int]$severityTotal -ne [int]$deduped) {
            Add-PackageValidationError -ErrorId 'PKG-COUNT-SEVERITY-001' -Message 'Severity summary count does not match DeduplicatedObservationCount.' -AffectedInvariant 'sum(SeveritySummary.Count) == DeduplicatedObservationCount'
        }
    }

    $observationIds = @{}
    $observationEvidenceById = @{}
    $observationIdValues = [System.Collections.Generic.List[string]]::new()
    foreach ($observation in @($SecurityObservations)) {
        $id = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'ObservationId')
        if ([string]::IsNullOrWhiteSpace($id)) {
            Add-PackageValidationError -ErrorId 'PKG-OBSERVATION-ID-001' -Message 'Canonical security observations contain a blank ObservationId.' -AffectedInvariant 'every canonical observation has a non-empty unique ObservationId'
            continue
        }
        $observationIdValues.Add($id)
        $observationIds[$id] = $true
        $observationEvidenceById[$id] = @(
            @(Get-InspectorReportProperty -InputObject $observation -Name 'EvidenceIds') |
                ForEach-Object { ConvertTo-InspectorReportString $_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique
        )
    }

    $duplicateObservationIds = @(
        $observationIdValues |
            Group-Object |
            Where-Object { $_.Count -gt 1 } |
            ForEach-Object { [string]$_.Name }
    )
    if ($duplicateObservationIds.Count -gt 0) {
        $preview = @($duplicateObservationIds | Select-Object -First 8) -join ', '
        Add-PackageValidationError -ErrorId 'PKG-OBSERVATION-ID-002' -Message "Canonical security observations contain duplicate ObservationIds: $preview" -AffectedInvariant 'canonical ObservationIds are unique'
    }

    $findingObservationReferenceCounts = @{}
    foreach ($finding in @($AssessmentFindings)) {
        foreach ($observationId in @(Get-InspectorReportProperty -InputObject $finding -Name 'ObservationIds')) {
            $id = ConvertTo-InspectorReportString $observationId
            if ([string]::IsNullOrWhiteSpace($id)) { continue }
            if (-not $findingObservationReferenceCounts.ContainsKey($id)) {
                $findingObservationReferenceCounts[$id] = 0
            }
            $findingObservationReferenceCounts[$id]++
        }
    }

    foreach ($finding in @($AssessmentFindings)) {
        $findingId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'FindingId')
        $findingObservationIds = @(
            @(Get-InspectorReportProperty -InputObject $finding -Name 'ObservationIds') |
                ForEach-Object { ConvertTo-InspectorReportString $_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )

        foreach ($observationId in @(Get-InspectorReportProperty -InputObject $finding -Name 'ObservationIds')) {
            $id = ConvertTo-InspectorReportString $observationId
            if (-not [string]::IsNullOrWhiteSpace($id) -and -not $observationIds.ContainsKey($id)) {
                Add-PackageValidationError -ErrorId 'PKG-REFERENCE-OBSERVATION-001' -Message "Finding references missing observation: $id" -AffectedInvariant 'every Finding.ObservationId exists in canonical observations'
            }
        }

        $affectedObjects = @(Get-InspectorReportProperty -InputObject $finding -Name 'AffectedObjects') | Where-Object { $null -ne $_ }
        $uniqueAffected = @($affectedObjects | ForEach-Object {
            "$(Get-InspectorReportProperty -InputObject $_ -Name 'ObjectType')|$(Get-InspectorReportProperty -InputObject $_ -Name 'ObjectId')"
        } | Where-Object { $_ -ne '|' } | Select-Object -Unique).Count
        $declaredAffected = Get-InspectorReportProperty -InputObject $finding -Name 'AffectedObjectCount'
        if ($null -ne $declaredAffected -and [int]$declaredAffected -ne $uniqueAffected) {
            Add-PackageValidationError -ErrorId 'PKG-COUNT-AFFECTEDOBJECT-001' -Message "Finding affected-object count does not reconcile: $(Get-InspectorReportProperty -InputObject $finding -Name 'FindingId')" -AffectedInvariant 'Finding.AffectedObjectCount == unique Finding.AffectedObjects'
        }

        $evidenceIds = @($EvidenceRows | ForEach-Object { ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'EvidenceId') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        $evidenceIdSet = @{}
        foreach ($evidenceId in $evidenceIds) { $evidenceIdSet[$evidenceId] = $true }
        foreach ($findingEvidenceId in @(Get-InspectorReportProperty -InputObject $finding -Name 'EvidenceIds')) {
            $id = ConvertTo-InspectorReportString $findingEvidenceId
            if (-not [string]::IsNullOrWhiteSpace($id) -and -not $evidenceIdSet.ContainsKey($id)) {
                Add-PackageValidationError -ErrorId 'PKG-REFERENCE-EVIDENCE-001' -Message "Finding references missing evidence: $id" -AffectedInvariant 'every Finding.EvidenceId exists in evidence index'
            }
        }

        $expectedFindingEvidenceIds = @(
            $findingObservationIds |
                Where-Object { $observationEvidenceById.ContainsKey($_) } |
                ForEach-Object { @($observationEvidenceById[$_]) } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique
        )
        $actualFindingEvidenceIds = @(
            @(Get-InspectorReportProperty -InputObject $finding -Name 'EvidenceIds') |
                ForEach-Object { ConvertTo-InspectorReportString $_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique
        )
        $expectedEvidenceSet = @{}
        foreach ($id in $expectedFindingEvidenceIds) { $expectedEvidenceSet[$id] = $true }
        $actualEvidenceSet = @{}
        foreach ($id in $actualFindingEvidenceIds) { $actualEvidenceSet[$id] = $true }

        $missingFindingEvidence = @($expectedFindingEvidenceIds | Where-Object { -not $actualEvidenceSet.ContainsKey($_) })
        $extraneousFindingEvidence = @($actualFindingEvidenceIds | Where-Object { -not $expectedEvidenceSet.ContainsKey($_) })
        if ($missingFindingEvidence.Count -gt 0 -or $extraneousFindingEvidence.Count -gt 0) {
            $evidencePreviewParts = [System.Collections.Generic.List[string]]::new()
            if ($missingFindingEvidence.Count -gt 0) { $evidencePreviewParts.Add("missing=$(@($missingFindingEvidence | Select-Object -First 6) -join ',')") }
            if ($extraneousFindingEvidence.Count -gt 0) { $evidencePreviewParts.Add("extraneous=$(@($extraneousFindingEvidence | Select-Object -First 6) -join ',')") }
            Add-PackageValidationError -ErrorId 'PKG-FINDING-EVIDENCE-RECONCILIATION-001' -Message "Finding evidence does not exactly match contributing observation evidence: $findingId. $(@($evidencePreviewParts) -join '; ')" -AffectedInvariant 'Finding.EvidenceIds exactly equals the unique union of EvidenceIds from contributing ObservationIds'
        }
    }

    $eligibleReferenceViolations = [System.Collections.Generic.List[string]]::new()
    $nonEligibleReferenceViolations = [System.Collections.Generic.List[string]]::new()
    $eligibilityContractObserved = $false

    foreach ($observation in @($SecurityObservations)) {
        $findingEligible = Get-InspectorReportProperty -InputObject $observation -Name 'FindingEligible'
        if ($null -eq $findingEligible) { continue }

        $eligibilityContractObserved = $true
        $id = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'ObservationId')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $referenceCount = if ($findingObservationReferenceCounts.ContainsKey($id)) { [int]$findingObservationReferenceCounts[$id] } else { 0 }

        if ([bool]$findingEligible) {
            if ($referenceCount -ne 1) {
                $eligibleReferenceViolations.Add("$id=$referenceCount")
            }
        }
        elseif ($referenceCount -gt 0) {
            $nonEligibleReferenceViolations.Add("$id=$referenceCount")
        }
    }

    if ($eligibilityContractObserved -and $eligibleReferenceViolations.Count -gt 0) {
        $preview = @($eligibleReferenceViolations | Select-Object -First 8) -join ', '
        Add-PackageValidationError -ErrorId 'PKG-FINDING-ELIGIBILITY-001' -Message "Finding-eligible observations must appear in exactly one grouped finding. Violations: $preview" -AffectedInvariant 'every FindingEligible=True canonical observation appears in exactly one grouped finding'
    }

    if ($eligibilityContractObserved -and $nonEligibleReferenceViolations.Count -gt 0) {
        $preview = @($nonEligibleReferenceViolations | Select-Object -First 8) -join ', '
        Add-PackageValidationError -ErrorId 'PKG-FINDING-ELIGIBILITY-002' -Message "Contextual/noneligible observations must not appear in grouped findings. Violations: $preview" -AffectedInvariant 'FindingEligible=False canonical observations are excluded from grouped findings'
    }

    $manifestEvidenceCount = Get-InspectorReportProperty -InputObject $Manifest -Name 'EvidenceRecordCount'
    $uniqueEvidenceCount = @($EvidenceRows | ForEach-Object { Get-InspectorReportProperty -InputObject $_ -Name 'EvidenceId' } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique).Count
    if ($null -ne $manifestEvidenceCount -and [int]$manifestEvidenceCount -ne $uniqueEvidenceCount) {
        Add-PackageValidationError -ErrorId 'PKG-COUNT-EVIDENCE-001' -Message 'Manifest evidence count does not match unique evidence IDs.' -AffectedInvariant 'unique evidence-index EvidenceIds == EvidenceRecordCount'
    }

    $findingCount = @($AssessmentFindings).Count
    $manifestFindingCount = Get-InspectorReportProperty -InputObject $Manifest -Name 'GroupedFindingCount'
    if ($null -ne $manifestFindingCount -and [int]$manifestFindingCount -ne $findingCount) {
        Add-PackageValidationError -ErrorId 'PKG-COUNT-FINDING-001' -Message 'Grouped finding count does not match assessment findings.' -AffectedInvariant 'assessment-findings records == GroupedFindingCount'
    }

    $summaryFindingCount = Get-InspectorReportProperty -InputObject $Summary -Name 'GroupedFindingCount'
    if ($null -ne $summaryFindingCount -and [int]$summaryFindingCount -ne $findingCount) {
        Add-PackageValidationError -ErrorId 'PKG-COUNT-FINDING-001' -Message 'Grouped finding count does not match assessment findings.' -AffectedInvariant 'assessment-findings records == GroupedFindingCount'
    }

    $recommendationCount = @(Get-InspectorReportProperty -InputObject $Manifest -Name 'RecommendationCount')[0]
    if ($null -ne $recommendationCount) {
        $summaryRecommendationCount = Get-InspectorReportProperty -InputObject $Summary -Name 'AssessmentRecommendationCount'
        if ($null -ne $summaryRecommendationCount -and [int]$summaryRecommendationCount -ne [int]$recommendationCount) {
            Add-PackageValidationError -ErrorId 'PKG-COUNT-RECOMMENDATION-001' -Message 'Recommendation count differs across assessment package artifacts.' -AffectedInvariant 'assessment-recommendations records == RecommendationCount'
        }
    }

    $discoveredCount = Get-InspectorReportProperty -InputObject $Summary -Name 'DiscoveredCount'
    $processedCount = Get-InspectorReportProperty -InputObject $Summary -Name 'ProcessedCount'
    $summaryFailedCount = Get-InspectorReportProperty -InputObject $Summary -Name 'FailedCount'
    $skippedCount = Get-InspectorReportProperty -InputObject $Summary -Name 'SkippedCount'
    if ($null -ne $discoveredCount -and $null -ne $processedCount -and $null -ne $summaryFailedCount -and $null -ne $skippedCount) {
        if ([int]$discoveredCount -ne ([int]$processedCount + [int]$summaryFailedCount + [int]$skippedCount)) {
            Add-PackageValidationError -ErrorId 'PKG-COUNT-OBJECTPROCESSING-001' -Message 'Discovered object count does not reconcile with processed, failed, and skipped objects.' -AffectedInvariant 'DiscoveredCount == ProcessedCount + FailedCount + SkippedCount'
        }
    }

    $failedObjectCount = @($FailedObjects).Count
    $failedCountValues = @(
        Get-InspectorReportProperty -InputObject $Summary -Name 'FailedCount'
        Get-InspectorReportProperty -InputObject $Manifest -Name 'FailedObjectCount'
        Get-InspectorReportProperty -InputObject $scopeInventory -Name 'FailedObjects'
    ) | Where-Object { $null -ne $_ }

    foreach ($failedCountValue in $failedCountValues) {
        if ([int]$failedCountValue -ne $failedObjectCount) {
            Add-PackageValidationError -ErrorId 'PKG-COUNT-FAILEDOBJECT-001' -Message 'Failed object count differs across assessment package artifacts.' -AffectedInvariant 'FailedObjectCount == failed object artifact records == failed object collection count'
            break
        }
    }

    $artifactRows = @(Get-InspectorReportProperty -InputObject $Manifest -Name 'Artifacts') | Where-Object { $null -ne $_ }

    if ($isCurrentPackageSchema -and -not [string]::IsNullOrWhiteSpace($SourcePath)) {
        $manifestArtifactNames = @(
            $artifactRows |
                ForEach-Object { ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Name') } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        foreach ($mandatoryArtifactName in @(Get-InspectorCurrentMandatoryArtifactNames)) {
            if ($mandatoryArtifactName -notin $manifestArtifactNames) {
                Add-PackageValidationError -ErrorId 'PKG-ARTIFACT-INVENTORY-001' -Message "Mandatory current-package artifact is absent from Manifest.Artifacts: $mandatoryArtifactName" -AffectedInvariant 'current Manifest.Artifacts contains every mandatory package artifact'
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($SourcePath)) {
        foreach ($artifactRow in $artifactRows) {
            $artifactName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $artifactRow -Name 'Name')
            if ([string]::IsNullOrWhiteSpace($artifactName)) {
                Add-PackageValidationError -ErrorId 'PKG-ARTIFACT-NAME-001' -Message 'Manifest contains an artifact record without a name.' -AffectedInvariant 'every manifest artifact has a file name'
                continue
            }

            $expectedArtifactPath = Join-Path -Path $SourcePath -ChildPath $artifactName
            if (-not (Test-Path -LiteralPath $expectedArtifactPath -PathType Leaf)) {
                Add-PackageValidationError -ErrorId 'PKG-ARTIFACT-MISSING-001' -Message "Manifest-declared artifact is missing from the export package: $artifactName" -AffectedInvariant 'every Manifest.Artifacts.Name exists as a file in the export directory'
                continue
            }

            $artifactHasPhysicalMetadata =
                $null -ne $artifactRow.PSObject.Properties['SizeBytes'] -or
                $null -ne $artifactRow.PSObject.Properties['Kind']
            $validatePhysicalMetadata = $isCurrentPackageEnvelope -or $artifactHasPhysicalMetadata

            if ($validatePhysicalMetadata) {
                $declaredSizeRaw = Get-InspectorReportProperty -InputObject $artifactRow -Name 'SizeBytes'
                $declaredSize = [long]0
                $declaredSizeIsNumeric =
                    $null -ne $declaredSizeRaw -and
                    [long]::TryParse([string]$declaredSizeRaw, [ref]$declaredSize)
                $physicalSize = [long](Get-Item -LiteralPath $expectedArtifactPath).Length

                if (-not $declaredSizeIsNumeric -or $declaredSize -ne $physicalSize) {
                    Add-PackageValidationError -ErrorId 'PKG-ARTIFACT-SIZE-001' -Message "Manifest SizeBytes does not match the physical artifact: $artifactName" -AffectedInvariant 'Manifest.Artifacts.SizeBytes == physical artifact length for every current package artifact'
                }

                $declaredRecordCountRaw = Get-InspectorReportProperty -InputObject $artifactRow -Name 'RecordCount'
                $declaredRecordCount = [long]0
                $declaredRecordCountIsNumeric =
                    $null -ne $declaredRecordCountRaw -and
                    [long]::TryParse([string]$declaredRecordCountRaw, [ref]$declaredRecordCount)
                $artifactKind = (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $artifactRow -Name 'Kind')).ToLowerInvariant()

                try {
                    $physicalRecordCount = switch ($artifactKind) {
                        'json' {
                            $rawArtifactContent = Get-Content -LiteralPath $expectedArtifactPath -Raw -ErrorAction Stop
                            if ([string]::IsNullOrWhiteSpace($rawArtifactContent)) {
                                [long]0
                            }
                            else {
                                $parsedArtifactContent = $rawArtifactContent | ConvertFrom-Json -ErrorAction Stop
                                if ($null -eq $parsedArtifactContent) {
                                    [long]0
                                }
                                else {
                                    [long](@($parsedArtifactContent).Count)
                                }
                            }
                            break
                        }
                        'csv' {
                            [long](@(Import-Csv -LiteralPath $expectedArtifactPath -ErrorAction Stop).Count)
                            break
                        }
                        default {
                            [long]1
                            break
                        }
                    }

                    if (-not $declaredRecordCountIsNumeric -or $declaredRecordCount -ne $physicalRecordCount) {
                        Add-PackageValidationError -ErrorId 'PKG-ARTIFACT-RECORDCOUNT-001' -Message "Manifest RecordCount does not match the physical artifact: $artifactName" -AffectedInvariant 'Manifest.Artifacts.RecordCount == physical structured record count for every current package artifact'
                    }
                }
                catch {
                    Add-PackageValidationError -ErrorId 'PKG-ARTIFACT-RECORDCOUNT-001' -Message "Physical artifact record count could not be reconciled: $artifactName" -AffectedInvariant 'Manifest.Artifacts.RecordCount == physical structured record count for every current package artifact'
                }
            }
        }
    }

    foreach ($artifactName in @('failed-objects.json', 'failed-objects.csv')) {
        $artifact = @($artifactRows | Where-Object { [string](Get-InspectorReportProperty -InputObject $_ -Name 'Name') -eq $artifactName } | Select-Object -First 1)
        if (@($artifact).Count -gt 0) {
            $recordCount = Get-InspectorReportProperty -InputObject $artifact[0] -Name 'RecordCount'
            if ($null -ne $recordCount -and [int]$recordCount -ne $failedObjectCount) {
                Add-PackageValidationError -ErrorId 'PKG-COUNT-FAILEDOBJECT-001' -Message 'Failed object count differs across assessment package artifacts.' -AffectedInvariant 'FailedObjectCount == failed object artifact records == failed object collection count'
                break
            }
        }
    }

    foreach ($evidenceRow in @($EvidenceRows)) {
        $scope = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $evidenceRow -Name 'EvidenceScope')
        if ($scope -eq 'ObjectRelationship' -or $scope -eq 'ObjectCollection') {
            $collectorName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $evidenceRow -Name 'CollectorName')
            $subjectType = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $evidenceRow -Name 'SubjectObjectType')
            $subjectId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $evidenceRow -Name 'SubjectObjectId')
            if ([string]::IsNullOrWhiteSpace($collectorName) -or [string]::IsNullOrWhiteSpace($subjectType) -or [string]::IsNullOrWhiteSpace($subjectId)) {
                Add-PackageValidationError -ErrorId 'PKG-EVIDENCE-SUBJECT-001' -Message 'Object-specific evidence is missing subject mapping metadata.' -AffectedInvariant 'object-specific evidence has CollectorName, EvidenceScope, SubjectObjectType, SubjectObjectId'
                break
            }
        }
    }

    # Release eligibility is evidence-completeness aware and plan-aware.
    # Current packages declare an expected evidence plan generated independently
    # from the evidence rows. The validator independently compares that plan to
    # the exported evidence so a silently omitted query cannot shrink the
    # denominator and still report Complete coverage.
    $requiredEvidenceRows = @(
        $EvidenceRows |
            Where-Object {
                $queryName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'QueryName')
                if ([string]::IsNullOrWhiteSpace($queryName) -or $queryName -eq 'Organization') {
                    return $false
                }

                $requiredForCoverage = Get-InspectorReportProperty -InputObject $_ -Name 'RequiredForCoverage'
                if ($null -ne $requiredForCoverage) {
                    try {
                        if (-not [System.Convert]::ToBoolean($requiredForCoverage)) {
                            return $false
                        }
                    }
                    catch {
                        # A malformed advisory marker must never shrink the
                        # required-evidence denominator. Treat it as required.
                    }
                }

                return $true
            }
    )
    $incompleteRequiredEvidenceRows = @(
        $requiredEvidenceRows |
            Where-Object {
                $status = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Status')
                $completeness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Completeness')
                $status -ne 'Success' -or $completeness -ne 'Complete'
            }
    )
    $requiredEvidenceComplete = $incompleteRequiredEvidenceRows.Count -eq 0

    if (-not $requiredEvidenceComplete) {
        $coveragePreview = @(
            $incompleteRequiredEvidenceRows |
                Select-Object -First 8 |
                ForEach-Object {
                    "$(ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'QueryName'))=$(ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Status'))"
                }
        ) -join ', '
        Add-PackageValidationError -ErrorId 'PKG-EVIDENCE-COVERAGE-001' -Message "Assessment-required evidence is incomplete: $($incompleteRequiredEvidenceRows.Count) collection(s) did not complete successfully. $coveragePreview" -AffectedInvariant 'all assessment-required evidence collections complete successfully before ReleaseEligible can be true'
    }

    $assessmentCoverage = Get-InspectorReportProperty -InputObject $Summary -Name 'AssessmentCoverage'
    if ($null -eq $assessmentCoverage) {
        $assessmentCoverage = Get-InspectorReportProperty -InputObject $Manifest -Name 'AssessmentCoverage'
    }

    if ($isCurrentPackageSchema -and $null -eq $assessmentCoverage) {
        Add-PackageValidationError -ErrorId 'PKG-COVERAGE-MISSING-001' -Message 'Current assessment package is missing AssessmentCoverage.' -AffectedInvariant 'current assessment packages include a non-null AssessmentCoverage envelope'
    }

    # Wrap the entire normalization pipeline in @(...), not only the source
    # property access. PowerShell otherwise unwraps a single ExpectedQueries
    # value to a scalar, and StrictMode then makes .Count unsafe.
    $expectedQueries = @(
        @(Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'ExpectedQueries') |
            ForEach-Object { ConvertTo-InspectorReportString $_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    if ($isCurrentPackageSchema -and $null -ne $assessmentCoverage) {
        $coverageStatus = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'Status')
        $coverageCompleteness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'Completeness')
        $coveragePlanMatches = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'EvidencePlanMatches'
        if ($coverageStatus -ne 'Success' -or $coverageCompleteness -ne 'Complete' -or $null -eq $coveragePlanMatches -or -not [bool]$coveragePlanMatches) {
            Add-PackageValidationError -ErrorId 'PKG-COVERAGE-ENVELOPE-001' -Message 'Current AssessmentCoverage must declare Status=Success, Completeness=Complete, and EvidencePlanMatches=True.' -AffectedInvariant 'AssessmentCoverage.Status == Success && Completeness == Complete && EvidencePlanMatches == True'
        }
    }

    $evidencePlanMatches = $true
    if ($null -ne $assessmentCoverage -and $requiredEvidenceRows.Count -gt 0 -and $expectedQueries.Count -eq 0) {
        $evidencePlanMatches = $false
        Add-PackageValidationError -ErrorId 'PKG-EVIDENCE-PLAN-001' -Message 'Assessment coverage is present but its expected evidence plan is missing; release eligibility cannot be established.' -AffectedInvariant 'current AssessmentCoverage includes a non-empty ExpectedQueries plan when assessment-required evidence exists'
    }
    elseif ($expectedQueries.Count -gt 0) {
        $expectedUnique = @($expectedQueries | Select-Object -Unique)
        $actualQueryNames = @(
            $requiredEvidenceRows |
                ForEach-Object { ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'QueryName') }
        )
        $actualUnique = @($actualQueryNames | Select-Object -Unique)

        $expectedSet = @{}
        foreach ($queryName in $expectedUnique) { $expectedSet[$queryName] = $true }
        $actualSet = @{}
        foreach ($queryName in $actualUnique) { $actualSet[$queryName] = $true }

        $missingExpected = @($expectedUnique | Where-Object { -not $actualSet.ContainsKey($_) })
        $unexpectedRequired = @($actualUnique | Where-Object { -not $expectedSet.ContainsKey($_) })
        $duplicateRequired = @(
            $actualQueryNames |
                Group-Object |
                Where-Object { $_.Count -gt 1 } |
                ForEach-Object { [string]$_.Name }
        )
        $duplicateExpected = @(
            $expectedQueries |
                Group-Object |
                Where-Object { $_.Count -gt 1 } |
                ForEach-Object { [string]$_.Name }
        )

        $declaredExpectedCount = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'ExpectedEvidenceCount'
        $declaredActualCount = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'ActualRequiredEvidenceCount'

        $evidencePlanMatches =
            $missingExpected.Count -eq 0 -and
            $unexpectedRequired.Count -eq 0 -and
            $duplicateRequired.Count -eq 0 -and
            $duplicateExpected.Count -eq 0 -and
            $actualQueryNames.Count -eq $expectedUnique.Count

        if ($null -ne $declaredExpectedCount -and [int]$declaredExpectedCount -ne $expectedUnique.Count) {
            $evidencePlanMatches = $false
        }
        if ($null -ne $declaredActualCount -and [int]$declaredActualCount -ne $actualQueryNames.Count) {
            $evidencePlanMatches = $false
        }

        if (-not $evidencePlanMatches) {
            $parts = [System.Collections.Generic.List[string]]::new()
            if ($missingExpected.Count -gt 0) { $parts.Add("missing=$(@($missingExpected | Select-Object -First 6) -join ',')") }
            if ($unexpectedRequired.Count -gt 0) { $parts.Add("unexpected=$(@($unexpectedRequired | Select-Object -First 6) -join ',')") }
            if ($duplicateRequired.Count -gt 0) { $parts.Add("duplicate=$(@($duplicateRequired | Select-Object -First 6) -join ',')") }
            if ($duplicateExpected.Count -gt 0) { $parts.Add("plan-duplicate=$(@($duplicateExpected | Select-Object -First 6) -join ',')") }
            Add-PackageValidationError -ErrorId 'PKG-EVIDENCE-PLAN-001' -Message "Expected evidence plan does not exactly match exported assessment-required evidence. $(@($parts) -join '; ')" -AffectedInvariant 'AssessmentCoverage.ExpectedQueries exactly equals the required evidence QueryName set with one row per query'
        }
    }

    $declaredPlanMatches = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'EvidencePlanMatches'
    if ($null -ne $declaredPlanMatches -and -not [bool]$declaredPlanMatches) {
        $evidencePlanMatches = $false
        if (-not $seenErrorIds.ContainsKey('PKG-EVIDENCE-PLAN-001')) {
            Add-PackageValidationError -ErrorId 'PKG-EVIDENCE-PLAN-001' -Message 'Assessment coverage declares an expected-evidence plan mismatch.' -AffectedInvariant 'AssessmentCoverage.EvidencePlanMatches == true for ReleaseEligible'
        }
    }

    $declaredCoverageCompleteness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $scopeInventory -Name 'AssessmentCoverageCompleteness')
    if ([string]::IsNullOrWhiteSpace($declaredCoverageCompleteness)) {
        $declaredCoverageCompleteness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'Completeness')
    }
    if (-not [string]::IsNullOrWhiteSpace($declaredCoverageCompleteness) -and $declaredCoverageCompleteness -ne 'Complete') {
        $requiredEvidenceComplete = $false
        $coverageErrorAlreadyPresent = @(
            $errors |
                Where-Object {
                    (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'ErrorId')) -eq 'PKG-EVIDENCE-COVERAGE-001'
                }
        ).Count -gt 0

        if (-not $coverageErrorAlreadyPresent) {
            Add-PackageValidationError -ErrorId 'PKG-EVIDENCE-COVERAGE-001' -Message 'Assessment scope declares incomplete required-evidence coverage.' -AffectedInvariant 'AssessmentCoverageCompleteness == Complete for ReleaseEligible'
        }
    }

    $sourceStatus = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $Summary -Name 'Status')
    if ([string]::IsNullOrWhiteSpace($sourceStatus)) {
        $sourceStatus = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $Manifest -Name 'SourceStatus')
    }

    if ([string]::IsNullOrWhiteSpace($sourceStatus)) {
        Add-PackageValidationError -ErrorId 'PKG-SOURCE-STATUS-001' -Message 'Assessment source status is missing; release eligibility cannot be established.' -AffectedInvariant 'SourceStatus is present and equals Success for release eligibility'
    }

    $summaryHasGraphCallsAfterSnapshot =
        $null -ne $Summary -and
        $null -ne $Summary.PSObject.Properties['GraphCallsAfterSnapshot']
    $manifestHasGraphCallsAfterSnapshot =
        $null -ne $Manifest -and
        $null -ne $Manifest.PSObject.Properties['GraphCallsAfterSnapshot']

    $summaryGraphCallsAfterSnapshot =
        if ($summaryHasGraphCallsAfterSnapshot) {
            Get-InspectorReportProperty -InputObject $Summary -Name 'GraphCallsAfterSnapshot'
        }
        else {
            $null
        }
    $manifestGraphCallsAfterSnapshot =
        if ($manifestHasGraphCallsAfterSnapshot) {
            Get-InspectorReportProperty -InputObject $Manifest -Name 'GraphCallsAfterSnapshot'
        }
        else {
            $null
        }

    $parsedSummaryGraphCallsAfterSnapshot = [int]0
    $parsedManifestGraphCallsAfterSnapshot = [int]0
    $summaryGraphCallsAfterSnapshotIsNumeric =
        $summaryHasGraphCallsAfterSnapshot -and
        $null -ne $summaryGraphCallsAfterSnapshot -and
        [int]::TryParse([string]$summaryGraphCallsAfterSnapshot, [ref]$parsedSummaryGraphCallsAfterSnapshot)
    $manifestGraphCallsAfterSnapshotIsNumeric =
        $manifestHasGraphCallsAfterSnapshot -and
        $null -ne $manifestGraphCallsAfterSnapshot -and
        [int]::TryParse([string]$manifestGraphCallsAfterSnapshot, [ref]$parsedManifestGraphCallsAfterSnapshot)

    if ($isCurrentPackageEnvelope) {
        $currentGraphProvenanceValid =
            $summaryHasGraphCallsAfterSnapshot -and
            $manifestHasGraphCallsAfterSnapshot -and
            $summaryGraphCallsAfterSnapshotIsNumeric -and
            $manifestGraphCallsAfterSnapshotIsNumeric -and
            ($parsedSummaryGraphCallsAfterSnapshot -eq $parsedManifestGraphCallsAfterSnapshot)

        if (-not $currentGraphProvenanceValid) {
            Add-PackageValidationError -ErrorId 'PKG-GRAPH-PROVENANCE-001' -Message 'Current assessment package must declare the same numeric GraphCallsAfterSnapshot value in both summary and manifest.' -AffectedInvariant 'Summary.GraphCallsAfterSnapshot == Manifest.GraphCallsAfterSnapshot and both values are present and numeric for current assessment packages'
        }
    }
    else {
        if (($summaryHasGraphCallsAfterSnapshot -and -not $summaryGraphCallsAfterSnapshotIsNumeric) -or ($manifestHasGraphCallsAfterSnapshot -and -not $manifestGraphCallsAfterSnapshotIsNumeric)) {
            Add-PackageValidationError -ErrorId 'PKG-GRAPH-PROVENANCE-001' -Message 'GraphCallsAfterSnapshot is present but is not numeric.' -AffectedInvariant 'GraphCallsAfterSnapshot is numeric when declared'
        }
        elseif ($summaryGraphCallsAfterSnapshotIsNumeric -and $manifestGraphCallsAfterSnapshotIsNumeric -and $parsedSummaryGraphCallsAfterSnapshot -ne $parsedManifestGraphCallsAfterSnapshot) {
            Add-PackageValidationError -ErrorId 'PKG-GRAPH-PROVENANCE-001' -Message 'GraphCallsAfterSnapshot differs between summary and manifest.' -AffectedInvariant 'Summary.GraphCallsAfterSnapshot == Manifest.GraphCallsAfterSnapshot when both are declared'
        }
    }

    if ($isCurrentPackageSchema) {
        $summarySnapshotRaw = Get-InspectorReportProperty -InputObject $Summary -Name 'GraphRequestsAtSnapshotCompletion'
        $manifestSnapshotRaw = Get-InspectorReportProperty -InputObject $Manifest -Name 'GraphRequestsAtSnapshotCompletion'
        $summaryAssessmentRaw = Get-InspectorReportProperty -InputObject $Summary -Name 'GraphRequestsAtAssessmentCompletion'
        $manifestAssessmentRaw = Get-InspectorReportProperty -InputObject $Manifest -Name 'GraphRequestsAtAssessmentCompletion'
        $summarySnapshot = [long]0; $manifestSnapshot = [long]0; $summaryAssessment = [long]0; $manifestAssessment = [long]0
        $summarySnapshotNumeric = $null -ne $summarySnapshotRaw -and [long]::TryParse([string]$summarySnapshotRaw, [ref]$summarySnapshot)
        $manifestSnapshotNumeric = $null -ne $manifestSnapshotRaw -and [long]::TryParse([string]$manifestSnapshotRaw, [ref]$manifestSnapshot)
        $summaryAssessmentNumeric = $null -ne $summaryAssessmentRaw -and [long]::TryParse([string]$summaryAssessmentRaw, [ref]$summaryAssessment)
        $manifestAssessmentNumeric = $null -ne $manifestAssessmentRaw -and [long]::TryParse([string]$manifestAssessmentRaw, [ref]$manifestAssessment)
        $graphLifecycleCountersValid =
            $summarySnapshotNumeric -and $manifestSnapshotNumeric -and
            $summaryAssessmentNumeric -and $manifestAssessmentNumeric -and
            $summarySnapshot -ge 0 -and $summaryAssessment -ge 0 -and
            $summarySnapshot -eq $manifestSnapshot -and
            $summaryAssessment -eq $manifestAssessment -and
            $summaryAssessment -ge $summarySnapshot -and
            $summaryGraphCallsAfterSnapshotIsNumeric -and
            ([long]$parsedSummaryGraphCallsAfterSnapshot -eq ($summaryAssessment - $summarySnapshot))

        if (-not $graphLifecycleCountersValid) {
            Add-PackageValidationError -ErrorId 'PKG-GRAPH-LIFECYCLE-001' -Message 'Current package Graph lifecycle counters are missing, nonnumeric, inconsistent, or do not reconcile with GraphCallsAfterSnapshot.' -AffectedInvariant 'GraphRequestsAtAssessmentCompletion >= GraphRequestsAtSnapshotCompletion and GraphCallsAfterSnapshot == their difference across summary and manifest'
        }
    }

    $measuredGraphCallsAfterSnapshot =
        if ($summaryGraphCallsAfterSnapshotIsNumeric) {
            $parsedSummaryGraphCallsAfterSnapshot
        }
        elseif ($manifestGraphCallsAfterSnapshotIsNumeric) {
            $parsedManifestGraphCallsAfterSnapshot
        }
        else {
            $null
        }

    if ($null -ne $measuredGraphCallsAfterSnapshot -and [int]$measuredGraphCallsAfterSnapshot -ne 0) {
        Add-PackageValidationError -ErrorId 'PKG-GRAPH-POSTSNAPSHOT-001' -Message "Graph activity was measured after snapshot completion: $measuredGraphCallsAfterSnapshot request(s)." -AffectedInvariant 'GraphCallsAfterSnapshot == 0 for release-eligible offline assessment processing'
    }

    $packageStatus = if ($errors.Count -eq 0) { 'Success' } else { 'Failed' }
    $releaseEligible =
        ($packageStatus -eq 'Success') -and
        ($failedObjectCount -eq 0) -and
        ($sourceStatus -eq 'Success') -and
        $scopeIsComplete -and
        $requiredEvidenceComplete -and
        $evidencePlanMatches

    $errorRows =
        if ($errors.Count -gt 0) {
            @($errors)
        }
        else {
            @([PSCustomObject][ordered]@{ ErrorId = $null; Message = $null; AffectedInvariant = $null })
        }
    $warningRows =
        if ($warnings.Count -gt 0) {
            @($warnings)
        }
        else {
            @([PSCustomObject][ordered]@{ WarningId = $null; Message = $null; AffectedInvariant = $null })
        }

    return [PSCustomObject][ordered]@{
        Status = $packageStatus
        ReleaseEligible = $releaseEligible
        SourceStatus = $sourceStatus
        FailedObjectCount = $failedObjectCount
        Errors = $errorRows
        Warnings = $warningRows
    }
}

function ConvertTo-InspectorReportModel {
    <#
    .SYNOPSIS
        Converts exported artifacts or in-memory objects into a report model.

    .DESCRIPTION
        presentation-only report conversion. It reshapes existing exported
        artifacts or in-memory objects for report rendering. It does not call
        Microsoft Graph, does not create observations, and does not add
        assessment intelligence.
    #>

    [CmdletBinding()]
    param (
        [string]$AssessmentName = 'Entra Object Inspector Assessment',

        [AllowNull()]
        [object]$InputObject,

        [AllowNull()]
        [object]$AssessmentIntelligence,

        [AllowNull()]
        [object]$Manifest,

        [AllowNull()]
        [object]$Summary,

        [object[]]$SecurityObservations = @(),

        [object[]]$ObjectIndex = @(),

        [object[]]$EvidenceRows = @(),

        [object[]]$FailedObjects = @(),

        [AllowNull()]
        [object]$TenantPosture,

        [object[]]$AssessmentFindings = @(),

        [object[]]$AssessmentRecommendations = @(),

        [object[]]$AssessmentCorrelations = @(),

        [object[]]$AssessmentLimitations = @(),

        [AllowNull()]
        [object]$RuntimeTelemetry,

        [AllowNull()]
        [object]$OrchestrationTelemetry,

        [string]$ClientName = '',

        [string]$ConsultantName = '',

        [string]$SourceKind = 'InMemoryObject',

        [string]$SourcePath = ''
    )

    $generatedAt =
        (Get-Date).ToUniversalTime().ToString('o')

    $resolvedIntelligence =
        Get-InspectorReportIntelligenceFromObject `
            -InputObject $InputObject `
            -AssessmentIntelligence $AssessmentIntelligence

    if ($null -eq $TenantPosture -and $null -ne $resolvedIntelligence) {
        $TenantPosture =
            Get-InspectorReportProperty `
                -InputObject $resolvedIntelligence `
                -Name 'TenantPosture'
    }

    if ($null -ne $resolvedIntelligence) {
        $deduplicatedObservations =
            @(
                Get-InspectorReportProperty `
                    -InputObject $resolvedIntelligence `
                    -Name 'DeduplicatedObservations'
            ) |
            Where-Object { $null -ne $_ }

        if (@($deduplicatedObservations).Count -gt 0) {
            $SecurityObservations = @($deduplicatedObservations)
        }
    }

    if (@($AssessmentFindings).Count -eq 0 -and $null -ne $resolvedIntelligence) {
        $AssessmentFindings =
            @(
                Get-InspectorReportProperty `
                    -InputObject $resolvedIntelligence `
                    -Name 'AssessmentFindings'
            ) |
            Where-Object { $null -ne $_ }
    }

    if (@($AssessmentRecommendations).Count -eq 0 -and $null -ne $resolvedIntelligence) {
        $AssessmentRecommendations =
            @(
                Get-InspectorReportProperty `
                    -InputObject $resolvedIntelligence `
                    -Name 'AssessmentRecommendations'
            ) |
            Where-Object { $null -ne $_ }
    }

    if (@($AssessmentCorrelations).Count -eq 0 -and $null -ne $resolvedIntelligence) {
        $AssessmentCorrelations =
            @(
                Get-InspectorReportProperty `
                    -InputObject $resolvedIntelligence `
                    -Name 'Correlations'
            ) |
            Where-Object { $null -ne $_ }
    }

    if (@($AssessmentLimitations).Count -eq 0 -and $null -ne $resolvedIntelligence) {
        $AssessmentLimitations =
            @(
                Get-InspectorReportProperty `
                    -InputObject $resolvedIntelligence `
                    -Name 'Limitations'
            ) |
            Where-Object { $null -ne $_ }
    }

    if (@($SecurityObservations).Count -eq 0 -and $null -ne $InputObject) {
        $SecurityObservations =
            Get-InspectorReportObservationsFromObject `
                -InputObject $InputObject
    }

    if (@($FailedObjects).Count -eq 0 -and $null -ne $InputObject) {
        $FailedObjects =
            @(
                Get-InspectorReportProperty `
                    -InputObject $InputObject `
                    -Name 'FailedObjects'
            ) |
            Where-Object { $null -ne $_ }
    }

    $FailedObjects = @($FailedObjects | Where-Object {
        $null -ne $_ -and (
            $_ -isnot [string] -or -not [string]::IsNullOrWhiteSpace([string]$_)
        )
    })

    $objectInsights =
        @(
            Get-InspectorReportProperty `
                -InputObject $InputObject `
                -Name 'ObjectInsights'
        ) |
        Where-Object { $null -ne $_ }

    if (@($ObjectIndex).Count -eq 0 -and $objectInsights.Count -gt 0) {
        $ObjectIndex =
            @(
                $objectInsights |
                ForEach-Object {
                    $inputValue =
                        ConvertTo-InspectorReportString `
                            (Get-InspectorReportProperty -InputObject $_ -Name 'Input')

                    $displayName =
                        Get-InspectorReportObjectDisplayNameFromInsight `
                            -ObjectInsight $_

                    [PSCustomObject][ordered]@{
                        DisplayName              = $displayName
                        ObjectType               = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'ResolutionType')
                        ObjectId                 = $inputValue
                        Input                    = $inputValue
                        Status                   = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Status')
                        ResolutionType           = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'ResolutionType')
                        RelationshipStatus       = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject (Get-InspectorReportProperty -InputObject $_ -Name 'RelationshipCollection') -Name 'Status')
                        RelationshipCompleteness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject (Get-InspectorReportProperty -InputObject $_ -Name 'RelationshipCollection') -Name 'Completeness')
                        SecurityObservationCount = @(
                            Get-InspectorReportProperty `
                                -InputObject $_ `
                                -Name 'SecurityObservations'
                        ).Count
                    }
                }
            )
    }
    else {
        $ObjectIndex =
            @(
                @($ObjectIndex) |
                ForEach-Object {
                    $displayName =
                        ConvertTo-InspectorReportString `
                            (Get-InspectorReportProperty -InputObject $_ -Name 'DisplayName')

                    if ([string]::IsNullOrWhiteSpace($displayName)) {
                        $displayName =
                            ConvertTo-InspectorReportString `
                                (Get-InspectorReportProperty -InputObject $_ -Name 'Input')
                    }

                    $objectType =
                        ConvertTo-InspectorReportString `
                            (Get-InspectorReportProperty -InputObject $_ -Name 'ObjectType')

                    if ([string]::IsNullOrWhiteSpace($objectType)) {
                        $objectType =
                            ConvertTo-InspectorReportString `
                                (Get-InspectorReportProperty -InputObject $_ -Name 'ResolutionType')
                    }

                    $objectId =
                        ConvertTo-InspectorReportString `
                            (Get-InspectorReportProperty -InputObject $_ -Name 'ObjectId')

                    if ([string]::IsNullOrWhiteSpace($objectId)) {
                        $objectId =
                            ConvertTo-InspectorReportString `
                                (Get-InspectorReportProperty -InputObject $_ -Name 'Input')
                    }

                    [PSCustomObject][ordered]@{
                        DisplayName              = $displayName
                        ObjectType               = $objectType
                        ObjectId                 = $objectId
                        Input                    = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Input')
                        Status                   = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Status')
                        ResolutionType           = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'ResolutionType')
                        RelationshipStatus       = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'RelationshipStatus')
                        RelationshipCompleteness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'RelationshipCompleteness')
                        SecurityObservationCount = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'SecurityObservationCount')
                    }
                }
            )
    }

    $findingEvidenceIdSet = @{}

    foreach ($finding in @($AssessmentFindings)) {
        foreach ($evidenceId in @(Get-InspectorReportProperty -InputObject $finding -Name 'EvidenceIds')) {
            $key = ConvertTo-InspectorReportString $evidenceId

            if (-not [string]::IsNullOrWhiteSpace($key)) {
                $findingEvidenceIdSet[$key] = $true
            }
        }
    }

    $limitEvidenceToFindings =
        @($AssessmentFindings).Count -gt 0 -and
        $findingEvidenceIdSet.Count -gt 0

    if (@($EvidenceRows).Count -eq 0 -and $objectInsights.Count -gt 0) {
        $EvidenceRows =
            @(
                $objectInsights |
                ForEach-Object {
                    $parentInput =
                        ConvertTo-InspectorReportString `
                            (Get-InspectorReportProperty -InputObject $_ -Name 'Input')

                    $parentResolutionType =
                        ConvertTo-InspectorReportString `
                            (Get-InspectorReportProperty -InputObject $_ -Name 'ResolutionType')

                    $evidence =
                        @(
                            Get-InspectorReportProperty `
                                -InputObject $_ `
                                -Name 'Evidence'
                        )

                    $relationshipCollection =
                        Get-InspectorReportProperty `
                            -InputObject $_ `
                            -Name 'RelationshipCollection'

                    $relationshipEvidence =
                        @(
                            Get-InspectorReportProperty `
                                -InputObject $relationshipCollection `
                                -Name 'Evidence'
                        )

                    @($evidence + $relationshipEvidence) |
                    Where-Object { $null -ne $_ } |
                    Where-Object {
                        if (-not $limitEvidenceToFindings) {
                            return $true
                        }

                        $evidenceId =
                            ConvertTo-InspectorReportString `
                                (Get-InspectorReportProperty -InputObject $_ -Name 'EvidenceId')

                        return $findingEvidenceIdSet.ContainsKey($evidenceId)
                    } |
                    ForEach-Object {
                        [PSCustomObject][ordered]@{
                            ParentInput          = $parentInput
                            ParentResolutionType = $parentResolutionType
                            EvidenceId           = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'EvidenceId')
                            QueryName            = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'QueryName')
                            CollectorName        = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'CollectorName')
                            Endpoint             = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Endpoint')
                            RequiredPermission   = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'RequiredPermission')
                            Status               = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Status')
                            Limitations          = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Limitations')
                        }
                    }
                }
            )
    }

    if ($null -eq $Manifest) {
        $Manifest =
            [PSCustomObject][ordered]@{
                SchemaVersion     = '0.11.0'
                AssessmentName    = $AssessmentName
                GeneratedAt       = $generatedAt
                SourceKind        = $SourceKind
                SourceStatus      = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $InputObject -Name 'Status')
                GraphCallsIssued  = 0
                IntelligenceAdded = $false
            }
    }

    if ($null -eq $Summary) {
        $Summary =
            Get-InspectorReportProperty `
                -InputObject $InputObject `
                -Name 'Summary'
    }

    if ($null -eq $RuntimeTelemetry -and $null -ne $InputObject) {
        $RuntimeTelemetry =
            Get-InspectorReportProperty `
                -InputObject $InputObject `
                -Name 'RuntimeTelemetry'
    }

    if ($null -eq $OrchestrationTelemetry -and $null -ne $InputObject) {
        $OrchestrationTelemetry =
            Get-InspectorReportProperty `
                -InputObject $InputObject `
                -Name 'OrchestrationTelemetry'
    }

    $runtimeStageDurations =
        Get-InspectorReportProperty `
            -InputObject $RuntimeTelemetry `
            -Name 'StageDurations'

    $runtimeStageSummary =
        Get-InspectorReportProperty `
            -InputObject $RuntimeTelemetry `
            -Name 'StageSummary'

    if ($null -eq $OrchestrationTelemetry -and $null -ne $RuntimeTelemetry) {
        $OrchestrationTelemetry = [PSCustomObject][ordered]@{
            PSTypeName                       = 'EntraObjectInspector.OrchestrationTelemetry'
            SchemaVersion                    = '1.0.0'
            TenantInspectionDurationMs       = Get-InspectorReportProperty -InputObject $RuntimeTelemetry -Name 'TotalDurationMs'
            SnapshotCollectionDurationMs     = Get-InspectorReportProperty -InputObject (Get-InspectorReportProperty -InputObject $runtimeStageDurations -Name 'TenantSnapshotCollection') -Name 'DurationMs'
            OfflineProcessingDurationMs      = $null
            AssessmentIntelligenceDurationMs = $null
            ExportDurationMs                 = $null
            ReportGenerationDurationMs       = $null
            TotalCommandDurationMs           = $null
        }
    }

    if ($null -ne $OrchestrationTelemetry) {
        $snapshotDuration =
            Get-InspectorReportFirstValue `
                -InputObjects @(
                    $OrchestrationTelemetry
                    $runtimeStageSummary
                    (Get-InspectorReportProperty -InputObject $runtimeStageDurations -Name 'TenantSnapshotCollection')
                ) `
                -Names @('SnapshotCollectionDurationMs','TenantSnapshotCollectionDurationMs','DurationMs')

        $offlineDuration =
            Get-InspectorReportFirstValue `
                -InputObjects @(
                    $OrchestrationTelemetry
                    $runtimeStageSummary
                ) `
                -Names @('OfflineProcessingDurationMs')

        if ($null -eq $offlineDuration -and $null -ne $runtimeStageDurations) {
            $offlineDuration =
                @(
                    'OfflineResolution'
                    'OfflineRelationshipBuilding'
                    'Normalization'
                    'PermissionIntelligence'
                    'ObservationEngine'
                ) |
                ForEach-Object {
                    Get-InspectorReportProperty `
                        -InputObject (Get-InspectorReportProperty -InputObject $runtimeStageDurations -Name $_) `
                        -Name 'DurationMs'
                } |
                Where-Object { $null -ne $_ } |
                Measure-Object -Sum |
                ForEach-Object { $_.Sum }
        }

        if ($null -ne $snapshotDuration) {
            $OrchestrationTelemetry |
                Add-Member -NotePropertyName SnapshotCollectionDurationMs -NotePropertyValue $snapshotDuration -Force
        }

        if ($null -ne $offlineDuration) {
            $OrchestrationTelemetry |
                Add-Member -NotePropertyName OfflineProcessingDurationMs -NotePropertyValue $offlineDuration -Force
        }
    }

    $tenantMetadata =
        Get-InspectorReportFirstValue `
            -InputObjects @($Summary, $Manifest, $InputObject) `
            -Names @('TenantMetadata')

    $tenantId =
        Get-InspectorReportFirstValue `
            -InputObjects @($Summary, $Manifest, $tenantMetadata, $InputObject) `
            -Names @('TenantId','TenantID')

    $tenantDisplayName =
        Get-InspectorReportFirstValue `
            -InputObjects @($Summary, $Manifest, $tenantMetadata, $InputObject) `
            -Names @('TenantDisplayName','TenantName','DisplayName')

    $moduleVersion =
        Get-InspectorReportFirstValue `
            -InputObjects @($Manifest, $Summary) `
            -Names @('ModuleVersion')

    if ([string]::IsNullOrWhiteSpace([string]$moduleVersion)) {
        $moduleVersion = Get-InspectorReportModuleVersion
    }

    if ($null -ne $Summary) {
        if ($null -ne $tenantId) {
            $Summary | Add-Member -NotePropertyName TenantId -NotePropertyValue $tenantId -Force
        }

        if ($null -ne $tenantDisplayName) {
            $Summary | Add-Member -NotePropertyName TenantDisplayName -NotePropertyValue $tenantDisplayName -Force
        }

        if ($null -ne $tenantMetadata) {
            $Summary | Add-Member -NotePropertyName TenantMetadata -NotePropertyValue $tenantMetadata -Force
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$moduleVersion)) {
            $Summary | Add-Member -NotePropertyName ModuleVersion -NotePropertyValue $moduleVersion -Force
        }
    }

    if ($null -ne $Manifest) {
        if ($null -ne $tenantId) {
            $Manifest | Add-Member -NotePropertyName TenantId -NotePropertyValue $tenantId -Force
        }

        if ($null -ne $tenantDisplayName) {
            $Manifest | Add-Member -NotePropertyName TenantDisplayName -NotePropertyValue $tenantDisplayName -Force
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$moduleVersion)) {
            $Manifest | Add-Member -NotePropertyName ModuleVersion -NotePropertyValue $moduleVersion -Force
        }
    }

    $scopeInventory =
        Get-InspectorReportFirstValue `
            -InputObjects @($Summary, $Manifest, $InputObject) `
            -Names @('ScopeInventory')

    $tenantCapabilities =
        Get-InspectorReportFirstValue `
            -InputObjects @($Summary, $Manifest, $InputObject) `
            -Names @('TenantCapabilities')

    $runId =
        Get-InspectorReportFirstValue `
            -InputObjects @($InputObject, $Manifest, $Summary) `
            -Names @('RunId')

    if ([string]::IsNullOrWhiteSpace([string]$runId)) {
        $runId =
            Get-InspectorReportFirstValue `
                -InputObjects @($InputObject, $Manifest, $Summary) `
                -Names @('SnapshotId')
    }

    if ([string]::IsNullOrWhiteSpace([string]$runId)) {
        $runId =
            Get-InspectorReportFirstValue `
                -InputObjects @($Manifest, $Summary, $InputObject) `
                -Names @('ExportId')
    }

    if ([string]::IsNullOrWhiteSpace([string]$runId)) {
        $runId = [guid]::NewGuid().ToString()
    }

    $reportId =
        Get-InspectorReportFirstValue `
            -InputObjects @($Manifest, $Summary) `
            -Names @('ReportId')

    if ([string]::IsNullOrWhiteSpace([string]$reportId)) {
        $reportId = [guid]::NewGuid().ToString()
    }

    if ($null -ne $Summary) {
        $Summary | Add-Member -NotePropertyName RunId -NotePropertyValue ([string]$runId) -Force
        $Summary | Add-Member -NotePropertyName ReportId -NotePropertyValue ([string]$reportId) -Force
        $Summary | Add-Member -NotePropertyName FailedObjectCount -NotePropertyValue @($FailedObjects).Count -Force
    }

    if ($null -ne $Manifest) {
        $Manifest | Add-Member -NotePropertyName RunId -NotePropertyValue ([string]$runId) -Force
        $Manifest | Add-Member -NotePropertyName ReportId -NotePropertyValue ([string]$reportId) -Force
        $Manifest | Add-Member -NotePropertyName FailedObjectCount -NotePropertyValue @($FailedObjects).Count -Force
    }

    $intelligenceSummary = Get-InspectorReportProperty -InputObject $AssessmentIntelligence -Name 'Summary'
    if ($null -ne $Summary -and $null -ne $intelligenceSummary) {
        foreach ($metricName in @('RawObservationCount','DeduplicatedObservationCount','DuplicateObservationCount','GroupedFindingCount')) {
            $metricValue = Get-InspectorReportProperty -InputObject $intelligenceSummary -Name $metricName
            if ($null -ne $metricValue -and -not [string]::IsNullOrWhiteSpace([string]$metricValue)) {
                $Summary | Add-Member -NotePropertyName $metricName -NotePropertyValue $metricValue -Force
            }
        }
    }

    $severitySummary =
        if ($null -ne $AssessmentIntelligence -and @((Get-InspectorReportProperty -InputObject $AssessmentIntelligence -Name 'SeveritySummary')).Count -gt 0) {
            @(Get-InspectorReportProperty -InputObject $AssessmentIntelligence -Name 'SeveritySummary')
        }
        else {
            @(
                @($SecurityObservations) |
                Where-Object { $null -ne $_ } |
                Group-Object Severity |
                Sort-Object {
                    Get-InspectorReportSeverityOrder -Severity $_.Name
                }, Name |
                ForEach-Object {
                    [PSCustomObject][ordered]@{
                        Severity = $_.Name
                        Count = $_.Count
                    }
                }
            )
        }

    $categorySummary =
        if ($null -ne $AssessmentIntelligence -and @((Get-InspectorReportProperty -InputObject $AssessmentIntelligence -Name 'CategorySummary')).Count -gt 0) {
            @(Get-InspectorReportProperty -InputObject $AssessmentIntelligence -Name 'CategorySummary')
        }
        else {
            @(
                @($SecurityObservations) |
                Where-Object { $null -ne $_ } |
                Group-Object Category |
                Sort-Object Name |
                ForEach-Object {
                    [PSCustomObject][ordered]@{
                        Category = $_.Name
                        Count = $_.Count
                    }
                }
            )
        }

    $findingsByCategory =
        @(
            @($AssessmentFindings) |
            Where-Object { $null -ne $_ } |
            Group-Object Category |
            Sort-Object Name |
            ForEach-Object {
                [PSCustomObject][ordered]@{
                    Category = $_.Name
                    Count = $_.Count
                }
            }
        )

    $observationGroups =
        ConvertTo-InspectorReportObservationGroup `
            -SecurityObservations @($SecurityObservations)

    $executiveNarrative =
        New-InspectorReportNarrative `
            -TenantPosture $TenantPosture `
            -AssessmentFindings @($AssessmentFindings) `
            -AssessmentRecommendations @($AssessmentRecommendations) `
            -SecurityObservations @($SecurityObservations)

    $packageValidation =
        Test-InspectorReportPackageConsistency `
            -Summary $Summary `
            -SecurityObservations @($SecurityObservations) `
            -EvidenceRows @($EvidenceRows) `
            -AssessmentFindings @($AssessmentFindings) `
            -FailedObjects @($FailedObjects) `
            -Manifest $Manifest `
            -SourcePath $(if ($SourceKind -eq 'ExportDirectory') { $SourcePath } else { '' })

    $reportLimitations =
        @(
            'The HTML report is presentation-only.',
            'The report does not call Microsoft Graph.',
            'The report does not create new observations, new recommendations, risk scores, exposure scores, attack paths, MITRE mappings, history, UI, or remediation automation.',
            @($AssessmentLimitations)
        ) |
        ForEach-Object {
            if ($_ -is [array]) {
                $_
            }
            else {
                ,$_
            }
        } |
        ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique

    $packageValidationDto = [PSCustomObject][ordered]@{
        PackageValidationStatus = $packageValidation.Status
        ReleaseEligible = $packageValidation.ReleaseEligible
        ValidationErrors = @($packageValidation.Errors)
        ValidationWarnings = @($packageValidation.Warnings)
    }

    $assessmentCoverage = Get-InspectorReportProperty -InputObject $Summary -Name 'AssessmentCoverage'
    if ($null -eq $assessmentCoverage) {
        $assessmentCoverage = Get-InspectorReportProperty -InputObject $Manifest -Name 'AssessmentCoverage'
    }

    foreach ($packageObject in @($AssessmentIntelligence, $TenantPosture)) {
        if ($null -eq $packageObject) { continue }
        $packageObject | Add-Member -NotePropertyName RunId -NotePropertyValue ([string]$runId) -Force
        $packageObject | Add-Member -NotePropertyName ReportId -NotePropertyValue ([string]$reportId) -Force
        $packageObject | Add-Member -NotePropertyName FailedObjectCount -NotePropertyValue $packageValidation.FailedObjectCount -Force
        $packageObject | Add-Member -NotePropertyName AssessmentCoverageStatus -NotePropertyValue (Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'Status') -Force
        $packageObject | Add-Member -NotePropertyName AssessmentCoverageCompleteness -NotePropertyValue (Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'Completeness') -Force
        $packageObject | Add-Member -NotePropertyName ExpectedEvidenceCount -NotePropertyValue (Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'ExpectedEvidenceCount') -Force
        $packageObject | Add-Member -NotePropertyName ActualRequiredEvidenceCount -NotePropertyValue (Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'ActualRequiredEvidenceCount') -Force
        $packageObject | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue $packageValidation.Status -Force
        $packageObject | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $packageValidation.ReleaseEligible -Force
        $packageObject | Add-Member -NotePropertyName ValidationErrors -NotePropertyValue @($packageValidation.Errors) -Force
        $packageObject | Add-Member -NotePropertyName ValidationWarnings -NotePropertyValue @($packageValidation.Warnings) -Force
    }

    $Summary | Add-Member -NotePropertyName PackageValidation -NotePropertyValue $packageValidationDto -Force
    $Summary | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue $packageValidation.Status -Force
    $Summary | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $packageValidation.ReleaseEligible -Force
    $Summary | Add-Member -NotePropertyName ValidationErrors -NotePropertyValue @($packageValidation.Errors) -Force
    $Summary | Add-Member -NotePropertyName ValidationWarnings -NotePropertyValue @($packageValidation.Warnings) -Force
    $Summary | Add-Member -NotePropertyName FailedObjectCount -NotePropertyValue $packageValidation.FailedObjectCount -Force
    $Manifest | Add-Member -NotePropertyName PackageValidation -NotePropertyValue $packageValidationDto -Force
    $Manifest | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue $packageValidation.Status -Force
    $Manifest | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $packageValidation.ReleaseEligible -Force
    $Manifest | Add-Member -NotePropertyName ValidationErrors -NotePropertyValue @($packageValidation.Errors) -Force
    $Manifest | Add-Member -NotePropertyName ValidationWarnings -NotePropertyValue @($packageValidation.Warnings) -Force
    $Manifest | Add-Member -NotePropertyName FailedObjectCount -NotePropertyValue $packageValidation.FailedObjectCount -Force

    return [PSCustomObject][ordered]@{
        PSTypeName                    = 'EntraObjectInspector.AssessmentReportModel'
        SchemaVersion                 = '0.12.0'
        AssessmentName                = $AssessmentName
        GeneratedAt                   = $generatedAt
        RunId                         = [string]$runId
        ReportId                      = [string]$reportId
        ClientName                    = $ClientName
        ConsultantName                = $ConsultantName
        OrchestrationTelemetry        = $OrchestrationTelemetry
        SourceKind                    = $SourceKind
        SourcePath                    = $SourcePath
        GraphCallsIssued              = 0
        IntelligenceAdded             = $false
        NewObservationsAdded          = $false
        RiskScoreProduced             = $false
        AttackPathsProduced           = $false
        ClientSideInteractivity       = $true
        SelfContainedHtml             = $true
        Printable                     = $true
        Manifest                      = $Manifest
        Summary                       = $Summary
        ScopeInventory                = $scopeInventory
        TenantCapabilities            = $tenantCapabilities
        AssessmentCoverage            = $assessmentCoverage
        AssessmentIntelligence        = $AssessmentIntelligence
        TenantPosture                 = $TenantPosture
        ExecutiveNarrative            = $executiveNarrative
        SecurityObservations          = @($SecurityObservations)
        ObservationGroups             = @($observationGroups)
        SeveritySummary               = @($severitySummary)
        CategorySummary               = @($categorySummary)
        AssessmentFindings            = @($AssessmentFindings)
        AssessmentRecommendations     = @($AssessmentRecommendations)
        AssessmentCorrelations        = @($AssessmentCorrelations)
        AssessmentLimitations         = @($AssessmentLimitations)
        ReportLimitations             = @($reportLimitations)
        RuntimeTelemetry              = $RuntimeTelemetry
        ObjectIndex                   = @($ObjectIndex)
        EvidenceRows                  = @($EvidenceRows)
        FailedObjects                 = @($FailedObjects)
        FindingsByCategory            = @($findingsByCategory)
        PackageValidationStatus       = $packageValidation.Status
        ReleaseEligible               = $packageValidation.ReleaseEligible
        FailedObjectCount             = $packageValidation.FailedObjectCount
        PackageValidation             = $packageValidationDto
        PackageValidationErrors       = @($packageValidation.Errors)
        PackageValidationWarnings     = @($packageValidation.Warnings)
        ReportFileName                = ''
        DiagnosticsReportFileName     = ''
        EvidenceReportFileName        = ''
    }
}

function New-InspectorReportNarrative {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$TenantPosture,

        [object[]]$AssessmentFindings = @(),

        [object[]]$AssessmentRecommendations = @(),

        [object[]]$SecurityObservations = @()
    )

    $postureLabel =
        ConvertTo-InspectorReportString `
            (Get-InspectorReportProperty -InputObject $TenantPosture -Name 'Label')

    if ([string]::IsNullOrWhiteSpace($postureLabel)) {
        $postureLabel = 'NotAvailable'
    }

    $highFindings =
        @($AssessmentFindings | Where-Object { (Get-InspectorReportProperty -InputObject $_ -Name 'Severity') -eq 'High' })

    $mediumFindings =
        @($AssessmentFindings | Where-Object { (Get-InspectorReportProperty -InputObject $_ -Name 'Severity') -eq 'Medium' })

    $topFindingTitles =
        @(
            @($AssessmentFindings) |
            Sort-Object {
                Get-InspectorReportSeverityOrder -Severity ([string](Get-InspectorReportProperty -InputObject $_ -Name 'Severity'))
            }, Category, Title |
            Select-Object -First 3 |
            ForEach-Object {
                ConvertTo-InspectorReportString `
                    (Get-InspectorReportProperty -InputObject $_ -Name 'Title')
            }
        )

    $topRecommendationTitles =
        @(
            @($AssessmentRecommendations) |
            Select-Object -First 3 |
            ForEach-Object {
                ConvertTo-InspectorReportString `
                    (Get-InspectorReportProperty -InputObject $_ -Name 'Title')
            }
        )

    $focus =
        if ($topFindingTitles.Count -gt 0) {
            $topFindingTitles -join '; '
        }
        else {
            'No assessment findings were supplied.'
        }

    $recommendedFocus =
        if ($topRecommendationTitles.Count -gt 0) {
            $topRecommendationTitles -join '; '
        }
        else {
            'No assessment recommendations were supplied.'
        }

    return [PSCustomObject][ordered]@{
        PostureStatement = "The assessed tenant posture is '$postureLabel' based only on existing assessment findings and observations."
        KeyConcern       = "Primary review areas: $focus"
        RecommendedFocus = "Recommended consultant focus: $recommendedFocus"
        EvidenceBasis    = "The narrative is derived from $(@($AssessmentFindings).Count) finding(s), $(@($AssessmentRecommendations).Count) recommendation(s), and $(@($SecurityObservations).Count) observation(s)."
        HighFindingCount = $highFindings.Count
        MediumFindingCount = $mediumFindings.Count
    }
}
