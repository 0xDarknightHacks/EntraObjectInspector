function Get-InspectorIntelligenceProperty {
    [CmdletBinding()]
    param (
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }

    return $property.Value
}

function ConvertTo-InspectorIntelligenceString {
    [CmdletBinding()]
    param ([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }

    if ($Value -is [array]) {
        return (@($Value) | ForEach-Object { [string]$_ }) -join '; '
    }

    if (
        $Value -is [System.Management.Automation.PSCustomObject] -or
        $Value -is [hashtable]
    ) {
        return ($Value | ConvertTo-Json -Depth 20 -Compress)
    }

    return [string]$Value
}

function New-InspectorIntelligenceId {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Seed
    )

    $sha = [System.Security.Cryptography.SHA256]::Create()

    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Seed)
        $hashBytes = $sha.ComputeHash($bytes)
        return "$Prefix-" + (-join ($hashBytes[0..7] | ForEach-Object { $_.ToString('x2') })).ToUpperInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-InspectorSeverityOrder {
    [CmdletBinding()]
    param ([string]$Severity)

    switch ($Severity) {
        'High' { return 1 }
        'Medium' { return 2 }
        'Low' { return 3 }
        'Informational' { return 4 }
        default { return 99 }
    }
}

function Get-InspectorConfidenceOrder {
    [CmdletBinding()]
    param ([string]$Confidence)

    switch ($Confidence) {
        'High' { return 1 }
        'Medium' { return 2 }
        'Low' { return 3 }
        default { return 99 }
    }
}

function Join-InspectorConfidence {
    [CmdletBinding()]
    param ([object[]]$Confidence)

    $values = @(
        @($Confidence) |
            ForEach-Object { [string]$_ } |
            Where-Object { $_ -in @('High', 'Medium', 'Low') }
    )

    if (@($values).Count -eq 0) { return 'Low' }
    if ('Low' -in @($values)) { return 'Low' }
    if ('Medium' -in @($values)) { return 'Medium' }
    return 'High'
}

function Join-InspectorSeverity {
    [CmdletBinding()]
    param ([object[]]$Severity)

    $values = @(
        @($Severity) |
            ForEach-Object { [string]$_ } |
            Where-Object { $_ -in @('High', 'Medium', 'Low', 'Informational') }
    )

    if (@($values).Count -eq 0) { return 'Informational' }
    if ('High' -in @($values)) { return 'High' }
    if ('Medium' -in @($values)) { return 'Medium' }
    if ('Low' -in @($values)) { return 'Low' }
    return 'Informational'
}

function Get-InspectorObservationKey {
    [CmdletBinding()]
    param ([Parameter(Mandatory)][object]$Observation)

    $semanticKey = [string](Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'SemanticKey')
    if (-not [string]::IsNullOrWhiteSpace($semanticKey)) { return $semanticKey }

    $affectedObject = Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'AffectedObject'
    $affectedObjectId = [string](Get-InspectorIntelligenceProperty -InputObject $affectedObject -Name 'ObjectId')
    $category = [string](Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'Category')
    $title = [string](Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'Title')
    $metadata = Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'Metadata'
    $sourceRuleIds = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'SourceRuleIds')
    $permissionName = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $metadata -Name 'PermissionName')
    $permissionType = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $metadata -Name 'PermissionType')
    $resourceAppId = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $metadata -Name 'ResourceAppId')
    $appRoleId = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $metadata -Name 'AppRoleId')
    $credentialId = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $metadata -Name 'KeyId')

    return New-InspectorIntelligenceId -Prefix 'OBSKEY' -Seed "$category|$title|$affectedObjectId|$sourceRuleIds|$permissionName|$permissionType|$resourceAppId|$appRoleId|$credentialId"
}

function Get-InspectorDeduplicatedObservations {
    [CmdletBinding()]
    param ([object[]]$Observation)

    $seen = @{}
    $deduped = [System.Collections.Generic.List[object]]::new()

    foreach ($item in @($Observation)) {
        if ($null -eq $item) { continue }

        $key = Get-InspectorObservationKey -Observation $item
        if ($seen.ContainsKey($key)) {
            $canonical = $seen[$key]
            foreach ($propertyName in @('EvidenceIds', 'SourceRuleIds', 'Limitations', 'References')) {
                $mergedValues = @(
                    @(Get-InspectorIntelligenceProperty -InputObject $canonical -Name $propertyName)
                    @(Get-InspectorIntelligenceProperty -InputObject $item -Name $propertyName)
                ) | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique

                $canonical | Add-Member -NotePropertyName $propertyName -NotePropertyValue @($mergedValues) -Force
            }
            continue
        }

        $seen[$key] = $item
        $deduped.Add($item)
    }

    return @(
        $deduped |
            Sort-Object `
                @{ Expression = { Get-InspectorIntelligenceProperty -InputObject $_ -Name 'Category' } },
                @{ Expression = { Get-InspectorSeverityOrder -Severity ([string](Get-InspectorIntelligenceProperty -InputObject $_ -Name 'Severity')) } },
                @{ Expression = { Get-InspectorIntelligenceProperty -InputObject $_ -Name 'Title' } },
                @{ Expression = { Get-InspectorIntelligenceProperty -InputObject $_ -Name 'ObservationId' } }
    )
}

function Get-InspectorTenantSecurityObservations {
    [CmdletBinding()]
    param ([Parameter(Mandatory)][object]$InputObject)

    $rootObservations = @(
        (Get-InspectorIntelligenceProperty -InputObject $InputObject -Name 'SecurityObservations') |
            Where-Object { $null -ne $_ }
    )

    if (@($rootObservations).Count -gt 0) { return @($rootObservations) }

    $objectInsights = @(
        (Get-InspectorIntelligenceProperty -InputObject $InputObject -Name 'ObjectInsights') |
            Where-Object { $null -ne $_ }
    )

    return @(
        $objectInsights |
            ForEach-Object {
                @(Get-InspectorIntelligenceProperty -InputObject $_ -Name 'SecurityObservations')
            } |
            Where-Object { $null -ne $_ }
    )
}

function Get-InspectorTenantObjectInsights {
    [CmdletBinding()]
    param ([Parameter(Mandatory)][object]$InputObject)

    $objectInsights = @(
        (Get-InspectorIntelligenceProperty -InputObject $InputObject -Name 'ObjectInsights') |
            Where-Object { $null -ne $_ }
    )

    if (@($objectInsights).Count -gt 0) { return @($objectInsights) }

    $typeName = @($InputObject.PSObject.TypeNames)[0]
    if ($typeName -eq 'EntraObjectInspector.ObjectInsight') { return @($InputObject) }

    return @()
}

function Get-InspectorObservationIds {
    [CmdletBinding()]
    param ([object[]]$Observation)

    return @(
        @($Observation) |
            ForEach-Object { Get-InspectorIntelligenceProperty -InputObject $_ -Name 'ObservationId' } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Select-Object -Unique
    )
}

function Get-InspectorEvidenceIdsFromObservation {
    [CmdletBinding()]
    param ([object[]]$Observation)

    return @(
        @($Observation) |
            ForEach-Object {
                @(Get-InspectorIntelligenceProperty -InputObject $_ -Name 'EvidenceIds')
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Select-Object -Unique
    )
}

function Get-InspectorAffectedObjectsFromObservation {
    [CmdletBinding()]
    param ([Alias('Observation')][object[]]$Observations)

    $seen = @{}

    $objects = @(
        foreach ($observation in @($Observations)) {
            $affected = Get-InspectorIntelligenceProperty -InputObject $observation -Name 'AffectedObject'
            if ($null -ne $affected) {
                $objectType = [string](Get-InspectorIntelligenceProperty -InputObject $affected -Name 'ObjectType')
                $objectId = [string](Get-InspectorIntelligenceProperty -InputObject $affected -Name 'ObjectId')
                $displayName = [string](Get-InspectorIntelligenceProperty -InputObject $affected -Name 'DisplayName')
                $appId = [string](Get-InspectorIntelligenceProperty -InputObject $affected -Name 'AppId')
                $upn = [string](Get-InspectorIntelligenceProperty -InputObject $affected -Name 'UserPrincipalName')
                $publisherClassification = [string](Get-InspectorIntelligenceProperty -InputObject $affected -Name 'PublisherClassification')
                $tenantOwnershipClassification = [string](Get-InspectorIntelligenceProperty -InputObject $affected -Name 'TenantOwnershipClassification')
                $classificationConfidence = [string](Get-InspectorIntelligenceProperty -InputObject $affected -Name 'ClassificationConfidence')
                $servicePrincipalType = [string](Get-InspectorIntelligenceProperty -InputObject $affected -Name 'ServicePrincipalType')
                $accountEnabled = Get-InspectorIntelligenceProperty -InputObject $affected -Name 'AccountEnabled'
                $isAssignableToRole = Get-InspectorIntelligenceProperty -InputObject $affected -Name 'IsAssignableToRole'
                $severity = [string](Get-InspectorIntelligenceProperty -InputObject $observation -Name 'Severity')
                $key = "$objectType|$objectId"

                if (-not $seen.ContainsKey($key)) {
                    $seen[$key] = $true

                    Write-Output ([PSCustomObject][ordered]@{
                        ObjectType = $objectType
                        ObjectId = $objectId
                        DisplayName = $displayName
                        AppId = $appId
                        UserPrincipalName = $upn
                        PublisherClassification = $publisherClassification
                        TenantOwnershipClassification = $tenantOwnershipClassification
                        ClassificationConfidence = $classificationConfidence
                        ServicePrincipalType = $servicePrincipalType
                        AccountEnabled = $accountEnabled
                        IsAssignableToRole = $isAssignableToRole
                        Severity = $severity
                        ObservationCount = @($Observations | Where-Object {
                            $candidate = Get-InspectorIntelligenceProperty -InputObject $_ -Name 'AffectedObject'
                            $candidateType = [string](Get-InspectorIntelligenceProperty -InputObject $candidate -Name 'ObjectType')
                            $candidateId = [string](Get-InspectorIntelligenceProperty -InputObject $candidate -Name 'ObjectId')
                            ($candidateType -eq $objectType) -and ($candidateId -eq $objectId)
                        }).Count
                    })
                }
            }
        }
    )

    return @($objects | Sort-Object @{ Expression = { Get-InspectorSeverityOrder -Severity ([string]$_.Severity) } }, ObjectType, DisplayName, ObjectId)
}

function Get-InspectorFindingEvidenceLinkStatus {
    [CmdletBinding()]
    param (
        [object[]]$EvidenceIds,
        [object[]]$AffectedObjects
    )

    if (@($EvidenceIds | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
        return 'DirectEvidence'
    }

    # An affected ObjectId identifies the subject but is not evidence that the
    # assessed condition was observed or derived from a complete collection.
    return 'InsufficientEvidence'
}

function Get-InspectorFindingResultState {
    [CmdletBinding()]
    param (
        [string]$Severity,
        [string]$EvidenceLinkStatus
    )

    if ($Severity -eq 'Informational') { return 'Informational' }
    if ($EvidenceLinkStatus -eq 'InsufficientEvidence') { return 'MoreEvidenceNeeded' }
    if ($Severity -in @('High', 'Medium')) { return 'Confirmed' }
    return 'ReviewRequired'
}

function Get-InspectorObservationEvidenceSupportStatus {
    [CmdletBinding()]
    param ([AllowNull()][object]$Observation)

    $metadata = Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'Metadata'
    $declaredSupport = [string](Get-InspectorIntelligenceProperty -InputObject $metadata -Name 'EvidenceSupportType')
    $evidenceIds = @(Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'EvidenceIds') |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }

    if ($declaredSupport -eq 'InsufficientEvidence') {
        return 'Unsupported'
    }

    if ($declaredSupport -in @('DerivedFromTenantCollection', 'DerivedFromCollectedState')) {
        if (@($evidenceIds).Count -gt 0) {
            return 'Derived'
        }

        return 'Unsupported'
    }

    if (@($evidenceIds).Count -gt 0) {
        return 'Direct'
    }

    # Object identity is context, not provenance. Without evidence IDs or an
    # explicitly supported derived-evidence contract, the observation is not
    # evidence-supported.
    return 'Unsupported'
}

function Get-InspectorFindingEvidenceSupportStatus {
    [CmdletBinding()]
    param (
        [int]$DirectCount,
        [int]$DerivedCount,
        [int]$UnsupportedCount
    )

    if ($UnsupportedCount -gt 0) { return 'Insufficient' }
    if ($DirectCount -gt 0 -and $DerivedCount -gt 0) { return 'Mixed' }
    if ($DirectCount -gt 0) { return 'AllDirect' }
    if ($DerivedCount -gt 0) { return 'DerivedOnly' }
    return 'Insufficient'
}

function Get-InspectorFindingSeverityReason {
    [CmdletBinding()]
    param (
        [string]$Category,
        [string]$Severity
    )

    switch ($Category) {
        'PermissionExposure' { return 'Severity reflects the potential impact of observed Microsoft Graph application permissions, not the number of observations.' }
        'CredentialHygiene' { return 'Severity reflects credential lifecycle exposure such as expired, expiring, long-lived, or overlapping credentials when metadata is available.' }
        'IdentityGovernance' { return 'Severity reflects ownership accountability gaps and owner state signals that can affect governance continuity.' }
        'GroupGovernance' { return 'Severity reflects privileged or role-assignable group conditions derived from collected group and role metadata.' }
        'ServicePrincipalGovernance' { return 'Severity reflects service-principal governance conditions requiring validation; routine state facts are treated as contextual signals.' }
        default { return "Severity is based on the potential security impact of the grouped condition and its supporting evidence." }
    }
}

function Get-InspectorIssueGroupsFromObservation {
    [CmdletBinding()]
    param ([object[]]$Observation)

    return @(
        @($Observation) |
            Group-Object Title |
            Sort-Object @{ Expression = 'Count'; Descending = $true }, Name |
            ForEach-Object {
                $first = @($_.Group)[0]
                [PSCustomObject][ordered]@{
                    Condition = [string]$_.Name
                    Criterion = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $first -Name 'WhyItMatters')
                    ObjectCount = @(Get-InspectorAffectedObjectsFromObservation -Observation @($_.Group)).Count
                    ObservationCount = @($_.Group).Count
                    Severity = Join-InspectorSeverity -Severity @($_.Group | ForEach-Object { Get-InspectorIntelligenceProperty -InputObject $_ -Name 'Severity' })
                    Confidence = Join-InspectorConfidence -Confidence @($_.Group | ForEach-Object { Get-InspectorIntelligenceProperty -InputObject $_ -Name 'Confidence' })
                    SampleAffectedObjects = @(Get-InspectorAffectedObjectsFromObservation -Observation @($_.Group) | Select-Object -First 5)
                }
            }
    )
}

function Get-InspectorLimitationsFromObservation {
    [CmdletBinding()]
    param ([object[]]$Observation)

    return @(
        @($Observation) |
            ForEach-Object {
                @(Get-InspectorIntelligenceProperty -InputObject $_ -Name 'Limitations')
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Select-Object -Unique
    )
}

function Test-InspectorObservationFindingEligibility {
    [CmdletBinding()]
    param ([AllowNull()][object]$Observation)

    if ($null -eq $Observation) { return $false }
    $findingEligible = Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'FindingEligible'
    if ($null -ne $findingEligible) {
        return [bool]$findingEligible
    }

    $signalDisposition = [string](Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'SignalDisposition')
    if ($signalDisposition -eq 'Contextual') { return $false }

    $severity = [string](Get-InspectorIntelligenceProperty -InputObject $Observation -Name 'Severity')
    return $severity -ne 'Informational'
}

function New-InspectorAssessmentFinding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('AssessmentOverview','IdentityGovernance','CredentialHygiene','PermissionExposure','ServicePrincipalGovernance','ConsentGovernance','UserGovernance','GroupGovernance')]
        [string]$Category,

        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Conclusion,

        [Parameter(Mandatory)]
        [ValidateSet('Informational','Low','Medium','High')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateSet('High','Medium','Low')]
        [string]$Confidence,

        [object[]]$RelatedObservations = @(),

        [Parameter(Mandatory)][string]$Recommendation,
        [Parameter(Mandatory)][string]$MicrosoftReference,

        [string[]]$Limitations = @(),
        [hashtable]$Metadata = @{}
    )

    $observationIds = Get-InspectorObservationIds -Observation $RelatedObservations
    $evidenceIds = Get-InspectorEvidenceIdsFromObservation -Observation $RelatedObservations
    $affectedObjects = Get-InspectorAffectedObjectsFromObservation -Observation $RelatedObservations
    $supportValues = @($RelatedObservations | ForEach-Object { Get-InspectorObservationEvidenceSupportStatus -Observation $_ })
    $directSupportCount = @($supportValues | Where-Object { $_ -eq 'Direct' }).Count
    $derivedSupportCount = @($supportValues | Where-Object { $_ -eq 'Derived' }).Count
    $unsupportedSupportCount = @($supportValues | Where-Object { $_ -eq 'Unsupported' }).Count
    $evidenceSupportStatus = Get-InspectorFindingEvidenceSupportStatus -DirectCount $directSupportCount -DerivedCount $derivedSupportCount -UnsupportedCount $unsupportedSupportCount
    $evidenceLinkStatus =
        switch ($evidenceSupportStatus) {
            'AllDirect' { 'DirectEvidence'; break }
            'Mixed' { 'Mixed'; break }
            'DerivedOnly' { 'DerivedFromCollectedState'; break }
            default { 'InsufficientEvidence'; break }
        }
    $resultState = Get-InspectorFindingResultState -Severity $Severity -EvidenceLinkStatus $evidenceLinkStatus
    $criterionSummary = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject ([PSCustomObject]$Metadata) -Name 'CriterionSummary')
    if ([string]::IsNullOrWhiteSpace($criterionSummary)) {
        $criterionSummary = "Related observations were evaluated for $Category conditions and grouped into this report-level finding."
    }
    $issueGroups = @(Get-InspectorIssueGroupsFromObservation -Observation $RelatedObservations)
    $whyItMattersValues = @(
        $RelatedObservations |
            ForEach-Object { [string](Get-InspectorIntelligenceProperty -InputObject $_ -Name 'WhyItMatters') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
    $whyItMatters = if ($whyItMattersValues.Count -gt 0) { $whyItMattersValues -join ' ' } else { Get-InspectorFindingSeverityReason -Category $Category -Severity $Severity }
    $baselineStates = @(
        $RelatedObservations |
            ForEach-Object { [string](Get-InspectorIntelligenceProperty -InputObject $_ -Name 'BaselineState') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    $baselineState =
        if ($baselineStates.Count -gt 0 -and @($baselineStates | Where-Object { $_ -ne 'Accepted' }).Count -eq 0) { 'Accepted' }
        elseif ('Changed' -in $baselineStates) { 'Changed' }
        elseif ('New' -in $baselineStates) { 'New' }
        else { 'Existing' }
    $evidenceProof = @(
        $RelatedObservations |
            Sort-Object ObservationId |
            ForEach-Object {
                [PSCustomObject][ordered]@{
                    ObservationId = [string](Get-InspectorIntelligenceProperty -InputObject $_ -Name 'ObservationId')
                    SemanticKey = [string](Get-InspectorIntelligenceProperty -InputObject $_ -Name 'SemanticKey')
                    EvidenceIds = @(Get-InspectorIntelligenceProperty -InputObject $_ -Name 'EvidenceIds')
                    EvidenceSupportStatus = Get-InspectorObservationEvidenceSupportStatus -Observation $_
                }
            }
    )
    $seed = "$Category|$Title|$($observationIds -join ',')|$Conclusion"

    $finding = [PSCustomObject][ordered]@{
        PSTypeName = 'EntraObjectInspector.AssessmentFinding'
        SchemaVersion = '1.0.0'
        FindingId = New-InspectorIntelligenceId -Prefix 'FINDING' -Seed $seed
        Category = $Category
        Title = $Title
        Conclusion = $Conclusion
        WhatHappened = $Conclusion
        WhyItMatters = $whyItMatters
        RecommendedAction = $Recommendation
        BaselineState = $baselineState
        Severity = $Severity
        Confidence = $Confidence
        ResultState = $resultState
        ObservationIds = @($observationIds)
        EvidenceIds = @($evidenceIds)
        EvidenceProof = @($evidenceProof)
        EvidenceLinkStatus = $evidenceLinkStatus
        EvidenceSupportStatus = $evidenceSupportStatus
        ContributingObservationCount = @($RelatedObservations).Count
        DirectEvidenceObservationCount = $directSupportCount
        DerivedEvidenceObservationCount = $derivedSupportCount
        UnsupportedObservationCount = $unsupportedSupportCount
        UniqueEvidenceCount = @($evidenceIds).Count
        DirectEvidenceCoveragePercent = $(if (@($RelatedObservations).Count -gt 0) { [math]::Round(($directSupportCount / @($RelatedObservations).Count) * 100, 2) } else { 0 })
        AffectedObjects = @($affectedObjects)
        AffectedObjectCount = @($affectedObjects).Count
        ObservationCount = @($observationIds).Count
        CriterionSummary = $criterionSummary
        SeverityReason = Get-InspectorFindingSeverityReason -Category $Category -Severity $Severity
        IssueGroups = @($issueGroups)
        RecommendationNotApplicable = [string]::IsNullOrWhiteSpace($Recommendation)
        MicrosoftReference = $MicrosoftReference
        Recommendation = $Recommendation
        Limitations = @(
            (@($Limitations) + @(Get-InspectorLimitationsFromObservation -Observation $RelatedObservations)) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                Select-Object -Unique
        )
        Metadata = [PSCustomObject]$Metadata
    }

    $finding | Add-Member -NotePropertyName References -NotePropertyValue @(Resolve-InspectorRecommendationReferences -InputObject $finding) -Force

    return $finding
}

function New-InspectorAssessmentRecommendation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Rationale,
        [Parameter(Mandatory)][string]$MicrosoftReference,
        [object[]]$RelatedObservations = @(),
        [ValidateSet('High','Medium','Low')][string]$Confidence = 'Medium',
        [string[]]$Limitations = @()
    )

    $observationIds = Get-InspectorObservationIds -Observation $RelatedObservations
    $seed = "$Category|$Title|$Action|$($observationIds -join ',')"

    $recommendation = [PSCustomObject][ordered]@{
        PSTypeName = 'EntraObjectInspector.AssessmentRecommendation'
        SchemaVersion = '0.9.0'
        RecommendationId = New-InspectorIntelligenceId -Prefix 'REC' -Seed $seed
        Category = $Category
        Title = $Title
        Action = $Action
        Rationale = $Rationale
        MicrosoftReference = $MicrosoftReference
        Confidence = $Confidence
        ObservationIds = @($observationIds)
        EvidenceIds = @(Get-InspectorEvidenceIdsFromObservation -Observation $RelatedObservations)
        Limitations = @(
            (@($Limitations) + @(Get-InspectorLimitationsFromObservation -Observation $RelatedObservations)) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                Select-Object -Unique
        )
    }

    $recommendation | Add-Member -NotePropertyName References -NotePropertyValue @(Resolve-InspectorRecommendationReferences -InputObject $recommendation) -Force

    return $recommendation
}

function New-InspectorAssessmentCorrelation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$CorrelationType,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Description,
        [object[]]$RelatedObservations = @(),
        [ValidateSet('High','Medium','Low')][string]$Confidence = 'Medium',
        [string[]]$Limitations = @()
    )

    $observationIds = Get-InspectorObservationIds -Observation $RelatedObservations
    $seed = "$CorrelationType|$Title|$($observationIds -join ',')"

    return [PSCustomObject][ordered]@{
        PSTypeName = 'EntraObjectInspector.AssessmentCorrelation'
        SchemaVersion = '0.9.0'
        CorrelationId = New-InspectorIntelligenceId -Prefix 'CORR' -Seed $seed
        CorrelationType = $CorrelationType
        Title = $Title
        Description = $Description
        Confidence = $Confidence
        ObservationIds = @($observationIds)
        EvidenceIds = @(Get-InspectorEvidenceIdsFromObservation -Observation $RelatedObservations)
        AffectedObjects = @(Get-InspectorAffectedObjectsFromObservation -Observation $RelatedObservations)
        Limitations = @(
            (@($Limitations) + @(Get-InspectorLimitationsFromObservation -Observation $RelatedObservations)) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                Select-Object -Unique
        )
    }
}
