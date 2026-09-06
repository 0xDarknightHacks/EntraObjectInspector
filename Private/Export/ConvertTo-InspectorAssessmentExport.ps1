function ConvertTo-InspectorFlatObservation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Observation
    )

    $affectedObject =
        Get-InspectorExportProperty `
            -InputObject $Observation `
            -Name 'AffectedObject'

    $metadata =
        Get-InspectorExportProperty `
            -InputObject $Observation `
            -Name 'Metadata'

    return [PSCustomObject][ordered]@{
        ObservationId       = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'ObservationId')
        Category            = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'Category')
        Severity            = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'Severity')
        Confidence          = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'Confidence')
        Title               = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'Title')
        Description         = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'Description')
        AffectedObjectType  = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $affectedObject -Name 'ObjectType')
        AffectedObjectId    = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $affectedObject -Name 'ObjectId')
        AffectedDisplayName = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $affectedObject -Name 'DisplayName')
        EvidenceIds         = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'EvidenceIds')
        MicrosoftReference  = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'MicrosoftReference')
        WhyItMatters        = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'WhyItMatters')
        Limitations         = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'Limitations')
        Recommendation      = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'Recommendation')
        SourceRuleIds       = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Observation -Name 'SourceRuleIds')
        Metadata            = ConvertTo-InspectorExportString $metadata
    }
}


function New-InspectorExportEvidenceLookup {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object[]]$Evidence
    )

    $bySubjectObjectId = @{}
    $byEvidenceId = @{}
    $ordinal = 0

    foreach ($item in @($Evidence)) {
        if ($null -eq $item) {
            $ordinal++
            continue
        }

        $scope =
            ConvertTo-InspectorExportString `
                (Get-InspectorExportProperty -InputObject $item -Name 'EvidenceScope')

        if ($scope -eq 'TenantCollection') {
            $ordinal++
            continue
        }

        $evidenceId =
            ConvertTo-InspectorExportString `
                (Get-InspectorExportProperty -InputObject $item -Name 'EvidenceId')

        if ([string]::IsNullOrWhiteSpace($evidenceId)) {
            $ordinal++
            continue
        }

        $entry = [PSCustomObject][ordered]@{
            Ordinal    = $ordinal
            EvidenceId = $evidenceId
            Evidence   = $item
        }

        $subjectObjectId =
            ConvertTo-InspectorExportString `
                (Get-InspectorExportProperty -InputObject $item -Name 'SubjectObjectId')

        if (-not [string]::IsNullOrWhiteSpace($subjectObjectId)) {
            if (-not $bySubjectObjectId.ContainsKey($subjectObjectId)) {
                $bySubjectObjectId[$subjectObjectId] =
                    [System.Collections.Generic.List[object]]::new()
            }

            $bySubjectObjectId[$subjectObjectId].Add($entry)
        }
        elseif (-not $byEvidenceId.ContainsKey($evidenceId)) {
            $byEvidenceId[$evidenceId] = $entry
        }

        $ordinal++
    }

    return [PSCustomObject][ordered]@{
        BySubjectObjectId = $bySubjectObjectId
        ByEvidenceId      = $byEvidenceId
    }
}

function ConvertTo-InspectorFlatObjectInsight {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [AllowNull()]
        [object]$EvidenceLookup
    )

    $relationshipCollection =
        Get-InspectorExportProperty `
            -InputObject $ObjectInsight `
            -Name 'RelationshipCollection'

    $summary =
        Get-InspectorExportProperty `
            -InputObject $ObjectInsight `
            -Name 'Summary'

    $discoveryObject =
        Get-InspectorExportProperty `
            -InputObject $ObjectInsight `
            -Name 'DiscoveryObject'

    $sourceObjects =
        @(
            Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'SourceObjects'
        ) |
        Where-Object { $null -ne $_ }

    $directObjectIds =
        @(
            ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $discoveryObject -Name 'ObjectId')
            $sourceObjects |
                ForEach-Object {
                    ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $_ -Name 'ObjectId')
                }
        ) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique

    $observationEvidenceIds =
        @(
            Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'SecurityObservations'
        ) |
        Where-Object { $null -ne $_ } |
        ForEach-Object {
            @(
                Get-InspectorExportProperty -InputObject $_ -Name 'EvidenceIds'
            )
        } |
        ForEach-Object { ConvertTo-InspectorExportString $_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique

    $evidenceIds =
        if ($null -ne $EvidenceLookup) {
            $candidateEntries = [System.Collections.Generic.List[object]]::new()
            $bySubjectObjectId =
                Get-InspectorExportProperty `
                    -InputObject $EvidenceLookup `
                    -Name 'BySubjectObjectId'
            $byEvidenceId =
                Get-InspectorExportProperty `
                    -InputObject $EvidenceLookup `
                    -Name 'ByEvidenceId'

            foreach ($directObjectId in @($directObjectIds)) {
                if (
                    -not [string]::IsNullOrWhiteSpace([string]$directObjectId) -and
                    $null -ne $bySubjectObjectId -and
                    $bySubjectObjectId.ContainsKey([string]$directObjectId)
                ) {
                    foreach ($entry in @($bySubjectObjectId[[string]$directObjectId])) {
                        if ($null -ne $entry) {
                            $candidateEntries.Add($entry)
                        }
                    }
                }
            }

            foreach ($observationEvidenceId in @($observationEvidenceIds)) {
                if (
                    -not [string]::IsNullOrWhiteSpace([string]$observationEvidenceId) -and
                    $null -ne $byEvidenceId -and
                    $byEvidenceId.ContainsKey([string]$observationEvidenceId)
                ) {
                    $candidateEntries.Add($byEvidenceId[[string]$observationEvidenceId])
                }
            }

            @(
                $candidateEntries |
                    Sort-Object Ordinal |
                    ForEach-Object {
                        ConvertTo-InspectorExportString `
                            (Get-InspectorExportProperty -InputObject $_ -Name 'EvidenceId')
                    } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Select-Object -Unique
            )
        }
        else {
            @(
                Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'Evidence'
                Get-InspectorExportProperty -InputObject (Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'RelationshipCollection') -Name 'Evidence'
            ) |
            Where-Object { $null -ne $_ } |
            Where-Object {
                $scope = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $_ -Name 'EvidenceScope')
                $subjectObjectId = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $_ -Name 'SubjectObjectId')
                $evidenceId = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $_ -Name 'EvidenceId')

                if ($scope -eq 'TenantCollection') {
                    return $false
                }

                if (-not [string]::IsNullOrWhiteSpace($subjectObjectId)) {
                    return $subjectObjectId -in @($directObjectIds)
                }

                return $evidenceId -in @($observationEvidenceIds)
            } |
            ForEach-Object {
                ConvertTo-InspectorExportString `
                    (Get-InspectorExportProperty -InputObject $_ -Name 'EvidenceId')
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
        }

    $evidenceSampleIds = @($evidenceIds | Select-Object -First 10)
    $securityObservations = @(
        Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'SecurityObservations'
    ) | Where-Object { $null -ne $_ }
    $findingEligibleObservationCount = @(
        $securityObservations |
            Where-Object { (Get-InspectorExportProperty -InputObject $_ -Name 'FindingEligible') -eq $true }
    ).Count
    $evidenceMappingStatus =
        if (@($evidenceIds).Count -gt 0) {
            'Mapped'
        }
        else {
            'NotMapped'
        }

    return [PSCustomObject][ordered]@{
        Input                    = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'Input')
        Status                   = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'Status')
        ResolutionType           = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'ResolutionType')
        DiscoveryObjectType      = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $discoveryObject -Name 'ObjectType')
        DiscoveryObjectId        = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $discoveryObject -Name 'ObjectId')
        DisplayName              = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $discoveryObject -Name 'DisplayName')
        RelationshipStatus       = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $relationshipCollection -Name 'Status')
        RelationshipCompleteness = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $relationshipCollection -Name 'Completeness')
        SourceObjectCount        = @(Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'SourceObjects').Count
        RelationshipCount        = @(Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'Relationships').Count
        ArtifactCount            = @(Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'Artifacts').Count
        EvidenceCount            = @($evidenceIds).Count
        DirectEvidenceCount      = @($evidenceIds).Count
        EvidenceSampleIds        = ConvertTo-InspectorExportString $evidenceSampleIds
        EvidenceTruncated        = @($evidenceIds).Count -gt @($evidenceSampleIds).Count
        EvidenceMappingStatus    = $evidenceMappingStatus
        EvidenceMappingLimitation = $(if ($evidenceMappingStatus -eq 'NotMapped') { 'No direct object-level evidence identifiers were mapped for this object.' } else { '' })
        RuleResultCount          = @(Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'RuleResults').Count
        PermissionInsightCount   = @(Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'PermissionInsights').Count
        SecurityObservationCount = @($securityObservations).Count
        FindingEligibleObservationCount = $findingEligibleObservationCount
        FindingCount             = $findingEligibleObservationCount
        Limitations              = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $ObjectInsight -Name 'Limitations')
    }
}

function ConvertTo-InspectorFlatEvidence {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Evidence,

        [string]$ParentInput = '',

        [string]$ParentResolutionType = ''
    )

    return [PSCustomObject][ordered]@{
        ParentInput          = $ParentInput
        ParentResolutionType = $ParentResolutionType
        EvidenceId           = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'EvidenceId')
        QueryName            = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'QueryName')
        CollectorName        = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'CollectorName')
        Endpoint             = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'Endpoint')
        RequiredPermission   = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'RequiredPermission')
        CollectionTime       = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'CollectionTime')
        Status               = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'Status')
        ResultCount          = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'ResultCount')
        SourceResultCount    = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'SourceResultCount')
        Completeness         = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'Completeness')
        Limitations          = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'Limitations')
        EvidenceScope        = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'EvidenceScope')
        SubjectObjectType    = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'SubjectObjectType')
        SubjectObjectId      = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Evidence -Name 'SubjectObjectId')
    }
}

function Get-InspectorExportEvidenceKey {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$EvidenceRow
    )

    $evidenceId =
        ConvertTo-InspectorExportString `
            (Get-InspectorExportProperty -InputObject $EvidenceRow -Name 'EvidenceId')

    if (-not [string]::IsNullOrWhiteSpace($evidenceId)) {
        return "EvidenceId|$evidenceId"
    }

    return @(
        'EvidenceId'
        'QueryName'
        'CollectorName'
        'Endpoint'
        'RequiredPermission'
        'CollectionTime'
        'Status'
        'ResultCount'
        'Limitations'
    ) |
        ForEach-Object {
            ConvertTo-InspectorExportString `
                (Get-InspectorExportProperty -InputObject $EvidenceRow -Name $_)
        } |
        ForEach-Object { [string]$_ } |
        Join-String -Separator '|'
}

function Get-InspectorExportModuleVersion {
    [CmdletBinding()]
    param ()

    $module = Get-Module -Name EntraObjectInspector

    if ($null -ne $module -and $null -ne $module.Version) {
        return [string]$module.Version
    }

    return ''
}

function ConvertTo-InspectorFlatFailedObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$FailedObject
    )

    return [PSCustomObject][ordered]@{
        ObjectKey          = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $FailedObject -Name 'ObjectKey')
        ObjectType         = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $FailedObject -Name 'ObjectType')
        ObjectId           = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $FailedObject -Name 'ObjectId')
        InspectionIdentity = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $FailedObject -Name 'InspectionIdentity')
        Attempts           = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $FailedObject -Name 'Attempts')
        Error              = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $FailedObject -Name 'Error')
    }
}

function ConvertTo-InspectorFlatLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Log
    )

    return [PSCustomObject][ordered]@{
        Timestamp = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Log -Name 'Timestamp')
        Stage     = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Log -Name 'Stage')
        Level     = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Log -Name 'Level')
        Message   = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Log -Name 'Message')
        Data      = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Log -Name 'Data')
    }
}

function ConvertTo-InspectorFlatAssessmentFinding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Finding
    )

    return [PSCustomObject][ordered]@{
        FindingId          = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'FindingId')
        Category           = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'Category')
        Severity           = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'Severity')
        Confidence         = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'Confidence')
        ResultState        = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'ResultState')
        EvidenceLinkStatus = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'EvidenceLinkStatus')
        EvidenceSupportStatus = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'EvidenceSupportStatus')
        ContributingObservationCount = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'ContributingObservationCount')
        DirectEvidenceObservationCount = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'DirectEvidenceObservationCount')
        DerivedEvidenceObservationCount = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'DerivedEvidenceObservationCount')
        UnsupportedObservationCount = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'UnsupportedObservationCount')
        UniqueEvidenceCount = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'UniqueEvidenceCount')
        DirectEvidenceCoveragePercent = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'DirectEvidenceCoveragePercent')
        Title              = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'Title')
        Conclusion         = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'Conclusion')
        CriterionSummary   = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'CriterionSummary')
        SeverityReason     = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'SeverityReason')
        ObservationCount   = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'ObservationCount')
        AffectedObjectCount = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'AffectedObjectCount')
        ObservationIds     = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'ObservationIds')
        EvidenceIds        = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'EvidenceIds')
        MicrosoftReference = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'MicrosoftReference')
        Recommendation     = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'Recommendation')
        RecommendationNotApplicable = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'RecommendationNotApplicable')
        Limitations        = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'Limitations')
        ReferenceIds       = ConvertTo-InspectorExportString (@(Get-InspectorExportProperty -InputObject $Finding -Name 'References') | ForEach-Object { Get-InspectorExportProperty -InputObject $_ -Name 'ReferenceId' })
        AffectedObjects    = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'AffectedObjects')
        IssueGroups        = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'IssueGroups')
        Metadata           = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Finding -Name 'Metadata')
    }
}

function ConvertTo-InspectorFlatAssessmentRecommendation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Recommendation
    )

    return [PSCustomObject][ordered]@{
        RecommendationId   = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Recommendation -Name 'RecommendationId')
        Category           = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Recommendation -Name 'Category')
        Confidence         = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Recommendation -Name 'Confidence')
        Title              = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Recommendation -Name 'Title')
        Action             = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Recommendation -Name 'Action')
        Rationale          = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Recommendation -Name 'Rationale')
        MicrosoftReference = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Recommendation -Name 'MicrosoftReference')
        ObservationIds     = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Recommendation -Name 'ObservationIds')
        EvidenceIds        = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Recommendation -Name 'EvidenceIds')
        Limitations        = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Recommendation -Name 'Limitations')
        ReferenceIds       = ConvertTo-InspectorExportString (@(Get-InspectorExportProperty -InputObject $Recommendation -Name 'References') | ForEach-Object { Get-InspectorExportProperty -InputObject $_ -Name 'ReferenceId' })
    }
}

function ConvertTo-InspectorFlatAssessmentCorrelation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Correlation
    )

    return [PSCustomObject][ordered]@{
        CorrelationId   = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Correlation -Name 'CorrelationId')
        CorrelationType = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Correlation -Name 'CorrelationType')
        Confidence      = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Correlation -Name 'Confidence')
        Title           = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Correlation -Name 'Title')
        Description     = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Correlation -Name 'Description')
        ObservationIds  = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Correlation -Name 'ObservationIds')
        EvidenceIds     = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Correlation -Name 'EvidenceIds')
        AffectedObjects = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Correlation -Name 'AffectedObjects')
        Limitations     = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $Correlation -Name 'Limitations')
    }
}

function ConvertTo-InspectorFlatAssessmentLimitation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Limitation
    )

    return [PSCustomObject][ordered]@{
        Limitation = $Limitation
    }
}

function ConvertTo-InspectorAssessmentExport {
    <#
    .SYNOPSIS
        Converts a tenant inspection result into deterministic export datasets.

    .DESCRIPTION
        assessment export conversion. This function reshapes existing tenant
        inspection data and optional AssessmentIntelligence into
        reviewable export datasets. It does not call Microsoft Graph, rerun
        discovery, invoke collection, or generate new intelligence.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$InputObject,

        [string]$AssessmentName = 'Entra Object Inspector Assessment',

        [AllowNull()]
        [object]$AssessmentIntelligence,

        [string]$RunId = '',

        [string]$ReportId = '',

        [switch]$IncludeFullObjectInsights
    )

    $generatedAt =
        (Get-Date).ToUniversalTime().ToString('o')

    if ([string]::IsNullOrWhiteSpace($RunId)) {
        $RunId = [string](Get-InspectorExportProperty -InputObject $InputObject -Name 'RunId')
    }

    if ([string]::IsNullOrWhiteSpace($RunId)) {
        $RunId = [string](Get-InspectorExportProperty -InputObject $InputObject -Name 'SnapshotId')
    }

    if ([string]::IsNullOrWhiteSpace($RunId)) {
        $RunId = [guid]::NewGuid().ToString()
    }

    if ([string]::IsNullOrWhiteSpace($ReportId)) {
        $ReportId = [guid]::NewGuid().ToString()
    }

    if ($null -eq $AssessmentIntelligence) {
        $AssessmentIntelligence =
            Get-InspectorExportProperty `
                -InputObject $InputObject `
                -Name 'AssessmentIntelligence'
    }

    $hasAssessmentIntelligence =
        $null -ne $AssessmentIntelligence

    $objectInsights =
        @(
            (Get-InspectorExportProperty `
                -InputObject $InputObject `
                -Name 'ObjectInsights') |
            Where-Object { $null -ne $_ }
        )

    $rawSecurityObservations =
        @(
            (Get-InspectorExportProperty `
                -InputObject $InputObject `
                -Name 'SecurityObservations') |
            Where-Object { $null -ne $_ }
        )

    if ($rawSecurityObservations.Count -eq 0) {
        $rawSecurityObservations =
            @(
                $objectInsights |
                ForEach-Object {
                    @(
                        Get-InspectorExportProperty `
                            -InputObject $_ `
                            -Name 'SecurityObservations'
                    )
                } |
                Where-Object { $null -ne $_ }
            )
    }

    $securityObservations =
        @(
            if ($hasAssessmentIntelligence) {
                Get-InspectorExportProperty `
                    -InputObject $AssessmentIntelligence `
                    -Name 'DeduplicatedObservations'
            }
        ) |
        Where-Object { $null -ne $_ }

    if (@($securityObservations).Count -eq 0) {
        $securityObservations = @($rawSecurityObservations)
    }

    $failedObjects =
        @(
            (Get-InspectorExportProperty `
                -InputObject $InputObject `
                -Name 'FailedObjects') |
            Where-Object { $null -ne $_ }
        )

    $logs =
        @(
            (Get-InspectorExportProperty `
                -InputObject $InputObject `
                -Name 'Logs') |
            Where-Object { $null -ne $_ }
        )

    $summary =
        Get-InspectorExportProperty `
            -InputObject $InputObject `
            -Name 'Summary'

    $discovery =
        Get-InspectorExportProperty `
            -InputObject $InputObject `
            -Name 'Discovery'

    $assessmentCoverage =
        Get-InspectorExportProperty `
            -InputObject $InputObject `
            -Name 'AssessmentCoverage'

    if ($null -eq $assessmentCoverage) {
        $assessmentCoverage =
            Get-InspectorExportProperty `
                -InputObject $summary `
                -Name 'AssessmentCoverage'
    }

    if ($null -eq $assessmentCoverage) {
        $assessmentCoverage =
            Get-InspectorExportProperty `
                -InputObject $discovery `
                -Name 'AssessmentCoverage'
    }

    $tenantMetadata =
        Get-InspectorExportProperty `
            -InputObject $InputObject `
            -Name 'TenantMetadata'

    if ($null -eq $tenantMetadata) {
        $tenantMetadata =
            Get-InspectorExportProperty `
                -InputObject $summary `
                -Name 'TenantMetadata'
    }

    if ($null -eq $tenantMetadata) {
        $tenantMetadata =
            Get-InspectorExportProperty `
                -InputObject $discovery `
                -Name 'TenantMetadata'
    }

    $tenantId =
        ConvertTo-InspectorExportString `
            (Get-InspectorExportProperty -InputObject $tenantMetadata -Name 'TenantId')

    if ([string]::IsNullOrWhiteSpace($tenantId)) {
        $tenantId =
            ConvertTo-InspectorExportString `
                (Get-InspectorExportProperty -InputObject $summary -Name 'TenantId')
    }

    $tenantDisplayName =
        ConvertTo-InspectorExportString `
            (Get-InspectorExportProperty -InputObject $tenantMetadata -Name 'TenantDisplayName')

    if ([string]::IsNullOrWhiteSpace($tenantDisplayName)) {
        $tenantDisplayName =
            ConvertTo-InspectorExportString `
                (Get-InspectorExportProperty -InputObject $summary -Name 'TenantDisplayName')
    }

    $moduleVersion = Get-InspectorExportModuleVersion
    $graphCallsAfterSnapshotRaw = Get-InspectorExportProperty -InputObject $InputObject -Name 'GraphCallsAfterSnapshot'
    $parsedGraphCallsAfterSnapshot = [int]0
    $graphCallsAfterSnapshot =
        if (
            $null -ne $graphCallsAfterSnapshotRaw -and
            [int]::TryParse([string]$graphCallsAfterSnapshotRaw, [ref]$parsedGraphCallsAfterSnapshot)
        ) {
            $parsedGraphCallsAfterSnapshot
        }
        else {
            $null
        }
    $graphRequestsAtSnapshotCompletion = Get-InspectorExportProperty -InputObject $InputObject -Name 'GraphRequestsAtSnapshotCompletion'
    $graphRequestsAtAssessmentCompletion = Get-InspectorExportProperty -InputObject $InputObject -Name 'GraphRequestsAtAssessmentCompletion'
    $scopeInventory =
        Get-InspectorExportProperty `
            -InputObject $InputObject `
            -Name 'ScopeInventory'

    if ($null -eq $scopeInventory) {
        $scopeInventory =
            Get-InspectorExportProperty `
                -InputObject $summary `
                -Name 'ScopeInventory'
    }

    if ($null -eq $scopeInventory) {
        $scopeInventory =
            Get-InspectorExportProperty `
                -InputObject $discovery `
                -Name 'ScopeInventory'
    }

    $observationsFlat =
        @(
            $securityObservations |
            Sort-Object Category, Severity, Title, ObservationId |
            ForEach-Object {
                ConvertTo-InspectorFlatObservation -Observation $_
            }
        )

    $discoveryEvidence =
        @(
            Get-InspectorExportProperty `
                -InputObject $discovery `
                -Name 'Evidence'
        ) |
        Where-Object { $null -ne $_ }

    $snapshotMode =
        ConvertTo-InspectorExportString `
            (Get-InspectorExportProperty -InputObject $InputObject -Name 'SnapshotMode')

    $useSnapshotExportFastPath =
        $snapshotMode -eq 'InMemory' -and
        $discoveryEvidence.Count -gt 0

    $evidenceLookup =
        if ($useSnapshotExportFastPath) {
            New-InspectorExportEvidenceLookup -Evidence $discoveryEvidence
        }
        else {
            $null
        }

    $objectIndex =
        @(
            $objectInsights |
            Sort-Object ResolutionType, Input |
            ForEach-Object {
                ConvertTo-InspectorFlatObjectInsight `
                    -ObjectInsight $_ `
                    -EvidenceLookup $evidenceLookup
            }
        )

    $evidenceRows = [System.Collections.Generic.List[object]]::new()

    if ($useSnapshotExportFastPath) {
        # Current snapshot-mode resolutions intentionally carry the complete
        # tenant evidence array on every ObjectInsight. The legacy export loop
        # therefore flattened the same evidence corpus once per object and
        # discarded all later copies during EvidenceId de-duplication. Flatten
        # the authoritative discovery evidence once while preserving the exact
        # first-object parent attribution produced by that legacy traversal.
        $firstObjectInsight = @($objectInsights | Select-Object -First 1)[0]
        $parentInput =
            if ($null -ne $firstObjectInsight) {
                ConvertTo-InspectorExportString `
                    (Get-InspectorExportProperty -InputObject $firstObjectInsight -Name 'Input')
            }
            else {
                'TenantDiscovery'
            }
        $parentResolutionType =
            if ($null -ne $firstObjectInsight) {
                ConvertTo-InspectorExportString `
                    (Get-InspectorExportProperty -InputObject $firstObjectInsight -Name 'ResolutionType')
            }
            else {
                'Discovery'
            }

        foreach ($evidence in $discoveryEvidence) {
            $evidenceRows.Add(
                (ConvertTo-InspectorFlatEvidence `
                    -Evidence $evidence `
                    -ParentInput $parentInput `
                    -ParentResolutionType $parentResolutionType)
            )
        }
    }
    else {
        # Preserve the compatibility path for older/in-memory fixtures whose
        # ObjectInsight evidence is not backed by the current tenant snapshot.
        foreach ($objectInsight in $objectInsights) {
            $parentInput =
                ConvertTo-InspectorExportString `
                    (Get-InspectorExportProperty -InputObject $objectInsight -Name 'Input')

            $parentResolutionType =
                ConvertTo-InspectorExportString `
                    (Get-InspectorExportProperty -InputObject $objectInsight -Name 'ResolutionType')

            $objectEvidence =
                @(
                    Get-InspectorExportProperty `
                        -InputObject $objectInsight `
                        -Name 'Evidence'
                )

            $relationshipCollection =
                Get-InspectorExportProperty `
                    -InputObject $objectInsight `
                    -Name 'RelationshipCollection'

            $relationshipEvidence =
                @(
                    Get-InspectorExportProperty `
                        -InputObject $relationshipCollection `
                        -Name 'Evidence'
                )

            foreach ($evidence in @($objectEvidence + $relationshipEvidence)) {
                if ($null -eq $evidence) {
                    continue
                }

                $evidenceRows.Add(
                    (ConvertTo-InspectorFlatEvidence `
                        -Evidence $evidence `
                        -ParentInput $parentInput `
                        -ParentResolutionType $parentResolutionType)
                )
            }
        }

        foreach ($evidence in $discoveryEvidence) {
            $evidenceRows.Add(
                (ConvertTo-InspectorFlatEvidence `
                    -Evidence $evidence `
                    -ParentInput 'TenantDiscovery' `
                    -ParentResolutionType 'Discovery')
            )
        }
    }

    $deduplicatedEvidenceRows = [System.Collections.Generic.List[object]]::new()
    $evidenceKeys = @{}

    foreach ($row in @($evidenceRows)) {
        $key = Get-InspectorExportEvidenceKey -EvidenceRow $row

        if ([string]::IsNullOrWhiteSpace($key) -or $evidenceKeys.ContainsKey($key)) {
            continue
        }

        $evidenceKeys[$key] = $true
        $deduplicatedEvidenceRows.Add($row)
    }

    $failedFlat =
        @(
            $failedObjects |
            Sort-Object ObjectType, ObjectId |
            ForEach-Object {
                ConvertTo-InspectorFlatFailedObject -FailedObject $_
            }
        )

    $logsFlat =
        @(
            $logs |
            ForEach-Object {
                ConvertTo-InspectorFlatLog -Log $_
            }
        )

    $severitySummary =
        @(
            $securityObservations |
            Group-Object Severity |
            Sort-Object {
                Get-InspectorExportSeverityOrder -Severity $_.Name
            }, Name |
            ForEach-Object {
                [PSCustomObject][ordered]@{
                    Severity = $_.Name
                    Count    = $_.Count
                }
            }
        )

    $categorySummary =
        @(
            $securityObservations |
            Group-Object Category |
            Sort-Object Name |
            ForEach-Object {
                [PSCustomObject][ordered]@{
                    Category = $_.Name
                    Count    = $_.Count
                }
            }
        )

    $tenantPosture =
        if ($hasAssessmentIntelligence) {
            Get-InspectorExportProperty `
                -InputObject $AssessmentIntelligence `
                -Name 'TenantPosture'
        }
        else {
            $null
        }

    $assessmentFindings =
        @(
            if ($hasAssessmentIntelligence) {
                Get-InspectorExportProperty `
                    -InputObject $AssessmentIntelligence `
                    -Name 'AssessmentFindings'
            }
        ) |
        Where-Object { $null -ne $_ }

    $assessmentRecommendations =
        @(
            if ($hasAssessmentIntelligence) {
                Get-InspectorExportProperty `
                    -InputObject $AssessmentIntelligence `
                    -Name 'AssessmentRecommendations'
            }
        ) |
        Where-Object { $null -ne $_ }

    $assessmentCorrelations =
        @(
            if ($hasAssessmentIntelligence) {
                Get-InspectorExportProperty `
                    -InputObject $AssessmentIntelligence `
                    -Name 'Correlations'
            }
        ) |
        Where-Object { $null -ne $_ }

    $assessmentLimitations =
        @(
            if ($hasAssessmentIntelligence) {
                Get-InspectorExportProperty `
                    -InputObject $AssessmentIntelligence `
                    -Name 'Limitations'
            }
        ) |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } |
        Sort-Object -Unique

    $assessmentFindingRows =
        @(
            $assessmentFindings |
            Sort-Object Category, Severity, Title, FindingId |
            ForEach-Object {
                ConvertTo-InspectorFlatAssessmentFinding -Finding $_
            }
        )

    $assessmentRecommendationRows =
        @(
            $assessmentRecommendations |
            Sort-Object Category, Title, RecommendationId |
            ForEach-Object {
                ConvertTo-InspectorFlatAssessmentRecommendation -Recommendation $_
            }
        )

    $assessmentCorrelationRows =
        @(
            $assessmentCorrelations |
            Sort-Object CorrelationType, Title, CorrelationId |
            ForEach-Object {
                ConvertTo-InspectorFlatAssessmentCorrelation -Correlation $_
            }
        )

    $assessmentLimitationRows =
        @(
            $assessmentLimitations |
            ForEach-Object {
                ConvertTo-InspectorFlatAssessmentLimitation -Limitation ([string]$_)
            }
        )

    # Package-level artifacts carry the same identity and integrity metadata as
    # the manifest/summary. Clone the intelligence/posture objects so export
    # metadata does not mutate the caller's in-memory assessment objects.
    $assessmentIntelligenceExport =
        if ($null -ne $AssessmentIntelligence) {
            $AssessmentIntelligence | Select-Object *
        }
        else {
            $null
        }

    $tenantPostureExport =
        if ($null -ne $tenantPosture) {
            $tenantPosture | Select-Object *
        }
        else {
            $null
        }

    foreach ($packageObject in @($assessmentIntelligenceExport, $tenantPostureExport)) {
        if ($null -eq $packageObject) { continue }
        $packageObject | Add-Member -NotePropertyName RunId -NotePropertyValue $RunId -Force
        $packageObject | Add-Member -NotePropertyName ReportId -NotePropertyValue $ReportId -Force
        $packageObject | Add-Member -NotePropertyName FailedObjectCount -NotePropertyValue @($failedObjects).Count -Force
        $packageObject | Add-Member -NotePropertyName AssessmentCoverageStatus -NotePropertyValue (Get-InspectorExportProperty -InputObject $assessmentCoverage -Name 'Status') -Force
        $packageObject | Add-Member -NotePropertyName AssessmentCoverageCompleteness -NotePropertyValue (Get-InspectorExportProperty -InputObject $assessmentCoverage -Name 'Completeness') -Force
        $packageObject | Add-Member -NotePropertyName ExpectedEvidenceCount -NotePropertyValue (Get-InspectorExportProperty -InputObject $assessmentCoverage -Name 'ExpectedEvidenceCount') -Force
        $packageObject | Add-Member -NotePropertyName ActualRequiredEvidenceCount -NotePropertyValue (Get-InspectorExportProperty -InputObject $assessmentCoverage -Name 'ActualRequiredEvidenceCount') -Force
        $packageObject | Add-Member -NotePropertyName PackageValidationStatus -NotePropertyValue 'NotRun' -Force
        $packageObject | Add-Member -NotePropertyName ReleaseEligible -NotePropertyValue $false -Force
        $packageObject | Add-Member -NotePropertyName ValidationErrors -NotePropertyValue @() -Force
        $packageObject | Add-Member -NotePropertyName ValidationWarnings -NotePropertyValue @() -Force
    }

    if ($null -eq $scopeInventory) {
        $countsByType =
            Get-InspectorExportProperty `
                -InputObject $discovery `
                -Name 'CountsByType'

        $scopeInventory = [PSCustomObject][ordered]@{
            UsersDiscovered                    = @(Get-InspectorExportProperty -InputObject $countsByType -Name 'User')[0]
            AppRegistrationsDiscovered         = @(Get-InspectorExportProperty -InputObject $countsByType -Name 'Application')[0]
            ServicePrincipalsDiscovered        = @(Get-InspectorExportProperty -InputObject $countsByType -Name 'ServicePrincipal')[0]
            GroupsDiscovered                   = @(Get-InspectorExportProperty -InputObject $countsByType -Name 'Group')[0]
            OAuth2PermissionGrantsDiscovered   = $null
            DirectoryRoleAssignmentsDiscovered = $null
            EvidenceRecordsCollected           = @($deduplicatedEvidenceRows).Count
            FailedObjects                      = @($failedObjects).Count
            MicrosoftPublishedServicePrincipals = $null
            FirstPartyClassificationConfidence = 'NotClassified'
            FirstPartyClassificationMethod     = 'Service principal publisher metadata was not available in this export.'
        }
    }

    $scopeInventory | Add-Member -NotePropertyName FailedObjects -NotePropertyValue @($failedObjects).Count -Force
    $scopeInventory | Add-Member -NotePropertyName EvidenceRecordsCollected -NotePropertyValue @($deduplicatedEvidenceRows).Count -Force

    $manifest =
        [PSCustomObject][ordered]@{
            PSTypeName                     = 'EntraObjectInspector.AssessmentManifest'
            SchemaVersion                  = '0.10.0'
            ExportId                       = [guid]::NewGuid().ToString()
            RunId                          = $RunId
            ReportId                       = $ReportId
            AssessmentName                 = $AssessmentName
            GeneratedAt                    = $generatedAt
            SourceSchemaVersion            = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $InputObject -Name 'SchemaVersion')
            SourceStatus                   = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $InputObject -Name 'Status')
            SourceStartedAt                = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $InputObject -Name 'StartedAt')
            SourceCompletedAt              = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $InputObject -Name 'CompletedAt')
            AssessmentIntelligenceIncluded = $hasAssessmentIntelligence
            AssessmentIntelligenceSchemaVersion = ConvertTo-InspectorExportString (Get-InspectorExportProperty -InputObject $AssessmentIntelligence -Name 'SchemaVersion')
            ExportMode                     = 'OfflineResultOnly'
            GraphCallsIssued               = 0
            GraphRequestsAtSnapshotCompletion = $graphRequestsAtSnapshotCompletion
            GraphRequestsAtAssessmentCompletion = $graphRequestsAtAssessmentCompletion
            GraphCallsAfterSnapshot         = $graphCallsAfterSnapshot
            IntelligenceAdded              = $false
            SecurityObservationCount       = @($securityObservations).Count
            RawObservationCount            = $(if ($hasAssessmentIntelligence) { Get-InspectorExportProperty -InputObject (Get-InspectorExportProperty -InputObject $AssessmentIntelligence -Name 'Summary') -Name 'RawObservationCount' } else { @($rawSecurityObservations).Count })
            DeduplicatedObservationCount   = $(if ($hasAssessmentIntelligence) { Get-InspectorExportProperty -InputObject (Get-InspectorExportProperty -InputObject $AssessmentIntelligence -Name 'Summary') -Name 'DeduplicatedObservationCount' } else { @($securityObservations).Count })
            DuplicateObservationCount      = $(if ($hasAssessmentIntelligence) { Get-InspectorExportProperty -InputObject (Get-InspectorExportProperty -InputObject $AssessmentIntelligence -Name 'Summary') -Name 'DuplicateObservationCount' } else { 0 })
            GroupedFindingCount            = @($assessmentFindings).Count
            EvidenceRecordCount            = @($deduplicatedEvidenceRows).Count
            FailedObjectCount              = @($failedObjects).Count
            TenantId                       = $tenantId
            TenantDisplayName              = $tenantDisplayName
            ModuleVersion                  = $moduleVersion
            ScopeInventory                 = $scopeInventory
            AssessmentCoverage             = $assessmentCoverage
            Artifacts                      = @()
            RecommendationCount            = @($assessmentRecommendations).Count
            PackageValidationStatus        = 'NotRun'
            ReleaseEligible                = $false
        }

    $summaryExport =
        [PSCustomObject][ordered]@{
            PSTypeName                = 'EntraObjectInspector.AssessmentSummary'
            SchemaVersion             = '0.10.0'
            AssessmentName            = $AssessmentName
            RunId                     = $RunId
            ReportId                  = $ReportId
            GeneratedAt               = $generatedAt
            Status                    = $manifest.SourceStatus
            TenantId                  = $tenantId
            TenantDisplayName         = $tenantDisplayName
            TenantMetadata            = $tenantMetadata
            ModuleVersion             = $moduleVersion
            ScopeInventory            = $scopeInventory
            AssessmentCoverage        = $assessmentCoverage
            DiscoveredCount           = Get-InspectorExportProperty -InputObject $summary -Name 'DiscoveredCount'
            ProcessedCount            = Get-InspectorExportProperty -InputObject $summary -Name 'ProcessedCount'
            FailedCount               = @($failedObjects).Count
            FailedObjectCount         = @($failedObjects).Count
            SkippedCount              = Get-InspectorExportProperty -InputObject $summary -Name 'SkippedCount'
            ObjectInsightCount        = Get-InspectorExportProperty -InputObject $summary -Name 'ObjectInsightCount'
            SecurityObservationCount  = @($securityObservations).Count
            GraphRequestsAtSnapshotCompletion = $graphRequestsAtSnapshotCompletion
            GraphRequestsAtAssessmentCompletion = $graphRequestsAtAssessmentCompletion
            GraphCallsAfterSnapshot    = $graphCallsAfterSnapshot
            RawObservationCount       = $(if ($hasAssessmentIntelligence) { Get-InspectorExportProperty -InputObject (Get-InspectorExportProperty -InputObject $AssessmentIntelligence -Name 'Summary') -Name 'RawObservationCount' } else { @($rawSecurityObservations).Count })
            DeduplicatedObservationCount = $(if ($hasAssessmentIntelligence) { Get-InspectorExportProperty -InputObject (Get-InspectorExportProperty -InputObject $AssessmentIntelligence -Name 'Summary') -Name 'DeduplicatedObservationCount' } else { @($securityObservations).Count })
            DuplicateObservationCount = $(if ($hasAssessmentIntelligence) { Get-InspectorExportProperty -InputObject (Get-InspectorExportProperty -InputObject $AssessmentIntelligence -Name 'Summary') -Name 'DuplicateObservationCount' } else { 0 })
            GroupedFindingCount       = @($assessmentFindings).Count
            EvidenceRecordCount       = @($deduplicatedEvidenceRows).Count
            AssessmentIntelligenceIncluded = $hasAssessmentIntelligence
            AssessmentFindingCount    = @($assessmentFindings).Count
            AssessmentRecommendationCount = @($assessmentRecommendations).Count
            AssessmentCorrelationCount = @($assessmentCorrelations).Count
            AssessmentLimitationCount  = @($assessmentLimitations).Count
            TenantPosture             = $tenantPostureExport
            SeveritySummary           = $(if ($hasAssessmentIntelligence) { @(Get-InspectorExportProperty -InputObject $AssessmentIntelligence -Name 'SeveritySummary') } else { @($severitySummary) })
            CategorySummary           = $(if ($hasAssessmentIntelligence) { @(Get-InspectorExportProperty -InputObject $AssessmentIntelligence -Name 'CategorySummary') } else { @($categorySummary) })
            ExportLimitations         = @(
                'Exports existing assessment and intelligence data only.',
                'Export does not run Microsoft Graph queries.',
                'Export does not add risk scoring, prioritization, attack paths, or new security intelligence.'
            )
            PackageValidationStatus   = 'NotRun'
            ReleaseEligible           = $false
        }

    return [PSCustomObject][ordered]@{
        PSTypeName                    = 'EntraObjectInspector.AssessmentExportModel'
        SchemaVersion                 = '0.10.0'
        Manifest                      = $manifest
        Summary                       = $summaryExport
        SecurityObservations          = @($securityObservations)
        SecurityObservationRows       = @($observationsFlat)
        ObjectInsights                = @($objectIndex)
        FullObjectInsights            = $(if ($IncludeFullObjectInsights) { @($objectInsights) } else { @() })
        ObjectIndexRows               = @($objectIndex)
        EvidenceRows                  = @($deduplicatedEvidenceRows)
        FailedObjectRows              = @($failedFlat)
        LogRows                       = @($logsFlat)
        AssessmentIntelligence        = $assessmentIntelligenceExport
        TenantPosture                 = $tenantPostureExport
        AssessmentFindings            = @($assessmentFindings)
        AssessmentFindingRows         = @($assessmentFindingRows)
        AssessmentRecommendations     = @($assessmentRecommendations)
        AssessmentRecommendationRows  = @($assessmentRecommendationRows)
        AssessmentCorrelations        = @($assessmentCorrelations)
        AssessmentCorrelationRows     = @($assessmentCorrelationRows)
        AssessmentLimitations         = @($assessmentLimitations)
        AssessmentLimitationRows      = @($assessmentLimitationRows)
    }
}
