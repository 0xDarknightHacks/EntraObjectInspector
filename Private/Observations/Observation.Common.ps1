function Get-InspectorObservationProperty {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Set-InspectorObservationProperty {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [object]$Value
    )

    $InputObject |
        Add-Member `
            -NotePropertyName $Name `
            -NotePropertyValue $Value `
            -Force
}

function Get-InspectorObservationMetadataValue {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $directValue =
        Get-InspectorObservationProperty `
            -InputObject $InputObject `
            -Name $Name

    if ($null -ne $directValue) {
        return $directValue
    }

    $metadata =
        Get-InspectorObservationProperty `
            -InputObject $InputObject `
            -Name 'Metadata'

    return Get-InspectorObservationProperty `
        -InputObject $metadata `
        -Name $Name
}

function Get-InspectorObservationDate {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [datetimeoffset]) {
        return ([datetimeoffset]$Value).UtcDateTime
    }

    if ($Value -is [datetime]) {
        $dateTime = [datetime]$Value
        if ($dateTime.Kind -eq [System.DateTimeKind]::Utc) {
            return $dateTime
        }
        if ($dateTime.Kind -eq [System.DateTimeKind]::Local) {
            return $dateTime.ToUniversalTime()
        }

        # Microsoft Graph timestamps are UTC ISO 8601 values. A live Graph
        # object can surface an Unspecified DateTime whereas the portable JSON
        # replay carries an explicit offset. Treat the unspecified live value as
        # UTC instead of applying the host's local timezone and changing the
        # semantic instant.
        return [datetime]::SpecifyKind($dateTime, [System.DateTimeKind]::Utc)
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $dateOffset = [datetimeoffset]::MinValue
    $styles =
        [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor
        [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal

    if ([datetimeoffset]::TryParse(
        $text,
        [System.Globalization.CultureInfo]::InvariantCulture,
        $styles,
        [ref]$dateOffset
    )) {
        return $dateOffset.UtcDateTime
    }

    return $null
}
function Get-InspectorObservationCanonicalDateText {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Value
    )

    $date = Get-InspectorObservationDate -Value $Value
    if ($null -eq $date) {
        return $null
    }

    return $date.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
}

function New-InspectorObservationId {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Seed
    )

    # PowerShell 7.6 runs on a modern .NET runtime with the static SHA256
    # HashData API. Avoid creating/disposing a hash object and a formatting
    # pipeline for every observation while preserving the exact 8-byte ID token.
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Seed)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return 'OBS-' + [System.BitConverter]::ToString($hashBytes, 0, 8).Replace('-', '')
}

function New-InspectorAffectedObject {
    [CmdletBinding()]
    param (
        [string]$ObjectType,

        [string]$ObjectId,

        [string]$DisplayName,

        [string]$AppId = '',

        [string]$UserPrincipalName = '',

        [string]$PublisherClassification = '',

        [string]$TenantOwnershipClassification = '',

        [string]$ClassificationConfidence = '',

        [string]$ServicePrincipalType = '',

        [AllowNull()][object]$AccountEnabled = $null,

        [AllowNull()][object]$IsAssignableToRole = $null
    )

    return [PSCustomObject][ordered]@{
        ObjectType   = $ObjectType
        ObjectId     = $ObjectId
        DisplayName  = $DisplayName
        AppId        = $AppId
        UserPrincipalName = $UserPrincipalName
        PublisherClassification = $PublisherClassification
        TenantOwnershipClassification = $TenantOwnershipClassification
        ClassificationConfidence = $ClassificationConfidence
        ServicePrincipalType = $ServicePrincipalType
        AccountEnabled = $AccountEnabled
        IsAssignableToRole = $IsAssignableToRole
    }
}

function New-InspectorAffectedObjectFromSourceObject {
    [CmdletBinding()]
    param (
        [AllowNull()][object]$SourceObject,
        [string]$FallbackObjectType = '',
        [string]$FallbackObjectId = '',
        [string]$FallbackDisplayName = ''
    )

    $objectType = [string](Get-InspectorObservationProperty -InputObject $SourceObject -Name 'ObjectType')
    if ([string]::IsNullOrWhiteSpace($objectType)) { $objectType = $FallbackObjectType }

    $objectId = [string](Get-InspectorObservationProperty -InputObject $SourceObject -Name 'ObjectId')
    if ([string]::IsNullOrWhiteSpace($objectId)) { $objectId = $FallbackObjectId }

    $displayName = [string](Get-InspectorObservationProperty -InputObject $SourceObject -Name 'DisplayName')
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        $displayName = Get-InspectorObservationDisplayName -InputObject $SourceObject
    }
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $FallbackDisplayName }
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $objectId }

    $properties = Get-InspectorObservationProperty -InputObject $SourceObject -Name 'Properties'
    $metadata = Get-InspectorObservationProperty -InputObject $SourceObject -Name 'Metadata'
    $identifiers = Get-InspectorObservationProperty -InputObject $SourceObject -Name 'Identifiers'

    $appId = [string](Get-InspectorObservationProperty -InputObject $SourceObject -Name 'AppId')
    if ([string]::IsNullOrWhiteSpace($appId)) {
        $appId = [string](Get-InspectorObservationProperty -InputObject $identifiers -Name 'AppId')
    }
    if ([string]::IsNullOrWhiteSpace($appId)) {
        $appId = [string](Get-InspectorObservationProperty -InputObject $properties -Name 'appId')
    }

    $upn = [string](Get-InspectorObservationProperty -InputObject $SourceObject -Name 'UserPrincipalName')
    if ([string]::IsNullOrWhiteSpace($upn)) {
        $upn = [string](Get-InspectorObservationProperty -InputObject $identifiers -Name 'UserPrincipalName')
    }
    if ([string]::IsNullOrWhiteSpace($upn)) {
        $upn = [string](Get-InspectorObservationProperty -InputObject $properties -Name 'userPrincipalName')
    }

    return New-InspectorAffectedObject `
        -ObjectType $objectType `
        -ObjectId $objectId `
        -DisplayName $displayName `
        -AppId $appId `
        -UserPrincipalName $upn `
        -PublisherClassification ([string](Get-InspectorObservationProperty -InputObject $metadata -Name 'PublisherClassification')) `
        -TenantOwnershipClassification ([string](Get-InspectorObservationProperty -InputObject $metadata -Name 'TenantOwnershipClassification')) `
        -ClassificationConfidence ([string](Get-InspectorObservationProperty -InputObject $metadata -Name 'ClassificationConfidence')) `
        -ServicePrincipalType ([string](Get-InspectorObservationProperty -InputObject $metadata -Name 'ServicePrincipalType')) `
        -AccountEnabled (Get-InspectorObservationProperty -InputObject $properties -Name 'accountEnabled') `
        -IsAssignableToRole (Get-InspectorObservationProperty -InputObject $properties -Name 'isAssignableToRole')
}


function Get-InspectorObservationSourceObject {
    [CmdletBinding()]
    param (
        [object[]]$SourceObjects = @(),
        [string]$ObjectType = '',
        [string]$ObjectId = ''
    )

    return $SourceObjects |
        Where-Object {
            $candidateType = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'ObjectType')
            $candidateId = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'ObjectId')
            ([string]::IsNullOrWhiteSpace($ObjectType) -or $candidateType -eq $ObjectType) -and
            ([string]::IsNullOrWhiteSpace($ObjectId) -or $candidateId -eq $ObjectId)
        } |
        Select-Object -First 1
}

function New-InspectorObservationSemanticKey {
    [CmdletBinding()]
    param (
        [string]$Category,
        [string]$Title,
        [AllowNull()][object]$AffectedObject,
        [string[]]$SourceRuleIds = @(),
        [hashtable]$Metadata = @{}
    )

    $objectType = [string](Get-InspectorObservationProperty -InputObject $AffectedObject -Name 'ObjectType')
    $objectId = [string](Get-InspectorObservationProperty -InputObject $AffectedObject -Name 'ObjectId')
    $ruleId = (@($SourceRuleIds) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -First 1)

    $semanticParts = @(
        $objectType
        $objectId
        $Category
        $ruleId
        $Title
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'PermissionName')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'PermissionType')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'ResourceAppId')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'AppRoleId')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'CredentialType')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'KeyId')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'RelationshipType')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'RelatedPrincipalId')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'RelatedGroupId')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'RelatedServicePrincipalId')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'OwnershipObjectId')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'RoleDefinitionId')
        [string](Get-InspectorObservationProperty -InputObject $Metadata -Name 'AdministrativeUnitId')
    )

    return New-InspectorObservationId -Seed (@($semanticParts) -join '|')
}

function New-InspectorSecurityObservation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet(
            'IdentityGovernance',
            'Credentials',
            'Permissions',
            'ServicePrincipal',
            'Consent',
            'Users',
            'Groups'
        )]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateSet('High', 'Medium', 'Low')]
        [string]$Confidence,

        [Parameter(Mandatory)]
        [object]$AffectedObject,

        [object[]]$EvidenceIds = @(),

        [Parameter(Mandatory)]
        [string]$MicrosoftReference,

        [Parameter(Mandatory)]
        [string]$WhyItMatters,

        [string[]]$Limitations = @(),

        [string]$Recommendation = '',

        [string[]]$SourceRuleIds = @(),

        [hashtable]$Metadata = @{}
    )

    $affectedObjectId =
        [string](Get-InspectorObservationProperty `
            -InputObject $AffectedObject `
            -Name 'ObjectId')

    $signalDisposition = [string](Get-InspectorObservationProperty -InputObject ([PSCustomObject]$Metadata) -Name 'SignalDisposition')
    if ([string]::IsNullOrWhiteSpace($signalDisposition)) {
        $signalDisposition =
            if ($Severity -eq 'Informational') {
                'Contextual'
            }
            elseif ($Severity -eq 'Low') {
                'Review'
            }
            else {
                'Actionable'
            }
    }

    $findingEligible = $signalDisposition -in @('Actionable', 'Review')
    $semanticKey = New-InspectorObservationSemanticKey -Category $Category -Title $Title -AffectedObject $AffectedObject -SourceRuleIds $SourceRuleIds -Metadata $Metadata

    # Metadata is exposed as a PSCustomObject. Always materialize a CustomRule
    # marker (default $false) so consumers can filter custom-policy observations
    # with direct property access even under StrictMode.
    $metadataObject =
        if ($null -eq $Metadata) {
            [PSCustomObject][ordered]@{}
        }
        else {
            [PSCustomObject]$Metadata
        }

    if ($null -eq $metadataObject.PSObject.Properties['CustomRule']) {
        $metadataObject |
            Add-Member -NotePropertyName 'CustomRule' -NotePropertyValue $false
    }

    $seed = $semanticKey

    return [PSCustomObject][ordered]@{
        PSTypeName         = 'EntraObjectInspector.SecurityObservation'
        SchemaVersion      = '0.7.0'
        ObservationId      = New-InspectorObservationId -Seed $seed
        SemanticKey        = $semanticKey
        Category           = $Category
        Title              = $Title
        Description        = $Description
        Severity           = $Severity
        Confidence         = $Confidence
        SignalDisposition  = $signalDisposition
        FindingEligible    = $findingEligible
        AffectedObject     = $AffectedObject
        EvidenceIds        = @($EvidenceIds | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } | Select-Object -Unique)
        MicrosoftReference = $MicrosoftReference
        WhyItMatters       = $WhyItMatters
        Limitations        = @($Limitations)
        Recommendation     = $Recommendation
        SourceRuleIds      = @($SourceRuleIds | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } | Select-Object -Unique)
        Metadata           = $metadataObject
    }
}

function Get-InspectorObservationDisplayName {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject
    )

    $properties =
        Get-InspectorObservationProperty `
            -InputObject $InputObject `
            -Name 'Properties'

    $displayName =
        Get-InspectorObservationProperty `
            -InputObject $properties `
            -Name 'DisplayName'

    if (-not [string]::IsNullOrWhiteSpace([string]$displayName)) {
        return [string]$displayName
    }

    $displayName =
        Get-InspectorObservationProperty `
            -InputObject $InputObject `
            -Name 'DisplayName'

    if (-not [string]::IsNullOrWhiteSpace([string]$displayName)) {
        return [string]$displayName
    }

    return [string](Get-InspectorObservationProperty `
        -InputObject $InputObject `
        -Name 'ObjectId')
}

function Get-InspectorObservationEvidenceIds {
    [CmdletBinding()]
    param (
        [object[]]$Items
    )

    return @(
        $Items |
        ForEach-Object {
            $evidenceId = Get-InspectorObservationProperty -InputObject $_ -Name 'EvidenceId'
            if ([string]::IsNullOrWhiteSpace([string]$evidenceId)) {
                $evidenceId = Get-InspectorObservationProperty -InputObject $_ -Name 'ParentEvidenceId'
            }
            $evidenceId
        } |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } |
        Select-Object -Unique
    )
}

function Get-InspectorObservationEvidenceIdsForSubject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [Parameter(Mandatory)]
        [string]$SubjectObjectType,

        [Parameter(Mandatory)]
        [string]$SubjectObjectId,

        [string]$QueryNamePattern = '*'
    )

    return @(
        (Get-InspectorObservationProperty -InputObject $ObjectInsight -Name 'Evidence') |
        Where-Object {
            $evidenceSubjectType = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'SubjectObjectType')
            $evidenceSubjectId = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'SubjectObjectId')
            $queryName = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'QueryName')
            $status = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'Status')

            $evidenceSubjectType -eq $SubjectObjectType -and
            $evidenceSubjectId -eq $SubjectObjectId -and
            $queryName -like $QueryNamePattern -and
            $status -eq 'Success'
        } |
        ForEach-Object {
            Get-InspectorObservationProperty -InputObject $_ -Name 'EvidenceId'
        } |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } |
        Select-Object -Unique
    )
}


function Get-InspectorObservationTenantCollectionEvidenceIds {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [Parameter(Mandatory)]
        [string[]]$QueryName
    )

    $queryNames = @($QueryName | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)

    return @(
        (Get-InspectorObservationProperty -InputObject $ObjectInsight -Name 'Evidence') |
        Where-Object {
            $scope = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'EvidenceScope')
            $currentQueryName = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'QueryName')
            $status = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'Status')

            $scope -eq 'TenantCollection' -and
            $currentQueryName -in $queryNames -and
            $status -eq 'Success'
        } |
        ForEach-Object {
            Get-InspectorObservationProperty -InputObject $_ -Name 'EvidenceId'
        } |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        Select-Object -Unique
    )
}

function Test-InspectorObservationTenantCollectionEvidenceSucceeded {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [Parameter(Mandatory)]
        [string[]]$QueryName
    )

    $queryNames = @($QueryName | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    if ($queryNames.Count -eq 0) {
        return $false
    }

    $evidence = @(
        (Get-InspectorObservationProperty -InputObject $ObjectInsight -Name 'Evidence') |
        Where-Object {
            [string](Get-InspectorObservationProperty -InputObject $_ -Name 'EvidenceScope') -eq 'TenantCollection' -and
            [string](Get-InspectorObservationProperty -InputObject $_ -Name 'Status') -eq 'Success'
        }
    )

    foreach ($requiredQueryName in $queryNames) {
        $matching = @(
            $evidence |
            Where-Object {
                [string](Get-InspectorObservationProperty -InputObject $_ -Name 'QueryName') -eq $requiredQueryName -and
                -not [string]::IsNullOrWhiteSpace([string](Get-InspectorObservationProperty -InputObject $_ -Name 'EvidenceId'))
            }
        )

        if ($matching.Count -eq 0) {
            return $false
        }
    }

    return $true
}

function Test-InspectorObservationSubjectEvidenceSucceeded {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [Parameter(Mandatory)]
        [string]$SubjectObjectType,

        [Parameter(Mandatory)]
        [string]$SubjectObjectId,

        [string]$QueryNamePattern = '*'
    )

    $matchingEvidence = @(
        (Get-InspectorObservationProperty -InputObject $ObjectInsight -Name 'Evidence') |
        Where-Object {
            [string](Get-InspectorObservationProperty -InputObject $_ -Name 'SubjectObjectType') -eq $SubjectObjectType -and
            [string](Get-InspectorObservationProperty -InputObject $_ -Name 'SubjectObjectId') -eq $SubjectObjectId -and
            [string](Get-InspectorObservationProperty -InputObject $_ -Name 'QueryName') -like $QueryNamePattern
        }
    )

    if ($matchingEvidence.Count -gt 0) {
        return @($matchingEvidence | Where-Object {
            [string](Get-InspectorObservationProperty -InputObject $_ -Name 'Status') -eq 'Success'
        }).Count -gt 0
    }

    # Backward-compatible proof path for normalized/in-memory ObjectInsight
    # shapes that predate per-query evidence envelopes.  A successful, complete
    # object relationship collector for the same subject proves that the
    # relationship collection ran to completion even when its Evidence array
    # is absent from an older fixture/result shape.  This fallback is used only
    # for subject-scoped relationship checks (for example owner collection); it
    # does not weaken tenant-collection proof requirements used for negative
    # application/service-principal counterpart observations.
    $expectedCollectorName =
        switch ($SubjectObjectType) {
            'Application'      { 'ApplicationRelationships' }
            'ServicePrincipal' { 'ServicePrincipalRelationships' }
            'User'             { 'UserRelationships' }
            'Group'            { 'GroupRelationships' }
            default            { $null }
        }

    if ([string]::IsNullOrWhiteSpace([string]$expectedCollectorName)) {
        return $false
    }

    $relationshipCollection =
        Get-InspectorObservationProperty `
            -InputObject $ObjectInsight `
            -Name 'RelationshipCollection'

    $relationshipCollectionCompleteness =
        [string](Get-InspectorObservationProperty `
            -InputObject $relationshipCollection `
            -Name 'Completeness')

    $matchingCollectorResults = @(
        (Get-InspectorObservationProperty -InputObject $ObjectInsight -Name 'CollectorResults') |
        Where-Object {
            $collectorCompleteness =
                [string](Get-InspectorObservationProperty -InputObject $_ -Name 'Completeness')

            $effectiveCompleteness =
                if (-not [string]::IsNullOrWhiteSpace($collectorCompleteness)) {
                    $collectorCompleteness
                }
                else {
                    $relationshipCollectionCompleteness
                }

            [string](Get-InspectorObservationProperty -InputObject $_ -Name 'CollectorName') -eq $expectedCollectorName -and
            [string](Get-InspectorObservationProperty -InputObject $_ -Name 'SourceObjectType') -eq $SubjectObjectType -and
            [string](Get-InspectorObservationProperty -InputObject $_ -Name 'SourceObjectId') -eq $SubjectObjectId -and
            [string](Get-InspectorObservationProperty -InputObject $_ -Name 'Status') -eq 'Success' -and
            $effectiveCompleteness -eq 'Complete'
        }
    )

    return $matchingCollectorResults.Count -gt 0
}

function Get-InspectorObservationSourceObjects {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [string[]]$ObjectType = @()
    )

    $objects = @(
        (Get-InspectorObservationProperty `
            -InputObject $ObjectInsight `
            -Name 'SourceObjects') |
        Where-Object { $null -ne $_ }
    )

    if (@($ObjectType).Count -gt 0) {
        $objects = @(
            $objects |
            Where-Object {
                if ($null -eq $_) {
                    return $false
                }

                $currentObjectType =
                    Get-InspectorObservationProperty `
                        -InputObject $_ `
                        -Name 'ObjectType'

                return $currentObjectType -in $ObjectType
            }
        )
    }

    return @($objects)
}

function Get-InspectorObservationRelationships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [string]$SourceObjectId,

        [string[]]$RelationshipType = @()
    )

    $relationships = @(
        (Get-InspectorObservationProperty `
            -InputObject $ObjectInsight `
            -Name 'Relationships') |
        Where-Object { $null -ne $_ }
    )

    if (-not [string]::IsNullOrWhiteSpace($SourceObjectId)) {
        $relationships = @(
            $relationships |
            Where-Object {
                if ($null -eq $_) {
                    return $false
                }

                $currentSourceObjectId =
                    Get-InspectorObservationProperty `
                        -InputObject $_ `
                        -Name 'SourceObjectId'

                return $currentSourceObjectId -eq $SourceObjectId
            }
        )
    }

    if (@($RelationshipType).Count -gt 0) {
        $relationships = @(
            $relationships |
            Where-Object {
                if ($null -eq $_) {
                    return $false
                }

                $currentRelationshipType =
                    Get-InspectorObservationProperty `
                        -InputObject $_ `
                        -Name 'RelationshipType'

                return $currentRelationshipType -in $RelationshipType
            }
        )
    }

    return @($relationships)
}

function Get-InspectorObservationRelationshipEvidenceIds {
    [CmdletBinding()]
    param (
        [object[]]$Items = @()
    )

    $evidenceIds = @(
        foreach ($item in @($Items)) {
            if ($null -eq $item) { continue }

            $directEvidenceId = [string](Get-InspectorObservationProperty -InputObject $item -Name 'EvidenceId')
            if (-not [string]::IsNullOrWhiteSpace($directEvidenceId)) {
                $directEvidenceId
            }

            foreach ($metadataEvidenceId in @(
                Get-InspectorObservationMetadataValue -InputObject $item -Name 'EvidenceIds'
            )) {
                if (-not [string]::IsNullOrWhiteSpace([string]$metadataEvidenceId)) {
                    [string]$metadataEvidenceId
                }
            }
        }
    )

    return @($evidenceIds | Select-Object -Unique)
}

function Get-InspectorCrossObjectSecurityObservations {
    <#
    .SYNOPSIS
        Derives evidence-backed security observations that require tenant-wide
        correlation across already-collected ObjectInsight records.

    .DESCRIPTION
        Correlates application/service-principal privilege, ownership, group
        membership, PIM role state, administrative-unit scope, and risky-user
        context without making any Microsoft Graph calls.

        These observations deliberately describe collected authorization and
        governance combinations. They do not claim exploitability, compromise,
        or executable attack paths.
    #>

    [CmdletBinding()]
    param (
        [object[]]$ObjectInsights = @()
    )

    $observations = [System.Collections.Generic.List[object]]::new()
    if (@($ObjectInsights).Count -eq 0) {
        return @()
    }

    $sourceObjectsById = @{}
    $relationships = [System.Collections.Generic.List[object]]::new()
    $relationshipSeen = @{}
    $permissionInsights = [System.Collections.Generic.List[object]]::new()
    $permissionSeen = @{}
    $riskArtifacts = [System.Collections.Generic.List[object]]::new()
    $riskSeen = @{}
    $applicationIdentities = [System.Collections.Generic.List[object]]::new()
    $applicationIdentitySeen = @{}

    foreach ($objectInsight in @($ObjectInsights)) {
        if ($null -eq $objectInsight) { continue }

        foreach ($sourceObject in @(Get-InspectorObservationProperty -InputObject $objectInsight -Name 'SourceObjects')) {
            if ($null -eq $sourceObject) { continue }
            $objectId = [string](Get-InspectorObservationProperty -InputObject $sourceObject -Name 'ObjectId')
            if ([string]::IsNullOrWhiteSpace($objectId)) { continue }
            if (-not $sourceObjectsById.ContainsKey($objectId)) {
                $sourceObjectsById[$objectId] = $sourceObject
            }
        }

        foreach ($relationship in @(Get-InspectorObservationProperty -InputObject $objectInsight -Name 'Relationships')) {
            if ($null -eq $relationship) { continue }
            $relationshipType = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'RelationshipType')
            $sourceObjectId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'SourceObjectId')
            $targetObjectId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'TargetObjectId')
            $evidenceId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'EvidenceId')
            $assignmentId = [string](Get-InspectorObservationMetadataValue -InputObject $relationship -Name 'AssignmentId')
            $scheduleInstanceId = [string](Get-InspectorObservationMetadataValue -InputObject $relationship -Name 'ScheduleInstanceId')
            $relationshipKey = "$relationshipType|$sourceObjectId|$targetObjectId|$assignmentId|$scheduleInstanceId|$evidenceId"
            if (-not $relationshipSeen.ContainsKey($relationshipKey)) {
                $relationshipSeen[$relationshipKey] = $true
                $relationships.Add($relationship)
            }
        }

        foreach ($permissionInsight in @(Get-InspectorObservationProperty -InputObject $objectInsight -Name 'PermissionInsights')) {
            if ($null -eq $permissionInsight) { continue }
            $sourceObjectId = [string](Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'SourceObjectId')
            $appRoleId = [string](Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'AppRoleId')
            $resourceAppId = [string](Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'ResourceAppId')
            $relationshipEvidenceId = [string](Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'RelationshipEvidenceId')
            $permissionKey = "$sourceObjectId|$resourceAppId|$appRoleId|$relationshipEvidenceId"
            if (-not $permissionSeen.ContainsKey($permissionKey)) {
                $permissionSeen[$permissionKey] = $true
                $permissionInsights.Add($permissionInsight)
            }
        }

        foreach ($artifact in @(Get-InspectorObservationProperty -InputObject $objectInsight -Name 'Artifacts')) {
            if ($null -eq $artifact) { continue }
            if ([string](Get-InspectorObservationProperty -InputObject $artifact -Name 'ArtifactType') -ne 'RiskyUserContext') { continue }
            $sourceObjectId = [string](Get-InspectorObservationProperty -InputObject $artifact -Name 'SourceObjectId')
            $evidenceId = [string](Get-InspectorObservationProperty -InputObject $artifact -Name 'EvidenceId')
            $riskKey = "$sourceObjectId|$evidenceId"
            if (-not $riskSeen.ContainsKey($riskKey)) {
                $riskSeen[$riskKey] = $true
                $riskArtifacts.Add($artifact)
            }
        }

        $applicationIdentity = Get-InspectorObservationProperty -InputObject $objectInsight -Name 'ApplicationIdentity'
        if ($null -ne $applicationIdentity) {
            $applicationObjectId = [string](Get-InspectorObservationProperty -InputObject $applicationIdentity -Name 'ApplicationObjectId')
            $servicePrincipalObjectId = [string](Get-InspectorObservationProperty -InputObject $applicationIdentity -Name 'ServicePrincipalObjectId')
            $identityKey = "$applicationObjectId|$servicePrincipalObjectId"
            if (-not [string]::IsNullOrWhiteSpace($identityKey.Replace('|','')) -and -not $applicationIdentitySeen.ContainsKey($identityKey)) {
                $applicationIdentitySeen[$identityKey] = $true
                $applicationIdentities.Add($applicationIdentity)
            }
        }
    }

    $highImpactPermissionsByPrincipal = @{}
    foreach ($permissionInsight in @($permissionInsights)) {
        $sourceObjectId = [string](Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'SourceObjectId')
        $resourceDisplayName = [string](Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'ResourceDisplayName')
        $resourceAppId = [string](Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'ResourceAppId')
        $isMicrosoftGraph = $resourceDisplayName -eq 'Microsoft Graph' -or $resourceAppId -eq '00000003-0000-0000-c000-000000000000'
        $isHighImpact = (Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'IsHighImpact') -eq $true
        if ([string]::IsNullOrWhiteSpace($sourceObjectId) -or -not $isMicrosoftGraph -or -not $isHighImpact) { continue }
        if (-not $highImpactPermissionsByPrincipal.ContainsKey($sourceObjectId)) {
            $highImpactPermissionsByPrincipal[$sourceObjectId] = [System.Collections.Generic.List[object]]::new()
        }
        $highImpactPermissionsByPrincipal[$sourceObjectId].Add($permissionInsight)
    }

    $activeRolesByPrincipal = @{}
    $eligibleRolesByPrincipal = @{}
    foreach ($relationship in @($relationships)) {
        $relationshipType = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'RelationshipType')
        $sourceObjectId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'SourceObjectId')
        if ([string]::IsNullOrWhiteSpace($sourceObjectId)) { continue }

        if ($relationshipType -in @('AssignedDirectoryRole', 'ActiveDirectoryRoleScheduleInstance')) {
            if (-not $activeRolesByPrincipal.ContainsKey($sourceObjectId)) {
                $activeRolesByPrincipal[$sourceObjectId] = [System.Collections.Generic.List[object]]::new()
            }
            $activeRolesByPrincipal[$sourceObjectId].Add($relationship)
        }
        elseif ($relationshipType -eq 'EligibleDirectoryRoleScheduleInstance') {
            if (-not $eligibleRolesByPrincipal.ContainsKey($sourceObjectId)) {
                $eligibleRolesByPrincipal[$sourceObjectId] = [System.Collections.Generic.List[object]]::new()
            }
            $eligibleRolesByPrincipal[$sourceObjectId].Add($relationship)
        }
    }

    $riskByUserId = @{}
    foreach ($riskArtifact in @($riskArtifacts)) {
        $userId = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'SourceObjectId')
        if ([string]::IsNullOrWhiteSpace($userId)) { continue }
        $riskState = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'RiskState')
        $isCurrentRisk = $riskState -in @('atRisk', 'confirmedCompromised')
        if (-not $riskByUserId.ContainsKey($userId) -or $isCurrentRisk) {
            $riskByUserId[$userId] = $riskArtifact
        }
    }

    $appToServicePrincipal = @{}
    foreach ($applicationIdentity in @($applicationIdentities)) {
        $applicationObjectId = [string](Get-InspectorObservationProperty -InputObject $applicationIdentity -Name 'ApplicationObjectId')
        $servicePrincipalObjectId = [string](Get-InspectorObservationProperty -InputObject $applicationIdentity -Name 'ServicePrincipalObjectId')
        if (-not [string]::IsNullOrWhiteSpace($applicationObjectId) -and -not [string]::IsNullOrWhiteSpace($servicePrincipalObjectId)) {
            $appToServicePrincipal[$applicationObjectId] = $servicePrincipalObjectId
        }
    }
    foreach ($relationship in @($relationships)) {
        $relationshipType = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'RelationshipType')
        if ($relationshipType -eq 'ApplicationToServicePrincipal') {
            $applicationObjectId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'SourceObjectId')
            $servicePrincipalObjectId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'TargetObjectId')
            if (-not [string]::IsNullOrWhiteSpace($applicationObjectId) -and -not [string]::IsNullOrWhiteSpace($servicePrincipalObjectId)) {
                $appToServicePrincipal[$applicationObjectId] = $servicePrincipalObjectId
            }
        }
        elseif ($relationshipType -eq 'ServicePrincipalToApplication') {
            $servicePrincipalObjectId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'SourceObjectId')
            $applicationObjectId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'TargetObjectId')
            if (-not [string]::IsNullOrWhiteSpace($applicationObjectId) -and -not [string]::IsNullOrWhiteSpace($servicePrincipalObjectId)) {
                $appToServicePrincipal[$applicationObjectId] = $servicePrincipalObjectId
            }
        }
    }

    $ownershipAssociations = @{}
    foreach ($relationship in @($relationships | Where-Object { [string](Get-InspectorObservationProperty -InputObject $_ -Name 'RelationshipType') -eq 'OwnedBy' })) {
        $sourceType = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'SourceObjectType')
        $sourceId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'SourceObjectId')
        $targetType = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'TargetObjectType')
        $ownerId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'TargetObjectId')
        if ($sourceType -notin @('Application', 'ServicePrincipal', 'Group') -or $targetType -ine 'User' -or [string]::IsNullOrWhiteSpace($ownerId)) { continue }
        $key = "$sourceType|$sourceId|$ownerId"
        if (-not $ownershipAssociations.ContainsKey($key)) {
            $ownershipAssociations[$key] = [PSCustomObject][ordered]@{
                SourceObjectType = $sourceType
                SourceObjectId = $sourceId
                OwnerId = $ownerId
                Relationships = [System.Collections.Generic.List[object]]::new()
            }
        }
        $ownershipAssociations[$key].Relationships.Add($relationship)
    }

    $applicationOwnerReference = 'Microsoft Entra enterprise application ownership guidance documents that an application can have more permissions than its owner and that this can create an elevation-of-privilege security concern.'
    $roleAssignableGroupReference = 'Microsoft Entra role-assignable group guidance documents indirect role inheritance through membership, delegated owner management, PIM eligibility, and the prohibition on group nesting.'
    $pimReference = 'Microsoft Entra Privileged Identity Management distinguishes active assignments, which are usable immediately, from eligible assignments, which require activation and can be subject to MFA, approval, justification, and time limits.'
    $identityProtectionReference = 'Microsoft Entra ID Protection risky-user data is intended for investigation and remediation of identity risk.'

    # Privileged application ownership: connect application-registration or
    # enterprise-application ownership to the correlated service principal that
    # actually holds Graph application permissions and/or Entra directory roles.
    foreach ($association in @($ownershipAssociations.Values | Where-Object { $_.SourceObjectType -in @('Application', 'ServicePrincipal') })) {
        $servicePrincipalId = ''
        if ($association.SourceObjectType -eq 'ServicePrincipal') {
            $servicePrincipalId = [string]$association.SourceObjectId
        }
        elseif ($appToServicePrincipal.ContainsKey([string]$association.SourceObjectId)) {
            $servicePrincipalId = [string]$appToServicePrincipal[[string]$association.SourceObjectId]
        }
        if ([string]::IsNullOrWhiteSpace($servicePrincipalId)) { continue }

        $highImpactPermissions = @(if ($highImpactPermissionsByPrincipal.ContainsKey($servicePrincipalId)) { $highImpactPermissionsByPrincipal[$servicePrincipalId] })
        $activeRoles = @(if ($activeRolesByPrincipal.ContainsKey($servicePrincipalId)) { $activeRolesByPrincipal[$servicePrincipalId] })
        if ($highImpactPermissions.Count -eq 0 -and $activeRoles.Count -eq 0) { continue }

        $sourceObject = if ($sourceObjectsById.ContainsKey([string]$association.SourceObjectId)) { $sourceObjectsById[[string]$association.SourceObjectId] } else { $null }
        $affectedApplication = New-InspectorAffectedObjectFromSourceObject -SourceObject $sourceObject -FallbackObjectType ([string]$association.SourceObjectType) -FallbackObjectId ([string]$association.SourceObjectId) -FallbackDisplayName ([string]$association.SourceObjectId)
        $permissionEvidenceIds = @($highImpactPermissions | ForEach-Object { [string](Get-InspectorObservationProperty -InputObject $_ -Name 'RelationshipEvidenceId') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $roleEvidenceIds = @(Get-InspectorObservationRelationshipEvidenceIds -Items $activeRoles)
        $ownerEvidenceIds = @(Get-InspectorObservationRelationshipEvidenceIds -Items @($association.Relationships))
        $permissionNames = @($highImpactPermissions | ForEach-Object { [string](Get-InspectorObservationProperty -InputObject $_ -Name 'PermissionName') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        $roleDisplayNames = @($activeRoles | ForEach-Object { [string](Get-InspectorObservationMetadataValue -InputObject $_ -Name 'RoleDisplayName') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        $privilegeSources = @()
        if ($permissionNames.Count -gt 0) { $privilegeSources += 'HighImpactMicrosoftGraphApplicationPermission' }
        if ($activeRoles.Count -gt 0) { $privilegeSources += 'ActiveDirectoryRole' }

        $observations.Add(
            (New-InspectorSecurityObservation `
                -Category 'IdentityGovernance' `
                -Title 'Privileged application identity has user owner' `
                -Description "$($association.SourceObjectType) '$($affectedApplication.DisplayName)' is owned by a user and is correlated to service principal '$servicePrincipalId' with privileged authorization." `
                -Severity 'Low' `
                -Confidence 'High' `
                -AffectedObject $affectedApplication `
                -EvidenceIds @($ownerEvidenceIds + $permissionEvidenceIds + $roleEvidenceIds) `
                -MicrosoftReference $applicationOwnerReference `
                -WhyItMatters 'An owner can administer the application object they control, while the correlated workload identity may hold permissions or roles that exceed the owner user account. The owner therefore belongs in the privileged access review boundary.' `
                -Limitations @('Ownership plus privilege is a governance control relationship, not proof of misuse, credential possession, or an executable privilege-escalation path.') `
                -Recommendation 'Treat owners of privileged application identities as privileged administrators for review purposes and validate that ownership remains necessary and accountable.' `
                -SourceRuleIds @('APP-PRIV-OWNER-001') `
                -Metadata @{
                    RelatedPrincipalId = [string]$association.OwnerId
                    RelatedServicePrincipalId = $servicePrincipalId
                    OwnershipObjectId = [string]$association.SourceObjectId
                    OwnershipObjectType = [string]$association.SourceObjectType
                    PermissionNames = @($permissionNames)
                    RoleDisplayNames = @($roleDisplayNames)
                    PrivilegeSources = @($privilegeSources)
                    EvidenceSupportType = 'DerivedFromTenantCollection'
                    SignalDisposition = 'Review'
                })
        )

        if ($riskByUserId.ContainsKey([string]$association.OwnerId)) {
            $riskArtifact = $riskByUserId[[string]$association.OwnerId]
            $riskState = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'RiskState')
            if ($riskState -in @('atRisk', 'confirmedCompromised')) {
                $riskLevel = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'RiskLevel')
                $ownerSourceObject = if ($sourceObjectsById.ContainsKey([string]$association.OwnerId)) { $sourceObjectsById[[string]$association.OwnerId] } else { $null }
                $affectedOwner = New-InspectorAffectedObjectFromSourceObject -SourceObject $ownerSourceObject -FallbackObjectType 'User' -FallbackObjectId ([string]$association.OwnerId) -FallbackDisplayName ([string]$association.OwnerId)
                $riskEvidenceId = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'EvidenceId')
                $observations.Add(
                    (New-InspectorSecurityObservation `
                        -Category 'Users' `
                        -Title 'Risky user owns privileged application identity' `
                        -Description "Risky user '$($affectedOwner.DisplayName)' owns $($association.SourceObjectType.ToLowerInvariant()) '$($affectedApplication.DisplayName)', whose correlated service principal has privileged authorization." `
                        -Severity $(if ($riskLevel -ieq 'high') { 'High' } else { 'Medium' }) `
                        -Confidence 'High' `
                        -AffectedObject $affectedOwner `
                        -EvidenceIds @(@($riskEvidenceId) + @($ownerEvidenceIds + $permissionEvidenceIds + $roleEvidenceIds)) `
                        -MicrosoftReference $identityProtectionReference `
                        -WhyItMatters 'Current unresolved user risk is materially more important when the same user controls an application identity that holds high-impact Graph permissions or active directory roles.' `
                        -Limitations @('Risk state does not by itself prove compromise, and application ownership does not prove that the user currently possesses a workload credential.') `
                        -Recommendation 'Investigate the risky user and validate or temporarily reduce ownership of the privileged application identity according to incident-response and access-governance procedures.' `
                        -SourceRuleIds @('RISK-APP-OWNER-001') `
                        -Metadata @{
                            RelatedPrincipalId = [string]$association.OwnerId
                            RelatedServicePrincipalId = $servicePrincipalId
                            OwnershipObjectId = [string]$association.SourceObjectId
                            OwnershipObjectType = [string]$association.SourceObjectType
                            RiskLevel = $riskLevel
                            RiskState = $riskState
                            PermissionNames = @($permissionNames)
                            RoleDisplayNames = @($roleDisplayNames)
                            PrivilegeSources = @($privilegeSources)
                            EvidenceSupportType = 'DerivedFromTenantCollection'
                        })
                )
            }
        }
    }

    # Build user -> group membership associations from either the user's
    # transitive membership view or the group's direct member view.
    $membershipAssociations = @{}
    foreach ($relationship in @($relationships)) {
        $relationshipType = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'RelationshipType')
        $sourceType = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'SourceObjectType')
        $targetType = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'TargetObjectType')
        $userId = ''
        $groupId = ''
        if ($relationshipType -eq 'MemberOfGroup' -and $sourceType -ieq 'User' -and $targetType -ieq 'Group') {
            $userId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'SourceObjectId')
            $groupId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'TargetObjectId')
        }
        elseif ($relationshipType -eq 'HasMember' -and $sourceType -ieq 'Group' -and $targetType -ieq 'User') {
            $userId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'TargetObjectId')
            $groupId = [string](Get-InspectorObservationProperty -InputObject $relationship -Name 'SourceObjectId')
        }
        if ([string]::IsNullOrWhiteSpace($userId) -or [string]::IsNullOrWhiteSpace($groupId)) { continue }

        $key = "$userId|$groupId"
        if (-not $membershipAssociations.ContainsKey($key)) {
            $membershipAssociations[$key] = [PSCustomObject][ordered]@{
                UserId = $userId
                GroupId = $groupId
                Relationships = [System.Collections.Generic.List[object]]::new()
            }
        }
        $membershipAssociations[$key].Relationships.Add($relationship)
    }

    foreach ($association in @($membershipAssociations.Values)) {
        $userId = [string]$association.UserId
        $groupId = [string]$association.GroupId
        if (-not $riskByUserId.ContainsKey($userId)) { continue }
        $riskArtifact = $riskByUserId[$userId]
        $riskState = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'RiskState')
        if ($riskState -notin @('atRisk', 'confirmedCompromised')) { continue }

        $activeRoles = @(if ($activeRolesByPrincipal.ContainsKey($groupId)) { $activeRolesByPrincipal[$groupId] })
        $eligibleRoles = @(if ($eligibleRolesByPrincipal.ContainsKey($groupId)) { $eligibleRolesByPrincipal[$groupId] })
        if ($activeRoles.Count -eq 0 -and $eligibleRoles.Count -eq 0) { continue }

        $riskLevel = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'RiskLevel')
        $userSourceObject = if ($sourceObjectsById.ContainsKey($userId)) { $sourceObjectsById[$userId] } else { $null }
        $affectedUser = New-InspectorAffectedObjectFromSourceObject -SourceObject $userSourceObject -FallbackObjectType 'User' -FallbackObjectId $userId -FallbackDisplayName $userId
        $groupSourceObject = if ($sourceObjectsById.ContainsKey($groupId)) { $sourceObjectsById[$groupId] } else { $null }
        $groupDisplayName = if ($null -ne $groupSourceObject) { Get-InspectorObservationDisplayName -InputObject $groupSourceObject } else { $groupId }
        $membershipEvidenceIds = @(Get-InspectorObservationRelationshipEvidenceIds -Items @($association.Relationships))
        $riskEvidenceId = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'EvidenceId')
        $activeRoleEvidenceIds = @(Get-InspectorObservationRelationshipEvidenceIds -Items $activeRoles)
        $eligibleRoleEvidenceIds = @(Get-InspectorObservationRelationshipEvidenceIds -Items $eligibleRoles)
        $restrictedManagementPrivilege = @(
            @($activeRoles + $eligibleRoles) |
                Where-Object { (Get-InspectorObservationMetadataValue -InputObject $_ -Name 'AdministrativeUnitRestrictedManagement') -eq $true }
        ).Count -gt 0

        if ($activeRoles.Count -gt 0) {
            $roleNames = @($activeRoles | ForEach-Object { [string](Get-InspectorObservationMetadataValue -InputObject $_ -Name 'RoleDisplayName') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Users' `
                    -Title 'Risky user inherits active directory privilege through group' `
                    -Description "Risky user '$($affectedUser.DisplayName)' is a collected member of privileged group '$groupDisplayName', which has active Microsoft Entra directory-role context." `
                    -Severity $(if ($riskLevel -ieq 'high') { 'High' } else { 'Medium' }) `
                    -Confidence 'High' `
                    -AffectedObject $affectedUser `
                    -EvidenceIds @(@($riskEvidenceId) + @($membershipEvidenceIds + $activeRoleEvidenceIds)) `
                    -MicrosoftReference $roleAssignableGroupReference `
                    -WhyItMatters 'Microsoft Entra role assignments to groups are inherited by group members, so unresolved user risk on a member of an actively privileged group is also privileged-identity risk.' `
                    -Limitations @('Membership is based on collected group relationship evidence; the observation does not prove malicious use of the inherited role.') `
                    -Recommendation 'Investigate the user risk and validate both the group membership and the group role assignment.' `
                    -SourceRuleIds @('RISK-GROUP-PRIV-001') `
                    -Metadata @{
                        RelatedPrincipalId = $userId
                        RelatedGroupId = $groupId
                        RiskLevel = $riskLevel
                        RiskState = $riskState
                        RoleDisplayNames = @($roleNames)
                        PrivilegeState = 'Active'
                        RestrictedManagementAdministrativeUnitPrivilege = [bool]$restrictedManagementPrivilege
                        EvidenceSupportType = 'DerivedFromTenantCollection'
                    })
            )
        }
        elseif ($eligibleRoles.Count -gt 0) {
            $roleNames = @($eligibleRoles | ForEach-Object { [string](Get-InspectorObservationMetadataValue -InputObject $_ -Name 'RoleDisplayName') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Users' `
                    -Title 'Risky user is eligible for directory privilege through group' `
                    -Description "Risky user '$($affectedUser.DisplayName)' is a collected member of group '$groupDisplayName', which is eligible to activate Microsoft Entra directory-role context." `
                    -Severity 'Medium' `
                    -Confidence 'High' `
                    -AffectedObject $affectedUser `
                    -EvidenceIds @(@($riskEvidenceId) + @($membershipEvidenceIds + $eligibleRoleEvidenceIds)) `
                    -MicrosoftReference $pimReference `
                    -WhyItMatters 'When a group is PIM-eligible for a Microsoft Entra role, its members can become eligible to activate that role. Unresolved identity risk therefore deserves review even though the privilege is not currently active.' `
                    -Limitations @('Eligibility is not active privilege. Activation controls such as approval, MFA, justification, and duration are not inferred unless separately collected.') `
                    -Recommendation 'Investigate the user risk and validate whether group-based PIM eligibility remains appropriate.' `
                    -SourceRuleIds @('RISK-GROUP-PIM-001') `
                    -Metadata @{
                        RelatedPrincipalId = $userId
                        RelatedGroupId = $groupId
                        RiskLevel = $riskLevel
                        RiskState = $riskState
                        RoleDisplayNames = @($roleNames)
                        PrivilegeState = 'Eligible'
                        RestrictedManagementAdministrativeUnitPrivilege = [bool]$restrictedManagementPrivilege
                        EvidenceSupportType = 'DerivedFromTenantCollection'
                    })
            )
        }
    }

    # Risky ownership of a group that already has active or eligible directory
    # privilege. Group ownership is a delegated management boundary, while the
    # role state determines whether the group itself is actively privileged or
    # only eligible for activation.
    foreach ($association in @($ownershipAssociations.Values | Where-Object { $_.SourceObjectType -eq 'Group' })) {
        $groupId = [string]$association.SourceObjectId
        $ownerId = [string]$association.OwnerId
        if (-not $riskByUserId.ContainsKey($ownerId)) { continue }
        $riskArtifact = $riskByUserId[$ownerId]
        $riskState = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'RiskState')
        if ($riskState -notin @('atRisk', 'confirmedCompromised')) { continue }

        $activeRoles = @(if ($activeRolesByPrincipal.ContainsKey($groupId)) { $activeRolesByPrincipal[$groupId] })
        $eligibleRoles = @(if ($eligibleRolesByPrincipal.ContainsKey($groupId)) { $eligibleRolesByPrincipal[$groupId] })
        if ($activeRoles.Count -eq 0 -and $eligibleRoles.Count -eq 0) { continue }

        $riskLevel = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'RiskLevel')
        $ownerSourceObject = if ($sourceObjectsById.ContainsKey($ownerId)) { $sourceObjectsById[$ownerId] } else { $null }
        $affectedOwner = New-InspectorAffectedObjectFromSourceObject -SourceObject $ownerSourceObject -FallbackObjectType 'User' -FallbackObjectId $ownerId -FallbackDisplayName $ownerId
        $groupSourceObject = if ($sourceObjectsById.ContainsKey($groupId)) { $sourceObjectsById[$groupId] } else { $null }
        $groupDisplayName = if ($null -ne $groupSourceObject) { Get-InspectorObservationDisplayName -InputObject $groupSourceObject } else { $groupId }
        $roleEvidenceIds = @(Get-InspectorObservationRelationshipEvidenceIds -Items @($activeRoles + $eligibleRoles))
        $ownerEvidenceIds = @(Get-InspectorObservationRelationshipEvidenceIds -Items @($association.Relationships))
        $riskEvidenceId = [string](Get-InspectorObservationProperty -InputObject $riskArtifact -Name 'EvidenceId')
        $privilegeState = if ($activeRoles.Count -gt 0) { 'Active' } else { 'Eligible' }
        $roleNames = @(@($activeRoles + $eligibleRoles) | ForEach-Object { [string](Get-InspectorObservationMetadataValue -InputObject $_ -Name 'RoleDisplayName') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

        $observations.Add(
            (New-InspectorSecurityObservation `
                -Category 'Users' `
                -Title 'Risky user owns privileged group' `
                -Description "Risky user '$($affectedOwner.DisplayName)' owns group '$groupDisplayName', which has $($privilegeState.ToLowerInvariant()) Microsoft Entra directory-role context." `
                -Severity $(if ($privilegeState -eq 'Active' -and $riskLevel -ieq 'high') { 'High' } else { 'Medium' }) `
                -Confidence 'High' `
                -AffectedObject $affectedOwner `
                -EvidenceIds @(@($riskEvidenceId) + @($ownerEvidenceIds + $roleEvidenceIds)) `
                -MicrosoftReference $roleAssignableGroupReference `
                -WhyItMatters 'Owners can be delegated management of role-assignable groups, so unresolved user risk on an owner belongs in the privileged group governance boundary.' `
                -Limitations @('Ownership does not prove the owner changed membership or activated privilege. Eligible role state is not active privilege.') `
                -Recommendation 'Investigate the user risk and validate whether ownership of the privileged group remains necessary.' `
                -SourceRuleIds @('RISK-GROUP-OWNER-001') `
                -Metadata @{
                    RelatedPrincipalId = $ownerId
                    RelatedGroupId = $groupId
                    RiskLevel = $riskLevel
                    RiskState = $riskState
                    RoleDisplayNames = @($roleNames)
                    PrivilegeState = $privilegeState
                    EvidenceSupportType = 'DerivedFromTenantCollection'
                })
        )
    }

    return @($observations)
}
