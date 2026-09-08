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

    $date = [datetime]::MinValue

    if ([datetime]::TryParse([string]$Value, [ref]$date)) {
        return $date.ToUniversalTime()
    }

    return $null
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
