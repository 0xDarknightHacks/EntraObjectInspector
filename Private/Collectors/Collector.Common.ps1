function Get-InspectorCollectorProperty {
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

function Get-InspectorDirectoryObjectTypeName {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject
    )

    $odataType = [string](Get-InspectorCollectorProperty `
        -InputObject $InputObject `
        -Name '@odata.type')

    if ([string]::IsNullOrWhiteSpace($odataType)) {
        return 'DirectoryObject'
    }

    return ($odataType -replace '^#microsoft\.graph\.', '')
}

function Invoke-InspectorCollectorQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CollectorName,

        [Parameter(Mandatory)]
        [string]$QueryName,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$RequiredPermission,

        [ValidateSet('TenantCollection','ObjectCollection','ObjectRelationship')]
        [string]$EvidenceScope = 'ObjectRelationship',

        [string]$SubjectObjectType = '',

        [string]$SubjectObjectId = ''
    )

    $graphResult = Invoke-InspectorGraphRequest `
        -Uri $Uri `
        -RequiredPermission $RequiredPermission

    return [PSCustomObject][ordered]@{
        PSTypeName         = 'EntraObjectInspector.CollectionEvidence'
        EvidenceId         = [guid]::NewGuid().ToString()
        CollectorName      = $CollectorName
        QueryName          = $QueryName
        Endpoint           = $graphResult.SourceEndpoint
        RequiredPermission = $graphResult.RequiredPermission
        CollectionTime     = $graphResult.CollectionTime
        Status             = $graphResult.Status
        Result             = $graphResult.ObservedValue
        Limitations        = @($graphResult.Limitations)
        EvidenceScope      = $EvidenceScope
        SubjectObjectType  = $SubjectObjectType
        SubjectObjectId    = $SubjectObjectId
    }
}

function New-InspectorSyntheticEvidence {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CollectorName,

        [Parameter(Mandatory)]
        [string]$QueryName,

        [Parameter(Mandatory)]
        [ValidateSet(
            'NotApplicable',
            'NotFound',
            'InsufficientPermission',
            'Failed'
        )]
        [string]$Status,

        [string]$Endpoint = $null,

        [string]$RequiredPermission = 'None',

        [string[]]$Limitations = @(),

        [ValidateSet('TenantCollection','ObjectCollection','ObjectRelationship')]
        [string]$EvidenceScope = 'ObjectRelationship',

        [string]$SubjectObjectType = '',

        [string]$SubjectObjectId = ''
    )

    return [PSCustomObject][ordered]@{
        PSTypeName         = 'EntraObjectInspector.CollectionEvidence'
        EvidenceId         = [guid]::NewGuid().ToString()
        CollectorName      = $CollectorName
        QueryName          = $QueryName
        Endpoint           = $Endpoint
        RequiredPermission = $RequiredPermission
        CollectionTime     = (Get-Date).ToUniversalTime().ToString('o')
        Status             = $Status
        Result             = $null
        Limitations        = @($Limitations)
        EvidenceScope      = $EvidenceScope
        SubjectObjectType  = $SubjectObjectType
        SubjectObjectId    = $SubjectObjectId
    }
}

function New-InspectorRelationship {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$RelationshipType,

        [Parameter(Mandatory)]
        [string]$SourceObjectId,

        [Parameter(Mandatory)]
        [string]$SourceObjectType,

        [Parameter(Mandatory)]
        [string]$TargetObjectId,

        [Parameter(Mandatory)]
        [string]$TargetObjectType,

        [string]$TargetDisplayName = $null,

        [ValidateSet('Direct', 'Transitive', 'Configured')]
        [string]$DirectOrTransitive = 'Direct',

        [ValidateSet('Outbound', 'Inbound')]
        [string]$Direction = 'Outbound',

        [hashtable]$Metadata = @{},

        [string]$EvidenceId = $null
    )

    return [PSCustomObject][ordered]@{
        PSTypeName          = 'EntraObjectInspector.Relationship'
        RelationshipType    = $RelationshipType
        SourceObjectId      = $SourceObjectId
        SourceObjectType    = $SourceObjectType
        TargetObjectId      = $TargetObjectId
        TargetObjectType    = $TargetObjectType
        TargetDisplayName   = $TargetDisplayName
        DirectOrTransitive  = $DirectOrTransitive
        Direction           = $Direction
        Metadata            = [PSCustomObject]$Metadata
        EvidenceId          = $EvidenceId
    }
}

function ConvertTo-InspectorCredentialArtifact {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Application', 'ServicePrincipal')]
        [string]$SourceObjectType,

        [Parameter(Mandatory)]
        [string]$SourceObjectId,

        [Parameter(Mandatory)]
        [ValidateSet('Certificate', 'Password')]
        [string]$CredentialType,

        [Parameter(Mandatory)]
        [object]$Credential,

        [string]$EvidenceId
    )

    return [PSCustomObject][ordered]@{
        PSTypeName       = 'EntraObjectInspector.CredentialArtifact'
        ArtifactType     = 'CredentialMetadata'
        CredentialType   = $CredentialType
        SourceObjectType = $SourceObjectType
        SourceObjectId   = $SourceObjectId
        KeyId            = [string](Get-InspectorCollectorProperty -InputObject $Credential -Name 'keyId')
        DisplayName      = [string](Get-InspectorCollectorProperty -InputObject $Credential -Name 'displayName')
        StartDateTime    = Get-InspectorCollectorProperty -InputObject $Credential -Name 'startDateTime'
        EndDateTime      = Get-InspectorCollectorProperty -InputObject $Credential -Name 'endDateTime'
        Type             = [string](Get-InspectorCollectorProperty -InputObject $Credential -Name 'type')
        Usage            = [string](Get-InspectorCollectorProperty -InputObject $Credential -Name 'usage')
        EvidenceId       = $EvidenceId
        ParentEvidenceId = $EvidenceId
    }
}

function Get-InspectorCollectorStatus {
    [CmdletBinding()]
    param (
        [object[]]$Evidence
    )

    $items = @($Evidence)

    if ($items.Count -eq 0) {
        return 'NotApplicable'
    }

    $statuses = @($items | ForEach-Object { $_.Status })

    if (@($statuses | Where-Object { $_ -ne 'NotApplicable' }).Count -eq 0) {
        return 'NotApplicable'
    }

    if (@($statuses | Where-Object {
        $_ -in @('Failed', 'Throttled', 'ServiceUnavailable')
    }).Count -gt 0) {
        return 'Failed'
    }

    if (@($statuses | Where-Object {
        $_ -eq 'InsufficientPermission'
    }).Count -gt 0) {
        return 'InsufficientPermission'
    }

    if (@($statuses | Where-Object { $_ -ne 'NotFound' }).Count -eq 0) {
        return 'NotFound'
    }

    return 'Success'
}

function Get-InspectorCollectorCompleteness {
    [CmdletBinding()]
    param (
        [object[]]$Evidence
    )

    $problemStatuses = @(
        'InsufficientPermission',
        'Failed',
        'Throttled',
        'ServiceUnavailable'
    )

    if (@($Evidence | Where-Object {
        $_.Status -in $problemStatuses
    }).Count -gt 0) {
        return 'Partial'
    }

    return 'Complete'
}

function New-InspectorCollectorResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CollectorName,

        [Parameter(Mandatory)]
        [string]$SourceObjectType,

        [string]$SourceObjectId,

        [object[]]$Evidence = @(),

        [object[]]$Relationships = @(),

        [object[]]$Artifacts = @(),

        [AllowNull()]
        [object]$Properties = $null,

        [string[]]$Limitations = @()
    )

    return [PSCustomObject][ordered]@{
        PSTypeName       = 'EntraObjectInspector.CollectorResult'
        CollectorName    = $CollectorName
        SourceObjectType = $SourceObjectType
        SourceObjectId   = $SourceObjectId
        Status           = Get-InspectorCollectorStatus -Evidence $Evidence
        Completeness     = Get-InspectorCollectorCompleteness -Evidence $Evidence
        Properties       = $Properties
        Relationships    = @($Relationships)
        Artifacts        = @($Artifacts)
        Evidence         = @($Evidence)
        Limitations      = @($Limitations)
    }
}

function New-InspectorNotApplicableCollectorResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CollectorName,

        [Parameter(Mandatory)]
        [string]$ExpectedObjectType,

        [Parameter(Mandatory)]
        [string]$ActualObjectType,

        [string]$SourceObjectId
    )

    $evidence = New-InspectorSyntheticEvidence `
        -CollectorName $CollectorName `
        -QueryName 'ObjectTypePrecondition' `
        -Status 'NotApplicable' `
        -Limitations @(
            "Collector requires '$ExpectedObjectType' but received '$ActualObjectType'."
        )

    return New-InspectorCollectorResult `
        -CollectorName $CollectorName `
        -SourceObjectType $ActualObjectType `
        -SourceObjectId $SourceObjectId `
        -Evidence @($evidence) `
        -Limitations @(
            "Collector is not applicable to object type '$ActualObjectType'."
        )
}
