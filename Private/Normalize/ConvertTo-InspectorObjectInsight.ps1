function Get-InspectorObjectInsightProperty {
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

function ConvertTo-InspectorObjectInsight {
    <#
    .SYNOPSIS
        Builds the normalized ObjectInsight model.

    .DESCRIPTION
        Combines resolver output, relationship collection results,
        relationships, artifacts, evidence, and limitations into one
        normalized object insight envelope.

        This function does not call Microsoft Graph.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Resolution,

        [AllowNull()]
        [object]$RelationshipCollection = $null
    )

    if ($null -eq $RelationshipCollection) {
        $RelationshipCollection =
            Get-InspectorObjectInsightProperty `
                -InputObject $Resolution `
                -Name 'RelationshipCollection'
    }

    $directMatches = @(
        (Get-InspectorObjectInsightProperty `
            -InputObject $Resolution `
            -Name 'DirectMatches') |
        Where-Object { $null -ne $_ }
    )

    $relatedObjects = @(
        (Get-InspectorObjectInsightProperty `
            -InputObject $Resolution `
            -Name 'RelatedObjects') |
        Where-Object { $null -ne $_ }
    )

    $allResolvedObjects = @(
        @($directMatches) +
        @($relatedObjects) |
        Where-Object { $null -ne $_ }
    )

    $primaryObject =
        Get-InspectorObjectInsightProperty `
            -InputObject $Resolution `
            -Name 'PrimaryObject'

    $relationships = @(
        (Get-InspectorObjectInsightProperty `
            -InputObject $Resolution `
            -Name 'Relationships') |
        Where-Object { $null -ne $_ }
    )

    if ($null -ne $RelationshipCollection) {
        $relationshipCollectionRelationships = @(
            (Get-InspectorObjectInsightProperty `
                -InputObject $RelationshipCollection `
                -Name 'Relationships') |
            Where-Object { $null -ne $_ }
        )

        $relationships =
            @($relationships) +
            @($relationshipCollectionRelationships)
    }

    $artifacts = @()

    if ($null -ne $RelationshipCollection) {
        $artifacts = @(
            (Get-InspectorObjectInsightProperty `
                -InputObject $RelationshipCollection `
                -Name 'Artifacts') |
            Where-Object { $null -ne $_ }
        )
    }

    $evidence = @(
        (Get-InspectorObjectInsightProperty `
            -InputObject $Resolution `
            -Name 'Evidence') |
        Where-Object { $null -ne $_ }
    )

    if ($null -ne $RelationshipCollection) {
        $collectionEvidence = @(
            (Get-InspectorObjectInsightProperty `
                -InputObject $RelationshipCollection `
                -Name 'Evidence') |
            Where-Object { $null -ne $_ }
        )

        $evidence =
            @($evidence) +
            @($collectionEvidence)
    }

    $limitations = @(
        (Get-InspectorObjectInsightProperty `
            -InputObject $Resolution `
            -Name 'Limitations') |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        }
    )

    if ($null -ne $RelationshipCollection) {
        $collectionLimitations = @(
            (Get-InspectorObjectInsightProperty `
                -InputObject $RelationshipCollection `
                -Name 'Limitations') |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            }
        )

        $limitations =
            @($limitations) +
            @($collectionLimitations)
    }

    $uniqueLimitations =
        @($limitations | Select-Object -Unique)

    $applications = @(
        $allResolvedObjects |
        Where-Object { $_.ObjectType -eq 'Application' }
    )

    $servicePrincipals = @(
        $allResolvedObjects |
        Where-Object { $_.ObjectType -eq 'ServicePrincipal' }
    )

    $applicationIdentity = $null

    if ($applications.Count -gt 0 -or $servicePrincipals.Count -gt 0) {
        $applicationObject =
            $applications |
            Select-Object -First 1

        $servicePrincipalObject =
            $servicePrincipals |
            Select-Object -First 1

        $appId =
            if ($null -ne $applicationObject) {
                Get-InspectorObjectInsightProperty `
                    -InputObject $applicationObject.Identifiers `
                    -Name 'AppId'
            }
            elseif ($null -ne $servicePrincipalObject) {
                Get-InspectorObjectInsightProperty `
                    -InputObject $servicePrincipalObject.Identifiers `
                    -Name 'AppId'
            }
            else {
                $null
            }

        $applicationIdentity = [PSCustomObject][ordered]@{
            AppId = $appId
            ApplicationObjectId =
                if ($null -ne $applicationObject) {
                    Get-InspectorObjectInsightProperty `
                        -InputObject $applicationObject.Identifiers `
                        -Name 'ObjectId'
                }
                else {
                    $null
                }
            ServicePrincipalObjectId =
                if ($null -ne $servicePrincipalObject) {
                    Get-InspectorObjectInsightProperty `
                        -InputObject $servicePrincipalObject.Identifiers `
                        -Name 'ObjectId'
                }
                else {
                    $null
                }
        }
    }

    $collectorResults = @()

    if ($null -ne $RelationshipCollection) {
        $collectorResults = @(
            (Get-InspectorObjectInsightProperty `
                -InputObject $RelationshipCollection `
                -Name 'CollectorResults') |
            Where-Object { $null -ne $_ }
        )
    }

    $sourceObjects = @(
        $collectorResults |
        ForEach-Object {
            $collectorResult = $_
            $objectType = [string](Get-InspectorObjectInsightProperty -InputObject $collectorResult -Name 'SourceObjectType')
            $objectId = [string](Get-InspectorObjectInsightProperty -InputObject $collectorResult -Name 'SourceObjectId')
            $properties = Get-InspectorObjectInsightProperty -InputObject $collectorResult -Name 'Properties'
            $displayName = [string](Get-InspectorObjectInsightProperty -InputObject $properties -Name 'displayName')
            $appId = [string](Get-InspectorObjectInsightProperty -InputObject $properties -Name 'appId')
            $userPrincipalName = [string](Get-InspectorObjectInsightProperty -InputObject $properties -Name 'userPrincipalName')
            $servicePrincipalType = [string](Get-InspectorObjectInsightProperty -InputObject $properties -Name 'servicePrincipalType')
            $appOwnerOrganizationId = [string](Get-InspectorObjectInsightProperty -InputObject $properties -Name 'appOwnerOrganizationId')
            $publisherName = [string](Get-InspectorObjectInsightProperty -InputObject $properties -Name 'publisherName')
            $verifiedPublisher = Get-InspectorObjectInsightProperty -InputObject $properties -Name 'verifiedPublisher'
            $inspectorTenantId = [string](Get-InspectorObjectInsightProperty -InputObject $properties -Name 'InspectorTenantId')
            $hasTenantApplicationCounterpart =
                $objectType -eq 'ServicePrincipal' -and
                $null -ne $applicationIdentity -and
                -not [string]::IsNullOrWhiteSpace([string]$applicationIdentity.ApplicationObjectId) -and
                -not [string]::IsNullOrWhiteSpace($appId) -and
                $appId -eq [string]$applicationIdentity.AppId

            $publisherClassification =
                Get-InspectorPublisherClassification `
                    -ObjectType $objectType `
                    -ServicePrincipalType $servicePrincipalType `
                    -AppId $appId `
                    -AppOwnerOrganizationId $appOwnerOrganizationId `
                    -VerifiedPublisher $verifiedPublisher `
                    -InspectorTenantId $inspectorTenantId `
                    -HasTenantApplicationCounterpart:$hasTenantApplicationCounterpart

            [PSCustomObject][ordered]@{
                ObjectType = $objectType
                ObjectId   = $objectId
                DisplayName = $displayName
                AppId = $appId
                UserPrincipalName = $userPrincipalName
                Identifiers = [PSCustomObject][ordered]@{
                    ObjectId = $objectId
                    AppId = $appId
                    UserPrincipalName = $userPrincipalName
                }
                Metadata = [PSCustomObject][ordered]@{
                    ServicePrincipalType = $servicePrincipalType
                    AppOwnerOrganizationId = $appOwnerOrganizationId
                    PublisherName = $publisherName
                    VerifiedPublisher = $verifiedPublisher
                    PublisherClassification = $publisherClassification
                    TenantOwnershipClassification = $publisherClassification
                    ClassificationConfidence = 'ConservativeMetadata'
                    ClassificationMethod = 'Collected publisher/app ownership metadata, Microsoft-documented exact AppId fallback, and local application counterpart.'
                }
                Collector  = Get-InspectorObjectInsightProperty -InputObject $collectorResult -Name 'CollectorName'
                Status     = Get-InspectorObjectInsightProperty -InputObject $collectorResult -Name 'Status'
                Properties = $properties
            }
        }
    )

    $status =
        Get-InspectorObjectInsightProperty `
            -InputObject $Resolution `
            -Name 'Status'

    $resolutionType =
        Get-InspectorObjectInsightProperty `
            -InputObject $Resolution `
            -Name 'ResolutionType'

    return [PSCustomObject][ordered]@{
        PSTypeName              = 'EntraObjectInspector.ObjectInsight'
        SchemaVersion           = '0.4.0'
        GeneratedAt             = (Get-Date).ToUniversalTime().ToString('o')

        Input                   = Get-InspectorObjectInsightProperty -InputObject $Resolution -Name 'Input'
        NormalizedInput         = Get-InspectorObjectInsightProperty -InputObject $Resolution -Name 'NormalizedInput'
        InputShape              = Get-InspectorObjectInsightProperty -InputObject $Resolution -Name 'InputShape'

        Status                  = $status
        ResolutionStatus        = $status
        ResolutionType          = $resolutionType
        PrimaryObject           = $primaryObject
        DirectMatches           = @($directMatches)
        RelatedObjects          = @($relatedObjects)
        ResolvedObjects         = @($allResolvedObjects)
        ApplicationIdentity     = $applicationIdentity

        RelationshipCollection  = $RelationshipCollection
        CollectorResults        = @($collectorResults)
        SourceObjects           = @($sourceObjects)
        Relationships           = @($relationships)
        Artifacts               = @($artifacts)
        Evidence                = @($evidence)
        Limitations             = @($uniqueLimitations)

        RuleResults             = @()
        Findings                = @()

        Summary                 = [PSCustomObject][ordered]@{
            ResolvedObjectCount = @($allResolvedObjects).Count
            RelationshipCount   = @($relationships).Count
            ArtifactCount       = @($artifacts).Count
            EvidenceCount       = @($evidence).Count
            LimitationCount     = @($uniqueLimitations).Count
            FindingCount        = 0
        }
    }
}

