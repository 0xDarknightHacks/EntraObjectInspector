function ConvertTo-InspectorPermissionInsight {
    <#
    .SYNOPSIS
        Converts a GrantedAppRole relationship into permission intelligence.

    .DESCRIPTION
        Resolves appRoleId metadata using the local permission catalog and
        returns a normalized permission insight object.

        This function never calls Microsoft Graph.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Relationship
    )

    $relationshipType =
        [string](Get-InspectorPermissionProperty `
            -InputObject $Relationship `
            -Name 'RelationshipType')

    if ($relationshipType -ne 'GrantedAppRole') {
        return $null
    }

    $metadata =
        Get-InspectorPermissionProperty `
            -InputObject $Relationship `
            -Name 'Metadata'

    $appRoleId =
        [string](Get-InspectorPermissionProperty `
            -InputObject $metadata `
            -Name 'AppRoleId')

    if ([string]::IsNullOrWhiteSpace($appRoleId)) {
        return [PSCustomObject][ordered]@{
            PSTypeName           = 'EntraObjectInspector.PermissionInsight'
            InsightId            = [guid]::NewGuid().ToString()
            CatalogStatus        = 'MissingAppRoleId'
            Confidence           = 'Low'
            RelationshipType     = $relationshipType
            RelationshipEvidenceId = Get-InspectorPermissionProperty -InputObject $Relationship -Name 'EvidenceId'
            SourceObjectId       = Get-InspectorPermissionProperty -InputObject $Relationship -Name 'SourceObjectId'
            TargetObjectId       = Get-InspectorPermissionProperty -InputObject $Relationship -Name 'TargetObjectId'
            ResourceDisplayName  = Get-InspectorPermissionProperty -InputObject $Relationship -Name 'TargetDisplayName'
            AppRoleId            = $null
            PermissionName       = $null
            PermissionType       = 'Application'
            PermissionCategory   = 'Unknown'
            ImpactLevel          = 'Medium'
            IsHighImpact         = $false
            AdministrativeImpact = 'The relationship did not include an appRoleId in metadata.'
            TypicalAbuse         = ''
            Reference            = 'Collected GrantedAppRole relationship without appRoleId metadata'
            SourceUrl            = $null
            Limitations          = @('Cannot resolve permission metadata without appRoleId.')
        }
    }

    $resourceDisplayName =
        [string](Get-InspectorPermissionProperty `
            -InputObject $Relationship `
            -Name 'TargetDisplayName')

    $resourceAppId =
        [string](Get-InspectorPermissionProperty `
            -InputObject $metadata `
            -Name 'ResourceAppId')

    if ([string]::IsNullOrWhiteSpace($resourceAppId)) {
        if ($resourceDisplayName -eq 'Microsoft Graph') {
            $resourceAppId = '00000003-0000-0000-c000-000000000000'
        }
    }

    $catalogEntry =
        Resolve-InspectorPermissionMetadata `
            -AppRoleId $appRoleId `
            -ResourceDisplayName $resourceDisplayName `
            -ResourceAppId $resourceAppId

    $permissionName =
        Get-InspectorPermissionProperty `
            -InputObject $catalogEntry `
            -Name 'PermissionName'

    $catalogStatus =
        [string](Get-InspectorPermissionProperty `
            -InputObject $catalogEntry `
            -Name 'CatalogStatus')

    $limitations = @()

    if ($catalogStatus -ne 'Resolved') {
        $limitations += 'Permission was collected but not resolved in the local permission catalog.'
    }

    return [PSCustomObject][ordered]@{
        PSTypeName             = 'EntraObjectInspector.PermissionInsight'
        InsightId              = [guid]::NewGuid().ToString()
        CatalogStatus          = $catalogStatus
        Confidence             = [string](Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'Confidence')
        RelationshipType       = $relationshipType
        RelationshipEvidenceId = Get-InspectorPermissionProperty -InputObject $Relationship -Name 'EvidenceId'
        SourceObjectId         = Get-InspectorPermissionProperty -InputObject $Relationship -Name 'SourceObjectId'
        SourceObjectType       = Get-InspectorPermissionProperty -InputObject $Relationship -Name 'SourceObjectType'
        TargetObjectId         = Get-InspectorPermissionProperty -InputObject $Relationship -Name 'TargetObjectId'
        ResourceDisplayName    = $resourceDisplayName
        ResourceAppId          = $resourceAppId
        AppRoleId              = $appRoleId
        PermissionName         = $permissionName
        PermissionType         = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'PermissionType'
        PermissionCategory     = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'CapabilityCategory'
        DisplayText            = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'DisplayText'
        Description            = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'Description'
        AdminConsentRequired   = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'AdminConsentRequired'
        ImpactLevel            = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'ImpactLevel'
        IsHighImpact           = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'IsHighImpact'
        AdministrativeImpact   = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'AdministrativeImpact'
        TypicalAbuse           = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'TypicalAbuse'
        Reference              = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'Reference'
        SourceUrl              = Get-InspectorPermissionProperty -InputObject $catalogEntry -Name 'SourceUrl'
        Limitations            = @($limitations)
    }
}

