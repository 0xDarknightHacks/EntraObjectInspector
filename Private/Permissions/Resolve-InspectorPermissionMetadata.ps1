function Resolve-InspectorPermissionMetadata {
    <#
    .SYNOPSIS
        Resolves collected permission identifiers to catalog metadata.

    .DESCRIPTION
        Uses the local local permission catalog only. This function never calls
        Microsoft Graph.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$AppRoleId,

        [string]$ResourceDisplayName = 'Microsoft Graph',

        [string]$ResourceAppId = '00000003-0000-0000-c000-000000000000'
    )

    $entry = $null

    if (
        $ResourceDisplayName -eq 'Microsoft Graph' -or
        $ResourceAppId -eq '00000003-0000-0000-c000-000000000000'
    ) {
        $entry =
            Get-InspectorPermissionCatalog `
                -PermissionId $AppRoleId `
                -ResourceAppId '00000003-0000-0000-c000-000000000000' |
            Select-Object -First 1
    }

    if ($null -ne $entry) {
        $entry |
            Add-Member `
                -NotePropertyName 'CatalogStatus' `
                -NotePropertyValue 'Resolved' `
                -Force

        $entry |
            Add-Member `
                -NotePropertyName 'Confidence' `
                -NotePropertyValue 'High' `
                -Force

        return $entry
    }

    return [PSCustomObject][ordered]@{
        PSTypeName             = 'EntraObjectInspector.PermissionCatalogEntry'
        CatalogVersion         = '0.6.0'
        CatalogStatus          = 'Unknown'
        Confidence             = 'Low'
        ResourceAppId          = $ResourceAppId
        ResourceDisplayName    = $ResourceDisplayName
        PermissionId           = $AppRoleId
        PermissionName         = $null
        PermissionType         = 'Application'
        DisplayText            = $null
        Description            = $null
        AdminConsentRequired   = $null
        ImpactLevel            = 'Medium'
        IsHighImpact           = $false
        CapabilityCategory     = 'Unknown application permission'
        AdministrativeImpact   = 'The app role ID was collected, but The local permission catalog could not resolve it in the local permission catalog.'
        TypicalAbuse           = ''
        Reference              = 'Unresolved appRoleId from collected appRoleAssignment evidence'
        SourceUrl              = $null
        SourceLastValidatedUtc = $null
    }
}

