function New-InspectorPermissionCatalogEntry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$PermissionId,

        [Parameter(Mandatory)]
        [string]$PermissionName,

        [Parameter(Mandatory)]
        [ValidateSet('Application', 'Delegated')]
        [string]$PermissionType,

        [Parameter(Mandatory)]
        [string]$DisplayText,

        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [ValidateSet('Low', 'Medium', 'High')]
        [string]$ImpactLevel,

        [Parameter(Mandatory)]
        [string]$CapabilityCategory,

        [Parameter(Mandatory)]
        [string]$AdministrativeImpact,

        [string]$TypicalAbuse = '',

        [bool]$AdminConsentRequired = $true,

        [string]$ResourceAppId = '00000003-0000-0000-c000-000000000000',

        [string]$ResourceDisplayName = 'Microsoft Graph',

        [string]$Reference = 'Microsoft Graph permissions reference'
    )

    return [PSCustomObject][ordered]@{
        PSTypeName             = 'EntraObjectInspector.PermissionCatalogEntry'
        CatalogVersion         = '0.5.0'
        ResourceAppId          = $ResourceAppId
        ResourceDisplayName    = $ResourceDisplayName
        PermissionId           = $PermissionId
        PermissionName         = $PermissionName
        PermissionType         = $PermissionType
        DisplayText            = $DisplayText
        Description            = $Description
        AdminConsentRequired   = $AdminConsentRequired
        ImpactLevel            = $ImpactLevel
        IsHighImpact           = ($ImpactLevel -eq 'High')
        CapabilityCategory     = $CapabilityCategory
        AdministrativeImpact   = $AdministrativeImpact
        TypicalAbuse           = $TypicalAbuse
        Reference              = $Reference
        SourceUrl              = 'https://learn.microsoft.com/graph/permissions-reference'
        SourceLastValidatedUtc = '2026-08-30'
    }
}

function Get-InspectorPermissionCatalog {
    <#
    .SYNOPSIS
        Returns the local Microsoft Graph permission catalog.

    .DESCRIPTION
        This catalog is a deliberately narrow, Microsoft-documentation-backed
        lookup table for commonly relevant Microsoft Graph application
        permissions.

        The function does not call Microsoft Graph.
    #>

    [CmdletBinding()]
    param (
        [string]$PermissionId,

        [string]$PermissionName,

        [string]$ResourceAppId = '00000003-0000-0000-c000-000000000000'
    )

    $catalog = @(
        New-InspectorPermissionCatalogEntry `
            -PermissionId '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30' `
            -PermissionName 'Application.Read.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read all applications' `
            -Description 'Allows the app to read all applications and service principals without a signed-in user.' `
            -ImpactLevel 'Medium' `
            -CapabilityCategory 'Application inventory' `
            -AdministrativeImpact 'Can enumerate application registrations and enterprise applications across the tenant.' `
            -TypicalAbuse 'Reconnaissance of applications, owners, exposed roles, and workload identities.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' `
            -PermissionName 'Application.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write all applications' `
            -Description 'Allows the app to create, read, update and delete applications and service principals without a signed-in user. Allows management of app role assignments except those exposed by Microsoft Graph. Does not allow management of delegated permission grants.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Application management' `
            -AdministrativeImpact 'Can create and modify application registrations and service principals, including credentials on applications.' `
            -TypicalAbuse 'Persisting access by adding credentials or modifying application configuration.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '18a4783c-866b-4cc7-a460-3d5e5662c884' `
            -PermissionName 'Application.ReadWrite.OwnedBy' `
            -PermissionType 'Application' `
            -DisplayText 'Manage apps that this app creates or owns' `
            -Description 'Allows the app to create other applications and fully manage applications it owns without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Application management' `
            -AdministrativeImpact 'Can manage applications and service principals where the calling app is an owner.' `
            -TypicalAbuse 'Maintaining workload identity persistence through owned applications.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '06b708a9-e830-4db3-a914-8e69da51d44f' `
            -PermissionName 'AppRoleAssignment.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText 'Manage app permission grants and app role assignments' `
            -Description 'Allows the app to manage permission grants for application permissions to any API, including Microsoft Graph, and application assignments for any app, without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Authorization grant management' `
            -AdministrativeImpact 'Can grant application permissions and app-role assignments to applications, users, or service principals.' `
            -TypicalAbuse 'Privilege escalation by granting additional application permissions.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '7ab1d382-f21e-4acd-a863-ba3e13f7da61' `
            -PermissionName 'Directory.Read.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read directory data' `
            -Description 'Allows the app to read data in the organization directory, such as users, groups, and apps, without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Directory inventory' `
            -AdministrativeImpact 'Can broadly enumerate Microsoft Entra directory resources.' `
            -TypicalAbuse 'Tenant-wide reconnaissance of users, groups, apps, and directory relationships.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '19dbc75e-c2e2-444c-a770-ec69d8559fc7' `
            -PermissionName 'Directory.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write directory data' `
            -Description 'Allows the app to read and write data in the organization directory, such as users and groups, without a signed-in user. Does not allow user or group deletion.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Directory management' `
            -AdministrativeImpact 'Can broadly modify directory objects such as users and groups.' `
            -TypicalAbuse 'Privilege escalation or persistence by changing directory objects and memberships.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '483bed4a-2ad3-4361-a73b-c83ccdbdc53c' `
            -PermissionName 'RoleManagement.Read.Directory' `
            -PermissionType 'Application' `
            -DisplayText 'Read all directory RBAC settings' `
            -Description 'Allows the app to read directory RBAC settings without a signed-in user, including directory role templates, directory roles, and memberships.' `
            -ImpactLevel 'Medium' `
            -CapabilityCategory 'Directory role inventory' `
            -AdministrativeImpact 'Can enumerate role definitions, role assignments, and role memberships.' `
            -TypicalAbuse 'Reconnaissance of privileged role assignments.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' `
            -PermissionName 'RoleManagement.ReadWrite.Directory' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write all directory RBAC settings' `
            -Description 'Allows the app to read and manage directory RBAC settings without a signed-in user, including directory role membership and PIM for Microsoft Entra roles APIs.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Directory role management' `
            -AdministrativeImpact 'Can manage Microsoft Entra role membership and role-management APIs.' `
            -TypicalAbuse 'Privilege escalation by adding users, groups, or applications to privileged Entra roles.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId 'df021288-bdef-4463-88db-98f22de89214' `
            -PermissionName 'User.Read.All' `
            -PermissionType 'Application' `
            -DisplayText "Read all users' full profiles" `
            -Description 'Allows the app to read user profiles without a signed-in user.' `
            -ImpactLevel 'Medium' `
            -CapabilityCategory 'User inventory' `
            -AdministrativeImpact 'Can enumerate user profile data across the tenant.' `
            -TypicalAbuse 'User and identity reconnaissance.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '741f803b-c850-494e-b5df-cde7c675a1ca' `
            -PermissionName 'User.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText "Read and write all users' full profiles" `
            -Description 'Allows the app to read and update user profiles without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'User management' `
            -AdministrativeImpact 'Can update user profile properties across the tenant, subject to Microsoft Graph constraints.' `
            -TypicalAbuse 'Changing user attributes that affect identity operations or downstream automation.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '01c0a623-fc9b-48e9-b794-0756f8e8f067' `
            -PermissionName 'Policy.ReadWrite.ConditionalAccess' `
            -PermissionType 'Application' `
            -DisplayText "Read and write your organization's conditional access policies" `
            -Description 'Allows the app to read and write Conditional Access policies without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Policy management' `
            -AdministrativeImpact 'Can modify Conditional Access controls that govern access to tenant resources.' `
            -TypicalAbuse 'Weakening or bypassing access controls by modifying policy conditions or exclusions.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '5e1e9171-754d-478c-812c-f1755a9a4c2d' `
            -PermissionName 'AuditLogsQuery.Read.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read audit logs data from all services' `
            -Description 'Allows the app to read and query audit logs from all services.' `
            -ImpactLevel 'Medium' `
            -CapabilityCategory 'Audit and monitoring' `
            -AdministrativeImpact 'Can query audit logs for investigation and monitoring scenarios.' `
            -TypicalAbuse 'Reconnaissance of administrative activity and detection posture.'
    )

    $result = @($catalog)

    if (-not [string]::IsNullOrWhiteSpace($ResourceAppId)) {
        $result = @(
            $result |
            Where-Object { $_.ResourceAppId -eq $ResourceAppId }
        )
    }

    if (-not [string]::IsNullOrWhiteSpace($PermissionId)) {
        $result = @(
            $result |
            Where-Object {
                $_.PermissionId -eq $PermissionId
            }
        )
    }

    if (-not [string]::IsNullOrWhiteSpace($PermissionName)) {
        $result = @(
            $result |
            Where-Object {
                $_.PermissionName -eq $PermissionName
            }
        )
    }

    return @($result)
}

