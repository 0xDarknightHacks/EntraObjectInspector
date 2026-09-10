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
        CatalogVersion         = '0.6.0'
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
        SourceLastValidatedUtc = '2026-09-10'
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
            -ImpactLevel 'Medium' `
            -CapabilityCategory 'Directory inventory' `
            -AdministrativeImpact 'Can broadly enumerate Microsoft Entra directory resources.' `
            -TypicalAbuse 'Tenant-wide reconnaissance of users, groups, apps, and directory relationships.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '5eb59dd3-1da2-4329-8733-9dabdc435916' `
            -PermissionName 'AdministrativeUnit.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write all administrative units' `
            -Description 'Allows the app to create, read, update, and delete administrative units and manage administrative unit membership without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Administrative unit management' `
            -AdministrativeImpact 'Can change administrative-unit configuration and membership across the tenant.' `
            -TypicalAbuse 'Changing administrative scope or membership to alter delegated-management boundaries.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '8e8e4742-1d95-4f68-9d56-6ee75648c72a' `
            -PermissionName 'DelegatedPermissionGrant.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText 'Manage all delegated permission grants' `
            -Description 'Allows the app to manage permission grants for delegated permissions exposed by any API, including Microsoft Graph, without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Authorization grant management' `
            -AdministrativeImpact 'Can create or change delegated permission grants for applications across APIs, including Microsoft Graph.' `
            -TypicalAbuse 'Granting additional delegated access that expands what an application can do on behalf of users.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '7e05723c-0bb0-42da-be95-ae9f08a6e53c' `
            -PermissionName 'Domain.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write domains' `
            -Description 'Allows the app to read and write all domain properties, and add, verify, or remove domains, without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Domain management' `
            -AdministrativeImpact 'Can change tenant domain configuration, including adding, verifying, and removing domains.' `
            -TypicalAbuse 'Changing trusted tenant domain configuration or disrupting identity routing.'

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
            -PermissionId '62a82d76-70ea-41e2-9197-370581804d09' `
            -PermissionName 'Group.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write all groups' `
            -Description 'Allows the app to create groups, read and update group properties and memberships, and delete groups without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Group management' `
            -AdministrativeImpact 'Can broadly create, modify, and delete groups and change membership, subject to extra protections for role-assignable groups.' `
            -TypicalAbuse 'Changing group membership or group configuration to expand access to resources.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId 'dbaae8cf-10b5-4b86-a4a1-f871c94c6695' `
            -PermissionName 'GroupMember.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write all group memberships' `
            -Description 'Allows the app to read and update membership of groups it can access without a signed-in user; group properties and owners cannot be updated.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Group membership management' `
            -AdministrativeImpact 'Can change memberships across accessible groups, although role-assignable group membership requires stronger role-management permission.' `
            -TypicalAbuse 'Adding identities to access-bearing groups to expand effective access.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '656f6061-f9fe-4807-9708-6a2e0934df76' `
            -PermissionName 'IdentityRiskyUser.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write all risky user information' `
            -Description 'Allows the app to read and update risky-user information for the organization without a signed-in user, including dismissing risky users.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Identity risk management' `
            -AdministrativeImpact 'Can change risky-user state used by identity-risk investigation and policy workflows.' `
            -TypicalAbuse 'Suppressing or changing risky-user state to reduce visibility or influence downstream risk handling.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '854d9ab1-6657-4ec8-be45-823027bcd009' `
            -PermissionName 'PrivilegedAccess.ReadWrite.AzureAD' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write privileged access to Azure AD roles' `
            -Description 'Allows the app to request and manage time-based assignment and just-in-time elevation of Microsoft Entra built-in and custom administrative roles without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Privileged role management' `
            -AdministrativeImpact 'Can manage time-based and just-in-time Microsoft Entra role access.' `
            -TypicalAbuse 'Creating or changing privileged role access for users or other principals.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '2f6817f8-7b12-4f0f-bc18-eeaf60705a9e' `
            -PermissionName 'PrivilegedAccess.ReadWrite.AzureADGroup' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write privileged access to Azure AD groups' `
            -Description 'Allows the app to manage privileged access for Microsoft Entra groups without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Privileged group management' `
            -AdministrativeImpact 'Can manage privileged group access and influence group-based privilege.' `
            -TypicalAbuse 'Changing privileged group membership or ownership access.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '41202f2c-f7ab-45be-b001-85c9728b9d69' `
            -PermissionName 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup' `
            -PermissionType 'Application' `
            -DisplayText 'Read, create, and delete assignment schedules for access to Azure AD groups' `
            -Description 'Allows the app to read, create, and delete time-based assignment schedules for access to Microsoft Entra groups without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Privileged group management' `
            -AdministrativeImpact 'Can create or remove active time-based privileged group membership or ownership schedules.' `
            -TypicalAbuse 'Granting active privileged group access through PIM for Groups.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '618b6020-bca8-4de6-99f6-ef445fa4d857' `
            -PermissionName 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup' `
            -PermissionType 'Application' `
            -DisplayText 'Read, create, and delete eligibility schedules for access to Azure AD groups' `
            -Description 'Allows the app to read, create, and delete time-based eligibility schedules for access to Microsoft Entra groups without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Privileged group management' `
            -AdministrativeImpact 'Can create or remove eligibility for privileged group membership or ownership.' `
            -TypicalAbuse 'Making identities eligible to obtain privileged group access.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId 'b38dcc4d-a239-4ed6-aa84-6c65b284f97c' `
            -PermissionName 'RoleManagementPolicy.ReadWrite.AzureADGroup' `
            -PermissionType 'Application' `
            -DisplayText 'Read, update, and delete all policies in PIM for Groups' `
            -Description 'Allows the app to read, update, and delete policies in Privileged Identity Management for Groups without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Privileged group policy management' `
            -AdministrativeImpact 'Can change PIM for Groups policy controls such as activation and assignment governance.' `
            -TypicalAbuse 'Weakening controls around activation or assignment of privileged group access.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId 'dd199f4a-f148-40a4-a2ec-f0069cc799ec' `
            -PermissionName 'RoleAssignmentSchedule.ReadWrite.Directory' `
            -PermissionType 'Application' `
            -DisplayText "Read, update, and delete all active role assignments for your company's directory" `
            -Description 'Allows the app to read and manage active Microsoft Entra RBAC assignments and schedules without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Privileged role management' `
            -AdministrativeImpact 'Can manage active Microsoft Entra directory-role assignments and schedules.' `
            -TypicalAbuse 'Creating or changing active privileged role assignments.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId 'fee28b28-e1f3-4841-818e-2704dc62245f' `
            -PermissionName 'RoleEligibilitySchedule.ReadWrite.Directory' `
            -PermissionType 'Application' `
            -DisplayText "Read, update, and delete all eligible role assignments and schedules for your company's directory" `
            -Description 'Allows the app to read and manage eligible Microsoft Entra RBAC assignments and schedules without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Privileged role management' `
            -AdministrativeImpact 'Can manage who is eligible to activate Microsoft Entra directory roles.' `
            -TypicalAbuse 'Making identities eligible for privileged Microsoft Entra roles.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad' `
            -PermissionName 'RoleManagementPolicy.ReadWrite.Directory' `
            -PermissionType 'Application' `
            -DisplayText "Read, update, and delete all policies for privileged role assignments of your company's directory" `
            -Description 'Allows the app to read, update, and delete policies for privileged Microsoft Entra RBAC assignments without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Privileged role policy management' `
            -AdministrativeImpact 'Can modify PIM role-management policy controls for Microsoft Entra roles.' `
            -TypicalAbuse 'Weakening activation requirements, approval, duration, or other privileged-role policy controls.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '81adad77-a25a-489d-ac43-321115620139' `
            -PermissionName 'PrivilegedAssignmentSchedule.ReadWrite.EntraAppRole' `
            -PermissionType 'Application' `
            -DisplayText 'Read, create, and delete assignment schedules for app permission grants and app role assignments' `
            -Description 'Allows the app to read, create, and delete time-based assignment schedules for application permission grants to APIs and application assignments without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Authorization grant management' `
            -AdministrativeImpact 'Can create or remove time-based active application permission grants and app-role assignments.' `
            -TypicalAbuse 'Granting time-based application authorization to applications or other principals.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '7f4c39f1-1aa7-44b7-ab05-38df2609c37a' `
            -PermissionName 'PrivilegedEligibilitySchedule.ReadWrite.EntraAppRole' `
            -PermissionType 'Application' `
            -DisplayText 'Read, create, and delete eligibility schedules for app permission grants and app role assignments' `
            -Description 'Allows the app to read, create, and delete time-based eligibility schedules for application permission grants to APIs and application assignments without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Authorization grant management' `
            -AdministrativeImpact 'Can create or remove eligibility for time-based application permission grants and app-role assignments.' `
            -TypicalAbuse 'Making principals eligible for privileged application authorization.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '9acd699f-1e81-4958-b001-93b1d2506e19' `
            -PermissionName 'EntitlementManagement.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write all entitlement management resources' `
            -Description 'Allows the app to read and write access packages and related entitlement management resources without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Authorization grant management' `
            -AdministrativeImpact 'Can manage authorizations for resources onboarded to entitlement management catalogs, including directory roles, app roles, API permissions, and group memberships.' `
            -TypicalAbuse 'Granting or changing privileged access through entitlement-management resources.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId 'a402ca1c-2696-4531-972d-6e5ee4aa11ea' `
            -PermissionName 'Policy.ReadWrite.PermissionGrant' `
            -PermissionType 'Application' `
            -DisplayText 'Manage consent and permission grant policies' `
            -Description 'Allows the app to manage policies related to consent and permission grants for applications, without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Authorization policy management' `
            -AdministrativeImpact 'Can change tenant policies that govern consent and application permission grants.' `
            -TypicalAbuse 'Weakening or changing consent controls around application authorization.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId 'ec563bdb-80dc-47c0-81d3-bff47cc6ac06' `
            -PermissionName 'RoleManagementPolicy.ReadWrite.EntraAppRole' `
            -PermissionType 'Application' `
            -DisplayText 'Manage all policies in PIM for App Roles' `
            -Description 'Allows the app to manage policies in Privileged Identity Management for App Roles, without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Authorization grant policy management' `
            -AdministrativeImpact 'Can change PIM policy controls for time-based application permission grants and app-role assignments.' `
            -TypicalAbuse 'Weakening controls around privileged application authorization.'

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
            -PermissionId '50483e42-d915-4231-9639-7fdb7fd190e5' `
            -PermissionName 'UserAuthenticationMethod.ReadWrite.All' `
            -PermissionType 'Application' `
            -DisplayText "Read and write all users' authentication methods" `
            -Description 'Allows the app to read and write authentication methods of all users in the organization without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Authentication method management' `
            -AdministrativeImpact 'Can change authentication methods for users across the tenant, subject to Microsoft Entra authorization constraints.' `
            -TypicalAbuse 'Changing authentication-method state to weaken or redirect identity verification.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId '29c18626-4985-4dcd-85c0-193eef327366' `
            -PermissionName 'Policy.ReadWrite.AuthenticationMethod' `
            -PermissionType 'Application' `
            -DisplayText 'Read and write all authentication method policies' `
            -Description 'Allows the app to read and write all authentication method policies for the tenant without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Authentication policy management' `
            -AdministrativeImpact 'Can change tenant-wide authentication method policy.' `
            -TypicalAbuse 'Weakening or changing authentication-method controls across the tenant.'

        New-InspectorPermissionCatalogEntry `
            -PermissionId 'fb221be6-99f2-473f-bd32-01c6a0e9ca3b' `
            -PermissionName 'Policy.ReadWrite.Authorization' `
            -PermissionType 'Application' `
            -DisplayText "Read and write your organization's authorization policy" `
            -Description 'Allows the app to read and write the organization authorization policy without a signed-in user.' `
            -ImpactLevel 'High' `
            -CapabilityCategory 'Authorization policy management' `
            -AdministrativeImpact 'Can change tenant authorization-policy settings that influence default user permissions and other authorization behavior.' `
            -TypicalAbuse 'Weakening tenant authorization policy to expand default capabilities.'

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

