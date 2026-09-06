function Get-InspectorRecommendationReferenceSourceOrder {
    [CmdletBinding()]
    param ([string]$SourceType)

    switch ($SourceType) {
        'MicrosoftLearn' { return 1 }
        'MicrosoftGraph' { return 1 }
        'MicrosoftZeroTrust' { return 2 }
        'NIST' { return 3 }
        'CIS' { return 3 }
        default { return 99 }
    }
}

function Get-InspectorRecommendationReferenceKeys {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject
    )

    $values = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $InputObject) {
        return @()
    }

    if ($InputObject -is [string]) {
        $values.Add([string]$InputObject)
    }
    else {
        foreach ($name in @('Category','Title','FindingId','RecommendationId','ObservationId','RuleId','RuleName')) {
            $value = Get-InspectorIntelligenceProperty -InputObject $InputObject -Name $name

            if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                $values.Add([string]$value)
            }
        }

        $metadata = Get-InspectorIntelligenceProperty -InputObject $InputObject -Name 'Metadata'

        foreach ($name in @('PermissionName','RuleId','Category','FindingCategory')) {
            $value = Get-InspectorIntelligenceProperty -InputObject $metadata -Name $name

            if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                $values.Add([string]$value)
            }
        }

        foreach ($ruleId in @(Get-InspectorIntelligenceProperty -InputObject $InputObject -Name 'SourceRuleIds')) {
            if (-not [string]::IsNullOrWhiteSpace([string]$ruleId)) {
                $values.Add([string]$ruleId)
            }
        }
    }

    return @(
        $values |
            ForEach-Object {
                $value = [string]$_
                $value
                $value -replace '[^A-Za-z0-9]', ''
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
}

function Resolve-InspectorRecommendationReferenceIds {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject
    )

    $keys = @(Get-InspectorRecommendationReferenceKeys -InputObject $InputObject)
    $referenceIds = [System.Collections.Generic.List[string]]::new()

    $mapping = [ordered]@{
        ApplicationOwnership = @('MS-APP-SECURITY-BEST-PRACTICES','MS-GOVERN-SERVICE-ACCOUNTS','MS-ENTRA-SECURE-BEST-PRACTICES','NIST-CSF-2-PR-AA','CIS-CONTROL-5-ACCOUNT-MANAGEMENT')
        OrphanedApplication = @('MS-APP-SECURITY-BEST-PRACTICES','MS-GOVERN-SERVICE-ACCOUNTS','MS-ENTRA-SECURE-BEST-PRACTICES','NIST-CSF-2-PR-AA','CIS-CONTROL-5-ACCOUNT-MANAGEMENT')
        MissingOwner = @('MS-APP-SECURITY-BEST-PRACTICES','MS-GOVERN-SERVICE-ACCOUNTS','MS-ENTRA-SECURE-BEST-PRACTICES','NIST-CSF-2-PR-AA','CIS-CONTROL-5-ACCOUNT-MANAGEMENT')
        IdentityGovernance = @('MS-APP-SECURITY-BEST-PRACTICES','MS-GOVERN-SERVICE-ACCOUNTS','MS-ACCESS-REVIEWS-DEPLOYMENT','NIST-CSF-2-PR-AA','CIS-CONTROL-5-ACCOUNT-MANAGEMENT')
        CredentialHygiene = @('MS-APP-SECURITY-BEST-PRACTICES','MS-APP-CREDENTIALS','MS-RECOMMEND-EXPIRING-APP-CREDENTIALS','MS-RECOMMEND-REMOVE-UNUSED-CREDENTIALS','NIST-CSF-2-PR-AA','CIS-CONTROL-5-ACCOUNT-MANAGEMENT')
        ExpiredCredential = @('MS-APP-SECURITY-BEST-PRACTICES','MS-APP-CREDENTIALS','MS-RECOMMEND-EXPIRING-APP-CREDENTIALS','MS-RECOMMEND-REMOVE-UNUSED-CREDENTIALS','NIST-CSF-2-PR-AA','CIS-CONTROL-5-ACCOUNT-MANAGEMENT')
        ExpiringCredential = @('MS-APP-SECURITY-BEST-PRACTICES','MS-APP-CREDENTIALS','MS-RECOMMEND-EXPIRING-APP-CREDENTIALS','MS-RECOMMEND-REMOVE-UNUSED-CREDENTIALS','NIST-CSF-2-PR-AA','CIS-CONTROL-5-ACCOUNT-MANAGEMENT')
        LongLivedCredential = @('MS-APP-SECURITY-BEST-PRACTICES','MS-APP-CREDENTIALS','MS-RECOMMEND-EXPIRING-APP-CREDENTIALS','MS-RECOMMEND-REMOVE-UNUSED-CREDENTIALS','NIST-CSF-2-PR-AA','CIS-CONTROL-5-ACCOUNT-MANAGEMENT')
        MultipleCredentials = @('MS-APP-SECURITY-BEST-PRACTICES','MS-APP-CREDENTIALS','MS-RECOMMEND-EXPIRING-APP-CREDENTIALS','MS-RECOMMEND-REMOVE-UNUSED-CREDENTIALS','NIST-CSF-2-PR-AA','CIS-CONTROL-5-ACCOUNT-MANAGEMENT')
        HighImpactPermissions = @('MS-APP-LEAST-PRIVILEGE','MS-GRAPH-PERMISSIONS-REFERENCE','MS-GRAPH-PERMISSION-BEST-PRACTICES','MS-ZERO-TRUST-OVERPRIVILEGED-PERMISSIONS','MS-ZERO-TRUST-OVERVIEW','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        PermissionExposure = @('MS-APP-LEAST-PRIVILEGE','MS-GRAPH-PERMISSIONS-REFERENCE','MS-GRAPH-PERMISSION-BEST-PRACTICES','MS-ZERO-TRUST-OVERPRIVILEGED-PERMISSIONS','MS-ZERO-TRUST-OVERVIEW','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        ApplicationPermissions = @('MS-APP-LEAST-PRIVILEGE','MS-GRAPH-PERMISSIONS-REFERENCE','MS-GRAPH-PERMISSION-BEST-PRACTICES','MS-ZERO-TRUST-OVERPRIVILEGED-PERMISSIONS','MS-ZERO-TRUST-OVERVIEW','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        OverprivilegedPermissions = @('MS-APP-LEAST-PRIVILEGE','MS-GRAPH-PERMISSIONS-REFERENCE','MS-GRAPH-PERMISSION-BEST-PRACTICES','MS-ZERO-TRUST-OVERPRIVILEGED-PERMISSIONS','MS-ZERO-TRUST-OVERVIEW','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        ConsentGovernance = @('MS-PERMISSIONS-CONSENT-OVERVIEW','MS-USER-ADMIN-CONSENT','MS-MANAGE-APP-PERMISSIONS','MS-GRANT-TENANT-WIDE-CONSENT','MS-APP-LEAST-PRIVILEGE','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        TenantWideConsent = @('MS-PERMISSIONS-CONSENT-OVERVIEW','MS-USER-ADMIN-CONSENT','MS-MANAGE-APP-PERMISSIONS','MS-GRANT-TENANT-WIDE-CONSENT','MS-APP-LEAST-PRIVILEGE','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        DelegatedGrant = @('MS-PERMISSIONS-CONSENT-OVERVIEW','MS-USER-ADMIN-CONSENT','MS-MANAGE-APP-PERMISSIONS','MS-GRANT-TENANT-WIDE-CONSENT','MS-APP-LEAST-PRIVILEGE','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        OAuth2PermissionGrant = @('MS-PERMISSIONS-CONSENT-OVERVIEW','MS-USER-ADMIN-CONSENT','MS-MANAGE-APP-PERMISSIONS','MS-GRANT-TENANT-WIDE-CONSENT','MS-APP-LEAST-PRIVILEGE','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        ServicePrincipalGovernance = @('MS-GOVERN-SERVICE-ACCOUNTS','MS-APP-SERVICE-PRINCIPAL-CONCEPTS','MS-ENTRA-AUTH-OPS-GUIDE','MS-ACCESS-REVIEWS-APP-PREPARATION','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        AssignmentRequiredDisabled = @('MS-GOVERN-SERVICE-ACCOUNTS','MS-APP-SERVICE-PRINCIPAL-CONCEPTS','MS-ENTRA-AUTH-OPS-GUIDE','MS-ACCESS-REVIEWS-APP-PREPARATION','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        SignInEnabled = @('MS-GOVERN-SERVICE-ACCOUNTS','MS-APP-SERVICE-PRINCIPAL-CONCEPTS','MS-ENTRA-AUTH-OPS-GUIDE','MS-ACCESS-REVIEWS-APP-PREPARATION','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        VisibleToUsers = @('MS-GOVERN-SERVICE-ACCOUNTS','MS-APP-SERVICE-PRINCIPAL-CONCEPTS','MS-ENTRA-AUTH-OPS-GUIDE','MS-ACCESS-REVIEWS-APP-PREPARATION','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        DirectoryRoles = @('MS-ENTRA-RBAC-BEST-PRACTICES','MS-PRIVILEGED-ROLES-PERMISSIONS','MS-ENTRA-SECURE-BEST-PRACTICES','MS-ZERO-TRUST-OVERVIEW','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        PrivilegedUser = @('MS-ENTRA-RBAC-BEST-PRACTICES','MS-PRIVILEGED-ROLES-PERMISSIONS','MS-ENTRA-SECURE-BEST-PRACTICES','MS-ZERO-TRUST-OVERVIEW','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        PrivilegedRoleAssignment = @('MS-ENTRA-RBAC-BEST-PRACTICES','MS-PRIVILEGED-ROLES-PERMISSIONS','MS-ENTRA-SECURE-BEST-PRACTICES','MS-ZERO-TRUST-OVERVIEW','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        UserGovernance = @('MS-ENTRA-RBAC-BEST-PRACTICES','MS-PRIVILEGED-ROLES-PERMISSIONS','MS-ZERO-TRUST-OVERVIEW','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        RoleAssignableGroups = @('MS-ROLE-ASSIGNABLE-GROUPS','MS-PIM-FOR-GROUPS','MS-ENTRA-RBAC-BEST-PRACTICES','MS-SECURE-GROUP-ACCESS-CONTROL','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        PrivilegedGroups = @('MS-ROLE-ASSIGNABLE-GROUPS','MS-PIM-FOR-GROUPS','MS-ENTRA-RBAC-BEST-PRACTICES','MS-SECURE-GROUP-ACCESS-CONTROL','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        NestedPrivilegedGroups = @('MS-ROLE-ASSIGNABLE-GROUPS','MS-PIM-FOR-GROUPS','MS-ENTRA-RBAC-BEST-PRACTICES','MS-SECURE-GROUP-ACCESS-CONTROL','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        GroupGovernance = @('MS-ROLE-ASSIGNABLE-GROUPS','MS-PIM-FOR-GROUPS','MS-ENTRA-RBAC-BEST-PRACTICES','MS-SECURE-GROUP-ACCESS-CONTROL','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        ApplicationAccess = @('MS-ACCESS-REVIEWS-DEPLOYMENT','MS-ACCESS-REVIEWS-APP-PREPARATION','MS-SECURE-GROUP-ACCESS-CONTROL','MS-ENTRA-AUTH-OPS-GUIDE','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        AppRoleAssignments = @('MS-ACCESS-REVIEWS-DEPLOYMENT','MS-ACCESS-REVIEWS-APP-PREPARATION','MS-SECURE-GROUP-ACCESS-CONTROL','MS-ENTRA-AUTH-OPS-GUIDE','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        GroupBasedAccess = @('MS-ACCESS-REVIEWS-DEPLOYMENT','MS-ACCESS-REVIEWS-APP-PREPARATION','MS-SECURE-GROUP-ACCESS-CONTROL','MS-ENTRA-AUTH-OPS-GUIDE','NIST-CSF-2-PR-AA','CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT')
        GraphCollection = @('MS-GRAPH-BEST-PRACTICES','MS-GRAPH-THROTTLING')
        RuntimeTelemetry = @('MS-GRAPH-BEST-PRACTICES','MS-GRAPH-THROTTLING')
        Throttling = @('MS-GRAPH-BEST-PRACTICES','MS-GRAPH-THROTTLING')
        UnusedApplication = @('MS-RECOMMEND-REMOVE-UNUSED-APPS','MS-APP-SECURITY-BEST-PRACTICES','CIS-M365-FOUNDATIONS-BENCHMARK')
        ApplicationLifecycle = @('MS-RECOMMEND-REMOVE-UNUSED-APPS','MS-APP-SECURITY-BEST-PRACTICES','CIS-M365-FOUNDATIONS-BENCHMARK')
    }

    foreach ($key in $keys) {
        foreach ($mappingKey in $mapping.Keys) {
            if ($key -like "*$mappingKey*") {
                foreach ($referenceId in @($mapping[$mappingKey])) {
                    $referenceIds.Add($referenceId)
                }
            }
        }
    }

    return @($referenceIds | Select-Object -Unique)
}

function Resolve-InspectorRecommendationReferences {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject
    )

    $referenceIds =
        Resolve-InspectorRecommendationReferenceIds `
            -InputObject $InputObject

    if (@($referenceIds).Count -eq 0) {
        return @()
    }

    $catalog = @(Get-InspectorRecommendationReferenceCatalog)
    $byId = @{}

    foreach ($reference in $catalog) {
        $byId[$reference.ReferenceId] = $reference
    }

    $resolved = [System.Collections.Generic.List[object]]::new()

    foreach ($referenceId in @($referenceIds)) {
        if (-not $byId.ContainsKey($referenceId)) {
            continue
        }

        $reference = $byId[$referenceId]

        $resolved.Add(
            [PSCustomObject][ordered]@{
                ReferenceId = $reference.ReferenceId
                StableId    = $reference.StableId
                Title       = $reference.Title
                SourceType  = $reference.SourceType
                Url         = $reference.Url
                Summary     = $reference.Summary
            }
        )
    }

    return @(
        $resolved |
        Sort-Object `
            @{ Expression = { Get-InspectorRecommendationReferenceSourceOrder -SourceType $_.SourceType } },
            ReferenceId -Unique
    )
}
