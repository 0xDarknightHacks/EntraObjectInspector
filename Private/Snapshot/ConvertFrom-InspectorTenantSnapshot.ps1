function New-InspectorTenantSnapshotIndexes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Collections
    )

    $indexes = [ordered]@{
        ApplicationByObjectId = @{}
        ApplicationByAppId = @{}
        ServicePrincipalByObjectId = @{}
        ServicePrincipalByAppId = @{}
        UserByObjectId = @{}
        UserByUserPrincipalName = @{}
        GroupByObjectId = @{}
        OwnersByObjectId = @{}
        MembersByGroupId = @{}
        MembershipsByObjectId = @{}
        AppRoleAssignmentsByPrincipalId = @{}
        AppRoleAssignmentsByResourceId = @{}
        OAuth2PermissionGrantsByClientId = @{}
        OAuth2PermissionGrantsByResourceId = @{}
        DirectoryRoleAssignmentsByPrincipalId = @{}
    }

    foreach ($item in @($Collections.Applications)) {
        Add-InspectorSnapshotIndexValue -Index $indexes.ApplicationByObjectId -Key ([string]$item.id) -Value $item
        Add-InspectorSnapshotIndexValue -Index $indexes.ApplicationByAppId -Key ([string](Get-InspectorSnapshotProperty -InputObject $item -Name 'appId')) -Value $item
    }

    foreach ($item in @($Collections.ServicePrincipals)) {
        Add-InspectorSnapshotIndexValue -Index $indexes.ServicePrincipalByObjectId -Key ([string]$item.id) -Value $item
        Add-InspectorSnapshotIndexValue -Index $indexes.ServicePrincipalByAppId -Key ([string](Get-InspectorSnapshotProperty -InputObject $item -Name 'appId')) -Value $item
    }

    foreach ($item in @($Collections.Users)) {
        Add-InspectorSnapshotIndexValue -Index $indexes.UserByObjectId -Key ([string]$item.id) -Value $item
        Add-InspectorSnapshotIndexValue -Index $indexes.UserByUserPrincipalName -Key ([string]$item.userPrincipalName).ToLowerInvariant() -Value $item
    }

    foreach ($item in @($Collections.Groups)) {
        Add-InspectorSnapshotIndexValue -Index $indexes.GroupByObjectId -Key ([string]$item.id) -Value $item
    }

    foreach ($item in @($Collections.ApplicationOwners + $Collections.ServicePrincipalOwners + $Collections.GroupOwners)) {
        Add-InspectorSnapshotIndexValue -Index $indexes.OwnersByObjectId -Key ([string]$item.SourceObjectId) -Value $item
    }

    foreach ($item in @($Collections.GroupMembers)) {
        Add-InspectorSnapshotIndexValue -Index $indexes.MembersByGroupId -Key ([string]$item.SourceObjectId) -Value $item
    }

    foreach ($item in @($Collections.GroupMemberships + $Collections.UserTransitiveMemberships)) {
        Add-InspectorSnapshotIndexValue -Index $indexes.MembershipsByObjectId -Key ([string]$item.SourceObjectId) -Value $item
    }

    foreach ($item in @($Collections.AppRoleAssignments)) {
        $assignment = Get-InspectorSnapshotProperty -InputObject $item -Name 'Assignment'
        if ($null -eq $assignment) { $assignment = $item }
        Add-InspectorSnapshotIndexValue -Index $indexes.AppRoleAssignmentsByPrincipalId -Key ([string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'principalId')) -Value $item
        Add-InspectorSnapshotIndexValue -Index $indexes.AppRoleAssignmentsByResourceId -Key ([string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'resourceId')) -Value $item
    }

    foreach ($item in @($Collections.AppRoleAssignedTo)) {
        $assignment = Get-InspectorSnapshotProperty -InputObject $item -Name 'Assignment'
        if ($null -eq $assignment) { $assignment = $item }
        Add-InspectorSnapshotIndexValue -Index $indexes.AppRoleAssignmentsByPrincipalId -Key ([string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'principalId')) -Value $item
        Add-InspectorSnapshotIndexValue -Index $indexes.AppRoleAssignmentsByResourceId -Key ([string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'resourceId')) -Value $item
    }

    foreach ($item in @($Collections.OAuth2PermissionGrants)) {
        Add-InspectorSnapshotIndexValue -Index $indexes.OAuth2PermissionGrantsByClientId -Key ([string]$item.clientId) -Value $item
        Add-InspectorSnapshotIndexValue -Index $indexes.OAuth2PermissionGrantsByResourceId -Key ([string]$item.resourceId) -Value $item
    }

    foreach ($item in @($Collections.DirectoryRoleAssignments)) {
        Add-InspectorSnapshotIndexValue -Index $indexes.DirectoryRoleAssignmentsByPrincipalId -Key ([string]$item.principalId) -Value $item
    }

    return [PSCustomObject]$indexes
}

function ConvertFrom-InspectorTenantSnapshot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$TenantSnapshot,

        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string[]]$ObjectType = @('Application', 'ServicePrincipal', 'User', 'Group')
    )

    $discovered = @(
        if ('Application' -in $ObjectType) {
            @($TenantSnapshot.Collections.Applications) | ForEach-Object {
                ConvertTo-InspectorSnapshotDiscoveredObject -ObjectType 'Application' -RawObject $_ -EvidenceId ($TenantSnapshot.Evidence | Where-Object QueryName -eq 'Applications' | Select-Object -First 1).EvidenceId
            }
        }
        if ('ServicePrincipal' -in $ObjectType) {
            @($TenantSnapshot.Collections.ServicePrincipals) | ForEach-Object {
                ConvertTo-InspectorSnapshotDiscoveredObject -ObjectType 'ServicePrincipal' -RawObject $_ -EvidenceId ($TenantSnapshot.Evidence | Where-Object QueryName -eq 'ServicePrincipals' | Select-Object -First 1).EvidenceId
            }
        }
        if ('User' -in $ObjectType) {
            @($TenantSnapshot.Collections.Users) | ForEach-Object {
                ConvertTo-InspectorSnapshotDiscoveredObject -ObjectType 'User' -RawObject $_ -EvidenceId ($TenantSnapshot.Evidence | Where-Object QueryName -eq 'Users' | Select-Object -First 1).EvidenceId
            }
        }
        if ('Group' -in $ObjectType) {
            @($TenantSnapshot.Collections.Groups) | ForEach-Object {
                ConvertTo-InspectorSnapshotDiscoveredObject -ObjectType 'Group' -RawObject $_ -EvidenceId ($TenantSnapshot.Evidence | Where-Object QueryName -eq 'Groups' | Select-Object -First 1).EvidenceId
            }
        }
) | Where-Object { $null -ne $_ } | Sort-Object ObjectType, ObjectId

    $collectionSummary = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'CollectionSummary'
    $requestedCollectionNames = @(
        foreach ($requestedType in @($ObjectType)) {
            switch ($requestedType) {
                'Application'      { 'Applications' }
                'ServicePrincipal' { 'ServicePrincipals' }
                'User'             { 'Users' }
                'Group'            { 'Groups' }
            }
        }
    )
    $requestedCollectionStatuses = @(
        foreach ($collectionName in $requestedCollectionNames) {
            [string](Get-InspectorSnapshotProperty -InputObject (Get-InspectorSnapshotProperty -InputObject $collectionSummary -Name $collectionName) -Name 'Status')
        }
    )

    $assessmentCoverage = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'AssessmentCoverage'
    $coverageStatus = [string](Get-InspectorSnapshotProperty -InputObject $assessmentCoverage -Name 'Status')
    $coverageCompleteness = [string](Get-InspectorSnapshotProperty -InputObject $assessmentCoverage -Name 'Completeness')

    $discoveryStatus =
        if ($coverageStatus -eq 'Failed') {
            'Failed'
        }
        elseif ($coverageStatus -eq 'Partial') {
            'Partial'
        }
        elseif (@($requestedCollectionStatuses | Where-Object { $_ -and $_ -ne 'Success' }).Count -gt 0) {
            'Partial'
        }
        else {
            'Success'
        }

    $discoveryCompleteness =
        if (-not [string]::IsNullOrWhiteSpace($coverageCompleteness)) {
            $coverageCompleteness
        }
        elseif ($discoveryStatus -eq 'Success') {
            'Complete'
        }
        else {
            'Partial'
        }

    return [PSCustomObject][ordered]@{
        PSTypeName        = 'EntraObjectInspector.DiscoveryResult'
        SchemaVersion     = '1.0.0'
        StartedAt         = $TenantSnapshot.CreatedAt
        CompletedAt       = $TenantSnapshot.CreatedAt
        Status            = $discoveryStatus
        Completeness      = $discoveryCompleteness
        ObjectTypes        = @($ObjectType | Sort-Object -Unique)
        CountsByType      = [PSCustomObject][ordered]@{
            Application      = @($discovered | Where-Object ObjectType -eq 'Application').Count
            ServicePrincipal = @($discovered | Where-Object ObjectType -eq 'ServicePrincipal').Count
            User             = @($discovered | Where-Object ObjectType -eq 'User').Count
            Group            = @($discovered | Where-Object ObjectType -eq 'Group').Count
        }
        TotalCount         = @($discovered).Count
        DiscoveredObjects = @($discovered)
        Evidence          = @($TenantSnapshot.Evidence)
        Limitations       = @($TenantSnapshot.Limitations)
        TenantMetadata    = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'TenantMetadata'
        ScopeInventory    = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'ScopeInventory'
        AssessmentCoverage = $assessmentCoverage
        Logs              = @()
    }
}
