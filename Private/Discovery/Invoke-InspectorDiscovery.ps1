function Invoke-InspectorObjectDiscovery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string]$ObjectType,

        [int]$MaxObjects = 0
    )

    $graphBaseUri = 'https://graph.microsoft.com/v1.0'

    $queryMap = @{
        Application = @{
            QueryName = 'DiscoverApplications'
            Uri = "$graphBaseUri/applications?`$select=id,appId,displayName&`$top=999"
            RequiredPermission = 'Application.Read.All'
        }
        ServicePrincipal = @{
            QueryName = 'DiscoverServicePrincipals'
            Uri = "$graphBaseUri/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType&`$top=999"
            RequiredPermission = 'Application.Read.All'
        }
        User = @{
            QueryName = 'DiscoverUsers'
            Uri = "$graphBaseUri/users?`$select=id,userPrincipalName,displayName&`$top=999"
            RequiredPermission = 'User.Read.All'
        }
        Group = @{
            QueryName = 'DiscoverGroups'
            Uri = "$graphBaseUri/groups?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes&`$top=999"
            RequiredPermission = 'GroupMember.Read.All'
        }
    }

    $definition = $queryMap[$ObjectType]

    $graphResult =
        Invoke-InspectorGraphRequest `
            -Uri $definition.Uri `
            -RequiredPermission $definition.RequiredPermission

    $evidence =
        New-InspectorDiscoveryEvidence `
            -QueryName $definition.QueryName `
            -GraphResult $graphResult

    $objects = [System.Collections.Generic.List[object]]::new()
    $limitations = [System.Collections.Generic.List[string]]::new()

    if ($graphResult.Status -ne 'Success') {
        foreach ($limitation in @($graphResult.Limitations)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) {
                $limitations.Add([string]$limitation)
            }
        }

        return [PSCustomObject][ordered]@{
            PSTypeName        = 'EntraObjectInspector.ObjectDiscoveryResult'
            ObjectType        = $ObjectType
            Status            = $graphResult.Status
            DiscoveredObjects = @()
            Evidence          = @($evidence)
            Limitations       = @($limitations)
        }
    }

    $rawObjects = @($graphResult.ObservedValue)

    if ($MaxObjects -gt 0) {
        $rawObjects =
            @(
                $rawObjects |
                Select-Object -First $MaxObjects
            )
    }

    foreach ($item in $rawObjects) {
        if ($null -eq $item) {
            continue
        }

        $id =
            [string](Get-InspectorOrchestrationProperty `
                -InputObject $item `
                -Name 'id')

        if ([string]::IsNullOrWhiteSpace($id)) {
            continue
        }

        $appId =
            [string](Get-InspectorOrchestrationProperty `
                -InputObject $item `
                -Name 'appId')

        $upn =
            [string](Get-InspectorOrchestrationProperty `
                -InputObject $item `
                -Name 'userPrincipalName')

        $displayName =
            [string](Get-InspectorOrchestrationProperty `
                -InputObject $item `
                -Name 'displayName')

        $objects.Add(
            (New-InspectorDiscoveredObject `
                -ObjectType $ObjectType `
                -ObjectId $id `
                -DisplayName $displayName `
                -AppId $appId `
                -UserPrincipalName $upn `
                -DiscoverySource $definition.QueryName `
                -EvidenceId $evidence.EvidenceId)
        )
    }

    return [PSCustomObject][ordered]@{
        PSTypeName        = 'EntraObjectInspector.ObjectDiscoveryResult'
        ObjectType        = $ObjectType
        Status            = 'Success'
        DiscoveredObjects = @(
            $objects |
            Sort-Object ObjectType, ObjectId
        )
        Evidence          = @($evidence)
        Limitations       = @($limitations)
    }
}

function Get-InspectorDiscoveredApplications {
    [CmdletBinding()]
    param (
        [int]$MaxObjects = 0
    )

    Invoke-InspectorObjectDiscovery `
        -ObjectType 'Application' `
        -MaxObjects $MaxObjects
}

function Get-InspectorDiscoveredServicePrincipals {
    [CmdletBinding()]
    param (
        [int]$MaxObjects = 0
    )

    Invoke-InspectorObjectDiscovery `
        -ObjectType 'ServicePrincipal' `
        -MaxObjects $MaxObjects
}

function Get-InspectorDiscoveredUsers {
    [CmdletBinding()]
    param (
        [int]$MaxObjects = 0
    )

    Invoke-InspectorObjectDiscovery `
        -ObjectType 'User' `
        -MaxObjects $MaxObjects
}

function Get-InspectorDiscoveredGroups {
    [CmdletBinding()]
    param (
        [int]$MaxObjects = 0
    )

    Invoke-InspectorObjectDiscovery `
        -ObjectType 'Group' `
        -MaxObjects $MaxObjects
}

function Invoke-InspectorDiscovery {
    [CmdletBinding()]
    param (
        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string[]]$ObjectType = @(
            'Application',
            'ServicePrincipal',
            'User',
            'Group'
        ),

        [int]$MaxObjectsPerType = 0
    )

    $startedAt = (Get-Date).ToUniversalTime().ToString('o')
    $results = [System.Collections.Generic.List[object]]::new()
    $logs = [System.Collections.Generic.List[object]]::new()

    foreach ($type in @($ObjectType | Sort-Object -Unique)) {
        $logs.Add(
            (New-InspectorStructuredLog `
                -Stage 'Discovery' `
                -Level 'Information' `
                -Message "Starting discovery for $type." `
                -Data @{ ObjectType = $type })
        )

        $result = switch ($type) {
            'Application' {
                Get-InspectorDiscoveredApplications `
                    -MaxObjects $MaxObjectsPerType
            }
            'ServicePrincipal' {
                Get-InspectorDiscoveredServicePrincipals `
                    -MaxObjects $MaxObjectsPerType
            }
            'User' {
                Get-InspectorDiscoveredUsers `
                    -MaxObjects $MaxObjectsPerType
            }
            'Group' {
                Get-InspectorDiscoveredGroups `
                    -MaxObjects $MaxObjectsPerType
            }
        }

        $results.Add($result)

        $logs.Add(
            (New-InspectorStructuredLog `
                -Stage 'Discovery' `
                -Level ($(if ($result.Status -eq 'Success') { 'Information' } else { 'Warning' })) `
                -Message "Completed discovery for $type with status $($result.Status)." `
                -Data @{
                    ObjectType = $type
                    Status = $result.Status
                    Count = @($result.DiscoveredObjects).Count
                })
        )
    }

    $discoveredObjects =
        @(
            $results |
            ForEach-Object { @($_.DiscoveredObjects) }
        ) |
        Sort-Object ObjectType, ObjectId

    $evidence =
        @(
            $results |
            ForEach-Object { @($_.Evidence) }
        )

    $limitations =
        @(
            $results |
            ForEach-Object { @($_.Limitations) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Select-Object -Unique
        )

    $statuses = @($results | ForEach-Object { $_.Status })

    $status =
        if (@($statuses | Where-Object { $_ -eq 'Failed' }).Count -gt 0) {
            'Failed'
        }
        elseif (@($statuses | Where-Object {
            $_ -in @('InsufficientPermission', 'Throttled', 'ServiceUnavailable')
        }).Count -gt 0) {
            'Partial'
        }
        else {
            'Success'
        }

    $countsByType = [ordered]@{}

    foreach ($type in @('Application', 'ServicePrincipal', 'User', 'Group')) {
        $countsByType[$type] =
            @($discoveredObjects | Where-Object { $_.ObjectType -eq $type }).Count
    }

    return [PSCustomObject][ordered]@{
        PSTypeName        = 'EntraObjectInspector.DiscoveryResult'
        SchemaVersion     = '0.6.0'
        StartedAt         = $startedAt
        CompletedAt       = (Get-Date).ToUniversalTime().ToString('o')
        Status            = $status
        ObjectTypes        = @($ObjectType | Sort-Object -Unique)
        CountsByType      = [PSCustomObject]$countsByType
        TotalCount         = @($discoveredObjects).Count
        DiscoveredObjects = @($discoveredObjects)
        Evidence          = @($evidence)
        Limitations       = @($limitations)
        Logs              = @($logs)
    }
}
