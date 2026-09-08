function Resolve-InspectorAssessmentTargets {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][object[]]$TargetSpecification,
        [string[]]$ObjectType = @('Application','ServicePrincipal','User','Group'),
        [AllowNull()][object]$RuntimeTelemetry
    )

    $collections = [ordered]@{ Applications=@(); ServicePrincipals=@(); Users=@(); Groups=@() }
    $evidence = [System.Collections.Generic.List[object]]::new()
    $resolutionRecords = [System.Collections.Generic.List[object]]::new()
    $expectedByCollection = @{ Applications=[System.Collections.Generic.List[string]]::new(); ServicePrincipals=[System.Collections.Generic.List[string]]::new(); Users=[System.Collections.Generic.List[string]]::new(); Groups=[System.Collections.Generic.List[string]]::new() }
    $objectKeys = @{}

    foreach ($spec in @($TargetSpecification)) {
        $identity = [string](Get-InspectorSnapshotProperty -InputObject $spec -Name 'Identity')
        $declaredType = [string](Get-InspectorSnapshotProperty -InputObject $spec -Name 'ObjectType')
        $candidateTypes = if ([string]::IsNullOrWhiteSpace($declaredType)) { @($ObjectType) } else { @($declaredType) }
        $matches = [System.Collections.Generic.List[object]]::new()
        $probeRows = [System.Collections.Generic.List[object]]::new()

        foreach ($candidateType in @($candidateTypes)) {
            $definition = Get-InspectorTargetQueryDefinition -ObjectType $candidateType -Identity $identity
            $result = New-InspectorSnapshotCollectionResult -Name $definition.QueryName -Uri $definition.Uri -RequiredPermission $definition.RequiredPermission -EvidenceScope 'TargetResolution' -SubjectObjectType $candidateType -RuntimeTelemetry $RuntimeTelemetry
            $result.Evidence | Add-Member -NotePropertyName 'RequiredForCoverage' -NotePropertyValue $false -Force
            $evidence.Add($result.Evidence)
            $probeRows.Add([PSCustomObject][ordered]@{ Definition=$definition; Result=$result })
            if ($result.Status -ne 'Success') {
                throw "Target resolution query '$($definition.QueryName)' failed with status '$($result.Status)'."
            }
            foreach ($item in @($result.Items)) {
                $matches.Add([PSCustomObject][ordered]@{ ObjectType=$candidateType; CollectionName=$definition.CollectionName; Item=$item; Evidence=$result.Evidence; QueryName=$definition.QueryName })
            }
        }

        $uniqueMatches = @($matches | Sort-Object ObjectType, { [string](Get-InspectorSnapshotProperty -InputObject $_.Item -Name 'id') } -Unique)
        if ($uniqueMatches.Count -eq 0) { throw "Target '$identity' could not be resolved in the requested object-type scope." }
        if ($uniqueMatches.Count -gt 1) {
            $preview = @($uniqueMatches | ForEach-Object { "$($_.ObjectType):$([string](Get-InspectorSnapshotProperty -InputObject $_.Item -Name 'id'))" }) -join ', '
            throw "Target '$identity' is ambiguous. Exact resolution matched $($uniqueMatches.Count) objects: $preview"
        }

        $winner = $uniqueMatches[0]
        $winner.Evidence | Add-Member -NotePropertyName 'RequiredForCoverage' -NotePropertyValue $true -Force
        $expectedByCollection[$winner.CollectionName].Add([string]$winner.QueryName)
        $rawObject = $winner.Item
        $rawObject | Add-Member -NotePropertyName 'EvidenceId' -NotePropertyValue ([string]$winner.Evidence.EvidenceId) -Force
        $objectId = [string](Get-InspectorSnapshotProperty -InputObject $rawObject -Name 'id')
        $key = "$($winner.ObjectType)|$objectId"
        if (-not $objectKeys.ContainsKey($key)) {
            $objectKeys[$key] = $true
            $collections[$winner.CollectionName] += $rawObject
        }
        $resolutionRecords.Add([PSCustomObject][ordered]@{
            Identity = $identity
            DeclaredObjectType = $declaredType
            ObjectType = $winner.ObjectType
            ObjectId = $objectId
            DisplayName = [string](Get-InspectorSnapshotProperty -InputObject $rawObject -Name 'displayName')
            QueryName = $winner.QueryName
            Status = 'Resolved'
        })
    }

    $summary = [ordered]@{}
    foreach ($entry in @(
        @{Name='Applications';Type='Application'}, @{Name='ServicePrincipals';Type='ServicePrincipal'}, @{Name='Users';Type='User'}, @{Name='Groups';Type='Group'}
    )) {
        $count = @($collections[$entry.Name]).Count
        $summary[$entry.Name] = [PSCustomObject][ordered]@{
            Status = if ($count -gt 0) { 'Success' } else { 'NotRun' }
            Count = $count
            SourceResultCount = $count
            Completeness = if ($count -gt 0) { 'Complete' } else { 'Partial' }
            Truncated = $false
            ExpectedQueries = @($expectedByCollection[$entry.Name])
        }
    }

    $resolvedKeys = @($resolutionRecords | ForEach-Object { "$($_.ObjectType)|$($_.ObjectId)" } | Sort-Object -Unique)
    $resolvedTypes = @($resolutionRecords | ForEach-Object { [string]$_.ObjectType } | Sort-Object -Unique)
    $scopeSignature = Get-InspectorDeterministicToken -Value ("Targeted|$($resolvedTypes -join ',')|$($resolvedKeys -join ',')")

    return [PSCustomObject][ordered]@{
        Collections = [PSCustomObject]$collections
        Evidence = @($evidence)
        CollectionSummary = [PSCustomObject]$summary
        Resolutions = @($resolutionRecords)
        ScopeSignature = $scopeSignature
        ResolvedObjectKeys = @($resolvedKeys)
        ResolvedObjectTypes = @($resolvedTypes)
    }
}

function Get-InspectorTargetedTenantCollections {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][object]$TargetResolution,
        [AllowNull()][object]$RuntimeTelemetry
    )

    $grants = [System.Collections.Generic.List[object]]::new()
    $roles = [System.Collections.Generic.List[object]]::new()
    $evidence = [System.Collections.Generic.List[object]]::new()
    $grantQueries = [System.Collections.Generic.List[string]]::new()
    $roleQueries = [System.Collections.Generic.List[string]]::new()
    $grantIds = @{}
    $roleIds = @{}
    $graphBaseUri = 'https://graph.microsoft.com/v1.0'

    foreach ($sp in @($TargetResolution.Collections.ServicePrincipals)) {
        $id = [string](Get-InspectorSnapshotProperty -InputObject $sp -Name 'id')
        foreach ($field in @('clientId','resourceId')) {
            $queryName = "OAuth2PermissionGrants:${field}:$id"
            $filter = [uri]::EscapeDataString("$field eq '$id'")
            $result = New-InspectorSnapshotCollectionResult -Name $queryName -Uri "$graphBaseUri/oauth2PermissionGrants?`$select=id,clientId,resourceId,principalId,consentType,scope&`$filter=$filter&`$top=999" -RequiredPermission 'Directory.Read.All' -EvidenceScope 'TargetedTenantCollection' -SubjectObjectType 'ServicePrincipal' -SubjectObjectId $id -RuntimeTelemetry $RuntimeTelemetry
            $result.Evidence | Add-Member -NotePropertyName 'RequiredForCoverage' -NotePropertyValue $true -Force
            $evidence.Add($result.Evidence); $grantQueries.Add($queryName)
            foreach ($grant in @($result.Items)) {
                $grant | Add-Member -NotePropertyName 'EvidenceId' -NotePropertyValue $result.Evidence.EvidenceId -Force
                $grantId = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'id')
                if (-not $grantIds.ContainsKey($grantId)) { $grantIds[$grantId]=$true; $grants.Add($grant) }
            }
        }
    }

    $principals = @($TargetResolution.Collections.ServicePrincipals) + @($TargetResolution.Collections.Users) + @($TargetResolution.Collections.Groups)
    foreach ($principal in @($principals)) {
        $id = [string](Get-InspectorSnapshotProperty -InputObject $principal -Name 'id')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $queryName = "DirectoryRoleAssignments:principalId:$id"
        $filter = [uri]::EscapeDataString("principalId eq '$id'")
        $result = New-InspectorSnapshotCollectionResult -Name $queryName -Uri "$graphBaseUri/roleManagement/directory/roleAssignments?`$filter=$filter&`$expand=roleDefinition&`$top=999" -RequiredPermission 'RoleManagement.Read.Directory' -EvidenceScope 'TargetedTenantCollection' -SubjectObjectId $id -RuntimeTelemetry $RuntimeTelemetry
        $result.Evidence | Add-Member -NotePropertyName 'RequiredForCoverage' -NotePropertyValue $true -Force
        $evidence.Add($result.Evidence); $roleQueries.Add($queryName)
        foreach ($role in @($result.Items)) {
            $role | Add-Member -NotePropertyName 'EvidenceId' -NotePropertyValue $result.Evidence.EvidenceId -Force
            $roleId = [string](Get-InspectorSnapshotProperty -InputObject $role -Name 'id')
            if (-not $roleIds.ContainsKey($roleId)) { $roleIds[$roleId]=$true; $roles.Add($role) }
        }
    }

    return [PSCustomObject][ordered]@{
        OAuth2PermissionGrants = @($grants)
        DirectoryRoleAssignments = @($roles)
        Evidence = @($evidence)
        GrantExpectedQueries = @($grantQueries)
        RoleExpectedQueries = @($roleQueries)
    }
}
