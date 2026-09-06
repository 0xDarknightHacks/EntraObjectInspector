function New-InspectorTenantSnapshot {
    [CmdletBinding()]
    param (
        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string[]]$ObjectType = @('Application', 'ServicePrincipal', 'User', 'Group'),

        [int]$MaxObjectsPerType = 0,

        [AllowNull()]
        [object]$RuntimeTelemetry
    )

    $context = Get-MgContext
    $graphBaseUri = 'https://graph.microsoft.com/v1.0'
    $contextScopes = @(
        @(Get-InspectorSnapshotProperty -InputObject $context -Name 'Scopes') |
            ForEach-Object { [string]$_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    $hasMemberReadHidden = 'Member.Read.Hidden' -in $contextScopes
    $collectionMap = [ordered]@{
        Applications = @{ ObjectType = 'Application'; Uri = "$graphBaseUri/applications?`$select=id,appId,displayName,signInAudience,publisherDomain,verifiedPublisher,appRoles,requiredResourceAccess,keyCredentials,passwordCredentials&`$top=999"; Permission = 'Application.Read.All' }
        ServicePrincipals = @{ ObjectType = 'ServicePrincipal'; Uri = "$graphBaseUri/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,tags,appRoles,appOwnerOrganizationId,publisherName,verifiedPublisher,keyCredentials,passwordCredentials&`$top=999"; Permission = 'Application.Read.All' }
        Users = @{ ObjectType = 'User'; Uri = "$graphBaseUri/users?`$select=id,userPrincipalName,displayName,userType,accountEnabled&`$top=999"; Permission = 'User.Read.All' }
        Groups = @{ ObjectType = 'Group'; Uri = "$graphBaseUri/groups?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,visibility,membershipRule,membershipRuleProcessingState&`$top=999"; Permission = 'GroupMember.Read.All' }
        Organization = @{ Uri = "$graphBaseUri/organization?`$select=id,displayName,verifiedDomains&`$top=999"; Permission = 'Organization.Read.All' }
        OAuth2PermissionGrants = @{ Uri = "$graphBaseUri/oauth2PermissionGrants?`$select=id,clientId,resourceId,principalId,consentType,scope&`$top=999"; Permission = 'Directory.Read.All' }
        DirectoryRoleAssignments = @{ Uri = "$graphBaseUri/roleManagement/directory/roleAssignments?`$expand=roleDefinition&`$top=999"; Permission = 'RoleManagement.Read.Directory' }
    }

    $collections = [ordered]@{}
    $evidence = [System.Collections.Generic.List[object]]::new()
    $limitations = [System.Collections.Generic.List[string]]::new()
    $summary = [ordered]@{}
    $truncatedCollections = [System.Collections.Generic.List[string]]::new()

    foreach ($name in $collectionMap.Keys) {
        $definition = $collectionMap[$name]

        if ($definition.ContainsKey('ObjectType') -and $definition.ObjectType -notin @($ObjectType)) {
            $collections[$name] = @()
            $summary[$name] = [PSCustomObject][ordered]@{ Status = 'NotRun'; Count = 0 }
            continue
        }

        $result = New-InspectorSnapshotCollectionResult `
            -Name $name `
            -Uri $definition.Uri `
            -RequiredPermission $definition.Permission `
            -RuntimeTelemetry $RuntimeTelemetry

        $sourceItemCount = @($result.Items).Count
        $items = @($result.Items)
        $isBoundedObjectCollection = $definition.ContainsKey('ObjectType') -and $MaxObjectsPerType -gt 0
        $wasTruncated = $isBoundedObjectCollection -and $sourceItemCount -gt $MaxObjectsPerType

        if ($isBoundedObjectCollection) {
            $items = @($items | Select-Object -First $MaxObjectsPerType)
        }

        if ($wasTruncated) {
            $truncatedCollections.Add($name)
            $boundedLimitation = "Tenant collection '$name' was intentionally truncated to $MaxObjectsPerType of $sourceItemCount collected objects by -MaxObjectsPerType. Negative-state conclusions that require complete tenant collection are disabled for this collection."
            $result.Status = 'Partial'
            $result.Limitations = @((@($result.Limitations) + @($boundedLimitation)) | Select-Object -Unique)
            $result.Evidence.Status = 'Partial'
            $result.Evidence.ResultCount = @($items).Count
            $result.Evidence.Limitations = @((@($result.Evidence.Limitations) + @($boundedLimitation)) | Select-Object -Unique)
            $result.Evidence | Add-Member -NotePropertyName 'Completeness' -NotePropertyValue 'Truncated' -Force
            $result.Evidence | Add-Member -NotePropertyName 'SourceResultCount' -NotePropertyValue $sourceItemCount -Force
        }
        else {
            $evidenceCompleteness = if ($result.Status -eq 'Success') { 'Complete' } else { 'Partial' }
            $result.Evidence | Add-Member -NotePropertyName 'Completeness' -NotePropertyValue $evidenceCompleteness -Force
            $result.Evidence | Add-Member -NotePropertyName 'SourceResultCount' -NotePropertyValue $sourceItemCount -Force
        }

        # Preserve the parent tenant-collection evidence identifier on every
        # collected item. Graph resource objects do not expose EvidenceId; this is
        # Inspector provenance used only by the offline normalization pipeline.
        foreach ($item in @($items)) {
            if ($null -ne $item) {
                $item | Add-Member -NotePropertyName 'EvidenceId' -NotePropertyValue $result.Evidence.EvidenceId -Force
            }
        }

        $collections[$name] = @($items)
        $result.Evidence |
            Add-Member -NotePropertyName 'EvidenceScope' -NotePropertyValue 'TenantCollection' -Force
        $evidence.Add($result.Evidence)
        foreach ($limitation in @($result.Limitations)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) {
                $limitations.Add([string]$limitation)
            }
        }
        $summary[$name] = [PSCustomObject][ordered]@{
            Status            = $result.Status
            Count             = @($items).Count
            SourceResultCount = $sourceItemCount
            Completeness      = $(if ($wasTruncated) { 'Truncated' } elseif ($result.Status -eq 'Success') { 'Complete' } else { 'Partial' })
            Truncated         = [bool]$wasTruncated
        }
    }

    $organization =
        @($collections.Organization) |
        Where-Object { $null -ne $_ } |
        Select-Object -First 1

    $verifiedDomains =
        @(
            Get-InspectorSnapshotProperty `
                -InputObject $organization `
                -Name 'verifiedDomains'
        ) |
        Where-Object { $null -ne $_ }

    $fallbackDomain =
        $verifiedDomains |
        Where-Object {
            (Get-InspectorSnapshotProperty -InputObject $_ -Name 'isDefault') -eq $true -or
            (Get-InspectorSnapshotProperty -InputObject $_ -Name 'isInitial') -eq $true
        } |
        ForEach-Object {
            Get-InspectorSnapshotProperty -InputObject $_ -Name 'name'
        } |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        Select-Object -First 1

    $tenantId =
        [string](Get-InspectorSnapshotProperty -InputObject $organization -Name 'id')

    if ([string]::IsNullOrWhiteSpace($tenantId) -and $context) {
        $tenantId = [string]$context.TenantId
    }

    $tenantDisplayName =
        [string](Get-InspectorSnapshotProperty -InputObject $organization -Name 'displayName')

    if ([string]::IsNullOrWhiteSpace($tenantDisplayName)) {
        $tenantDisplayName = [string]$fallbackDomain
    }

    if ($summary.Organization.Status -ne 'Success') {
        $limitations.Add('Tenant display metadata from /organization was not available; report metadata falls back to the current Graph context when possible.')
    }

    $tenantMetadata = [PSCustomObject][ordered]@{
        TenantId            = $tenantId
        TenantDisplayName   = $tenantDisplayName
        VerifiedDomains     = @($verifiedDomains)
        OrganizationStatus  = $summary.Organization.Status
    }

    # Carry the current tenant identifier into the in-memory snapshot resource
    # envelopes so offline classification can distinguish tenant-owned service
    # principals from external/multitenant instances without additional Graph calls.
    foreach ($resource in @(@($collections.Applications) + @($collections.ServicePrincipals))) {
        if ($null -ne $resource) {
            $resource | Add-Member -NotePropertyName 'InspectorTenantId' -NotePropertyValue $tenantId -Force
        }
    }

    foreach ($name in @(
        'ApplicationOwners','ServicePrincipalOwners','ServicePrincipalGroupMemberships','GroupOwners','GroupMembers',
        'GroupMemberships','UserTransitiveMemberships','AppRoleAssignments',
        'AppRoleAssignedTo','ApplicationCredentials','ServicePrincipalCredentials',
        'RequiredResourceAccess','ExposedAppRoles'
    )) {
        $collections[$name] = @()
        $summary[$name] = [PSCustomObject][ordered]@{ Status = 'Success'; Count = 0 }
    }

    # High-volume independent relationship GETs are transported through
    # Microsoft Graph JSON batching. The batch wrapper still emits one logical
    # Graph result/telemetry record per request, and snapshot evidence is built
    # through the same evidence constructor used by non-batched collection.
    $graphRelationshipBatchSize = 10

    $applicationOwnerRequests = [System.Collections.Generic.List[object]]::new()
    foreach ($application in @($collections.Applications)) {
        $id = [string](Get-InspectorSnapshotProperty -InputObject $application -Name 'id')
        if ([string]::IsNullOrWhiteSpace($id)) {
            continue
        }

        $applicationOwnerRequests.Add([PSCustomObject][ordered]@{
            Name               = "ApplicationOwners:$id"
            Uri                = "$graphBaseUri/applications/${id}/owners?`$select=id,displayName&`$top=999"
            RequiredPermission = 'Application.Read.All'
            EvidenceScope      = 'ObjectRelationship'
            SubjectObjectType  = 'Application'
            SubjectObjectId    = $id
        })
    }

    if ($applicationOwnerRequests.Count -gt 0) {
        foreach ($owners in @(New-InspectorSnapshotBatchCollectionResults -Requests $applicationOwnerRequests.ToArray() -BatchSize $graphRelationshipBatchSize -RuntimeTelemetry $RuntimeTelemetry)) {
            $id = [string](Get-InspectorSnapshotProperty -InputObject (Get-InspectorSnapshotProperty -InputObject $owners -Name 'Request') -Name 'SubjectObjectId')
            $evidence.Add($owners.Evidence)
            foreach ($limitation in @($owners.Limitations)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) { $limitations.Add([string]$limitation) }
            }
            foreach ($owner in @($owners.Items)) {
                $collections['ApplicationOwners'] += [PSCustomObject]@{
                    SourceObjectId = $id
                    Owner = $owner
                    EvidenceId = $owners.Evidence.EvidenceId
                }
            }
        }
    }

    $servicePrincipalRequests = [System.Collections.Generic.List[object]]::new()
    foreach ($servicePrincipal in @($collections.ServicePrincipals)) {
        $id = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'id')
        if ([string]::IsNullOrWhiteSpace($id)) {
            continue
        }

        $servicePrincipalDefinitions = @(
            @{ Name = "ServicePrincipalOwners:$id"; Bucket = 'ServicePrincipalOwners'; Uri = "$graphBaseUri/servicePrincipals/${id}/owners?`$select=id,displayName&`$top=999"; ItemName = 'Owner'; Permission = 'Application.Read.All' },
            @{ Name = "AppRoleAssignments:$id"; Bucket = 'AppRoleAssignments'; Uri = "$graphBaseUri/servicePrincipals/${id}/appRoleAssignments?`$top=999"; ItemName = 'Assignment'; Permission = 'Application.Read.All' },
            @{ Name = "AppRoleAssignedTo:$id"; Bucket = 'AppRoleAssignedTo'; Uri = "$graphBaseUri/servicePrincipals/${id}/appRoleAssignedTo?`$top=999"; ItemName = 'Assignment'; Permission = 'Application.Read.All' }
        )

        if (@($collections.Groups).Count -gt 0) {
            $servicePrincipalDefinitions += @{
                Name       = "ServicePrincipalGroupMemberships:$id"
                Bucket     = 'ServicePrincipalGroupMemberships'
                Uri        = "$graphBaseUri/servicePrincipals/${id}/memberOf"
                ItemName   = 'Membership'
                Permission = 'Application.Read.All'
            }
        }

        foreach ($definition in @($servicePrincipalDefinitions)) {
            $servicePrincipalRequests.Add([PSCustomObject][ordered]@{
                Name               = [string]$definition.Name
                Uri                = [string]$definition.Uri
                RequiredPermission = [string]$definition.Permission
                EvidenceScope      = 'ObjectRelationship'
                SubjectObjectType  = 'ServicePrincipal'
                SubjectObjectId    = $id
                Bucket             = [string]$definition.Bucket
                ItemName           = [string]$definition.ItemName
            })
        }
    }

    if ($servicePrincipalRequests.Count -gt 0) {
        foreach ($result in @(New-InspectorSnapshotBatchCollectionResults -Requests $servicePrincipalRequests.ToArray() -BatchSize $graphRelationshipBatchSize -RuntimeTelemetry $RuntimeTelemetry)) {
            $request = Get-InspectorSnapshotProperty -InputObject $result -Name 'Request'
            $id = [string](Get-InspectorSnapshotProperty -InputObject $request -Name 'SubjectObjectId')
            $bucket = [string](Get-InspectorSnapshotProperty -InputObject $request -Name 'Bucket')
            $itemName = [string](Get-InspectorSnapshotProperty -InputObject $request -Name 'ItemName')

            $evidence.Add($result.Evidence)
            foreach ($limitation in @($result.Limitations)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) { $limitations.Add([string]$limitation) }
            }
            foreach ($item in @($result.Items)) {
                $row = [ordered]@{
                    SourceObjectId = $id
                    EvidenceId = $result.Evidence.EvidenceId
                }
                $row[$itemName] = $item
                $collections[$bucket] += [PSCustomObject]$row
            }
        }
    }

    foreach ($group in @($collections.Groups)) {
        $id = [string](Get-InspectorSnapshotProperty -InputObject $group -Name 'id')
        if ([string]::IsNullOrWhiteSpace($id)) {
            continue
        }

        foreach ($definition in @(
            @{ Name = "GroupOwners:$id"; Bucket = 'GroupOwners'; Uri = "$graphBaseUri/groups/${id}/owners?`$select=id,displayName&`$top=999"; ItemName = 'Owner' },
            @{ Name = "GroupMemberships:$id"; Bucket = 'GroupMemberships'; Uri = "$graphBaseUri/groups/${id}/memberOf?`$select=id,displayName&`$top=999"; ItemName = 'Membership' }
        )) {
            $result = New-InspectorSnapshotCollectionResult `
                -Name $definition.Name `
                -Uri $definition.Uri `
                -RequiredPermission 'GroupMember.Read.All' `
                -EvidenceScope 'ObjectRelationship' `
                -SubjectObjectType 'Group' `
                -SubjectObjectId $id `
                -RuntimeTelemetry $RuntimeTelemetry

            $evidence.Add($result.Evidence)
            foreach ($limitation in @($result.Limitations)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) { $limitations.Add([string]$limitation) }
            }
            foreach ($item in @($result.Items)) {
                $row = [ordered]@{
                    SourceObjectId = $id
                    EvidenceId = $result.Evidence.EvidenceId
                }
                $row[$definition.ItemName] = $item
                $collections[$definition.Bucket] += [PSCustomObject]$row
            }
        }

        $memberQueryName = "GroupMembers:$id"
        $memberUri = "$graphBaseUri/groups/${id}/members?`$select=id,displayName&`$top=999"
        $groupVisibility = [string](Get-InspectorSnapshotProperty -InputObject $group -Name 'visibility')

        if ($groupVisibility -eq 'HiddenMembership' -and -not $hasMemberReadHidden) {
            # Microsoft Graph requires Member.Read.Hidden to enumerate members of
            # hidden-membership groups. Do not issue a query that cannot establish
            # completeness and do not convert an inaccessible/empty response into
            # a false Complete state.
            $hiddenLimitation = "Group '$id' uses HiddenMembership visibility, but the current app-only Graph context does not declare Member.Read.Hidden. Direct member completeness cannot be established."
            $hiddenEvidence = [PSCustomObject][ordered]@{
                PSTypeName         = 'EntraObjectInspector.SnapshotEvidence'
                EvidenceId         = [guid]::NewGuid().ToString()
                QueryName          = $memberQueryName
                Endpoint           = $memberUri
                RequiredPermission = 'GroupMember.Read.All + Member.Read.Hidden'
                CollectionTime     = (Get-Date).ToUniversalTime().ToString('o')
                Status             = 'InsufficientPermission'
                ResultCount        = 0
                Limitations        = @($hiddenLimitation)
                CollectorName      = $memberQueryName
                EvidenceScope      = 'ObjectRelationship'
                SubjectObjectType  = 'Group'
                SubjectObjectId    = $id
                Completeness       = 'Partial'
                SourceResultCount  = 0
            }
            $evidence.Add($hiddenEvidence)
            $limitations.Add($hiddenLimitation)
        }
        else {
            $members = New-InspectorSnapshotCollectionResult `
                -Name $memberQueryName `
                -Uri $memberUri `
                -RequiredPermission $(if ($groupVisibility -eq 'HiddenMembership') { 'GroupMember.Read.All + Member.Read.Hidden' } else { 'GroupMember.Read.All' }) `
                -EvidenceScope 'ObjectRelationship' `
                -SubjectObjectType 'Group' `
                -SubjectObjectId $id `
                -RuntimeTelemetry $RuntimeTelemetry

            $servicePrincipalSummary = $summary.ServicePrincipals
            $servicePrincipalStatus = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipalSummary -Name 'Status')
            $servicePrincipalCompleteness = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipalSummary -Name 'Completeness')
            if ($servicePrincipalStatus -ne 'Success' -or $servicePrincipalCompleteness -ne 'Complete') {
                # The v1.0 group-members endpoint omits service principals. When
                # the service-principal tenant collection is outside scope, failed,
                # or truncated, reverse membership reconstruction cannot establish
                # a complete direct-membership set. Fail closed at the canonical
                # GroupMembers evidence row.
                $servicePrincipalCoverageLimitation = "Group '$id' member completeness cannot be established because the ServicePrincipals tenant collection is not Success/Complete; Microsoft Graph v1.0 group members can omit service principals. Include ServicePrincipal assessment scope and complete that collection."
                $members.Status = 'Partial'
                $members.Limitations = @((@($members.Limitations) + @($servicePrincipalCoverageLimitation)) | Select-Object -Unique)
                $members.Evidence.Status = 'Partial'
                $members.Evidence.Limitations = @((@($members.Evidence.Limitations) + @($servicePrincipalCoverageLimitation)) | Select-Object -Unique)
                $members.Evidence | Add-Member -NotePropertyName 'Completeness' -NotePropertyValue 'Partial' -Force
            }

            $evidence.Add($members.Evidence)
            foreach ($limitation in @($members.Limitations)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) { $limitations.Add([string]$limitation) }
            }
            foreach ($member in @($members.Items)) {
                $collections['GroupMembers'] += [PSCustomObject]@{
                    SourceObjectId = $id
                    Member = $member
                    EvidenceId = $members.Evidence.EvidenceId
                }
            }
        }
    }

    # Microsoft Graph v1.0 currently omits service principals from
    # /groups/{id}/members. Reconstruct those direct memberships through the
    # stable v1.0 /servicePrincipals/{id}/memberOf relationship, then merge them
    # into the canonical GroupMembers bucket without duplicating a member if the
    # forward endpoint behavior changes in the future.
    $groupIdsInScope = @{}
    foreach ($group in @($collections.Groups)) {
        $groupId = [string](Get-InspectorSnapshotProperty -InputObject $group -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($groupId)) { $groupIdsInScope[$groupId] = $true }
    }

    $servicePrincipalsById = @{}
    foreach ($servicePrincipal in @($collections.ServicePrincipals)) {
        $servicePrincipalId = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($servicePrincipalId)) { $servicePrincipalsById[$servicePrincipalId] = $servicePrincipal }
    }

    $groupMemberKeys = @{}
    foreach ($memberRow in @($collections.GroupMembers)) {
        $groupId = [string](Get-InspectorSnapshotProperty -InputObject $memberRow -Name 'SourceObjectId')
        $member = Get-InspectorSnapshotProperty -InputObject $memberRow -Name 'Member'
        $memberId = [string](Get-InspectorSnapshotProperty -InputObject $member -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($groupId) -and -not [string]::IsNullOrWhiteSpace($memberId)) {
            $groupMemberKeys["$groupId|$memberId"] = $true
        }
    }

    foreach ($membershipRow in @($collections.ServicePrincipalGroupMemberships)) {
        $servicePrincipalId = [string](Get-InspectorSnapshotProperty -InputObject $membershipRow -Name 'SourceObjectId')
        $membership = Get-InspectorSnapshotProperty -InputObject $membershipRow -Name 'Membership'
        $groupId = [string](Get-InspectorSnapshotProperty -InputObject $membership -Name 'id')

        if (
            [string]::IsNullOrWhiteSpace($servicePrincipalId) -or
            [string]::IsNullOrWhiteSpace($groupId) -or
            -not $groupIdsInScope.ContainsKey($groupId) -or
            -not $servicePrincipalsById.ContainsKey($servicePrincipalId)
        ) {
            continue
        }

        $memberKey = "$groupId|$servicePrincipalId"
        if ($groupMemberKeys.ContainsKey($memberKey)) {
            continue
        }

        $servicePrincipal = $servicePrincipalsById[$servicePrincipalId]
        $servicePrincipalMember = [PSCustomObject][ordered]@{
            '@odata.type' = '#microsoft.graph.servicePrincipal'
            id            = $servicePrincipalId
            displayName   = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'displayName')
        }

        $collections['GroupMembers'] += [PSCustomObject]@{
            SourceObjectId = $groupId
            Member         = $servicePrincipalMember
            EvidenceId     = [string](Get-InspectorSnapshotProperty -InputObject $membershipRow -Name 'EvidenceId')
        }
        $groupMemberKeys[$memberKey] = $true
    }

    foreach ($user in @($collections.Users)) {
        $id = [string](Get-InspectorSnapshotProperty -InputObject $user -Name 'id')
        if ([string]::IsNullOrWhiteSpace($id)) {
            continue
        }

        $memberships = New-InspectorSnapshotCollectionResult `
            -Name "UserTransitiveMemberships:$id" `
            -Uri "$graphBaseUri/users/${id}/transitiveMemberOf?`$select=id,displayName&`$top=999" `
            -RequiredPermission 'User.Read.All' `
            -EvidenceScope 'ObjectRelationship' `
            -SubjectObjectType 'User' `
            -SubjectObjectId $id `
            -RuntimeTelemetry $RuntimeTelemetry

        $evidence.Add($memberships.Evidence)
        foreach ($limitation in @($memberships.Limitations)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) { $limitations.Add([string]$limitation) }
        }
        foreach ($membership in @($memberships.Items)) {
            $collections['UserTransitiveMemberships'] += [PSCustomObject]@{
                SourceObjectId = $id
                Membership = $membership
                EvidenceId = $memberships.Evidence.EvidenceId
            }
        }
    }

    foreach ($assignment in @($collections.DirectoryRoleAssignments)) {
        $principalId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'principalId')
        if ([string]::IsNullOrWhiteSpace($principalId)) {
            continue
        }

        $collections['DirectoryRoleAssignments'] = @(
            @($collections['DirectoryRoleAssignments']) |
            ForEach-Object { $_ }
        )
    }

    foreach ($application in @($collections.Applications)) {
        $id = [string](Get-InspectorSnapshotProperty -InputObject $application -Name 'id')
        foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $application -Name 'keyCredentials')) {
            $collections['ApplicationCredentials'] += [PSCustomObject]@{ SourceObjectId = $id; CredentialType = 'Certificate'; Credential = $credential }
        }
        foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $application -Name 'passwordCredentials')) {
            $collections['ApplicationCredentials'] += [PSCustomObject]@{ SourceObjectId = $id; CredentialType = 'Password'; Credential = $credential }
        }
        foreach ($access in @(Get-InspectorSnapshotProperty -InputObject $application -Name 'requiredResourceAccess')) {
            $collections['RequiredResourceAccess'] += [PSCustomObject]@{ SourceObjectId = $id; Access = $access }
        }
        foreach ($role in @(Get-InspectorSnapshotProperty -InputObject $application -Name 'appRoles')) {
            $collections['ExposedAppRoles'] += [PSCustomObject]@{ SourceObjectId = $id; AppRole = $role }
        }
    }

    foreach ($servicePrincipal in @($collections.ServicePrincipals)) {
        $id = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'id')
        foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'keyCredentials')) {
            $collections['ServicePrincipalCredentials'] += [PSCustomObject]@{ SourceObjectId = $id; CredentialType = 'Certificate'; Credential = $credential }
        }
        foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'passwordCredentials')) {
            $collections['ServicePrincipalCredentials'] += [PSCustomObject]@{ SourceObjectId = $id; CredentialType = 'Password'; Credential = $credential }
        }
    }

    # Relationship-bucket status is derived from the actual per-object Graph
    # evidence. Never overwrite failed/partial relationship collection with a
    # synthetic Success summary: downstream negative-state logic and release
    # eligibility depend on these statuses being authoritative.
    $relationshipSummaryDefinitions = @(
        [PSCustomObject]@{ Name = 'ApplicationOwners'; Parent = 'Applications'; QueryPrefixes = @('ApplicationOwners:') },
        [PSCustomObject]@{ Name = 'ServicePrincipalOwners'; Parent = 'ServicePrincipals'; QueryPrefixes = @('ServicePrincipalOwners:') },
        [PSCustomObject]@{ Name = 'ServicePrincipalGroupMemberships'; Parent = 'ServicePrincipals'; QueryPrefixes = @('ServicePrincipalGroupMemberships:') },
        [PSCustomObject]@{ Name = 'AppRoleAssignments'; Parent = 'ServicePrincipals'; QueryPrefixes = @('AppRoleAssignments:') },
        [PSCustomObject]@{ Name = 'AppRoleAssignedTo'; Parent = 'ServicePrincipals'; QueryPrefixes = @('AppRoleAssignedTo:') },
        [PSCustomObject]@{ Name = 'GroupOwners'; Parent = 'Groups'; QueryPrefixes = @('GroupOwners:') },
        [PSCustomObject]@{ Name = 'GroupMembers'; Parent = 'Groups'; QueryPrefixes = @('GroupMembers:', 'ServicePrincipalGroupMemberships:') },
        [PSCustomObject]@{ Name = 'GroupMemberships'; Parent = 'Groups'; QueryPrefixes = @('GroupMemberships:') },
        [PSCustomObject]@{ Name = 'UserTransitiveMemberships'; Parent = 'Users'; QueryPrefixes = @('UserTransitiveMemberships:') }
    )

    foreach ($definition in $relationshipSummaryDefinitions) {
        $parentSummary = $summary[$definition.Parent]
        $parentStatus = [string](Get-InspectorSnapshotProperty -InputObject $parentSummary -Name 'Status')
        $parentCompleteness = [string](Get-InspectorSnapshotProperty -InputObject $parentSummary -Name 'Completeness')
        $queryPrefixes = @(Get-InspectorSnapshotProperty -InputObject $definition -Name 'QueryPrefixes')
        $matchingEvidence = @(
            $evidence |
                Where-Object {
                    $queryName = [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'QueryName')
                    $matchesPrefix = $false
                    foreach ($queryPrefix in $queryPrefixes) {
                        if ($queryName -like "$queryPrefix*") {
                            $matchesPrefix = $true
                            break
                        }
                    }
                    $matchesPrefix
                }
        )

        if ($parentStatus -eq 'NotRun') {
            $summary[$definition.Name] = [PSCustomObject][ordered]@{
                Status            = 'NotRun'
                Count             = 0
                Completeness      = 'Partial'
                QueryCount        = 0
                IncompleteQueries = @()
                Statuses          = @('NotRun')
            }
            continue
        }

        $aggregate =
            Get-InspectorSnapshotAggregateState `
                -Evidence $matchingEvidence `
                -FallbackStatus $(if ($parentStatus -eq 'Success') { 'Success' } else { $parentStatus }) `
                -Count @($collections[$definition.Name]).Count `
                -Truncated:($parentCompleteness -eq 'Truncated')

        if ($parentCompleteness -ne 'Complete' -and $aggregate.Status -eq 'Success') {
            $aggregate.Status = 'Partial'
            $aggregate.Completeness = $(if ($parentCompleteness -eq 'Truncated') { 'Truncated' } else { 'Partial' })
        }

        $summary[$definition.Name] = $aggregate
    }

    foreach ($definition in @(
        [PSCustomObject]@{ Name = 'ApplicationCredentials'; Parent = 'Applications' },
        [PSCustomObject]@{ Name = 'RequiredResourceAccess'; Parent = 'Applications' },
        [PSCustomObject]@{ Name = 'ExposedAppRoles'; Parent = 'Applications' },
        [PSCustomObject]@{ Name = 'ServicePrincipalCredentials'; Parent = 'ServicePrincipals' }
    )) {
        $parentSummary = $summary[$definition.Parent]
        $summary[$definition.Name] = [PSCustomObject][ordered]@{
            Status       = [string](Get-InspectorSnapshotProperty -InputObject $parentSummary -Name 'Status')
            Count        = @($collections[$definition.Name]).Count
            Completeness = [string](Get-InspectorSnapshotProperty -InputObject $parentSummary -Name 'Completeness')
            QueryCount   = 0
        }
    }

    $expectedEvidencePlan =
        Get-InspectorSnapshotExpectedEvidencePlan `
            -Collections ([PSCustomObject]$collections) `
            -CollectionSummary ([PSCustomObject]$summary)

    $assessmentCoverage =
        Get-InspectorSnapshotAssessmentCoverage `
            -Evidence @($evidence) `
            -ExpectedQueries @($expectedEvidencePlan.ExpectedQueries)
    $summary['AssessmentCoverage'] = $assessmentCoverage

    if ($assessmentCoverage.Completeness -ne 'Complete') {
        $coveragePreview = @($assessmentCoverage.IncompleteQueries | Select-Object -First 8) -join ', '
        $coverageLimitation = "Assessment evidence coverage is incomplete. Expected/incomplete: $($assessmentCoverage.IncompleteRequiredEvidenceCount); missing: $($assessmentCoverage.MissingExpectedEvidenceCount); unexpected: $($assessmentCoverage.UnexpectedRequiredEvidenceCount); duplicate: $($assessmentCoverage.DuplicateRequiredEvidenceCount). Affected queries: $coveragePreview. Release eligibility must remain false until the expected evidence plan matches and every required collection succeeds completely."
        $limitations.Add($coverageLimitation)
    }

    $indexes = New-InspectorTenantSnapshotIndexes -Collections ([PSCustomObject]$collections)
    $microsoftPublishedServicePrincipals =
        @($collections.ServicePrincipals) |
        Where-Object {
            $candidateClassification =
                Get-InspectorPublisherClassification `
                    -ObjectType 'ServicePrincipal' `
                    -ServicePrincipalType ([string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'servicePrincipalType')) `
                    -AppId ([string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'appId')) `
                    -AppOwnerOrganizationId ([string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'appOwnerOrganizationId')) `
                    -VerifiedPublisher (Get-InspectorSnapshotProperty -InputObject $_ -Name 'verifiedPublisher') `
                    -InspectorTenantId ([string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'InspectorTenantId'))

            $candidateClassification -eq 'MicrosoftPublished'
        }

    $scopeInventory = [PSCustomObject][ordered]@{
        UsersDiscovered                    = @($collections.Users).Count
        AppRegistrationsDiscovered         = @($collections.Applications).Count
        ServicePrincipalsDiscovered        = @($collections.ServicePrincipals).Count
        GroupsDiscovered                   = @($collections.Groups).Count
        OAuth2PermissionGrantsDiscovered   = @($collections.OAuth2PermissionGrants).Count
        DirectoryRoleAssignmentsDiscovered = @($collections.DirectoryRoleAssignments).Count
        EvidenceRecordsCollected           = @($evidence).Count
        FailedObjects                      = 0
        MicrosoftPublishedServicePrincipals = @($microsoftPublishedServicePrincipals).Count
        FirstPartyClassificationConfidence = $(if (@($collections.ServicePrincipals).Count -gt 0) { 'ConservativeMetadata' } else { 'NotClassified' })
        FirstPartyClassificationMethod     = 'Central publisher classification using Microsoft owner-tenant IDs, a narrow Microsoft-documented exact AppId fallback, and collected Graph publisher metadata; display-name strings are not classification proof.'
        BoundedRun                         = ($MaxObjectsPerType -gt 0)
        MaxObjectsPerType                  = $MaxObjectsPerType
        TruncatedCollections               = @($truncatedCollections)
        CollectionCompleteness             = $assessmentCoverage.Completeness
        AssessmentCoverageStatus           = $assessmentCoverage.Status
        AssessmentCoverageCompleteness     = $assessmentCoverage.Completeness
        EvidencePlanMatches                = $assessmentCoverage.EvidencePlanMatches
        ExpectedEvidenceCount               = $assessmentCoverage.ExpectedEvidenceCount
        ActualRequiredEvidenceCount         = $assessmentCoverage.ActualRequiredEvidenceCount
        RequiredEvidenceCount               = $assessmentCoverage.RequiredEvidenceCount
        SuccessfulRequiredEvidenceCount     = $assessmentCoverage.SuccessfulRequiredEvidenceCount
        IncompleteRequiredEvidenceCount     = $assessmentCoverage.IncompleteRequiredEvidenceCount
        MissingExpectedEvidenceCount        = $assessmentCoverage.MissingExpectedEvidenceCount
        UnexpectedRequiredEvidenceCount     = $assessmentCoverage.UnexpectedRequiredEvidenceCount
        DuplicateRequiredEvidenceCount      = $assessmentCoverage.DuplicateRequiredEvidenceCount
        IncompleteRequiredQueries           = @($assessmentCoverage.IncompleteQueries)
    }

    return [PSCustomObject][ordered]@{
        PSTypeName                      = 'EntraObjectInspector.TenantSnapshot'
        SchemaVersion                   = '1.0.0'
        SnapshotId                      = [guid]::NewGuid().ToString()
        CreatedAt                       = (Get-Date).ToUniversalTime().ToString('o')
        CollectionMode                  = 'GraphIngestionOnly'
        PersistenceMode                 = 'InMemoryTemporary'
        GraphCallsAllowedAfterSnapshot  = $false
        SourceTenantId                  = if ($context) { $context.TenantId } else { $null }
        SourceClientId                  = if ($context) { $context.ClientId } else { $null }
        Collections                     = [PSCustomObject]$collections
        Indexes                         = $indexes
        CollectionSummary               = [PSCustomObject]$summary
        AssessmentCoverage              = $assessmentCoverage
        TenantMetadata                  = $tenantMetadata
        ScopeInventory                  = $scopeInventory
        Evidence                        = @($evidence)
        Limitations                     = @($limitations | Select-Object -Unique)
        RuntimeTelemetry                = $RuntimeTelemetry
    }
}
