function New-InspectorTenantSnapshot {
    [CmdletBinding()]
    param (
        [ValidateSet('Application', 'ServicePrincipal', 'User', 'Group')]
        [string[]]$ObjectType = @('Application', 'ServicePrincipal', 'User', 'Group'),

        [int]$MaxObjectsPerType = 0,

        [object[]]$TargetSpecification = @(),

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
        ServicePrincipals = @{ ObjectType = 'ServicePrincipal'; Uri = "$graphBaseUri/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,tags,appRoles,appOwnerOrganizationId,publisherName,verifiedPublisher,keyCredentials,passwordCredentials&`$top=100"; Permission = 'Application.Read.All' }
        Users = @{ ObjectType = 'User'; Uri = "$graphBaseUri/users?`$select=id,userPrincipalName,displayName,userType,accountEnabled&`$top=999"; Permission = 'User.Read.All' }
        Groups = @{ ObjectType = 'Group'; Uri = "$graphBaseUri/groups?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,visibility,membershipRule,membershipRuleProcessingState,onPremisesSyncEnabled&`$top=999"; Permission = 'GroupMember.Read.All' }
        Organization = @{ Uri = "$graphBaseUri/organization?`$select=id,displayName,verifiedDomains"; Permission = 'Organization.Read.All' }
        SubscribedSkus = @{ Uri = "$graphBaseUri/subscribedSkus?`$select=id,skuId,skuPartNumber,capabilityStatus,servicePlans"; Permission = 'LicenseAssignment.Read.All (least privileged), Directory.Read.All, or Organization.Read.All'; RequiredForCoverage = $false }
        OAuth2PermissionGrants = @{ Uri = "$graphBaseUri/oauth2PermissionGrants?`$top=999"; Permission = 'Directory.Read.All' }
        DirectoryRoleDefinitions = @{ Uri = "$graphBaseUri/roleManagement/directory/roleDefinitions"; Permission = 'RoleManagement.Read.Directory' }
        DirectoryRoleAssignments = @{ Uri = "$graphBaseUri/roleManagement/directory/roleAssignments?`$expand=roleDefinition"; Permission = 'RoleManagement.Read.Directory' }
        RoleAssignmentScheduleInstances = @{ Uri = "$graphBaseUri/roleManagement/directory/roleAssignmentScheduleInstances"; Permission = 'RoleAssignmentSchedule.Read.Directory' }
        RoleEligibilityScheduleInstances = @{ Uri = "$graphBaseUri/roleManagement/directory/roleEligibilityScheduleInstances"; Permission = 'RoleEligibilitySchedule.Read.Directory' }
        AdministrativeUnits = @{ Uri = "$graphBaseUri/directory/administrativeUnits?`$select=id,displayName,description,visibility,isMemberManagementRestricted,membershipType,membershipRule,membershipRuleProcessingState"; Permission = 'AdministrativeUnit.Read.All' }
        RiskyUsers = @{ Uri = "$graphBaseUri/identityProtection/riskyUsers?`$select=id,userPrincipalName,riskLevel,riskState,riskDetail,riskLastUpdatedDateTime,isDeleted,isProcessing&`$top=500"; Permission = 'IdentityRiskyUser.Read.All' }
    }

    $collections = [ordered]@{}
    $evidence = [System.Collections.Generic.List[object]]::new()
    $limitations = [System.Collections.Generic.List[string]]::new()
    $summary = [ordered]@{}
    $truncatedCollections = [System.Collections.Generic.List[string]]::new()
    $targetedMode = @($TargetSpecification | Where-Object { $null -ne $_ }).Count -gt 0
    $targetResolution = $null
    $targetedTenantCollections = $null
    $tenantLicenseProfile = Get-InspectorTenantLicenseCapabilityProfile

    if ($targetedMode) {
        $targetResolution = Resolve-InspectorAssessmentTargets -TargetSpecification $TargetSpecification -ObjectType $ObjectType -RuntimeTelemetry $RuntimeTelemetry
        foreach ($targetEvidence in @($targetResolution.Evidence)) { $evidence.Add($targetEvidence) }
        $targetedTenantCollections = Get-InspectorTargetedTenantCollections -TargetResolution $targetResolution -RuntimeTelemetry $RuntimeTelemetry
        foreach ($targetEvidence in @($targetedTenantCollections.Evidence)) { $evidence.Add($targetEvidence) }
    }

    foreach ($name in $collectionMap.Keys) {
        $definition = $collectionMap[$name]

        if ($targetedMode -and $definition.ContainsKey('ObjectType')) {
            $targetItems = @(Get-InspectorSnapshotProperty -InputObject $targetResolution.Collections -Name $name)
            $targetSummary = Get-InspectorSnapshotProperty -InputObject $targetResolution.CollectionSummary -Name $name
            $collections[$name] = @($targetItems)
            $summary[$name] = $targetSummary
            continue
        }

        if ($targetedMode -and $name -eq 'OAuth2PermissionGrants') {
            $targetItems = @($targetedTenantCollections.OAuth2PermissionGrants)
            $expectedQueries = @($targetedTenantCollections.GrantExpectedQueries)
            $collections[$name] = @($targetItems)
            $summary[$name] = [PSCustomObject][ordered]@{ Status=$(if($expectedQueries.Count -gt 0){'Success'}else{'NotRun'}); Count=$targetItems.Count; SourceResultCount=$targetItems.Count; Completeness=$(if($expectedQueries.Count -gt 0){'Complete'}else{'Partial'}); Truncated=$false; ExpectedQueries=@($expectedQueries) }
            continue
        }

        if ($targetedMode -and $name -eq 'DirectoryRoleAssignments') {
            $targetItems = @($targetedTenantCollections.DirectoryRoleAssignments)
            $expectedQueries = @($targetedTenantCollections.RoleExpectedQueries)
            $collections[$name] = @($targetItems)
            $summary[$name] = [PSCustomObject][ordered]@{ Status=$(if($expectedQueries.Count -gt 0){'Success'}else{'NotRun'}); Count=$targetItems.Count; SourceResultCount=$targetItems.Count; Completeness=$(if($expectedQueries.Count -gt 0){'Complete'}else{'Partial'}); Truncated=$false; ExpectedQueries=@($expectedQueries) }
            continue
        }

        if ($targetedMode -and $name -in @('SubscribedSkus','DirectoryRoleDefinitions','RoleAssignmentScheduleInstances','RoleEligibilityScheduleInstances','AdministrativeUnits','RiskyUsers')) {
            $collections[$name] = @()
            $summary[$name] = [PSCustomObject][ordered]@{
                Status       = 'NotRun'
                Count        = 0
                Completeness = 'Partial'
                Truncated    = $false
                Limitations  = @("Tenant-wide privileged identity context collection '$name' is not run during targeted assessments.")
            }
            continue
        }

        if ($definition.ContainsKey('ObjectType') -and $definition.ObjectType -notin @($ObjectType)) {
            $collections[$name] = @()
            $summary[$name] = [PSCustomObject][ordered]@{ Status = 'NotRun'; Count = 0 }
            continue
        }

        $licenseCapability = $null
        if (-not $targetedMode -and $name -in @('RoleAssignmentScheduleInstances', 'RoleEligibilityScheduleInstances')) {
            $licenseCapability = Get-InspectorSnapshotProperty -InputObject $tenantLicenseProfile -Name 'PrivilegedIdentityManagement'
        }
        elseif (-not $targetedMode -and $name -eq 'RiskyUsers') {
            $licenseCapability = Get-InspectorSnapshotProperty -InputObject $tenantLicenseProfile -Name 'IdentityProtectionRiskyUsers'
        }

        if ($null -ne $licenseCapability -and [string](Get-InspectorSnapshotProperty -InputObject $licenseCapability -Name 'Status') -eq 'NotLicensed') {
            $result =
                New-InspectorSnapshotLicenseUnavailableCollectionResult `
                    -Name $name `
                    -Uri $definition.Uri `
                    -RequiredPermission $definition.Permission `
                    -CapabilityName $(if ($name -eq 'RiskyUsers') { 'Microsoft Entra ID Protection risky-user Graph access' } else { 'Microsoft Entra Privileged Identity Management' }) `
                    -LicenseRequirement ([string](Get-InspectorSnapshotProperty -InputObject $licenseCapability -Name 'Requirement'))
        }
        else {
            $result =
                New-InspectorSnapshotCollectionResult `
                    -Name $name `
                    -Uri $definition.Uri `
                    -RequiredPermission $definition.Permission `
                    -RuntimeTelemetry $RuntimeTelemetry
        }

        if ($definition.ContainsKey('RequiredForCoverage')) {
            $result.Evidence |
                Add-Member -NotePropertyName 'RequiredForCoverage' -NotePropertyValue ([bool]$definition.RequiredForCoverage) -Force
        }

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

        if ($name -eq 'SubscribedSkus') {
            $tenantLicenseProfile =
                Get-InspectorTenantLicenseCapabilityProfile `
                    -SubscribedSkus @($items) `
                    -InventoryStatus ([string]$result.Status) `
                    -InventoryLimitations @($result.Limitations) `
                    -Evaluated

            if ($result.Status -ne 'Success') {
                $limitations.Add(
                    'Tenant license capability inventory from /subscribedSkus was unavailable. PIM and Identity Protection license prevalidation is therefore unknown; their feature endpoint evidence remains authoritative.'
                )
            }
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
        LicenseValidation    = $tenantLicenseProfile
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
        'ApplicationOwners','ServicePrincipalOwners','ServicePrincipalOwnedObjects','ServicePrincipalGroupMemberships','GroupOwners','GroupMembers',
        'GroupMemberships','UserTransitiveMemberships','AppRoleAssignments',
        'AppRoleAssignedTo','ApplicationCredentials','ServicePrincipalCredentials',
        'RequiredResourceAccess','ExposedAppRoles','AdministrativeUnitMembers','AdministrativeUnitScopedRoleMembers'
    )) {
        $collections[$name] = @()
        $summary[$name] = [PSCustomObject][ordered]@{ Status = 'Success'; Count = 0 }
    }

    foreach ($administrativeUnit in @($collections.AdministrativeUnits)) {
        $auId = [string](Get-InspectorSnapshotProperty -InputObject $administrativeUnit -Name 'id')
        if ([string]::IsNullOrWhiteSpace($auId)) { continue }

        $auVisibility = [string](Get-InspectorSnapshotProperty -InputObject $administrativeUnit -Name 'visibility')
        $memberQueryName = "AdministrativeUnitMembers:$auId"
        $memberUri = "$graphBaseUri/directory/administrativeUnits/${auId}/members?`$top=999"
        if ($auVisibility -eq 'HiddenMembership' -and -not $hasMemberReadHidden) {
            $hiddenLimitation = "Administrative unit '$auId' uses HiddenMembership visibility, but the current app-only Graph context does not declare Member.Read.Hidden. Member completeness cannot be established."
            $hiddenEvidence = [PSCustomObject][ordered]@{
                PSTypeName         = 'EntraObjectInspector.SnapshotEvidence'
                EvidenceId         = [guid]::NewGuid().ToString()
                QueryName          = $memberQueryName
                Endpoint           = $memberUri
                RequiredPermission = 'AdministrativeUnit.Read.All + Member.Read.Hidden'
                CollectionTime     = (Get-Date).ToUniversalTime().ToString('o')
                Status             = 'InsufficientPermission'
                ResultCount        = 0
                Limitations        = @($hiddenLimitation)
                CollectorName      = $memberQueryName
                EvidenceScope      = 'TenantCollection'
                SubjectObjectType  = 'AdministrativeUnit'
                SubjectObjectId    = $auId
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
                -RequiredPermission $(if ($auVisibility -eq 'HiddenMembership') { 'AdministrativeUnit.Read.All + Member.Read.Hidden' } else { 'AdministrativeUnit.Read.All' }) `
                -EvidenceScope 'TenantCollection' `
                -SubjectObjectType 'AdministrativeUnit' `
                -SubjectObjectId $auId `
                -RuntimeTelemetry $RuntimeTelemetry
            $evidence.Add($members.Evidence)
            foreach ($limitation in @($members.Limitations)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) { $limitations.Add([string]$limitation) }
            }
            foreach ($member in @($members.Items)) {
                $collections['AdministrativeUnitMembers'] += [PSCustomObject]@{
                    AdministrativeUnitId = $auId
                    Member = $member
                    EvidenceId = $members.Evidence.EvidenceId
                }
            }
        }

    }

    foreach ($definition in @(
        [PSCustomObject]@{ Name = 'AdministrativeUnitMembers'; QueryPrefix = 'AdministrativeUnitMembers:' }
    )) {
        $matchingEvidence = @(
            $evidence |
                Where-Object {
                    [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'QueryName') -like "$($definition.QueryPrefix)*"
                }
        )
        $summary[$definition.Name] =
            Get-InspectorSnapshotAggregateState `
                -Evidence $matchingEvidence `
                -FallbackStatus $(if (@($collections.AdministrativeUnits).Count -gt 0) { 'Success' } else { [string](Get-InspectorSnapshotProperty -InputObject $summary.AdministrativeUnits -Name 'Status') }) `
                -Count @($collections[$definition.Name]).Count
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
            @{ Name = "ServicePrincipalOwnedObjects:$id"; Bucket = 'ServicePrincipalOwnedObjects'; Uri = "$graphBaseUri/servicePrincipals/${id}/ownedObjects?`$select=id,displayName&`$top=999"; ItemName = 'OwnedObject'; Permission = 'Application.Read.All' },
            @{ Name = "AppRoleAssignments:$id"; Bucket = 'AppRoleAssignments'; Uri = "$graphBaseUri/servicePrincipals/${id}/appRoleAssignments?`$top=999"; ItemName = 'Assignment'; Permission = 'Application.Read.All' },
            @{ Name = "AppRoleAssignedTo:$id"; Bucket = 'AppRoleAssignedTo'; Uri = "$graphBaseUri/servicePrincipals/${id}/appRoleAssignedTo"; ItemName = 'Assignment'; Permission = 'Application.Read.All' }
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

    if (@($collections.ServicePrincipals).Count -gt 0) {
        $summary['ServicePrincipalOwnedObjects'] =
            Get-InspectorSnapshotAggregateState `
                -Evidence @($evidence | Where-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'QueryName') -like 'ServicePrincipalOwnedObjects:*' }) `
                -FallbackStatus 'Success' `
                -Count @($collections.ServicePrincipalOwnedObjects).Count
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

        $ownerEvidence = @($evidence | Where-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'QueryName') -eq "GroupOwners:$id" } | Select-Object -First 1)
        $groupTypes = @(Get-InspectorSnapshotProperty -InputObject $group -Name 'groupTypes')
        $isExchangeManagedMailGroup =
            (Get-InspectorSnapshotProperty -InputObject $group -Name 'mailEnabled') -eq $true -and
            'Unified' -notin $groupTypes
        $isOnPremisesSynchronized =
            (Get-InspectorSnapshotProperty -InputObject $group -Name 'onPremisesSyncEnabled') -eq $true
        $servicePrincipalSummary = $summary.ServicePrincipals
        $servicePrincipalOwnedObjectSummary = $summary.ServicePrincipalOwnedObjects
        $servicePrincipalStatus = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipalSummary -Name 'Status')
        $servicePrincipalCompleteness = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipalSummary -Name 'Completeness')
        $servicePrincipalOwnedObjectCompleteness = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipalOwnedObjectSummary -Name 'Completeness')
        $ownerCompletenessLimitations = [System.Collections.Generic.List[string]]::new()

        if ($targetedMode -or $servicePrincipalStatus -ne 'Success' -or $servicePrincipalCompleteness -ne 'Complete' -or $servicePrincipalOwnedObjectCompleteness -ne 'Complete') {
            $ownerCompletenessLimitations.Add("Group '$id' owner completeness cannot be established because Microsoft Graph v1.0 /groups/{id}/owners can omit service-principal owners and the service-principal ownedObjects corpus is not tenant-complete.")
        }
        if ($isExchangeManagedMailGroup) {
            $ownerCompletenessLimitations.Add("Group '$id' is a non-Unified mail-enabled group (distribution or mail-enabled security group); Microsoft documents that owners are not available through /groups/{id}/owners for Exchange-created groups.")
        }
        if ($isOnPremisesSynchronized) {
            $ownerCompletenessLimitations.Add("Group '$id' appears to be synchronized from on-premises; Microsoft documents that owners are not available through /groups/{id}/owners for on-premises-synchronized groups.")
        }

        if ($ownerEvidence.Count -gt 0 -and $ownerCompletenessLimitations.Count -gt 0) {
            $ownerEvidence[0].Status = 'Partial'
            $ownerEvidence[0].Limitations = @((@($ownerEvidence[0].Limitations) + @($ownerCompletenessLimitations)) | Select-Object -Unique)
            $ownerEvidence[0] | Add-Member -NotePropertyName 'Completeness' -NotePropertyValue 'Partial' -Force
            foreach ($ownerLimitation in @($ownerCompletenessLimitations)) {
                if (-not [string]::IsNullOrWhiteSpace($ownerLimitation)) { $limitations.Add($ownerLimitation) }
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
            if ($targetedMode -or $servicePrincipalStatus -ne 'Success' -or $servicePrincipalCompleteness -ne 'Complete') {
                # The v1.0 group-members endpoint can omit service principals. A
                # targeted service-principal collection is intentionally not a
                # tenant-complete corpus, so even a successful targeted collection
                # cannot prove that all service-principal group members were seen.
                # Fail closed at the canonical GroupMembers evidence row.
                $servicePrincipalCoverageLimitation = if ($targetedMode) {
                    "Group '$id' member completeness cannot be established during a targeted assessment because the ServicePrincipals collection is scope-limited; Microsoft Graph v1.0 group members can omit service principals."
                }
                else {
                    "Group '$id' member completeness cannot be established because the ServicePrincipals tenant collection is not Success/Complete; Microsoft Graph v1.0 group members can omit service principals. Include ServicePrincipal assessment scope and complete that collection."
                }
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

    $groupOwnerKeys = @{}
    foreach ($ownerRow in @($collections.GroupOwners)) {
        $groupId = [string](Get-InspectorSnapshotProperty -InputObject $ownerRow -Name 'SourceObjectId')
        $owner = Get-InspectorSnapshotProperty -InputObject $ownerRow -Name 'Owner'
        $ownerId = [string](Get-InspectorSnapshotProperty -InputObject $owner -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($groupId) -and -not [string]::IsNullOrWhiteSpace($ownerId)) {
            $groupOwnerKeys["$groupId|$ownerId"] = $true
        }
    }

    foreach ($ownedObjectRow in @($collections.ServicePrincipalOwnedObjects)) {
        $servicePrincipalId = [string](Get-InspectorSnapshotProperty -InputObject $ownedObjectRow -Name 'SourceObjectId')
        $ownedObject = Get-InspectorSnapshotProperty -InputObject $ownedObjectRow -Name 'OwnedObject'
        $ownedObjectId = [string](Get-InspectorSnapshotProperty -InputObject $ownedObject -Name 'id')
        $ownedObjectType = Get-InspectorDirectoryObjectTypeName -InputObject $ownedObject

        if (
            [string]::IsNullOrWhiteSpace($servicePrincipalId) -or
            [string]::IsNullOrWhiteSpace($ownedObjectId) -or
            $ownedObjectType -ne 'group' -or
            -not $groupIdsInScope.ContainsKey($ownedObjectId) -or
            -not $servicePrincipalsById.ContainsKey($servicePrincipalId)
        ) {
            continue
        }

        $ownerKey = "$ownedObjectId|$servicePrincipalId"
        if ($groupOwnerKeys.ContainsKey($ownerKey)) {
            continue
        }

        $servicePrincipal = $servicePrincipalsById[$servicePrincipalId]
        $servicePrincipalOwner = [PSCustomObject][ordered]@{
            '@odata.type' = '#microsoft.graph.servicePrincipal'
            id            = $servicePrincipalId
            displayName   = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'displayName')
        }

        $collections['GroupOwners'] += [PSCustomObject]@{
            SourceObjectId = $ownedObjectId
            Owner          = $servicePrincipalOwner
            EvidenceId     = [string](Get-InspectorSnapshotProperty -InputObject $ownedObjectRow -Name 'EvidenceId')
        }
        $groupOwnerKeys[$ownerKey] = $true
    }

    $dedupedGroupOwners = [System.Collections.Generic.List[object]]::new()
    $dedupedGroupOwnerKeys = @{}
    foreach ($ownerRow in @($collections.GroupOwners | Sort-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'SourceObjectId') }, { [string](Get-InspectorSnapshotProperty -InputObject (Get-InspectorSnapshotProperty -InputObject $_ -Name 'Owner') -Name 'id') }, { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'EvidenceId') })) {
        $groupId = [string](Get-InspectorSnapshotProperty -InputObject $ownerRow -Name 'SourceObjectId')
        $owner = Get-InspectorSnapshotProperty -InputObject $ownerRow -Name 'Owner'
        $ownerId = [string](Get-InspectorSnapshotProperty -InputObject $owner -Name 'id')
        $key = "$groupId|$ownerId"
        if ([string]::IsNullOrWhiteSpace($groupId) -or [string]::IsNullOrWhiteSpace($ownerId) -or $dedupedGroupOwnerKeys.ContainsKey($key)) {
            continue
        }
        $dedupedGroupOwnerKeys[$key] = $true
        $dedupedGroupOwners.Add($ownerRow)
    }
    $collections['GroupOwners'] = @($dedupedGroupOwners)

    # Microsoft Graph v1.0 currently omits service principals from
    # /groups/{id}/members. Reconstruct those direct memberships through the
    # stable v1.0 /servicePrincipals/{id}/memberOf relationship, then merge them
    # into the canonical GroupMembers bucket without duplicating a member if the
    # forward endpoint behavior changes in the future.
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
            $collections['ApplicationCredentials'] += [PSCustomObject]@{ SourceObjectId = $id; CredentialType = 'Certificate'; Credential = $credential; EvidenceId = (Get-InspectorSnapshotProperty -InputObject $application -Name 'EvidenceId') }
        }
        foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $application -Name 'passwordCredentials')) {
            $collections['ApplicationCredentials'] += [PSCustomObject]@{ SourceObjectId = $id; CredentialType = 'Password'; Credential = $credential; EvidenceId = (Get-InspectorSnapshotProperty -InputObject $application -Name 'EvidenceId') }
        }
        foreach ($access in @(Get-InspectorSnapshotProperty -InputObject $application -Name 'requiredResourceAccess')) {
            $collections['RequiredResourceAccess'] += [PSCustomObject]@{ SourceObjectId = $id; Access = $access; EvidenceId = (Get-InspectorSnapshotProperty -InputObject $application -Name 'EvidenceId') }
        }
        foreach ($role in @(Get-InspectorSnapshotProperty -InputObject $application -Name 'appRoles')) {
            $collections['ExposedAppRoles'] += [PSCustomObject]@{ SourceObjectId = $id; AppRole = $role }
        }
    }

    foreach ($servicePrincipal in @($collections.ServicePrincipals)) {
        $id = [string](Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'id')
        foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'keyCredentials')) {
            $collections['ServicePrincipalCredentials'] += [PSCustomObject]@{ SourceObjectId = $id; CredentialType = 'Certificate'; Credential = $credential; EvidenceId = (Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'EvidenceId') }
        }
        foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'passwordCredentials')) {
            $collections['ServicePrincipalCredentials'] += [PSCustomObject]@{ SourceObjectId = $id; CredentialType = 'Password'; Credential = $credential; EvidenceId = (Get-InspectorSnapshotProperty -InputObject $servicePrincipal -Name 'EvidenceId') }
        }
    }

    # Relationship-bucket status is derived from the actual per-object Graph
    # evidence. Never overwrite failed/partial relationship collection with a
    # synthetic Success summary: downstream negative-state logic and release
    # eligibility depend on these statuses being authoritative.
    $relationshipSummaryDefinitions = @(
        [PSCustomObject]@{ Name = 'ApplicationOwners'; Parent = 'Applications'; QueryPrefixes = @('ApplicationOwners:') },
        [PSCustomObject]@{ Name = 'ServicePrincipalOwners'; Parent = 'ServicePrincipals'; QueryPrefixes = @('ServicePrincipalOwners:') },
        [PSCustomObject]@{ Name = 'ServicePrincipalOwnedObjects'; Parent = 'ServicePrincipals'; QueryPrefixes = @('ServicePrincipalOwnedObjects:') },
        [PSCustomObject]@{ Name = 'ServicePrincipalGroupMemberships'; Parent = 'ServicePrincipals'; QueryPrefixes = @('ServicePrincipalGroupMemberships:') },
        [PSCustomObject]@{ Name = 'AppRoleAssignments'; Parent = 'ServicePrincipals'; QueryPrefixes = @('AppRoleAssignments:') },
        [PSCustomObject]@{ Name = 'AppRoleAssignedTo'; Parent = 'ServicePrincipals'; QueryPrefixes = @('AppRoleAssignedTo:') },
        [PSCustomObject]@{ Name = 'GroupOwners'; Parent = 'Groups'; QueryPrefixes = @('GroupOwners:', 'ServicePrincipalOwnedObjects:') },
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

    $indexes = New-InspectorTenantSnapshotIndexes -Collections ([PSCustomObject]$collections) -Evidence @($evidence)
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
        SubscribedSkusDiscovered            = @($collections.SubscribedSkus).Count
        LicenseInventoryStatus              = [string](Get-InspectorSnapshotProperty -InputObject $tenantLicenseProfile -Name 'InventoryStatus')
        LicenseValidationStatus             = [string](Get-InspectorSnapshotProperty -InputObject $tenantLicenseProfile -Name 'ValidationStatus')
        PimLicenseCapability                = [string](Get-InspectorSnapshotProperty -InputObject (Get-InspectorSnapshotProperty -InputObject $tenantLicenseProfile -Name 'PrivilegedIdentityManagement') -Name 'Status')
        IdentityProtectionLicenseCapability = [string](Get-InspectorSnapshotProperty -InputObject (Get-InspectorSnapshotProperty -InputObject $tenantLicenseProfile -Name 'IdentityProtectionRiskyUsers') -Name 'Status')
        DirectoryRoleDefinitionsDiscovered = @($collections.DirectoryRoleDefinitions).Count
        DirectoryRoleAssignmentsDiscovered = @($collections.DirectoryRoleAssignments).Count
        RoleAssignmentScheduleInstancesDiscovered = @($collections.RoleAssignmentScheduleInstances).Count
        RoleEligibilityScheduleInstancesDiscovered = @($collections.RoleEligibilityScheduleInstances).Count
        AdministrativeUnitsDiscovered      = @($collections.AdministrativeUnits).Count
        AdministrativeUnitMembersDiscovered = @($collections.AdministrativeUnitMembers).Count
        AdministrativeUnitScopedRoleMembersDiscovered = @($collections.AdministrativeUnitScopedRoleMembers).Count
        RiskyUsersDiscovered               = @($collections.RiskyUsers).Count
        EvidenceRecordsCollected           = @($evidence).Count
        FailedObjects                      = 0
        MicrosoftPublishedServicePrincipals = @($microsoftPublishedServicePrincipals).Count
        FirstPartyClassificationConfidence = $(if (@($collections.ServicePrincipals).Count -gt 0) { 'ConservativeMetadata' } else { 'NotClassified' })
        FirstPartyClassificationMethod     = 'Central publisher classification using Microsoft owner-tenant IDs, a narrow Microsoft-documented exact AppId fallback, and collected Graph publisher metadata; display-name strings are not classification proof.'
        BoundedRun                         = ($MaxObjectsPerType -gt 0)
        MaxObjectsPerType                  = $MaxObjectsPerType
        TargetedRun                        = [bool]$targetedMode
        TargetCount                        = $(if($targetedMode){@($targetResolution.Resolutions).Count}else{0})
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

    $collectionScope =
        if ($targetedMode) {
            [PSCustomObject][ordered]@{
                Mode = 'Targeted'
                ObjectTypes = @($targetResolution.ResolvedObjectTypes)
                ResolvedTargets = @($targetResolution.Resolutions)
                ResolvedObjectKeys = @($targetResolution.ResolvedObjectKeys)
                ScopeSignature = [string]$targetResolution.ScopeSignature
            }
        }
        else {
            [PSCustomObject][ordered]@{
                Mode = 'TenantWide'
                ObjectTypes = @($ObjectType | Sort-Object -Unique)
                ResolvedTargets = @()
                ResolvedObjectKeys = @()
                ScopeSignature = Get-InspectorDeterministicToken -Value ("TenantWide|$((@($ObjectType | Sort-Object -Unique) -join ','))|Max=$MaxObjectsPerType")
            }
        }

    return [PSCustomObject][ordered]@{
        PSTypeName                      = 'EntraObjectInspector.TenantSnapshot'
        SchemaVersion                   = '1.1.0'
        SnapshotId                      = [guid]::NewGuid().ToString()
        CreatedAt                       = (Get-Date).ToUniversalTime().ToString('o')
        CollectionMode                  = 'GraphIngestionOnly'
        PersistenceMode                 = 'PortableCapable'
        GraphCallsAllowedAfterSnapshot  = $false
        CollectionScope                 = $collectionScope
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
