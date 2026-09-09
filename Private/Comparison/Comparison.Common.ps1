function Get-InspectorComparisonHash {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Value
    )

    return Get-InspectorDeterministicToken -Value $Value
}

function New-InspectorComparableRecord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$RecordType,

        [Parameter(Mandatory)]
        [string]$SemanticKey,

        [Parameter(Mandatory)]
        [string]$SubjectObjectType,

        [Parameter(Mandatory)]
        [string]$SubjectObjectId,

        [string]$RelatedObjectId = '',

        [AllowNull()]
        [object]$Value,

        [object[]]$EvidenceIds = @()
    )

    $valueJson = if ($null -eq $Value) { '' } else { $Value | ConvertTo-Json -Depth 30 -Compress }
    return [PSCustomObject][ordered]@{
        PSTypeName        = 'EntraObjectInspector.ComparableSnapshotRecord'
        SchemaVersion     = '1.0.0'
        RecordType        = $RecordType
        SemanticKey       = $SemanticKey
        SubjectObjectType = $SubjectObjectType
        SubjectObjectId   = $SubjectObjectId
        RelatedObjectId   = $RelatedObjectId
        Fingerprint       = Get-InspectorComparisonHash -Value $valueJson
        Value             = $Value
        EvidenceIds       = @(
            $EvidenceIds |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ } |
                Sort-Object -Unique
        )
    }
}

function ConvertTo-InspectorSnapshotComparableRecords {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$TenantSnapshot
    )

    $collections = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'Collections'
    $recordByKey = @{}

    $ownerComparableAllowedBySubjectKey = @{}
    $snapshotIndexes = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'Indexes'
    $objectRelationshipEvidenceIndex = Get-InspectorSnapshotProperty -InputObject $snapshotIndexes -Name 'ObjectRelationshipEvidenceByObjectKey'
    foreach ($definition in @(
        @{ Collection = 'Applications'; Subject = 'Application'; Prefix = 'ApplicationOwners:' },
        @{ Collection = 'ServicePrincipals'; Subject = 'ServicePrincipal'; Prefix = 'ServicePrincipalOwners:' },
        @{ Collection = 'Groups'; Subject = 'Group'; Prefix = 'GroupOwners:' }
    )) {
        foreach ($sourceObject in @(Get-InspectorSnapshotProperty -InputObject $collections -Name $definition.Collection)) {
            $subjectId = [string](Get-InspectorSnapshotProperty -InputObject $sourceObject -Name 'id')
            if ([string]::IsNullOrWhiteSpace($subjectId)) { continue }
            $subjectKey = "$($definition.Subject)|$subjectId"
            $evidenceRows = @(Get-InspectorSnapshotIndexSingle -Index $objectRelationshipEvidenceIndex -Key $subjectKey)
            if ($evidenceRows.Count -eq 0) {
                $evidenceRows = @(
                    Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'Evidence' |
                        Where-Object {
                            [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'EvidenceScope') -eq 'ObjectRelationship' -and
                            [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'SubjectObjectType') -eq $definition.Subject -and
                            [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'SubjectObjectId') -eq $subjectId
                        }
                )
            }

            $ownerEvidenceRows = @(
                $evidenceRows |
                    Where-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'QueryName') -like "$($definition.Prefix)*" }
            )
            $ownerComparableAllowedBySubjectKey[$subjectKey] =
                $ownerEvidenceRows.Count -eq 0 -or
                @(
                    $ownerEvidenceRows |
                        Where-Object {
                            [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'Status') -ne 'Success' -or
                            [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'Completeness') -ne 'Complete'
                        }
                ).Count -eq 0
        }
    }

    function Add-InspectorComparableRecord {
        param (
            [Parameter(Mandatory)]
            [object]$Record
        )

        $key = [string](Get-InspectorSnapshotProperty -InputObject $Record -Name 'SemanticKey')
        if ([string]::IsNullOrWhiteSpace($key)) { return }

        if (-not $recordByKey.ContainsKey($key)) {
            $recordByKey[$key] = $Record
            return
        }

        $existing = $recordByKey[$key]
        $evidenceIds = @(
            @((Get-InspectorSnapshotProperty -InputObject $existing -Name 'EvidenceIds')) +
            @((Get-InspectorSnapshotProperty -InputObject $Record -Name 'EvidenceIds')) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ } |
                Sort-Object -Unique
        )
        $existing | Add-Member -NotePropertyName 'EvidenceIds' -NotePropertyValue @($evidenceIds) -Force
    }

    foreach ($definition in @(
        @{ Collection = 'ApplicationOwners'; Subject = 'Application' },
        @{ Collection = 'ServicePrincipalOwners'; Subject = 'ServicePrincipal' },
        @{ Collection = 'GroupOwners'; Subject = 'Group' }
    )) {
        foreach ($row in @(Get-InspectorSnapshotProperty -InputObject $collections -Name $definition.Collection)) {
            $owner = Get-InspectorSnapshotProperty -InputObject $row -Name 'Owner'
            $subjectId = [string](Get-InspectorSnapshotProperty -InputObject $row -Name 'SourceObjectId')
            $ownerId = [string](Get-InspectorSnapshotProperty -InputObject $owner -Name 'id')
            if ([string]::IsNullOrWhiteSpace($subjectId) -or [string]::IsNullOrWhiteSpace($ownerId)) { continue }
            if ($ownerComparableAllowedBySubjectKey.ContainsKey("$($definition.Subject)|$subjectId") -and -not $ownerComparableAllowedBySubjectKey["$($definition.Subject)|$subjectId"]) { continue }

            Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
                -RecordType 'Owner' `
                -SemanticKey "Owner|$($definition.Subject)|$subjectId|$ownerId" `
                -SubjectObjectType $definition.Subject `
                -SubjectObjectId $subjectId `
                -RelatedObjectId $ownerId `
                -Value ([PSCustomObject][ordered]@{ SubjectObjectId = $subjectId; OwnerId = $ownerId }) `
                -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $row -Name 'EvidenceId')))
        }
    }

    foreach ($definition in @(
        @{ Collection = 'ApplicationCredentials'; Subject = 'Application' },
        @{ Collection = 'ServicePrincipalCredentials'; Subject = 'ServicePrincipal' }
    )) {
        foreach ($row in @(Get-InspectorSnapshotProperty -InputObject $collections -Name $definition.Collection)) {
            $credential = Get-InspectorSnapshotProperty -InputObject $row -Name 'Credential'
            $subjectId = [string](Get-InspectorSnapshotProperty -InputObject $row -Name 'SourceObjectId')
            $keyId = [string](Get-InspectorSnapshotProperty -InputObject $credential -Name 'keyId')
            if ([string]::IsNullOrWhiteSpace($keyId)) {
                $keyId = [string](Get-InspectorSnapshotProperty -InputObject $credential -Name 'displayName')
            }
            if ([string]::IsNullOrWhiteSpace($subjectId) -or [string]::IsNullOrWhiteSpace($keyId)) { continue }

            $credentialType = [string](Get-InspectorSnapshotProperty -InputObject $row -Name 'CredentialType')
            $value = [PSCustomObject][ordered]@{
                KeyId          = $keyId
                CredentialType = $credentialType
                DisplayName    = [string](Get-InspectorSnapshotProperty -InputObject $credential -Name 'displayName')
                StartDateTime  = Get-InspectorSnapshotProperty -InputObject $credential -Name 'startDateTime'
                EndDateTime    = Get-InspectorSnapshotProperty -InputObject $credential -Name 'endDateTime'
            }
            Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
                -RecordType 'Credential' `
                -SemanticKey "Credential|$($definition.Subject)|$subjectId|$credentialType|$keyId" `
                -SubjectObjectType $definition.Subject `
                -SubjectObjectId $subjectId `
                -RelatedObjectId $keyId `
                -Value $value `
                -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $row -Name 'EvidenceId')))
        }
    }

    # Normalize all membership views to one semantic relation: group <- member.
    # This deduplicates forward group-members evidence and reverse memberOf evidence
    # while preserving the union of all evidence that proves the relation.
    foreach ($row in @(Get-InspectorSnapshotProperty -InputObject $collections -Name 'GroupMembers')) {
        $member = Get-InspectorSnapshotProperty -InputObject $row -Name 'Member'
        $groupId = [string](Get-InspectorSnapshotProperty -InputObject $row -Name 'SourceObjectId')
        $memberId = [string](Get-InspectorSnapshotProperty -InputObject $member -Name 'id')
        if ([string]::IsNullOrWhiteSpace($groupId) -or [string]::IsNullOrWhiteSpace($memberId)) { continue }

        Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
            -RecordType 'GroupMember' `
            -SemanticKey "GroupMember|$groupId|$memberId" `
            -SubjectObjectType 'Group' `
            -SubjectObjectId $groupId `
            -RelatedObjectId $memberId `
            -Value ([PSCustomObject][ordered]@{ GroupId = $groupId; MemberId = $memberId }) `
            -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $row -Name 'EvidenceId')))
    }

    foreach ($definition in @(
        @{ Collection = 'GroupMemberships'; MemberType = 'Group' },
        @{ Collection = 'ServicePrincipalGroupMemberships'; MemberType = 'ServicePrincipal' },
        @{ Collection = 'UserTransitiveMemberships'; MemberType = 'User' }
    )) {
        foreach ($row in @(Get-InspectorSnapshotProperty -InputObject $collections -Name $definition.Collection)) {
            $membership = Get-InspectorSnapshotProperty -InputObject $row -Name 'Membership'
            $memberId = [string](Get-InspectorSnapshotProperty -InputObject $row -Name 'SourceObjectId')
            $groupId = [string](Get-InspectorSnapshotProperty -InputObject $membership -Name 'id')
            if ([string]::IsNullOrWhiteSpace($groupId) -or [string]::IsNullOrWhiteSpace($memberId)) { continue }

            Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
                -RecordType 'GroupMember' `
                -SemanticKey "GroupMember|$groupId|$memberId" `
                -SubjectObjectType 'Group' `
                -SubjectObjectId $groupId `
                -RelatedObjectId $memberId `
                -Value ([PSCustomObject][ordered]@{ GroupId = $groupId; MemberId = $memberId }) `
                -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $row -Name 'EvidenceId')))
        }
    }

    # Requested application permissions are part of the application object and
    # therefore work for both tenant-wide and targeted application snapshots.
    foreach ($row in @(Get-InspectorSnapshotProperty -InputObject $collections -Name 'RequiredResourceAccess')) {
        $applicationId = [string](Get-InspectorSnapshotProperty -InputObject $row -Name 'SourceObjectId')
        $access = Get-InspectorSnapshotProperty -InputObject $row -Name 'Access'
        $resourceAppId = [string](Get-InspectorSnapshotProperty -InputObject $access -Name 'resourceAppId')
        foreach ($permission in @(Get-InspectorSnapshotProperty -InputObject $access -Name 'resourceAccess')) {
            $permissionId = [string](Get-InspectorSnapshotProperty -InputObject $permission -Name 'id')
            $permissionType = [string](Get-InspectorSnapshotProperty -InputObject $permission -Name 'type')
            if ([string]::IsNullOrWhiteSpace($applicationId) -or
                [string]::IsNullOrWhiteSpace($resourceAppId) -or
                [string]::IsNullOrWhiteSpace($permissionId)) { continue }

            $key = "RequiredPermission|$applicationId|$resourceAppId|$permissionType|$permissionId"
            Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
                -RecordType 'Permission' `
                -SemanticKey $key `
                -SubjectObjectType 'Application' `
                -SubjectObjectId $applicationId `
                -RelatedObjectId $resourceAppId `
                -Value ([PSCustomObject][ordered]@{
                    PermissionType = 'RequiredResourceAccess'
                    ResourceAppId  = $resourceAppId
                    AccessType     = $permissionType
                    PermissionId   = $permissionId
                }) `
                -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $row -Name 'EvidenceId')))
        }
    }

    foreach ($row in @(
        @(Get-InspectorSnapshotProperty -InputObject $collections -Name 'AppRoleAssignments') +
        @(Get-InspectorSnapshotProperty -InputObject $collections -Name 'AppRoleAssignedTo')
    )) {
        $assignment = Get-InspectorSnapshotProperty -InputObject $row -Name 'Assignment'
        if ($null -eq $assignment) { $assignment = $row }
        $principalId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'principalId')
        $resourceId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'resourceId')
        $appRoleId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'appRoleId')
        if ([string]::IsNullOrWhiteSpace($principalId) -or
            [string]::IsNullOrWhiteSpace($resourceId) -or
            [string]::IsNullOrWhiteSpace($appRoleId)) { continue }

        $key = "ApplicationPermission|$principalId|$resourceId|$appRoleId"
        Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
            -RecordType 'Permission' `
            -SemanticKey $key `
            -SubjectObjectType 'ServicePrincipal' `
            -SubjectObjectId $principalId `
            -RelatedObjectId $resourceId `
            -Value ([PSCustomObject][ordered]@{
                PermissionType = 'Application'
                PrincipalId    = $principalId
                ResourceId     = $resourceId
                AppRoleId      = $appRoleId
            }) `
            -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $row -Name 'EvidenceId')))
    }

    foreach ($grant in @(Get-InspectorSnapshotProperty -InputObject $collections -Name 'OAuth2PermissionGrants')) {
        $clientId = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'clientId')
        $resourceId = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'resourceId')
        $principalId = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'principalId')
        $consentType = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'consentType')
        foreach ($scope in @(
            ([string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'scope')) -split '\s+' |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object -Unique
        )) {
            if ([string]::IsNullOrWhiteSpace($clientId) -or [string]::IsNullOrWhiteSpace($resourceId)) { continue }
            $key = "DelegatedPermission|$clientId|$resourceId|$principalId|$consentType|$scope"
            Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
                -RecordType 'Permission' `
                -SemanticKey $key `
                -SubjectObjectType 'ServicePrincipal' `
                -SubjectObjectId $clientId `
                -RelatedObjectId $resourceId `
                -Value ([PSCustomObject][ordered]@{
                    PermissionType = 'Delegated'
                    ClientId       = $clientId
                    ResourceId     = $resourceId
                    Scope          = $scope
                    ConsentType    = $consentType
                    PrincipalId    = $principalId
                }) `
                -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'EvidenceId')))
        }
    }

    $roleAssignmentIds = @{}
    $roleAssignmentTupleKeys = @{}
    foreach ($assignment in @(Get-InspectorSnapshotProperty -InputObject $collections -Name 'DirectoryRoleAssignments')) {
        $principalId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'principalId')
        $roleDefinitionId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'roleDefinitionId')
        $directoryScopeId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'directoryScopeId')
        $appScopeId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'appScopeId')
        if ([string]::IsNullOrWhiteSpace($principalId) -or [string]::IsNullOrWhiteSpace($roleDefinitionId)) { continue }
        $assignmentId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'id')
        if (-not [string]::IsNullOrWhiteSpace($assignmentId)) { $roleAssignmentIds[$assignmentId] = $true }
        $directoryScopeKey = if ([string]::IsNullOrWhiteSpace($directoryScopeId)) { '<null>' } else { $directoryScopeId }
        $appScopeKey = if ([string]::IsNullOrWhiteSpace($appScopeId)) { '<null>' } else { $appScopeId }
        $scopeKey = "$directoryScopeKey|$appScopeKey"
        $roleAssignmentTupleKeys["$principalId|$roleDefinitionId|$scopeKey"] = $true
        $key = "DirectoryRoleAssignment|$principalId|$roleDefinitionId|$scopeKey"
        Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
            -RecordType 'DirectoryRoleAssignment' `
            -SemanticKey $key `
            -SubjectObjectType 'Principal' `
            -SubjectObjectId $principalId `
            -RelatedObjectId $roleDefinitionId `
            -Value ([PSCustomObject][ordered]@{
                PrincipalId = $principalId
                RoleDefinitionId = $roleDefinitionId
                DirectoryScopeId = $directoryScopeId
                AppScopeId = $appScopeId
            }) `
            -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'EvidenceId')))
    }

    foreach ($definition in @(
        @{ Collection = 'RoleAssignmentScheduleInstances'; RecordType = 'ActiveDirectoryRoleScheduleInstance'; State = 'Active' },
        @{ Collection = 'RoleEligibilityScheduleInstances'; RecordType = 'EligibleDirectoryRoleScheduleInstance'; State = 'Eligible' }
    )) {
        foreach ($scheduleInstance in @(Get-InspectorSnapshotProperty -InputObject $collections -Name $definition.Collection)) {
            $principalId = [string](Get-InspectorSnapshotProperty -InputObject $scheduleInstance -Name 'principalId')
            $roleDefinitionId = [string](Get-InspectorSnapshotProperty -InputObject $scheduleInstance -Name 'roleDefinitionId')
            $directoryScopeId = [string](Get-InspectorSnapshotProperty -InputObject $scheduleInstance -Name 'directoryScopeId')
            $appScopeId = [string](Get-InspectorSnapshotProperty -InputObject $scheduleInstance -Name 'appScopeId')
            $scheduleId = [string](Get-InspectorSnapshotProperty -InputObject $scheduleInstance -Name 'id')
            if ([string]::IsNullOrWhiteSpace($principalId) -or [string]::IsNullOrWhiteSpace($roleDefinitionId)) { continue }
            $directoryScopeKey = if ([string]::IsNullOrWhiteSpace($directoryScopeId)) { '<null>' } else { $directoryScopeId }
            $appScopeKey = if ([string]::IsNullOrWhiteSpace($appScopeId)) { '<null>' } else { $appScopeId }
            $scopeKey = "$directoryScopeKey|$appScopeKey"
            $originId = [string](Get-InspectorSnapshotProperty -InputObject $scheduleInstance -Name 'roleAssignmentOriginId')
            $tupleKey = "$principalId|$roleDefinitionId|$scopeKey"
            $assignmentType = [string](Get-InspectorSnapshotProperty -InputObject $scheduleInstance -Name 'assignmentType')
            if (
                $definition.Collection -eq 'RoleAssignmentScheduleInstances' -and
                $assignmentType -eq 'Assigned' -and
                (
                    (-not [string]::IsNullOrWhiteSpace($originId) -and $roleAssignmentIds.ContainsKey($originId)) -or
                    $roleAssignmentTupleKeys.ContainsKey($tupleKey)
                )
            ) {
                # Assigned schedule instances corroborate an effective unified
                # role assignment and must not create a second semantic drift
                # record. Activated instances represent active PIM state and are
                # intentionally retained even when Graph also exposes the
                # resulting unifiedRoleAssignment.
                continue
            }
            $key = "$($definition.RecordType)|$principalId|$roleDefinitionId|$scopeKey|$scheduleId"
            Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
                -RecordType $definition.RecordType `
                -SemanticKey $key `
                -SubjectObjectType 'Principal' `
                -SubjectObjectId $principalId `
                -RelatedObjectId $roleDefinitionId `
                -Value ([PSCustomObject][ordered]@{
                    PrincipalId = $principalId
                    RoleDefinitionId = $roleDefinitionId
                    DirectoryScopeId = $directoryScopeId
                    AppScopeId = $appScopeId
                    AssignmentState = $definition.State
                    AssignmentType = $assignmentType
                    MemberType = [string](Get-InspectorSnapshotProperty -InputObject $scheduleInstance -Name 'memberType')
                }) `
                -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $scheduleInstance -Name 'EvidenceId')))
        }
    }

    foreach ($auMemberRow in @(Get-InspectorSnapshotProperty -InputObject $collections -Name 'AdministrativeUnitMembers')) {
        $auId = [string](Get-InspectorSnapshotProperty -InputObject $auMemberRow -Name 'AdministrativeUnitId')
        $member = Get-InspectorSnapshotProperty -InputObject $auMemberRow -Name 'Member'
        $memberId = [string](Get-InspectorSnapshotProperty -InputObject $member -Name 'id')
        if ([string]::IsNullOrWhiteSpace($auId) -or [string]::IsNullOrWhiteSpace($memberId)) { continue }
        Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
            -RecordType 'AdministrativeUnitMember' `
            -SemanticKey "AdministrativeUnitMember|$auId|$memberId" `
            -SubjectObjectType 'AdministrativeUnit' `
            -SubjectObjectId $auId `
            -RelatedObjectId $memberId `
            -Value ([PSCustomObject][ordered]@{ AdministrativeUnitId = $auId; MemberId = $memberId }) `
            -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $auMemberRow -Name 'EvidenceId')))
    }

    foreach ($riskyUser in @(Get-InspectorSnapshotProperty -InputObject $collections -Name 'RiskyUsers')) {
        $userId = [string](Get-InspectorSnapshotProperty -InputObject $riskyUser -Name 'id')
        if ([string]::IsNullOrWhiteSpace($userId)) { continue }
        Add-InspectorComparableRecord -Record (New-InspectorComparableRecord `
            -RecordType 'RiskyUser' `
            -SemanticKey "RiskyUser|$userId" `
            -SubjectObjectType 'User' `
            -SubjectObjectId $userId `
            -RelatedObjectId $userId `
            -Value ([PSCustomObject][ordered]@{
                UserId = $userId
                RiskLevel = [string](Get-InspectorSnapshotProperty -InputObject $riskyUser -Name 'riskLevel')
                RiskState = [string](Get-InspectorSnapshotProperty -InputObject $riskyUser -Name 'riskState')
                RiskDetail = [string](Get-InspectorSnapshotProperty -InputObject $riskyUser -Name 'riskDetail')
            }) `
            -EvidenceIds @([string](Get-InspectorSnapshotProperty -InputObject $riskyUser -Name 'EvidenceId')))
    }

    return @($recordByKey.Values | Sort-Object SemanticKey)
}

function Get-InspectorSnapshotScopeSignature {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$TenantSnapshot
    )

    $scope = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'CollectionScope'
    $signature = [string](Get-InspectorSnapshotProperty -InputObject $scope -Name 'ScopeSignature')
    if (-not [string]::IsNullOrWhiteSpace($signature)) { return $signature }

    $collections = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'Collections'
    $objectTypes = @(
        @('Applications','ServicePrincipals','Users','Groups') |
            Where-Object { @((Get-InspectorSnapshotProperty -InputObject $collections -Name $_)).Count -gt 0 } |
            Sort-Object
    )
    return Get-InspectorComparisonHash -Value ($objectTypes -join ',')
}
