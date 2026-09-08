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
