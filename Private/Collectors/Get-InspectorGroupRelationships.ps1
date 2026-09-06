function Get-InspectorGroupRelationships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Candidate
    )

    $collectorName = 'GroupRelationships'
    $objectType = [string]$Candidate.ObjectType
    $objectId = [string]$Candidate.Identifiers.ObjectId

    if ($objectType -ne 'Group') {
        return New-InspectorNotApplicableCollectorResult `
            -CollectorName $collectorName `
            -ExpectedObjectType 'Group' `
            -ActualObjectType $objectType `
            -SourceObjectId $objectId
    }

    $graphBaseUri = 'https://graph.microsoft.com/v1.0'
    $evidence = [System.Collections.Generic.List[object]]::new()
    $relationships = [System.Collections.Generic.List[object]]::new()
    $limitations = [System.Collections.Generic.List[string]]::new()

    $metadataEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'GroupMetadata' `
        -Uri "$graphBaseUri/groups/${objectId}" `
        -RequiredPermission 'GroupMember.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'Group' `
        -SubjectObjectId $objectId

    $evidence.Add($metadataEvidence)

    if ($metadataEvidence.Status -ne 'Success') {
        return New-InspectorCollectorResult `
            -CollectorName $collectorName `
            -SourceObjectType 'Group' `
            -SourceObjectId $objectId `
            -Evidence @($evidence) `
            -Limitations @($metadataEvidence.Limitations)
    }

    $group = @($metadataEvidence.Result) | Select-Object -First 1

    $ownersEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'GroupOwners' `
        -Uri "$graphBaseUri/groups/${objectId}/owners?`$select=id,displayName" `
        -RequiredPermission 'GroupMember.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'Group' `
        -SubjectObjectId $objectId

    $evidence.Add($ownersEvidence)

    if ($ownersEvidence.Status -eq 'Success') {
        foreach ($owner in @($ownersEvidence.Result)) {
            if ($null -eq $owner) {
                continue
            }

            $ownerId = [string](Get-InspectorCollectorProperty -InputObject $owner -Name 'id')

            if ([string]::IsNullOrWhiteSpace($ownerId)) {
                continue
            }

            $relationships.Add(
                (New-InspectorRelationship `
                    -RelationshipType 'OwnedBy' `
                    -SourceObjectId $objectId `
                    -SourceObjectType 'Group' `
                    -TargetObjectId $ownerId `
                    -TargetObjectType (Get-InspectorDirectoryObjectTypeName -InputObject $owner) `
                    -TargetDisplayName ([string](Get-InspectorCollectorProperty -InputObject $owner -Name 'displayName')) `
                    -DirectOrTransitive 'Direct' `
                    -Direction 'Outbound' `
                    -Metadata @{ ControlCategory = 'Ownership' } `
                    -EvidenceId $ownersEvidence.EvidenceId)
            )
        }
    }

    $membersEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'GroupMembers' `
        -Uri "$graphBaseUri/groups/${objectId}/members?`$select=id,displayName" `
        -RequiredPermission 'GroupMember.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'Group' `
        -SubjectObjectId $objectId

    $evidence.Add($membersEvidence)

    if ($membersEvidence.Status -eq 'Success') {
        foreach ($member in @($membersEvidence.Result)) {
            if ($null -eq $member) {
                continue
            }

            $memberId = [string](Get-InspectorCollectorProperty -InputObject $member -Name 'id')

            if ([string]::IsNullOrWhiteSpace($memberId)) {
                continue
            }

            $relationships.Add(
                (New-InspectorRelationship `
                    -RelationshipType 'HasMember' `
                    -SourceObjectId $objectId `
                    -SourceObjectType 'Group' `
                    -TargetObjectId $memberId `
                    -TargetObjectType (Get-InspectorDirectoryObjectTypeName -InputObject $member) `
                    -TargetDisplayName ([string](Get-InspectorCollectorProperty -InputObject $member -Name 'displayName')) `
                    -DirectOrTransitive 'Direct' `
                    -Direction 'Outbound' `
                    -EvidenceId $membersEvidence.EvidenceId)
            )
        }
    }

    $memberOfEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'GroupMemberships' `
        -Uri "$graphBaseUri/groups/${objectId}/memberOf?`$select=id,displayName" `
        -RequiredPermission 'GroupMember.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'Group' `
        -SubjectObjectId $objectId

    $evidence.Add($memberOfEvidence)

    if ($memberOfEvidence.Status -eq 'Success') {
        foreach ($parent in @($memberOfEvidence.Result)) {
            if ($null -eq $parent) {
                continue
            }

            $parentId = [string](Get-InspectorCollectorProperty -InputObject $parent -Name 'id')

            if ([string]::IsNullOrWhiteSpace($parentId)) {
                continue
            }

            $relationships.Add(
                (New-InspectorRelationship `
                    -RelationshipType 'MemberOf' `
                    -SourceObjectId $objectId `
                    -SourceObjectType 'Group' `
                    -TargetObjectId $parentId `
                    -TargetObjectType (Get-InspectorDirectoryObjectTypeName -InputObject $parent) `
                    -TargetDisplayName ([string](Get-InspectorCollectorProperty -InputObject $parent -Name 'displayName')) `
                    -DirectOrTransitive 'Direct' `
                    -Direction 'Outbound' `
                    -EvidenceId $memberOfEvidence.EvidenceId)
            )
        }
    }

    $roleFilter = [uri]::EscapeDataString("principalId eq '$objectId'")
    $roleAssignmentsEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'DirectoryRoleAssignments' `
        -Uri "$graphBaseUri/roleManagement/directory/roleAssignments?`$filter=${roleFilter}&`$expand=roleDefinition" `
        -RequiredPermission 'RoleManagement.Read.Directory' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'Group' `
        -SubjectObjectId $objectId

    $evidence.Add($roleAssignmentsEvidence)

    if ($roleAssignmentsEvidence.Status -eq 'Success') {
        foreach ($assignment in @($roleAssignmentsEvidence.Result)) {
            if ($null -eq $assignment) {
                continue
            }

            $roleDefinitionId = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'roleDefinitionId')

            if ([string]::IsNullOrWhiteSpace($roleDefinitionId)) {
                continue
            }

            $roleDefinition = Get-InspectorCollectorProperty -InputObject $assignment -Name 'roleDefinition'

            $relationships.Add(
                (New-InspectorRelationship `
                    -RelationshipType 'AssignedDirectoryRole' `
                    -SourceObjectId $objectId `
                    -SourceObjectType 'Group' `
                    -TargetObjectId $roleDefinitionId `
                    -TargetObjectType 'DirectoryRoleDefinition' `
                    -TargetDisplayName ([string](Get-InspectorCollectorProperty -InputObject $roleDefinition -Name 'displayName')) `
                    -DirectOrTransitive 'Direct' `
                    -Direction 'Outbound' `
                    -Metadata @{
                        AssignmentId     = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'id')
                        DirectoryScopeId = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'directoryScopeId')
                    } `
                    -EvidenceId $roleAssignmentsEvidence.EvidenceId)
            )
        }
    }

    $visibility = [string](Get-InspectorCollectorProperty -InputObject $group -Name 'visibility')

    if ($visibility -eq 'HiddenMembership') {
        $limitations.Add(
            'This group uses hidden membership. Complete member enumeration may require Member.Read.Hidden.'
        )
    }

    $limitations.Add(
        'Microsoft Graph v1.0 currently documents that service principals might not be returned in the group owners relationship during staged rollout.'
    )

    $properties = [PSCustomObject][ordered]@{
        Id                            = $objectId
        DisplayName                   = [string](Get-InspectorCollectorProperty -InputObject $group -Name 'displayName')
        GroupTypes                    = @(Get-InspectorCollectorProperty -InputObject $group -Name 'groupTypes')
        SecurityEnabled               = Get-InspectorCollectorProperty -InputObject $group -Name 'securityEnabled'
        MailEnabled                   = Get-InspectorCollectorProperty -InputObject $group -Name 'mailEnabled'
        IsAssignableToRole            = Get-InspectorCollectorProperty -InputObject $group -Name 'isAssignableToRole'
        Visibility                    = $visibility
        MembershipRule                = [string](Get-InspectorCollectorProperty -InputObject $group -Name 'membershipRule')
        MembershipRuleProcessingState = [string](Get-InspectorCollectorProperty -InputObject $group -Name 'membershipRuleProcessingState')
    }

    return New-InspectorCollectorResult `
        -CollectorName $collectorName `
        -SourceObjectType 'Group' `
        -SourceObjectId $objectId `
        -Evidence @($evidence) `
        -Relationships @($relationships) `
        -Artifacts @() `
        -Properties $properties `
        -Limitations @($limitations)
}
