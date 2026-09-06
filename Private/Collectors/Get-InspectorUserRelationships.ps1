function Get-InspectorUserRelationships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Candidate
    )

    $collectorName = 'UserRelationships'
    $objectType = [string]$Candidate.ObjectType
    $objectId = [string]$Candidate.Identifiers.ObjectId

    if ($objectType -ne 'User') {
        return New-InspectorNotApplicableCollectorResult `
            -CollectorName $collectorName `
            -ExpectedObjectType 'User' `
            -ActualObjectType $objectType `
            -SourceObjectId $objectId
    }

    $graphBaseUri = 'https://graph.microsoft.com/v1.0'
    $evidence = [System.Collections.Generic.List[object]]::new()
    $relationships = [System.Collections.Generic.List[object]]::new()
    $limitations = [System.Collections.Generic.List[string]]::new()

    $membershipEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'TransitiveMemberships' `
        -Uri "$graphBaseUri/users/${objectId}/transitiveMemberOf?`$select=id,displayName" `
        -RequiredPermission 'User.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'User' `
        -SubjectObjectId $objectId

    $evidence.Add($membershipEvidence)

    if ($membershipEvidence.Status -eq 'Success') {
        foreach ($membership in @($membershipEvidence.Result)) {
            if ($null -eq $membership) {
                continue
            }

            $targetId = [string](Get-InspectorCollectorProperty -InputObject $membership -Name 'id')

            if ([string]::IsNullOrWhiteSpace($targetId)) {
                continue
            }

            $targetType = Get-InspectorDirectoryObjectTypeName -InputObject $membership
            $relationshipType = switch ($targetType) {
                'group'              { 'MemberOfGroup' }
                'directoryRole'      { 'MemberOfDirectoryRole' }
                'administrativeUnit' { 'MemberOfAdministrativeUnit' }
                default              { 'TransitiveMemberOf' }
            }

            $relationships.Add(
                (New-InspectorRelationship `
                    -RelationshipType $relationshipType `
                    -SourceObjectId $objectId `
                    -SourceObjectType 'User' `
                    -TargetObjectId $targetId `
                    -TargetObjectType $targetType `
                    -TargetDisplayName ([string](Get-InspectorCollectorProperty -InputObject $membership -Name 'displayName')) `
                    -DirectOrTransitive 'Transitive' `
                    -Direction 'Outbound' `
                    -EvidenceId $membershipEvidence.EvidenceId)
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
        -SubjectObjectType 'User' `
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
                    -SourceObjectType 'User' `
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

    $ownedObjectsEvidence = New-InspectorSyntheticEvidence `
        -CollectorName $collectorName `
        -QueryName 'OwnedObjects' `
        -Status 'NotApplicable' `
        -Endpoint "$graphBaseUri/users/${objectId}/ownedObjects" `
        -RequiredPermission 'Delegated access only' `
        -Limitations @(
            'Microsoft Graph v1.0 does not support application permissions for user ownedObjects. This collector does not perform a tenant-wide ownership scan as a workaround.'
        ) `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'User' `
        -SubjectObjectId $objectId

    $evidence.Add($ownedObjectsEvidence)
    $limitations.Add(
        'User-owned directory objects are not collected in the current app-only runtime because Microsoft Graph does not support application permissions for /users/{id}/ownedObjects.'
    )

    return New-InspectorCollectorResult `
        -CollectorName $collectorName `
        -SourceObjectType 'User' `
        -SourceObjectId $objectId `
        -Evidence @($evidence) `
        -Relationships @($relationships) `
        -Artifacts @() `
        -Properties $null `
        -Limitations @($limitations)
}

