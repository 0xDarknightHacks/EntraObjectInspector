function Get-InspectorSnapshotRelationships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Resolution,

        [Parameter(Mandatory)]
        [object]$TenantSnapshot
    )

    $collectorResults = [System.Collections.Generic.List[object]]::new()
    $candidates = @(@($Resolution.DirectMatches) + @($Resolution.RelatedObjects))
    $snapshotIndexes = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'Indexes'
    $snapshotEvidenceById = Get-InspectorSnapshotProperty -InputObject $snapshotIndexes -Name 'EvidenceById'
    $objectRelationshipEvidenceIndex = Get-InspectorSnapshotProperty -InputObject $snapshotIndexes -Name 'ObjectRelationshipEvidenceByObjectKey'

    # Current snapshots index evidence once at snapshot construction/import. Keep
    # the legacy fallback for older fixtures/artifacts that do not expose the
    # evidence indexes, but never rescan the corpus for every candidate.
    if ($null -eq $snapshotEvidenceById) {
        $snapshotEvidenceById = @{}
        foreach ($snapshotEvidence in @($TenantSnapshot.Evidence)) {
            $evidenceId = [string](Get-InspectorSnapshotProperty -InputObject $snapshotEvidence -Name 'EvidenceId')
            if (-not [string]::IsNullOrWhiteSpace($evidenceId) -and -not $snapshotEvidenceById.ContainsKey($evidenceId)) {
                $snapshotEvidenceById[$evidenceId] = [System.Collections.Generic.List[object]]::new()
                $snapshotEvidenceById[$evidenceId].Add($snapshotEvidence)
            }
        }
    }

    foreach ($candidate in $candidates) {
        # Accept both normalized ResolutionCandidate objects and discovery rows.
        # The latter intentionally expose ObjectId/AppId directly and do not carry
        # an Identifiers or RawObject property. All access must remain StrictMode-safe.
        $objectType = [string](Get-InspectorSnapshotProperty -InputObject $candidate -Name 'ObjectType')
        $candidateIdentifiers = Get-InspectorSnapshotProperty -InputObject $candidate -Name 'Identifiers'
        $objectId = [string](Get-InspectorSnapshotProperty -InputObject $candidateIdentifiers -Name 'ObjectId')
        if ([string]::IsNullOrWhiteSpace($objectId)) {
            $objectId = [string](Get-InspectorSnapshotProperty -InputObject $candidate -Name 'ObjectId')
        }

        $appId = [string](Get-InspectorSnapshotProperty -InputObject $candidateIdentifiers -Name 'AppId')
        if ([string]::IsNullOrWhiteSpace($appId)) {
            $appId = [string](Get-InspectorSnapshotProperty -InputObject $candidate -Name 'AppId')
        }

        $rawObject = Get-InspectorSnapshotProperty -InputObject $candidate -Name 'RawObject'
        if ($null -eq $rawObject -and -not [string]::IsNullOrWhiteSpace($objectId)) {
            $rawObject =
                switch ($objectType) {
                    'Application' {
                        Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.ApplicationByObjectId -Key $objectId |
                            Select-Object -First 1
                    }
                    'ServicePrincipal' {
                        Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.ServicePrincipalByObjectId -Key $objectId |
                            Select-Object -First 1
                    }
                    'User' {
                        Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.UserByObjectId -Key $objectId |
                            Select-Object -First 1
                    }
                    'Group' {
                        Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.GroupByObjectId -Key $objectId |
                            Select-Object -First 1
                    }
                }
        }

        if ($null -eq $rawObject) {
            # A discovery row still contains useful metadata. Using it as a final
            # fallback avoids unsafe dereferences while keeping the offline path
            # deterministic for partial/legacy snapshot shapes.
            $rawObject = $candidate
        }

        $relationships = [System.Collections.Generic.List[object]]::new()
        $artifacts = [System.Collections.Generic.List[object]]::new()
        $evidence = [System.Collections.Generic.List[object]]::new()
        $evidenceIdsSeen = @{}
        $collectorLimitations = [System.Collections.Generic.List[string]]::new()
        $properties = $rawObject
        $collectorName = "$($objectType)Relationships"

        # ResolutionCandidate always exposes EvidenceId after normalization, but
        # retain a safe fallback to the raw snapshot item for older/partial shapes.
        # Never access optional properties directly under StrictMode.
        $candidateEvidenceId = [string](Get-InspectorSnapshotProperty -InputObject $candidate -Name 'EvidenceId')
        if ([string]::IsNullOrWhiteSpace($candidateEvidenceId)) {
            $candidateEvidenceId = [string](Get-InspectorSnapshotProperty -InputObject $rawObject -Name 'EvidenceId')
        }

        if ($objectType -eq 'Application') {
            foreach ($ownerRow in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.OwnersByObjectId -Key $objectId)) {
                $owner = Get-InspectorSnapshotProperty -InputObject $ownerRow -Name 'Owner'
                $relationships.Add((New-InspectorRelationship -RelationshipType 'OwnedBy' -SourceObjectId $objectId -SourceObjectType 'Application' -TargetObjectId ([string](Get-InspectorSnapshotProperty -InputObject $owner -Name 'id')) -TargetObjectType (Get-InspectorDirectoryObjectTypeName -InputObject $owner) -TargetDisplayName ([string](Get-InspectorSnapshotProperty -InputObject $owner -Name 'displayName')) -Metadata @{ ControlCategory = 'Ownership' } -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $ownerRow -Name 'EvidenceId'))))
            }
            foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $rawObject -Name 'keyCredentials')) {
                $artifacts.Add((ConvertTo-InspectorCredentialArtifact -SourceObjectType 'Application' -SourceObjectId $objectId -CredentialType 'Certificate' -Credential $credential -EvidenceId $candidateEvidenceId))
            }
            foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $rawObject -Name 'passwordCredentials')) {
                $artifacts.Add((ConvertTo-InspectorCredentialArtifact -SourceObjectType 'Application' -SourceObjectId $objectId -CredentialType 'Password' -Credential $credential -EvidenceId $candidateEvidenceId))
            }
            foreach ($sp in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.ServicePrincipalByAppId -Key $appId)) {
                $relationships.Add((New-InspectorRelationship -RelationshipType 'ApplicationToServicePrincipal' -SourceObjectId $objectId -SourceObjectType 'Application' -TargetObjectId ([string]$sp.id) -TargetObjectType 'ServicePrincipal' -TargetDisplayName ([string]$sp.displayName) -Metadata @{ AppId = $appId }))
            }
        }
        elseif ($objectType -eq 'ServicePrincipal') {
                        foreach ($ownerRow in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.OwnersByObjectId -Key $objectId)) {
                $owner = Get-InspectorSnapshotProperty -InputObject $ownerRow -Name 'Owner'
                $relationships.Add((New-InspectorRelationship -RelationshipType 'OwnedBy' -SourceObjectId $objectId -SourceObjectType 'ServicePrincipal' -TargetObjectId ([string](Get-InspectorSnapshotProperty -InputObject $owner -Name 'id')) -TargetObjectType (Get-InspectorDirectoryObjectTypeName -InputObject $owner) -TargetDisplayName ([string](Get-InspectorSnapshotProperty -InputObject $owner -Name 'displayName')) -Metadata @{ ControlCategory = 'Ownership' } -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $ownerRow -Name 'EvidenceId'))))
            }
            foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $rawObject -Name 'keyCredentials')) {
                $artifacts.Add((ConvertTo-InspectorCredentialArtifact -SourceObjectType 'ServicePrincipal' -SourceObjectId $objectId -CredentialType 'Certificate' -Credential $credential -EvidenceId $candidateEvidenceId))
            }
            foreach ($credential in @(Get-InspectorSnapshotProperty -InputObject $rawObject -Name 'passwordCredentials')) {
                $artifacts.Add((ConvertTo-InspectorCredentialArtifact -SourceObjectType 'ServicePrincipal' -SourceObjectId $objectId -CredentialType 'Password' -Credential $credential -EvidenceId $candidateEvidenceId))
            }
            foreach ($app in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.ApplicationByAppId -Key $appId)) {
                $relationships.Add((New-InspectorRelationship -RelationshipType 'ServicePrincipalToApplication' -SourceObjectId $objectId -SourceObjectType 'ServicePrincipal' -TargetObjectId ([string]$app.id) -TargetObjectType 'Application' -TargetDisplayName ([string]$app.displayName) -Metadata @{ AppId = $appId }))
            }
            foreach ($assignmentRow in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.AppRoleAssignmentsByPrincipalId -Key $objectId)) {
                $assignment = Get-InspectorSnapshotProperty -InputObject $assignmentRow -Name 'Assignment'
                if ($null -eq $assignment) { $assignment = $assignmentRow }
                $relationships.Add((New-InspectorRelationship -RelationshipType 'GrantedAppRole' -SourceObjectId $objectId -SourceObjectType 'ServicePrincipal' -TargetObjectId ([string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'resourceId')) -TargetObjectType 'ServicePrincipal' -TargetDisplayName ([string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'resourceDisplayName')) -Metadata @{ AssignmentId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'id'); AppRoleId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'appRoleId') } -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $assignmentRow -Name 'EvidenceId'))))
            }
            foreach ($assignmentRow in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.AppRoleAssignmentsByResourceId -Key $objectId)) {
                $assignment = Get-InspectorSnapshotProperty -InputObject $assignmentRow -Name 'Assignment'
                if ($null -eq $assignment) { $assignment = $assignmentRow }
                $relationships.Add((New-InspectorRelationship -RelationshipType 'AssignedToAppRole' -SourceObjectId ([string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'principalId')) -SourceObjectType ([string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'principalType')) -TargetObjectId $objectId -TargetObjectType 'ServicePrincipal' -TargetDisplayName ([string](Get-InspectorSnapshotProperty -InputObject $rawObject -Name 'displayName')) -Direction 'Inbound' -Metadata @{ AssignmentId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'id'); AppRoleId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'appRoleId'); PrincipalDisplayName = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'principalDisplayName') } -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $assignmentRow -Name 'EvidenceId'))))
            }
            foreach ($grant in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.OAuth2PermissionGrantsByClientId -Key $objectId)) {
                $relationships.Add((New-InspectorRelationship -RelationshipType 'DelegatedPermissionGrant' -SourceObjectId $objectId -SourceObjectType 'ServicePrincipal' -TargetObjectId ([string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'resourceId')) -TargetObjectType 'ServicePrincipal' -Metadata @{ GrantId = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'id'); ConsentType = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'consentType'); PrincipalId = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'principalId'); Scope = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'scope') } -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'EvidenceId'))))
            }
            foreach ($grant in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.OAuth2PermissionGrantsByResourceId -Key $objectId)) {
                $relationships.Add((New-InspectorRelationship -RelationshipType 'DelegatedPermissionGrantToResource' -SourceObjectId ([string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'clientId')) -SourceObjectType 'ServicePrincipal' -TargetObjectId $objectId -TargetObjectType 'ServicePrincipal' -Direction 'Inbound' -Metadata @{ GrantId = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'id'); ConsentType = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'consentType'); PrincipalId = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'principalId'); Scope = [string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'scope') } -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $grant -Name 'EvidenceId'))))
            }
        }
        elseif ($objectType -eq 'Group') {
            foreach ($ownerRow in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.OwnersByObjectId -Key $objectId)) {
                $owner = Get-InspectorSnapshotProperty -InputObject $ownerRow -Name 'Owner'
                $relationships.Add((New-InspectorRelationship -RelationshipType 'OwnedBy' -SourceObjectId $objectId -SourceObjectType 'Group' -TargetObjectId ([string](Get-InspectorSnapshotProperty -InputObject $owner -Name 'id')) -TargetObjectType (Get-InspectorDirectoryObjectTypeName -InputObject $owner) -TargetDisplayName ([string](Get-InspectorSnapshotProperty -InputObject $owner -Name 'displayName')) -Metadata @{ ControlCategory = 'Ownership' } -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $ownerRow -Name 'EvidenceId'))))
            }
            foreach ($memberRow in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.MembersByGroupId -Key $objectId)) {
                $member = Get-InspectorSnapshotProperty -InputObject $memberRow -Name 'Member'
                $relationships.Add((New-InspectorRelationship -RelationshipType 'HasMember' -SourceObjectId $objectId -SourceObjectType 'Group' -TargetObjectId ([string](Get-InspectorSnapshotProperty -InputObject $member -Name 'id')) -TargetObjectType (Get-InspectorDirectoryObjectTypeName -InputObject $member) -TargetDisplayName ([string](Get-InspectorSnapshotProperty -InputObject $member -Name 'displayName')) -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $memberRow -Name 'EvidenceId'))))
            }
            foreach ($membershipRow in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.MembershipsByObjectId -Key $objectId)) {
                $parent = Get-InspectorSnapshotProperty -InputObject $membershipRow -Name 'Membership'
                $relationships.Add((New-InspectorRelationship -RelationshipType 'MemberOf' -SourceObjectId $objectId -SourceObjectType 'Group' -TargetObjectId ([string](Get-InspectorSnapshotProperty -InputObject $parent -Name 'id')) -TargetObjectType (Get-InspectorDirectoryObjectTypeName -InputObject $parent) -TargetDisplayName ([string](Get-InspectorSnapshotProperty -InputObject $parent -Name 'displayName')) -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $membershipRow -Name 'EvidenceId'))))
            }
        }
        elseif ($objectType -eq 'User') {
            foreach ($membershipRow in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.MembershipsByObjectId -Key $objectId)) {
                $membership = Get-InspectorSnapshotProperty -InputObject $membershipRow -Name 'Membership'
                $targetType = Get-InspectorDirectoryObjectTypeName -InputObject $membership
                $relationshipType = switch ($targetType) {
                    'group' { 'MemberOfGroup' }
                    'directoryRole' { 'MemberOfDirectoryRole' }
                    'administrativeUnit' { 'MemberOfAdministrativeUnit' }
                    default { 'TransitiveMemberOf' }
                }
                $relationships.Add((New-InspectorRelationship -RelationshipType $relationshipType -SourceObjectId $objectId -SourceObjectType 'User' -TargetObjectId ([string](Get-InspectorSnapshotProperty -InputObject $membership -Name 'id')) -TargetObjectType $targetType -TargetDisplayName ([string](Get-InspectorSnapshotProperty -InputObject $membership -Name 'displayName')) -DirectOrTransitive 'Transitive' -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $membershipRow -Name 'EvidenceId'))))
            }
        }

        foreach ($assignment in @(Get-InspectorSnapshotIndexSingle -Index $TenantSnapshot.Indexes.DirectoryRoleAssignmentsByPrincipalId -Key $objectId)) {
            $roleDefinition = Get-InspectorSnapshotProperty -InputObject $assignment -Name 'roleDefinition'
            $principalId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'principalId')
            if ($principalId -ne $objectId) {
                continue
            }

            $roleDefinitionId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'roleDefinitionId')
            $relationships.Add((New-InspectorRelationship -RelationshipType 'AssignedDirectoryRole' -SourceObjectId $objectId -SourceObjectType $objectType -TargetObjectId $roleDefinitionId -TargetObjectType 'DirectoryRoleDefinition' -TargetDisplayName ([string](Get-InspectorSnapshotProperty -InputObject $roleDefinition -Name 'displayName')) -Metadata @{ AssignmentId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'id'); RoleDefinitionId = $roleDefinitionId; RoleDisplayName = [string](Get-InspectorSnapshotProperty -InputObject $roleDefinition -Name 'displayName'); DirectoryScopeId = [string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'directoryScopeId'); PrincipalId = $principalId } -EvidenceId ([string](Get-InspectorSnapshotProperty -InputObject $assignment -Name 'EvidenceId') )))
        }

        # Include every object-scoped snapshot query for this candidate, even
        # when the query returned zero rows. Zero-result successful evidence is
        # required to prove ownerless/memberless/assignment-absence conditions,
        # while failed evidence must make the relationship collection partial.
        $candidateEvidenceRows =
            if ($null -ne $objectRelationshipEvidenceIndex) {
                @(Get-InspectorSnapshotIndexSingle -Index $objectRelationshipEvidenceIndex -Key ("$objectType|$objectId"))
            }
            else {
                @($TenantSnapshot.Evidence | Where-Object {
                    [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'EvidenceScope') -eq 'ObjectRelationship' -and
                    [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'SubjectObjectType') -eq $objectType -and
                    [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'SubjectObjectId') -eq $objectId
                })
            }

        foreach ($candidateEvidence in @($candidateEvidenceRows)) {
            $candidateEvidenceIdValue = [string](Get-InspectorSnapshotProperty -InputObject $candidateEvidence -Name 'EvidenceId')
            if (-not [string]::IsNullOrWhiteSpace($candidateEvidenceIdValue) -and -not $evidenceIdsSeen.ContainsKey($candidateEvidenceIdValue)) {
                $evidenceIdsSeen[$candidateEvidenceIdValue] = $true
                $evidence.Add($candidateEvidence)
            }
            foreach ($limitation in @(Get-InspectorSnapshotProperty -InputObject $candidateEvidence -Name 'Limitations')) {
                if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) { $collectorLimitations.Add([string]$limitation) }
            }
        }

        $directEvidenceIds =
            @(
                @($relationships) | ForEach-Object { Get-InspectorSnapshotProperty -InputObject $_ -Name 'EvidenceId' }
                @($artifacts) | ForEach-Object { Get-InspectorSnapshotProperty -InputObject $_ -Name 'EvidenceId' }
            ) |
            ForEach-Object { [string]$_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique

        foreach ($directEvidenceId in $directEvidenceIds) {
            if ($snapshotEvidenceById.ContainsKey($directEvidenceId) -and -not $evidenceIdsSeen.ContainsKey($directEvidenceId)) {
                $evidenceIdsSeen[$directEvidenceId] = $true
                foreach ($indexedEvidence in @(Get-InspectorSnapshotIndexSingle -Index $snapshotEvidenceById -Key $directEvidenceId)) {
                    $evidence.Add($indexedEvidence)
                }
            }
        }

        $collectorResult = New-InspectorCollectorResult -CollectorName $collectorName -SourceObjectType $objectType -SourceObjectId $objectId -Evidence @($evidence) -Relationships @($relationships) -Artifacts @($artifacts) -Properties $properties -Limitations @($collectorLimitations | Select-Object -Unique)

        # Backward compatibility for pre-coverage snapshot fixtures/artifacts:
        # older snapshots did not persist object-scoped evidence envelopes, but
        # relationships could still be deterministically projected from complete
        # in-memory indexes. Do not apply this fallback to current snapshots that
        # expose AssessmentCoverage; their evidence status is authoritative and
        # must remain fail-closed.
        $assessmentCoverage = Get-InspectorSnapshotProperty -InputObject $TenantSnapshot -Name 'AssessmentCoverage'
        if ($null -eq $assessmentCoverage -and @($evidence).Count -eq 0) {
            $collectorResult.Status = 'Success'
            $collectorResult.Completeness = 'Complete'
        }

        $collectorResults.Add($collectorResult)
    }

    $collectorStatuses = @($collectorResults | ForEach-Object { [string]$_.Status })
    $overallStatus =
        if (@($collectorStatuses | Where-Object { $_ -eq 'Failed' }).Count -gt 0) { 'Failed' }
        elseif (@($collectorStatuses | Where-Object { $_ -eq 'InsufficientPermission' }).Count -gt 0) { 'InsufficientPermission' }
        elseif (@($collectorStatuses | Where-Object { $_ -eq 'Success' }).Count -gt 0) { 'Success' }
        elseif (@($collectorStatuses | Where-Object { $_ -eq 'NotFound' }).Count -gt 0) { 'NotFound' }
        else { 'NotApplicable' }

    $overallCompleteness =
        if (@($collectorResults | Where-Object { [string]$_.Completeness -eq 'Partial' }).Count -gt 0) { 'Partial' }
        else { 'Complete' }

    return [PSCustomObject][ordered]@{
        PSTypeName       = 'EntraObjectInspector.RelationshipCollection'
        Status           = $overallStatus
        Completeness     = $overallCompleteness
        CollectorResults = @($collectorResults)
        Relationships    = @($collectorResults | ForEach-Object { @($_.Relationships) })
        Artifacts        = @($collectorResults | ForEach-Object { @($_.Artifacts) })
        Evidence         = @($collectorResults | ForEach-Object { @($_.Evidence) })
        Limitations      = @($collectorResults | ForEach-Object { @($_.Limitations) } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    }
}
