function Get-InspectorServicePrincipalRelationships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Candidate
    )

    $collectorName = 'ServicePrincipalRelationships'
    $objectType = [string]$Candidate.ObjectType
    $objectId = [string]$Candidate.Identifiers.ObjectId

    if ($objectType -ne 'ServicePrincipal') {
        return New-InspectorNotApplicableCollectorResult `
            -CollectorName $collectorName `
            -ExpectedObjectType 'ServicePrincipal' `
            -ActualObjectType $objectType `
            -SourceObjectId $objectId
    }

    $graphBaseUri = 'https://graph.microsoft.com/v1.0'
    $evidence = [System.Collections.Generic.List[object]]::new()
    $relationships = [System.Collections.Generic.List[object]]::new()
    $artifacts = [System.Collections.Generic.List[object]]::new()
    $limitations = [System.Collections.Generic.List[string]]::new()

    $metadataEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'ServicePrincipalMetadata' `
        -Uri "$graphBaseUri/servicePrincipals/${objectId}" `
        -RequiredPermission 'Application.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'ServicePrincipal' `
        -SubjectObjectId $objectId

    $evidence.Add($metadataEvidence)

    if ($metadataEvidence.Status -ne 'Success') {
        return New-InspectorCollectorResult `
            -CollectorName $collectorName `
            -SourceObjectType 'ServicePrincipal' `
            -SourceObjectId $objectId `
            -Evidence @($evidence) `
            -Limitations @($metadataEvidence.Limitations)
    }

    $servicePrincipal = @($metadataEvidence.Result) | Select-Object -First 1
    $appId = [string](Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'appId')

    foreach ($credential in @(
        Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'keyCredentials'
    )) {
        if ($null -ne $credential) {
            $artifacts.Add(
                (ConvertTo-InspectorCredentialArtifact `
                    -SourceObjectType 'ServicePrincipal' `
                    -SourceObjectId $objectId `
                    -CredentialType 'Certificate' `
                    -Credential $credential `
                    -EvidenceId $metadataEvidence.EvidenceId)
            )
        }
    }

    foreach ($credential in @(
        Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'passwordCredentials'
    )) {
        if ($null -ne $credential) {
            $artifacts.Add(
                (ConvertTo-InspectorCredentialArtifact `
                    -SourceObjectType 'ServicePrincipal' `
                    -SourceObjectId $objectId `
                    -CredentialType 'Password' `
                    -Credential $credential `
                    -EvidenceId $metadataEvidence.EvidenceId)
            )
        }
    }

    $ownersEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'ServicePrincipalOwners' `
        -Uri "$graphBaseUri/servicePrincipals/${objectId}/owners?`$select=id,displayName" `
        -RequiredPermission 'Application.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'ServicePrincipal' `
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
                    -SourceObjectType 'ServicePrincipal' `
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

    if (-not [string]::IsNullOrWhiteSpace($appId)) {
        $counterpartEvidence = Invoke-InspectorCollectorQuery `
            -CollectorName $collectorName `
            -QueryName 'ApplicationCounterpart' `
            -Uri "$graphBaseUri/applications(appId='$appId')?`$select=id,appId,displayName" `
            -RequiredPermission 'Application.Read.All' `
            -EvidenceScope 'ObjectRelationship' `
            -SubjectObjectType 'ServicePrincipal' `
            -SubjectObjectId $objectId

        $evidence.Add($counterpartEvidence)

        if ($counterpartEvidence.Status -eq 'Success') {
            foreach ($application in @($counterpartEvidence.Result)) {
                if ($null -eq $application) {
                    continue
                }

                $applicationId = [string](Get-InspectorCollectorProperty -InputObject $application -Name 'id')

                if ([string]::IsNullOrWhiteSpace($applicationId)) {
                    continue
                }

                $relationships.Add(
                    (New-InspectorRelationship `
                        -RelationshipType 'ServicePrincipalToApplication' `
                        -SourceObjectId $objectId `
                        -SourceObjectType 'ServicePrincipal' `
                        -TargetObjectId $applicationId `
                        -TargetObjectType 'Application' `
                        -TargetDisplayName ([string](Get-InspectorCollectorProperty -InputObject $application -Name 'displayName')) `
                        -DirectOrTransitive 'Direct' `
                        -Direction 'Outbound' `
                        -Metadata @{ AppId = $appId } `
                        -EvidenceId $counterpartEvidence.EvidenceId)
                )
            }
        }
    }

    $appRoleAssignmentsEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'GrantedApplicationPermissions' `
        -Uri "$graphBaseUri/servicePrincipals/${objectId}/appRoleAssignments" `
        -RequiredPermission 'Application.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'ServicePrincipal' `
        -SubjectObjectId $objectId

    $evidence.Add($appRoleAssignmentsEvidence)

    if ($appRoleAssignmentsEvidence.Status -eq 'Success') {
        foreach ($assignment in @($appRoleAssignmentsEvidence.Result)) {
            if ($null -eq $assignment) {
                continue
            }

            $resourceId = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'resourceId')

            if ([string]::IsNullOrWhiteSpace($resourceId)) {
                continue
            }

            $relationships.Add(
                (New-InspectorRelationship `
                    -RelationshipType 'GrantedAppRole' `
                    -SourceObjectId $objectId `
                    -SourceObjectType 'ServicePrincipal' `
                    -TargetObjectId $resourceId `
                    -TargetObjectType 'ServicePrincipal' `
                    -TargetDisplayName ([string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'resourceDisplayName')) `
                    -DirectOrTransitive 'Direct' `
                    -Direction 'Outbound' `
                    -Metadata @{
                        AssignmentId = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'id')
                        AppRoleId    = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'appRoleId')
                    } `
                    -EvidenceId $appRoleAssignmentsEvidence.EvidenceId)
            )
        }
    }

    $appRoleAssignedToEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'IncomingAppRoleAssignments' `
        -Uri "$graphBaseUri/servicePrincipals/${objectId}/appRoleAssignedTo" `
        -RequiredPermission 'Application.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'ServicePrincipal' `
        -SubjectObjectId $objectId

    $evidence.Add($appRoleAssignedToEvidence)

    if ($appRoleAssignedToEvidence.Status -eq 'Success') {
        foreach ($assignment in @($appRoleAssignedToEvidence.Result)) {
            if ($null -eq $assignment) {
                continue
            }

            $principalId = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'principalId')

            if ([string]::IsNullOrWhiteSpace($principalId)) {
                continue
            }

            $relationships.Add(
                (New-InspectorRelationship `
                    -RelationshipType 'AssignedToAppRole' `
                    -SourceObjectId $principalId `
                    -SourceObjectType ([string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'principalType')) `
                    -TargetObjectId $objectId `
                    -TargetObjectType 'ServicePrincipal' `
                    -TargetDisplayName ([string](Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'displayName')) `
                    -DirectOrTransitive 'Direct' `
                    -Direction 'Inbound' `
                    -Metadata @{
                        AssignmentId = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'id')
                        AppRoleId    = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'appRoleId')
                        PrincipalDisplayName = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'principalDisplayName')
                    } `
                    -EvidenceId $appRoleAssignedToEvidence.EvidenceId)
            )
        }
    }

    $clientFilter = [uri]::EscapeDataString("clientId eq '$objectId'")
    $outgoingOauthEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'OutgoingDelegatedPermissionGrants' `
        -Uri "$graphBaseUri/oauth2PermissionGrants?`$filter=${clientFilter}" `
        -RequiredPermission 'Directory.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'ServicePrincipal' `
        -SubjectObjectId $objectId

    $evidence.Add($outgoingOauthEvidence)

    if ($outgoingOauthEvidence.Status -eq 'Success') {
        foreach ($grant in @($outgoingOauthEvidence.Result)) {
            if ($null -eq $grant) {
                continue
            }

            $resourceId = [string](Get-InspectorCollectorProperty -InputObject $grant -Name 'resourceId')

            if ([string]::IsNullOrWhiteSpace($resourceId)) {
                continue
            }

            $relationships.Add(
                (New-InspectorRelationship `
                    -RelationshipType 'DelegatedPermissionGrant' `
                    -SourceObjectId $objectId `
                    -SourceObjectType 'ServicePrincipal' `
                    -TargetObjectId $resourceId `
                    -TargetObjectType 'ServicePrincipal' `
                    -DirectOrTransitive 'Direct' `
                    -Direction 'Outbound' `
                    -Metadata @{
                        GrantId      = [string](Get-InspectorCollectorProperty -InputObject $grant -Name 'id')
                        ConsentType  = [string](Get-InspectorCollectorProperty -InputObject $grant -Name 'consentType')
                        PrincipalId  = [string](Get-InspectorCollectorProperty -InputObject $grant -Name 'principalId')
                        Scope        = [string](Get-InspectorCollectorProperty -InputObject $grant -Name 'scope')
                    } `
                    -EvidenceId $outgoingOauthEvidence.EvidenceId)
            )
        }
    }

    $resourceFilter = [uri]::EscapeDataString("resourceId eq '$objectId'")
    $incomingOauthEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'IncomingDelegatedPermissionGrants' `
        -Uri "$graphBaseUri/oauth2PermissionGrants?`$filter=${resourceFilter}" `
        -RequiredPermission 'Directory.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'ServicePrincipal' `
        -SubjectObjectId $objectId

    $evidence.Add($incomingOauthEvidence)

    if ($incomingOauthEvidence.Status -eq 'Success') {
        foreach ($grant in @($incomingOauthEvidence.Result)) {
            if ($null -eq $grant) {
                continue
            }

            $clientId = [string](Get-InspectorCollectorProperty -InputObject $grant -Name 'clientId')

            if ([string]::IsNullOrWhiteSpace($clientId)) {
                continue
            }

            $relationships.Add(
                (New-InspectorRelationship `
                    -RelationshipType 'DelegatedPermissionGrantToResource' `
                    -SourceObjectId $clientId `
                    -SourceObjectType 'ServicePrincipal' `
                    -TargetObjectId $objectId `
                    -TargetObjectType 'ServicePrincipal' `
                    -DirectOrTransitive 'Direct' `
                    -Direction 'Inbound' `
                    -Metadata @{
                        GrantId      = [string](Get-InspectorCollectorProperty -InputObject $grant -Name 'id')
                        ConsentType  = [string](Get-InspectorCollectorProperty -InputObject $grant -Name 'consentType')
                        PrincipalId  = [string](Get-InspectorCollectorProperty -InputObject $grant -Name 'principalId')
                        Scope        = [string](Get-InspectorCollectorProperty -InputObject $grant -Name 'scope')
                    } `
                    -EvidenceId $incomingOauthEvidence.EvidenceId)
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
        -SubjectObjectType 'ServicePrincipal' `
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
                    -SourceObjectType 'ServicePrincipal' `
                    -TargetObjectId $roleDefinitionId `
                    -TargetObjectType 'DirectoryRoleDefinition' `
                    -TargetDisplayName ([string](Get-InspectorCollectorProperty -InputObject $roleDefinition -Name 'displayName')) `
                    -DirectOrTransitive 'Direct' `
                    -Direction 'Outbound' `
                    -Metadata @{
                        AssignmentId    = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'id')
                        DirectoryScopeId = [string](Get-InspectorCollectorProperty -InputObject $assignment -Name 'directoryScopeId')
                    } `
                    -EvidenceId $roleAssignmentsEvidence.EvidenceId)
            )
        }
    }

    $properties = [PSCustomObject][ordered]@{
        Id                        = $objectId
        AppId                     = $appId
        DisplayName               = [string](Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'displayName')
        AccountEnabled            = Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'accountEnabled'
        AppRoleAssignmentRequired = Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'appRoleAssignmentRequired'
        ServicePrincipalType      = [string](Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'servicePrincipalType')
        Tags                      = @(Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'tags')
        AppRoles                  = @(Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'appRoles')
    }

    if (
        $outgoingOauthEvidence.Status -eq 'InsufficientPermission' -or
        $incomingOauthEvidence.Status -eq 'InsufficientPermission'
    ) {
        $limitations.Add(
            'Delegated permission grant collection was denied. Microsoft Graph v1.0 currently documents Directory.Read.All as the least-privileged application permission for this method.'
        )
    }

    return New-InspectorCollectorResult `
        -CollectorName $collectorName `
        -SourceObjectType 'ServicePrincipal' `
        -SourceObjectId $objectId `
        -Evidence @($evidence) `
        -Relationships @($relationships) `
        -Artifacts @($artifacts) `
        -Properties $properties `
        -Limitations @($limitations)
}
