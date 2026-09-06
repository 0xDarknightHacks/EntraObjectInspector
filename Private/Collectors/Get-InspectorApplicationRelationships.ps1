function Get-InspectorApplicationRelationships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Candidate
    )

    $collectorName = 'ApplicationRelationships'
    $objectType = [string]$Candidate.ObjectType
    $objectId = [string]$Candidate.Identifiers.ObjectId

    if ($objectType -ne 'Application') {
        return New-InspectorNotApplicableCollectorResult `
            -CollectorName $collectorName `
            -ExpectedObjectType 'Application' `
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
        -QueryName 'ApplicationMetadata' `
        -Uri "$graphBaseUri/applications/${objectId}" `
        -RequiredPermission 'Application.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'Application' `
        -SubjectObjectId $objectId

    $evidence.Add($metadataEvidence)

    if ($metadataEvidence.Status -ne 'Success') {
        return New-InspectorCollectorResult `
            -CollectorName $collectorName `
            -SourceObjectType 'Application' `
            -SourceObjectId $objectId `
            -Evidence @($evidence) `
            -Limitations @($metadataEvidence.Limitations)
    }

    $application = @($metadataEvidence.Result) | Select-Object -First 1

    if ($null -eq $application) {
        $limitations.Add('Application metadata query returned no object.')
        return New-InspectorCollectorResult `
            -CollectorName $collectorName `
            -SourceObjectType 'Application' `
            -SourceObjectId $objectId `
            -Evidence @($evidence) `
            -Limitations @($limitations)
    }

    $appId = [string](Get-InspectorCollectorProperty -InputObject $application -Name 'appId')

    foreach ($credential in @(
        Get-InspectorCollectorProperty -InputObject $application -Name 'keyCredentials'
    )) {
        if ($null -ne $credential) {
            $artifacts.Add(
                (ConvertTo-InspectorCredentialArtifact `
                    -SourceObjectType 'Application' `
                    -SourceObjectId $objectId `
                    -CredentialType 'Certificate' `
                    -Credential $credential `
                    -EvidenceId $metadataEvidence.EvidenceId)
            )
        }
    }

    foreach ($credential in @(
        Get-InspectorCollectorProperty -InputObject $application -Name 'passwordCredentials'
    )) {
        if ($null -ne $credential) {
            $artifacts.Add(
                (ConvertTo-InspectorCredentialArtifact `
                    -SourceObjectType 'Application' `
                    -SourceObjectId $objectId `
                    -CredentialType 'Password' `
                    -Credential $credential `
                    -EvidenceId $metadataEvidence.EvidenceId)
            )
        }
    }

    $ownersEvidence = Invoke-InspectorCollectorQuery `
        -CollectorName $collectorName `
        -QueryName 'ApplicationOwners' `
        -Uri "$graphBaseUri/applications/${objectId}/owners?`$select=id,displayName" `
        -RequiredPermission 'Application.Read.All' `
        -EvidenceScope 'ObjectRelationship' `
        -SubjectObjectType 'Application' `
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
                    -SourceObjectType 'Application' `
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
            -QueryName 'ServicePrincipalCounterpart' `
            -Uri "$graphBaseUri/servicePrincipals(appId='$appId')?`$select=id,appId,displayName,servicePrincipalType" `
            -RequiredPermission 'Application.Read.All'

        $evidence.Add($counterpartEvidence)

        if ($counterpartEvidence.Status -eq 'Success') {
            foreach ($servicePrincipal in @($counterpartEvidence.Result)) {
                if ($null -eq $servicePrincipal) {
                    continue
                }

                $spId = [string](Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'id')

                if ([string]::IsNullOrWhiteSpace($spId)) {
                    continue
                }

                $relationships.Add(
                    (New-InspectorRelationship `
                        -RelationshipType 'ApplicationToServicePrincipal' `
                        -SourceObjectId $objectId `
                        -SourceObjectType 'Application' `
                        -TargetObjectId $spId `
                        -TargetObjectType 'ServicePrincipal' `
                        -TargetDisplayName ([string](Get-InspectorCollectorProperty -InputObject $servicePrincipal -Name 'displayName')) `
                        -DirectOrTransitive 'Direct' `
                        -Direction 'Outbound' `
                        -Metadata @{ AppId = $appId } `
                        -EvidenceId $counterpartEvidence.EvidenceId)
                )
            }
        }
    }

    $properties = [PSCustomObject][ordered]@{
        Id                     = $objectId
        AppId                  = $appId
        DisplayName            = [string](Get-InspectorCollectorProperty -InputObject $application -Name 'displayName')
        SignInAudience         = [string](Get-InspectorCollectorProperty -InputObject $application -Name 'signInAudience')
        PublisherDomain        = [string](Get-InspectorCollectorProperty -InputObject $application -Name 'publisherDomain')
        VerifiedPublisher      = Get-InspectorCollectorProperty -InputObject $application -Name 'verifiedPublisher'
        AppRoles               = @(Get-InspectorCollectorProperty -InputObject $application -Name 'appRoles')
        RequiredResourceAccess = @(Get-InspectorCollectorProperty -InputObject $application -Name 'requiredResourceAccess')
    }

    return New-InspectorCollectorResult `
        -CollectorName $collectorName `
        -SourceObjectType 'Application' `
        -SourceObjectId $objectId `
        -Evidence @($evidence) `
        -Relationships @($relationships) `
        -Artifacts @($artifacts) `
        -Properties $properties `
        -Limitations @($limitations)
}
