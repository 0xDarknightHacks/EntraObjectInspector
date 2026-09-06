function Invoke-InspectorRules {
    <#
    .SYNOPSIS
        Evaluates the baseline rules over existing ObjectInsight data.

    .DESCRIPTION
        This rule engine never calls Microsoft Graph. It evaluates only the
        normalized resolver, collector, relationship, artifact, and evidence
        data that already exists in ObjectInsight.

        No numerical risk score is produced.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [int]$CredentialExpiryWarningDays = 30
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $now = (Get-Date).ToUniversalTime()
    $expiryCutoff = $now.AddDays($CredentialExpiryWarningDays)

    $ownerReference =
        'Microsoft Entra enterprise application ownership guidance: monitor applications to ensure at least two owners where possible.'

    $credentialReference =
        'Microsoft Entra application credential guidance: renew application credentials before expiration to avoid application downtime.'

    $appPermissionReference =
        'Microsoft Graph app role assignments represent application permissions granted to a service principal.'

    $servicePrincipalReference =
        'Microsoft Entra service principal properties include accountEnabled and appRoleAssignmentRequired for application access control.'

    # APP-OWNER-001 / APP-OWNER-002
    foreach ($sourceObject in Get-InspectorSourceObjectsByType `
        -ObjectInsight $ObjectInsight `
        -ObjectType @('Application', 'ServicePrincipal')) {

        $objectId = [string]$sourceObject.ObjectId
        $objectType = [string]$sourceObject.ObjectType
        $displayName = Get-InspectorObjectDisplayName -SourceObject $sourceObject

        $owners = @(
            Get-InspectorRelationshipsForSource `
                -ObjectInsight $ObjectInsight `
                -SourceObjectId $objectId `
                -RelationshipType @('OwnedBy')
        )

        if ($owners.Count -eq 0) {
            $results.Add(
                (New-InspectorRuleResult `
                    -RuleId 'APP-OWNER-001' `
                    -Title "$objectType has no owner" `
                    -Severity 'High' `
                    -Description "No owner relationship was collected for '$displayName'." `
                    -EvidenceIds @() `
                    -Source $ownerReference `
                    -Confidence 'Medium' `
                    -Limitations @(
                        'This rule relies on owner relationship collection. Verify collector completeness before using the finding operationally.'
                    ) `
                    -Metadata @{
                        ObjectType = $objectType
                        ObjectId   = $objectId
                        DisplayName = $displayName
                    })
            )
        }
        elseif ($owners.Count -eq 1) {
            $results.Add(
                (New-InspectorRuleResult `
                    -RuleId 'APP-OWNER-002' `
                    -Title "$objectType has a single owner" `
                    -Severity 'Medium' `
                    -Description "Only one owner relationship was collected for '$displayName'." `
                    -EvidenceIds (Get-InspectorEvidenceIdsFromItems -Items $owners) `
                    -Source $ownerReference `
                    -Confidence 'High' `
                    -Limitations @() `
                    -Metadata @{
                        ObjectType = $objectType
                        ObjectId   = $objectId
                        DisplayName = $displayName
                        OwnerCount = $owners.Count
                    })
            )
        }
    }

    # CRED-001 / CRED-002
    foreach ($credential in @(
        Get-InspectorRuleProperty -InputObject $ObjectInsight -Name 'Artifacts'
    ) | Where-Object { (Get-InspectorRuleProperty -InputObject $_ -Name 'ArtifactType') -eq 'CredentialMetadata' }) {
        $credentialEvidenceId = [string](Get-InspectorRuleProperty -InputObject $credential -Name 'EvidenceId')
        if ([string]::IsNullOrWhiteSpace($credentialEvidenceId)) {
            $credentialEvidenceId = [string](Get-InspectorRuleProperty -InputObject $credential -Name 'ParentEvidenceId')
        }
        $credentialEvidenceIds =
            if ([string]::IsNullOrWhiteSpace($credentialEvidenceId)) {
                @()
            }
            else {
                @($credentialEvidenceId)
            }
        $credentialSourceObjectType = [string](Get-InspectorRuleProperty -InputObject $credential -Name 'SourceObjectType')
        $credentialSourceObjectId = [string](Get-InspectorRuleProperty -InputObject $credential -Name 'SourceObjectId')
        $credentialType = [string](Get-InspectorRuleProperty -InputObject $credential -Name 'CredentialType')
        $credentialKeyId = [string](Get-InspectorRuleProperty -InputObject $credential -Name 'KeyId')

        $endDateRaw =
            Get-InspectorRuleProperty `
                -InputObject $credential `
                -Name 'EndDateTime'

        if ($null -eq $endDateRaw) {
            continue
        }

        $endDate = [datetime]::MinValue

        if (-not [datetime]::TryParse([string]$endDateRaw, [ref]$endDate)) {
            continue
        }

        $endDateUtc = $endDate.ToUniversalTime()
        $credentialDisplayName =
            [string](Get-InspectorRuleProperty `
                -InputObject $credential `
                -Name 'DisplayName')

        if ([string]::IsNullOrWhiteSpace($credentialDisplayName)) {
            $credentialDisplayName =
                [string](Get-InspectorRuleProperty `
                    -InputObject $credential `
                    -Name 'KeyId')
        }

        if ($endDateUtc -lt $now) {
            $results.Add(
                (New-InspectorRuleResult `
                    -RuleId 'CRED-002' `
                    -Title 'Expired credential is still present' `
                    -Severity 'High' `
                    -Description "Credential '$credentialDisplayName' expired on $($endDateUtc.ToString('o'))." `
                    -EvidenceIds $credentialEvidenceIds `
                    -Source $credentialReference `
                    -Confidence 'High' `
                    -Limitations @(
                        'The rule evaluates credential metadata only. It does not prove whether the credential is still used.'
                    ) `
                    -Metadata @{
                        SourceObjectType = $credentialSourceObjectType
                        SourceObjectId   = $credentialSourceObjectId
                        CredentialType   = $credentialType
                        KeyId            = $credentialKeyId
                        ParentEvidenceId = $credentialEvidenceId
                        EndDateTime      = $endDateUtc.ToString('o')
                    })
            )
        }
        elseif ($endDateUtc -le $expiryCutoff) {
            $results.Add(
                (New-InspectorRuleResult `
                    -RuleId 'CRED-001' `
                    -Title 'Credential expires soon' `
                    -Severity 'Medium' `
                    -Description "Credential '$credentialDisplayName' expires within $CredentialExpiryWarningDays days." `
                    -EvidenceIds $credentialEvidenceIds `
                    -Source $credentialReference `
                    -Confidence 'High' `
                    -Limitations @(
                        'The rule evaluates credential metadata only. It does not prove whether the credential is actively used.'
                    ) `
                    -Metadata @{
                        SourceObjectType = $credentialSourceObjectType
                        SourceObjectId   = $credentialSourceObjectId
                        CredentialType   = $credentialType
                        KeyId            = $credentialKeyId
                        ParentEvidenceId = $credentialEvidenceId
                        EndDateTime      = $endDateUtc.ToString('o')
                        WarningDays      = $CredentialExpiryWarningDays
                    })
            )
        }
    }

    # PERM-APP-001
    $applicationPermissionRelationships = @(
        Get-InspectorRuleProperty -InputObject $ObjectInsight -Name 'Relationships'
    ) | Where-Object {
        $_.RelationshipType -eq 'GrantedAppRole'
    }

    foreach ($relationship in $applicationPermissionRelationships) {
        $results.Add(
            (New-InspectorRuleResult `
                -RuleId 'PERM-APP-001' `
                -Title 'Application permission is granted' `
                -Severity 'Informational' `
                -Description "A service principal has an app role assignment to '$($relationship.TargetDisplayName)'." `
                -EvidenceIds @($relationship.EvidenceId) `
                -Source $appPermissionReference `
                -Confidence 'High' `
                -Limitations @(
                    'This rule records the presence of an application permission. It does not classify the permission as excessive.'
                ) `
                -Metadata @{
                    SourceObjectId = $relationship.SourceObjectId
                    TargetObjectId = $relationship.TargetObjectId
                    TargetDisplayName = $relationship.TargetDisplayName
                    AppRoleId = [string](Get-InspectorMetadataValue -Metadata $relationship.Metadata -Name 'AppRoleId')
                })
        )
    }

    # PERM-GRAPH-HIGH-001
    $permissionInsights = @(
        (Get-InspectorRuleProperty `
            -InputObject $ObjectInsight `
            -Name 'PermissionInsights') |
        Where-Object { $null -ne $_ }
    )

    if (@($permissionInsights).Count -gt 0) {
        foreach ($permissionInsight in $permissionInsights) {
            if ($permissionInsight.ResourceDisplayName -ne 'Microsoft Graph') {
                continue
            }

            if ($permissionInsight.IsHighImpact -ne $true) {
                continue
            }

            $results.Add(
                (New-InspectorRuleResult `
                    -RuleId 'PERM-GRAPH-HIGH-001' `
                    -Title 'High-impact Microsoft Graph application permission is granted' `
                    -Severity 'High' `
                    -Description "Microsoft Graph application permission '$($permissionInsight.PermissionName)' is granted." `
                    -EvidenceIds @($permissionInsight.RelationshipEvidenceId) `
                    -Source 'Microsoft Graph permissions reference.' `
                    -Confidence $permissionInsight.Confidence `
                    -Limitations @(
                        'This rule uses the local permission catalog. Keep the catalog aligned with the Microsoft Graph permissions reference.'
                    ) `
                    -Metadata @{
                        SourceObjectId = $permissionInsight.SourceObjectId
                        PermissionName = $permissionInsight.PermissionName
                        AppRoleId = $permissionInsight.AppRoleId
                        PermissionCategory = $permissionInsight.PermissionCategory
                        AdministrativeImpact = $permissionInsight.AdministrativeImpact
                    })
            )
        }
    }
    else {
        $highImpactPermissionNames = @(
            'Directory.Read.All',
            'Directory.ReadWrite.All',
            'RoleManagement.ReadWrite.Directory',
            'AppRoleAssignment.ReadWrite.All',
            'Application.ReadWrite.All',
            'User.ReadWrite.All',
            'Group.ReadWrite.All'
        )

        foreach ($relationship in $applicationPermissionRelationships) {
            if ($relationship.TargetDisplayName -ne 'Microsoft Graph') {
                continue
            }

            $permissionName =
                [string](Get-InspectorMetadataValue `
                    -Metadata $relationship.Metadata `
                    -Name 'PermissionName')

            if (
                [string]::IsNullOrWhiteSpace($permissionName) -or
                $permissionName -notin $highImpactPermissionNames
            ) {
                continue
            }

            $results.Add(
                (New-InspectorRuleResult `
                    -RuleId 'PERM-GRAPH-HIGH-001' `
                    -Title 'High-impact Microsoft Graph application permission is granted' `
                    -Severity 'High' `
                    -Description "Microsoft Graph application permission '$permissionName' is granted." `
                    -EvidenceIds @($relationship.EvidenceId) `
                    -Source 'Microsoft Graph permissions reference.' `
                    -Confidence 'Medium' `
                    -Limitations @(
                        'Fallback mode: relationship metadata included a permission name, but PermissionInsights were not present.'
                    ) `
                    -Metadata @{
                        SourceObjectId = $relationship.SourceObjectId
                        PermissionName = $permissionName
                        AppRoleId = [string](Get-InspectorMetadataValue -Metadata $relationship.Metadata -Name 'AppRoleId')
                    })
            )
        }
    }

    # APP-OWNERSHIP-001
    $applicationIdentity =
        Get-InspectorRuleProperty `
            -InputObject $ObjectInsight `
            -Name 'ApplicationIdentity'

    if ($null -ne $applicationIdentity) {
        $applicationObjectId =
            [string](Get-InspectorRuleProperty `
                -InputObject $applicationIdentity `
                -Name 'ApplicationObjectId')

        $servicePrincipalObjectId =
            [string](Get-InspectorRuleProperty `
                -InputObject $applicationIdentity `
                -Name 'ServicePrincipalObjectId')

        if (
            -not [string]::IsNullOrWhiteSpace($applicationObjectId) -and
            -not [string]::IsNullOrWhiteSpace($servicePrincipalObjectId)
        ) {
            $applicationOwners = @(
                Get-InspectorRelationshipsForSource `
                    -ObjectInsight $ObjectInsight `
                    -SourceObjectId $applicationObjectId `
                    -RelationshipType @('OwnedBy')
            )

            $servicePrincipalOwners = @(
                Get-InspectorRelationshipsForSource `
                    -ObjectInsight $ObjectInsight `
                    -SourceObjectId $servicePrincipalObjectId `
                    -RelationshipType @('OwnedBy')
            )

            $applicationOwnerIds = @(
                $applicationOwners |
                ForEach-Object { $_.TargetObjectId } |
                Sort-Object -Unique
            )

            $servicePrincipalOwnerIds = @(
                $servicePrincipalOwners |
                ForEach-Object { $_.TargetObjectId } |
                Sort-Object -Unique
            )

            $ownerSetsDiffer =
                (@($applicationOwnerIds | Where-Object {
                    $_ -notin $servicePrincipalOwnerIds
                }).Count -gt 0) -or
                (@($servicePrincipalOwnerIds | Where-Object {
                    $_ -notin $applicationOwnerIds
                }).Count -gt 0)

            if ($ownerSetsDiffer) {
                $results.Add(
                    (New-InspectorRuleResult `
                        -RuleId 'APP-OWNERSHIP-001' `
                        -Title 'Application and service principal owners differ' `
                        -Severity 'Low' `
                        -Description 'The application object and its service principal have different owner sets.' `
                        -EvidenceIds (Get-InspectorEvidenceIdsFromItems -Items @($applicationOwners + $servicePrincipalOwners)) `
                        -Source 'Microsoft Entra separates application objects from service principals; each object has its own owners relationship.' `
                        -Confidence 'High' `
                        -Limitations @(
                            'Ownership difference is an operational observation, not automatically a misconfiguration.'
                        ) `
                        -Metadata @{
                            ApplicationObjectId = $applicationObjectId
                            ServicePrincipalObjectId = $servicePrincipalObjectId
                            ApplicationOwnerCount = $applicationOwnerIds.Count
                            ServicePrincipalOwnerCount = $servicePrincipalOwnerIds.Count
                        })
                )
            }
        }
    }

    # SP-STATE-001 / SP-STATE-002 / SP-STATE-003
    foreach ($sourceObject in Get-InspectorSourceObjectsByType `
        -ObjectInsight $ObjectInsight `
        -ObjectType @('ServicePrincipal')) {

        $properties =
            Get-InspectorRuleProperty `
                -InputObject $sourceObject `
                -Name 'Properties'

        $accountEnabled =
            Get-InspectorRuleProperty `
                -InputObject $properties `
                -Name 'AccountEnabled'

        $assignmentRequired =
            Get-InspectorRuleProperty `
                -InputObject $properties `
                -Name 'AppRoleAssignmentRequired'

        $objectId = [string]$sourceObject.ObjectId
        $displayName = Get-InspectorObjectDisplayName -SourceObject $sourceObject

        if ($accountEnabled -eq $false) {
            $results.Add(
                (New-InspectorRuleResult `
                    -RuleId 'SP-STATE-001' `
                    -Title 'Service principal is disabled' `
                    -Severity 'Informational' `
                    -Description "Service principal '$displayName' has accountEnabled set to false." `
                    -EvidenceIds @() `
                    -Source $servicePrincipalReference `
                    -Confidence 'High' `
                    -Limitations @(
                        'This is a state observation. It is not automatically a negative finding.'
                    ) `
                    -Metadata @{
                        ServicePrincipalObjectId = $objectId
                        AccountEnabled = $false
                    })
            )
        }

        if ($assignmentRequired -eq $true) {
            $results.Add(
                (New-InspectorRuleResult `
                    -RuleId 'SP-STATE-002' `
                    -Title 'Service principal requires assignment' `
                    -Severity 'Informational' `
                    -Description "Service principal '$displayName' has appRoleAssignmentRequired set to true." `
                    -EvidenceIds @() `
                    -Source $servicePrincipalReference `
                    -Confidence 'High' `
                    -Limitations @(
                        'This is a state observation showing access is constrained to assigned principals.'
                    ) `
                    -Metadata @{
                        ServicePrincipalObjectId = $objectId
                        AppRoleAssignmentRequired = $true
                    })
            )
        }
        elseif ($assignmentRequired -eq $false) {
            $results.Add(
                (New-InspectorRuleResult `
                    -RuleId 'SP-STATE-003' `
                    -Title 'Service principal does not require assignment' `
                    -Severity 'Informational' `
                    -Description "Service principal '$displayName' has appRoleAssignmentRequired set to false." `
                    -EvidenceIds @() `
                    -Source $servicePrincipalReference `
                    -Confidence 'High' `
                    -Limitations @(
                        'This is a state observation. Whether this is acceptable depends on the application access model.'
                    ) `
                    -Metadata @{
                        ServicePrincipalObjectId = $objectId
                        AppRoleAssignmentRequired = $false
                    })
            )
        }
    }

    return @($results)
}

