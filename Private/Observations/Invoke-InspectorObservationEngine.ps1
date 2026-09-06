function Invoke-InspectorObservationEngine {
    <#
    .SYNOPSIS
        Builds deterministic security observations from ObjectInsight.

    .DESCRIPTION
        Observation engine. It consumes only already-collected
        ObjectInsight data, RuleResults, and PermissionInsights. It never
        calls Microsoft Graph and never produces a risk score.

        Observations are evidence-driven. Conditions that require data not
        currently collected only fire when the relevant metadata is present.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ObjectInsight,

        [ValidateRange(1, 365)]
        [int]$CredentialExpiryWarningDays = 30,

        [ValidateRange(30, 3650)]
        [int]$LongLivedSecretDays = 365,

        [ValidateRange(1, 1000)]
        [int]$HighConnectivityThreshold = 10,

        [ValidateRange(1, 3650)]
        [int]$InactiveOwnerDays = 90,

        [ValidateRange(1, 3650)]
        [int]$UnusedConsentDays = 90
    )

    $observations = [System.Collections.Generic.List[object]]::new()
    $now = (Get-Date).ToUniversalTime()

    $sourceObjects = @(
        Get-InspectorObservationSourceObjects `
            -ObjectInsight $ObjectInsight
    )

    $relationships = @(
        Get-InspectorObservationRelationships `
            -ObjectInsight $ObjectInsight
    )

    $artifacts = @(
        (Get-InspectorObservationProperty `
            -InputObject $ObjectInsight `
            -Name 'Artifacts') |
        Where-Object { $null -ne $_ }
    )

    $permissionInsights = @(
        (Get-InspectorObservationProperty `
            -InputObject $ObjectInsight `
            -Name 'PermissionInsights') |
        Where-Object { $null -ne $_ }
    )

    $ruleResults = @(
        (Get-InspectorObservationProperty `
            -InputObject $ObjectInsight `
            -Name 'RuleResults') |
        Where-Object { $null -ne $_ }
    )

    $applicationOwnershipReference =
        'Microsoft Entra application ownership guidance recommends proactively monitoring applications to ensure at least two owners where possible.'

    $credentialReference =
        'Microsoft Graph application and service principal credential resources expose startDateTime and endDateTime metadata for password and key credentials.'

    $permissionReference =
        'Microsoft Graph permissions reference documents application permissions and their administrative capabilities.'

    $servicePrincipalReference =
        'Microsoft Graph servicePrincipal resource exposes accountEnabled and appRoleAssignmentRequired state properties.'

    $consentReference =
        'Microsoft Graph oAuth2PermissionGrant represents delegated permission grants; AllPrincipals indicates tenant-wide consent.'

    $roleAssignableGroupReference =
        'Microsoft Entra role-assignable groups use isAssignableToRole=true to allow Microsoft Entra role assignment to a group.'

    # Identity Governance: ownership posture and owner metadata.
    foreach ($sourceObject in @(
        $sourceObjects |
        Where-Object { $_.ObjectType -in @('Application', 'ServicePrincipal') }
    )) {
        $sourceObjectId = [string]$sourceObject.ObjectId
        $sourceObjectType = [string]$sourceObject.ObjectType
        $displayName = Get-InspectorObservationDisplayName -InputObject $sourceObject
        $sourceMetadata = Get-InspectorObservationProperty -InputObject $sourceObject -Name 'Metadata'
        $publisherClassification = [string](Get-InspectorObservationProperty -InputObject $sourceMetadata -Name 'PublisherClassification')
        $tenantOwnershipClassification = [string](Get-InspectorObservationProperty -InputObject $sourceMetadata -Name 'TenantOwnershipClassification')
        $appId = [string](Get-InspectorObservationProperty -InputObject $sourceObject -Name 'AppId')
        if ([string]::IsNullOrWhiteSpace($appId)) {
            $appId = [string](Get-InspectorObservationProperty -InputObject (Get-InspectorObservationProperty -InputObject $sourceObject -Name 'Identifiers') -Name 'AppId')
        }

        $affectedObject =
            New-InspectorAffectedObject `
                -ObjectType $sourceObjectType `
                -ObjectId $sourceObjectId `
                -DisplayName $displayName `
                -AppId $appId `
                -PublisherClassification $publisherClassification `
                -TenantOwnershipClassification $tenantOwnershipClassification `
                -ClassificationConfidence ([string](Get-InspectorObservationProperty -InputObject $sourceMetadata -Name 'ClassificationConfidence')) `
                -ServicePrincipalType ([string](Get-InspectorObservationProperty -InputObject $sourceMetadata -Name 'ServicePrincipalType')) `
                -AccountEnabled (Get-InspectorObservationProperty -InputObject (Get-InspectorObservationProperty -InputObject $sourceObject -Name 'Properties') -Name 'AccountEnabled')

        $owners = @(
            Get-InspectorObservationRelationships `
                -ObjectInsight $ObjectInsight `
                -SourceObjectId $sourceObjectId `
                -RelationshipType @('OwnedBy')
        )

        $ownerEvidenceSucceeded =
            Test-InspectorObservationSubjectEvidenceSucceeded `
                -ObjectInsight $ObjectInsight `
                -SubjectObjectType $sourceObjectType `
                -SubjectObjectId $sourceObjectId `
                -QueryNamePattern '*Owners*'

        if ($owners.Count -eq 0 -and $ownerEvidenceSucceeded) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'IdentityGovernance' `
                    -Title "$sourceObjectType has no owner" `
                    -Description "No owner relationship was collected for '$displayName'." `
                    -Severity $(if ($sourceObjectType -eq 'ServicePrincipal' -and $publisherClassification -eq 'MicrosoftPublished') { 'Informational' } elseif ($sourceObjectType -eq 'ServicePrincipal' -and $tenantOwnershipClassification -ne 'TenantOwned') { 'Low' } else { 'High' }) `
                    -Confidence 'Medium' `
                    -AffectedObject $affectedObject `
                    -EvidenceIds (Get-InspectorObservationEvidenceIdsForSubject -ObjectInsight $ObjectInsight -SubjectObjectType $sourceObjectType -SubjectObjectId $sourceObjectId -QueryNamePattern '*Owners*') `
                    -MicrosoftReference $applicationOwnershipReference `
                    -WhyItMatters 'Ownerless applications and service principals can lack operational accountability and timely credential or permission review.' `
                    -Limitations @('This observation depends on owner relationship collection completeness.') `
                    -Recommendation 'Assign at least two accountable owners where possible.' `
                    -SourceRuleIds @('APP-OWNER-001') `
                    -Metadata @{
                        OwnerCount = 0
                        PublisherClassification = $publisherClassification
                        TenantOwnershipClassification = $tenantOwnershipClassification
                        EvaluationCriterion = 'Collected owner relationship count equals zero.'
                    })
            )
        }
        elseif ($owners.Count -eq 1) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'IdentityGovernance' `
                    -Title "$sourceObjectType has a single owner" `
                    -Description "Only one owner relationship was collected for '$displayName'." `
                    -Severity 'Medium' `
                    -Confidence 'High' `
                    -AffectedObject $affectedObject `
                    -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $owners) `
                    -MicrosoftReference $applicationOwnershipReference `
                    -WhyItMatters 'A single owner creates operational dependency on one account for governance, review, and continuity.' `
                    -Recommendation 'Add at least one additional accountable owner where possible.' `
                    -SourceRuleIds @('APP-OWNER-002') `
                    -Metadata @{
                        OwnerCount = 1
                        PublisherClassification = $publisherClassification
                        TenantOwnershipClassification = $tenantOwnershipClassification
                        EvaluationCriterion = 'Collected owner relationship count equals one.'
                    })
            )
        }

        foreach ($owner in $owners) {
            $ownerId = [string]$owner.TargetObjectId
            $ownerName = [string]$owner.TargetDisplayName
            $ownerAffectedObject =
                New-InspectorAffectedObject `
                    -ObjectType ([string]$owner.TargetObjectType) `
                    -ObjectId $ownerId `
                    -DisplayName $ownerName

            $accountEnabled =
                Get-InspectorObservationMetadataValue `
                    -InputObject $owner `
                    -Name 'AccountEnabled'

            if ($accountEnabled -eq $false) {
                $observations.Add(
                    (New-InspectorSecurityObservation `
                        -Category 'IdentityGovernance' `
                        -Title 'Application owner is disabled' `
                        -Description "Owner '$ownerName' for '$displayName' appears disabled in collected metadata." `
                        -Severity 'Medium' `
                        -Confidence 'Medium' `
                        -AffectedObject $ownerAffectedObject `
                        -EvidenceIds @($owner.EvidenceId) `
                        -MicrosoftReference $applicationOwnershipReference `
                        -WhyItMatters 'A disabled owner may not be able to perform ownership duties such as access review or credential renewal.' `
                        -Limitations @('This observation fires only when owner account state metadata is available.') `
                        -Recommendation 'Replace disabled owners with active accountable owners.' `
                        -Metadata @{
                            OwnedObjectId = $sourceObjectId
                            OwnedObjectType = $sourceObjectType
                        })
                )
            }

            $ownerUserType =
                [string](Get-InspectorObservationMetadataValue `
                    -InputObject $owner `
                    -Name 'UserType')

            $ownerUpn =
                [string](Get-InspectorObservationMetadataValue `
                    -InputObject $owner `
                    -Name 'UserPrincipalName')

            if ($ownerUserType -eq 'Guest' -or $ownerUpn -like '*#EXT#*') {
                $observations.Add(
                    (New-InspectorSecurityObservation `
                        -Category 'IdentityGovernance' `
                        -Title 'Application owner appears external' `
                        -Description "Owner '$ownerName' for '$displayName' appears to be an external or guest identity." `
                        -Severity 'Medium' `
                        -Confidence 'Medium' `
                        -AffectedObject $ownerAffectedObject `
                        -EvidenceIds @($owner.EvidenceId) `
                        -MicrosoftReference $applicationOwnershipReference `
                        -WhyItMatters 'External ownership can complicate accountability, incident response, and lifecycle control.' `
                        -Limitations @('This observation fires only when owner userType or UPN metadata is available.') `
                        -Recommendation 'Confirm that external ownership is intentional and documented.' `
                        -Metadata @{
                            OwnedObjectId = $sourceObjectId
                            OwnedObjectType = $sourceObjectType
                            UserType = $ownerUserType
                            UserPrincipalName = $ownerUpn
                        })
                )
            }

            $lastSignIn =
                Get-InspectorObservationDate `
                    -Value (Get-InspectorObservationMetadataValue `
                        -InputObject $owner `
                        -Name 'LastSignInDateTime')

            if ($null -ne $lastSignIn -and $lastSignIn -lt $now.AddDays(-1 * $InactiveOwnerDays)) {
                $observations.Add(
                    (New-InspectorSecurityObservation `
                        -Category 'IdentityGovernance' `
                        -Title 'Application owner appears inactive' `
                        -Description "Owner '$ownerName' for '$displayName' has no recent sign-in in the available metadata." `
                        -Severity 'Low' `
                        -Confidence 'Medium' `
                        -AffectedObject $ownerAffectedObject `
                        -EvidenceIds @($owner.EvidenceId) `
                        -MicrosoftReference $applicationOwnershipReference `
                        -WhyItMatters 'Inactive owners may not respond to operational or security ownership responsibilities.' `
                        -Limitations @('This observation fires only when owner sign-in metadata is available in ObjectInsight.') `
                        -Recommendation 'Validate whether the owner is still accountable for the application.' `
                        -Metadata @{
                            OwnedObjectId = $sourceObjectId
                            LastSignInDateTime = $lastSignIn.ToString('o')
                            InactiveOwnerDays = $InactiveOwnerDays
                        })
                )
            }
        }
    }

    # Credentials.
    $credentialArtifacts = @(
        $artifacts |
        Where-Object { (Get-InspectorObservationProperty -InputObject $_ -Name 'ArtifactType') -eq 'CredentialMetadata' }
    )

    foreach ($credential in $credentialArtifacts) {
        $sourceObjectId = [string](Get-InspectorObservationProperty -InputObject $credential -Name 'SourceObjectId')
        $sourceObjectType = [string](Get-InspectorObservationProperty -InputObject $credential -Name 'SourceObjectType')
        $credentialType = [string](Get-InspectorObservationProperty -InputObject $credential -Name 'CredentialType')
        $credentialKeyId = [string](Get-InspectorObservationProperty -InputObject $credential -Name 'KeyId')
        $credentialEvidenceId = [string](Get-InspectorObservationProperty -InputObject $credential -Name 'EvidenceId')
        if ([string]::IsNullOrWhiteSpace($credentialEvidenceId)) {
            $credentialEvidenceId = [string](Get-InspectorObservationProperty -InputObject $credential -Name 'ParentEvidenceId')
        }
        $credentialEvidenceIds =
            if ([string]::IsNullOrWhiteSpace($credentialEvidenceId)) {
                @()
            }
            else {
                @($credentialEvidenceId)
            }
        $credentialName = [string](Get-InspectorObservationProperty -InputObject $credential -Name 'DisplayName')

        if ([string]::IsNullOrWhiteSpace($credentialName)) {
            $credentialName = $credentialKeyId
        }

        $credentialSourceObject =
            Get-InspectorObservationSourceObject `
                -SourceObjects $sourceObjects `
                -ObjectType $sourceObjectType `
                -ObjectId $sourceObjectId
        $affectedObject =
            New-InspectorAffectedObjectFromSourceObject `
                -SourceObject $credentialSourceObject `
                -FallbackObjectType $sourceObjectType `
                -FallbackObjectId $sourceObjectId `
                -FallbackDisplayName $sourceObjectId

        $startDate =
            Get-InspectorObservationDate `
                -Value (Get-InspectorObservationProperty -InputObject $credential -Name 'StartDateTime')

        $endDate =
            Get-InspectorObservationDate `
                -Value (Get-InspectorObservationProperty -InputObject $credential -Name 'EndDateTime')

        if ($null -ne $endDate -and $endDate -lt $now) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Credentials' `
                    -Title 'Expired credential is still present' `
                    -Description "Credential '$credentialName' expired on $($endDate.ToString('o'))." `
                    -Severity 'High' `
                    -Confidence 'High' `
                    -AffectedObject $affectedObject `
                    -EvidenceIds $credentialEvidenceIds `
                    -MicrosoftReference $credentialReference `
                    -WhyItMatters 'Expired credentials increase operational noise and can indicate weak credential lifecycle hygiene.' `
                    -Limitations @('The observation does not prove whether the credential was ever used.') `
                    -Recommendation 'Remove expired credentials after confirming they are no longer required.' `
                    -SourceRuleIds @('CRED-002') `
                    -Metadata @{
                        CredentialType = $credentialType
                        KeyId = $credentialKeyId
                        ParentEvidenceId = $credentialEvidenceId
                        EvidenceSupportType = 'DerivedFromTenantCollection'
                        StartDateTime = $(if ($null -ne $startDate) { $startDate.ToString('o') } else { $null })
                        EndDateTime = $endDate.ToString('o')
                        EvaluationTime = $now.ToString('o')
                        DaysUntilExpiration = [math]::Floor(($endDate - $now).TotalDays)
                        IsExpired = $true
                        IsExpiring = $false
                        IsLongLived = $false
                        EvaluationCriterion = 'Credential endDateTime is earlier than the assessment time.'
                    })
            )
        }
        elseif ($null -ne $endDate -and $endDate -le $now.AddDays($CredentialExpiryWarningDays)) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Credentials' `
                    -Title 'Credential expires soon' `
                    -Description "Credential '$credentialName' expires within $CredentialExpiryWarningDays days." `
                    -Severity 'Medium' `
                    -Confidence 'High' `
                    -AffectedObject $affectedObject `
                    -EvidenceIds $credentialEvidenceIds `
                    -MicrosoftReference $credentialReference `
                    -WhyItMatters 'Soon-expiring credentials can cause workload outages if not renewed before expiration.' `
                    -Limitations @('The observation does not prove whether the credential is actively used.') `
                    -Recommendation 'Plan credential renewal before the expiration date.' `
                    -SourceRuleIds @('CRED-001') `
                    -Metadata @{
                        CredentialType = $credentialType
                        KeyId = $credentialKeyId
                        ParentEvidenceId = $credentialEvidenceId
                        EvidenceSupportType = 'DerivedFromTenantCollection'
                        StartDateTime = $(if ($null -ne $startDate) { $startDate.ToString('o') } else { $null })
                        EndDateTime = $endDate.ToString('o')
                        EvaluationTime = $now.ToString('o')
                        DaysUntilExpiration = [math]::Floor(($endDate - $now).TotalDays)
                        IsExpired = $false
                        IsExpiring = $true
                        IsLongLived = $false
                        EvaluationCriterion = "Credential endDateTime is within $CredentialExpiryWarningDays days."
                    })
            )
        }

        if (
            $credentialType -eq 'Password' -and
            $null -ne $startDate -and
            $null -ne $endDate -and
            ($endDate - $startDate).TotalDays -gt $LongLivedSecretDays
        ) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Credentials' `
                    -Title 'Long-lived client secret' `
                    -Description "Password credential '$credentialName' is valid for more than $LongLivedSecretDays days." `
                    -Severity 'Medium' `
                    -Confidence 'High' `
                    -AffectedObject $affectedObject `
                    -EvidenceIds $credentialEvidenceIds `
                    -MicrosoftReference $credentialReference `
                    -WhyItMatters 'Long-lived secrets increase the window of exposure if the secret is leaked.' `
                    -Recommendation 'Use shorter secret lifetimes or certificate/federated credentials where appropriate.' `
                    -Metadata @{
                        KeyId = $credentialKeyId
                        CredentialType = $credentialType
                        ParentEvidenceId = $credentialEvidenceId
                        EvidenceSupportType = 'DerivedFromTenantCollection'
                        StartDateTime = $startDate.ToString('o')
                        EndDateTime = $endDate.ToString('o')
                        EvaluationTime = $now.ToString('o')
                        ValidityDays = [math]::Round(($endDate - $startDate).TotalDays, 2)
                        CredentialAgeDays = [math]::Floor(($now - $startDate).TotalDays)
                        LongLivedSecretDays = $LongLivedSecretDays
                        IsExpired = $false
                        IsExpiring = $false
                        IsLongLived = $true
                        EvaluationCriterion = "Password credential validity exceeds $LongLivedSecretDays days."
                    })
            )
        }
    }

    foreach ($group in @($credentialArtifacts | Group-Object SourceObjectId)) {
        $sourceCredentials = @($group.Group)
        $activeSecrets = @(
            $sourceCredentials |
            Where-Object {
                (Get-InspectorObservationProperty -InputObject $_ -Name 'CredentialType') -eq 'Password' -and
                (
                    (Get-InspectorObservationDate -Value (Get-InspectorObservationProperty -InputObject $_ -Name 'EndDateTime')) -gt $now -or
                    $null -eq (Get-InspectorObservationDate -Value (Get-InspectorObservationProperty -InputObject $_ -Name 'EndDateTime'))
                )
            }
        )

        if ($activeSecrets.Count -gt 1) {
            $firstCredential = $activeSecrets | Select-Object -First 1
            $firstCredentialSourceType = [string](Get-InspectorObservationProperty -InputObject $firstCredential -Name 'SourceObjectType')
            $firstCredentialEvidenceId = [string](Get-InspectorObservationProperty -InputObject $firstCredential -Name 'EvidenceId')
            if ([string]::IsNullOrWhiteSpace($firstCredentialEvidenceId)) {
                $firstCredentialEvidenceId = [string](Get-InspectorObservationProperty -InputObject $firstCredential -Name 'ParentEvidenceId')
            }
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Credentials' `
                    -Title 'Multiple active client secrets' `
                    -Description "Object '$($group.Name)' has multiple active password credentials." `
                    -Severity 'Medium' `
                    -Confidence 'High' `
                    -AffectedObject (New-InspectorAffectedObjectFromSourceObject -SourceObject (Get-InspectorObservationSourceObject -SourceObjects $sourceObjects -ObjectType $firstCredentialSourceType -ObjectId ([string]$group.Name)) -FallbackObjectType $firstCredentialSourceType -FallbackObjectId ([string]$group.Name) -FallbackDisplayName ([string]$group.Name)) `
                    -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $activeSecrets) `
                    -MicrosoftReference $credentialReference `
                    -WhyItMatters 'Multiple active secrets increase credential inventory complexity and the number of secrets that must be protected.' `
                    -Recommendation 'Keep only necessary active secrets and document rotation windows.' `
                    -Metadata @{
                        ActiveSecretCount = $activeSecrets.Count
                        OverlappingCredentialCount = 0
                        ParentEvidenceId = $firstCredentialEvidenceId
                        EvidenceSupportType = 'DerivedFromTenantCollection'
                        EvaluationTime = $now.ToString('o')
                        Credentials = @($activeSecrets | ForEach-Object {
                            [PSCustomObject]@{
                                CredentialType = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'CredentialType')
                                KeyId = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'KeyId')
                                StartDateTime = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'StartDateTime')
                                EndDateTime = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'EndDateTime')
                                IsActive = $true
                            }
                        })
                        EvaluationCriterion = 'More than one active password credential exists for the object.'
                    })
            )
        }

        $overlapFound = $false
        $overlapLeft = $null
        $overlapRight = $null
        $overlapStart = $null
        $overlapEnd = $null

        for ($i = 0; $i -lt $sourceCredentials.Count; $i++) {
            for ($j = $i + 1; $j -lt $sourceCredentials.Count; $j++) {
                $left = $sourceCredentials[$i]
                $right = $sourceCredentials[$j]
                $leftStart = Get-InspectorObservationDate -Value (Get-InspectorObservationProperty -InputObject $left -Name 'StartDateTime')
                $leftEnd = Get-InspectorObservationDate -Value (Get-InspectorObservationProperty -InputObject $left -Name 'EndDateTime')
                $rightStart = Get-InspectorObservationDate -Value (Get-InspectorObservationProperty -InputObject $right -Name 'StartDateTime')
                $rightEnd = Get-InspectorObservationDate -Value (Get-InspectorObservationProperty -InputObject $right -Name 'EndDateTime')

                if ($null -eq $leftStart -or $null -eq $leftEnd -or $null -eq $rightStart -or $null -eq $rightEnd) {
                    continue
                }

                if ($leftStart -le $rightEnd -and $rightStart -le $leftEnd) {
                    $overlapFound = $true
                    $overlapLeft = $left
                    $overlapRight = $right
                    $overlapStart = if ($leftStart -gt $rightStart) { $leftStart } else { $rightStart }
                    $overlapEnd = if ($leftEnd -lt $rightEnd) { $leftEnd } else { $rightEnd }
                    break
                }
            }
            if ($overlapFound) { break }
        }

        if ($overlapFound) {
            $firstCredential = $sourceCredentials | Select-Object -First 1
            $firstCredentialSourceType = [string](Get-InspectorObservationProperty -InputObject $firstCredential -Name 'SourceObjectType')
            $firstCredentialEvidenceId = [string](Get-InspectorObservationProperty -InputObject $firstCredential -Name 'EvidenceId')
            if ([string]::IsNullOrWhiteSpace($firstCredentialEvidenceId)) {
                $firstCredentialEvidenceId = [string](Get-InspectorObservationProperty -InputObject $firstCredential -Name 'ParentEvidenceId')
            }
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Credentials' `
                    -Title 'Overlapping credential validity windows' `
                    -Description "Object '$($group.Name)' has credentials with overlapping validity windows." `
                    -Severity 'Low' `
                    -Confidence 'Medium' `
                    -AffectedObject (New-InspectorAffectedObjectFromSourceObject -SourceObject (Get-InspectorObservationSourceObject -SourceObjects $sourceObjects -ObjectType $firstCredentialSourceType -ObjectId ([string]$group.Name)) -FallbackObjectType $firstCredentialSourceType -FallbackObjectId ([string]$group.Name) -FallbackDisplayName ([string]$group.Name)) `
                    -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $sourceCredentials) `
                    -MicrosoftReference $credentialReference `
                    -WhyItMatters 'Overlapping credentials may be intentional for rotation, but they should be reviewed to avoid unnecessary active credentials.' `
                    -Recommendation 'Confirm overlap is part of a documented rotation window.' `
                    -Metadata @{
                        CredentialCount = $sourceCredentials.Count
                        OverlappingCredentialCount = $sourceCredentials.Count
                        ParentEvidenceId = $firstCredentialEvidenceId
                        EvidenceSupportType = 'DerivedFromTenantCollection'
                        CredentialA = [PSCustomObject]@{
                            CredentialType = [string](Get-InspectorObservationProperty -InputObject $overlapLeft -Name 'CredentialType')
                            KeyId = [string](Get-InspectorObservationProperty -InputObject $overlapLeft -Name 'KeyId')
                            StartDateTime = [string](Get-InspectorObservationProperty -InputObject $overlapLeft -Name 'StartDateTime')
                            EndDateTime = [string](Get-InspectorObservationProperty -InputObject $overlapLeft -Name 'EndDateTime')
                        }
                        CredentialB = [PSCustomObject]@{
                            CredentialType = [string](Get-InspectorObservationProperty -InputObject $overlapRight -Name 'CredentialType')
                            KeyId = [string](Get-InspectorObservationProperty -InputObject $overlapRight -Name 'KeyId')
                            StartDateTime = [string](Get-InspectorObservationProperty -InputObject $overlapRight -Name 'StartDateTime')
                            EndDateTime = [string](Get-InspectorObservationProperty -InputObject $overlapRight -Name 'EndDateTime')
                        }
                        OverlapStart = $(if ($null -ne $overlapStart) { $overlapStart.ToString('o') } else { $null })
                        OverlapEnd = $(if ($null -ne $overlapEnd) { $overlapEnd.ToString('o') } else { $null })
                        EvaluationTime = $now.ToString('o')
                        EvaluationCriterion = 'Credential validity windows overlap for the same object.'
                    })
            )
        }
    }

    # Permissions.
    $highImpactPermissionNames = @(
        'Directory.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory',
        'Policy.ReadWrite.ConditionalAccess',
        'AppRoleAssignment.ReadWrite.All'
    )

    foreach ($permissionInsight in $permissionInsights) {
        $permissionName = [string]$permissionInsight.PermissionName

        if ($permissionName -in $highImpactPermissionNames) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Permissions' `
                    -Title "High-impact permission: $permissionName" `
                    -Description "The object has Microsoft Graph application permission '$permissionName'." `
                    -Severity 'High' `
                    -Confidence $permissionInsight.Confidence `
                    -AffectedObject (New-InspectorAffectedObjectFromSourceObject -SourceObject (Get-InspectorObservationSourceObject -SourceObjects $sourceObjects -ObjectType 'ServicePrincipal' -ObjectId ([string]$permissionInsight.SourceObjectId)) -FallbackObjectType 'ServicePrincipal' -FallbackObjectId ([string]$permissionInsight.SourceObjectId) -FallbackDisplayName ([string]$permissionInsight.SourceObjectId)) `
                    -EvidenceIds @($permissionInsight.RelationshipEvidenceId) `
                    -MicrosoftReference $permissionReference `
                    -WhyItMatters $permissionInsight.AdministrativeImpact `
                    -Limitations @($permissionInsight.Limitations) `
                    -Recommendation 'Validate that this permission is required and covered by ownership, credential hygiene, and consent review.' `
                    -SourceRuleIds @('PERM-GRAPH-HIGH-001') `
                    -Metadata @{
                        PermissionName = $permissionName
                        PermissionType = Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'PermissionType'
                        PermissionCategory = Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'PermissionCategory'
                        ResourceApi = Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'ResourceDisplayName'
                        ResourceAppId = Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'ResourceAppId'
                        ImpactLevel = Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'ImpactLevel'
                        AppRoleId = Get-InspectorObservationProperty -InputObject $permissionInsight -Name 'AppRoleId'
                        EvaluationCriterion = 'Permission is present in the local high-impact Microsoft Graph application permission catalog.'
                    })
            )
        }
    }

    # Service Principal state.
    foreach ($servicePrincipal in @(
        $sourceObjects |
        Where-Object { $_.ObjectType -eq 'ServicePrincipal' }
    )) {
        $properties = $servicePrincipal.Properties
        $objectId = [string]$servicePrincipal.ObjectId
        $displayName = Get-InspectorObservationDisplayName -InputObject $servicePrincipal
        $sourceMetadata = Get-InspectorObservationProperty -InputObject $servicePrincipal -Name 'Metadata'
        $publisherClassification = [string](Get-InspectorObservationProperty -InputObject $sourceMetadata -Name 'PublisherClassification')
        $tenantOwnershipClassification = [string](Get-InspectorObservationProperty -InputObject $sourceMetadata -Name 'TenantOwnershipClassification')
        $classificationConfidence = [string](Get-InspectorObservationProperty -InputObject $sourceMetadata -Name 'ClassificationConfidence')
        $appId = [string](Get-InspectorObservationProperty -InputObject $servicePrincipal -Name 'AppId')
        if ([string]::IsNullOrWhiteSpace($appId)) {
            $appId = [string](Get-InspectorObservationProperty -InputObject (Get-InspectorObservationProperty -InputObject $servicePrincipal -Name 'Identifiers') -Name 'AppId')
        }
        $affectedObject = New-InspectorAffectedObject -ObjectType 'ServicePrincipal' -ObjectId $objectId -DisplayName $displayName -AppId $appId -PublisherClassification $publisherClassification -TenantOwnershipClassification $tenantOwnershipClassification -ClassificationConfidence $classificationConfidence -ServicePrincipalType ([string](Get-InspectorObservationProperty -InputObject $sourceMetadata -Name 'ServicePrincipalType')) -AccountEnabled (Get-InspectorObservationProperty -InputObject $properties -Name 'AccountEnabled')

        $assignmentRequired =
            Get-InspectorObservationProperty `
                -InputObject $properties `
                -Name 'AppRoleAssignmentRequired'

        if ($assignmentRequired -eq $false) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'ServicePrincipal' `
                    -Title 'Service principal does not require assignment' `
                    -Description "Service principal '$displayName' has appRoleAssignmentRequired set to false." `
                    -Severity 'Informational' `
                    -Confidence 'High' `
                    -AffectedObject $affectedObject `
                    -EvidenceIds @() `
                    -MicrosoftReference $servicePrincipalReference `
                    -WhyItMatters 'This is an access-model fact that requires business context before it can be treated as adverse.' `
                    -Recommendation 'Confirm that the application access model intentionally does not require assignment.' `
                    -SourceRuleIds @('SP-STATE-003') `
                    -Metadata @{
                        AppRoleAssignmentRequired = $false
                        EvaluationCriterion = 'appRoleAssignmentRequired equals false in collected service-principal metadata.'
                    })
            )
        }

        $accountEnabled =
            Get-InspectorObservationProperty `
                -InputObject $properties `
                -Name 'AccountEnabled'

        if ($accountEnabled -eq $true) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'ServicePrincipal' `
                    -Title 'Service principal sign-in is enabled' `
                    -Description "Service principal '$displayName' has accountEnabled set to true." `
                    -Severity 'Informational' `
                    -Confidence 'High' `
                    -AffectedObject $affectedObject `
                    -EvidenceIds @() `
                    -MicrosoftReference $servicePrincipalReference `
                    -WhyItMatters 'Enabled service principals can be used by applications or workloads according to their credentials and assignments.' `
                    -Recommendation 'Confirm the service principal is expected to remain enabled.' `
                    -Metadata @{
                        AccountEnabled = $true
                    })
            )
        }

        $visibleToUsers =
            Get-InspectorObservationProperty `
                -InputObject $properties `
                -Name 'VisibleToUsers'

        if ($null -ne $visibleToUsers) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'ServicePrincipal' `
                    -Title 'Service principal visibility state captured' `
                    -Description "Service principal '$displayName' has VisibleToUsers set to $visibleToUsers in collected metadata." `
                    -Severity 'Informational' `
                    -Confidence 'Medium' `
                    -AffectedObject $affectedObject `
                    -EvidenceIds @() `
                    -MicrosoftReference $servicePrincipalReference `
                    -WhyItMatters 'Visibility metadata helps explain user-facing application exposure, when collected.' `
                    -Limitations @('This observation fires only when visibility metadata exists in ObjectInsight.') `
                    -Recommendation 'Validate that the visibility state matches the intended application audience.' `
                    -Metadata @{
                        VisibleToUsers = $visibleToUsers
                    })
            )
        }
    }

    $applicationIdentity =
        Get-InspectorObservationProperty `
            -InputObject $ObjectInsight `
            -Name 'ApplicationIdentity'

    if ($null -ne $applicationIdentity) {
        $applicationObjectId = [string](Get-InspectorObservationProperty -InputObject $applicationIdentity -Name 'ApplicationObjectId')
        $servicePrincipalObjectId = [string](Get-InspectorObservationProperty -InputObject $applicationIdentity -Name 'ServicePrincipalObjectId')
        $counterpartCollectionQueries = @('Applications', 'ServicePrincipals')
        $counterpartCollectionEvidenceSucceeded =
            Test-InspectorObservationTenantCollectionEvidenceSucceeded `
                -ObjectInsight $ObjectInsight `
                -QueryName $counterpartCollectionQueries
        $counterpartCollectionEvidenceIds =
            Get-InspectorObservationTenantCollectionEvidenceIds `
                -ObjectInsight $ObjectInsight `
                -QueryName $counterpartCollectionQueries

        if (
            -not [string]::IsNullOrWhiteSpace($applicationObjectId) -and
            [string]::IsNullOrWhiteSpace($servicePrincipalObjectId) -and
            $counterpartCollectionEvidenceSucceeded
        ) {
            $applicationSourceObject = Get-InspectorObservationSourceObject -SourceObjects $sourceObjects -ObjectType 'Application' -ObjectId $applicationObjectId
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'ServicePrincipal' `
                    -Title 'Application has no discovered service principal counterpart' `
                    -Description 'The application identity has an application object but no service principal object in the normalized identity mapping.' `
                    -Severity 'Low' `
                    -Confidence 'Medium' `
                    -AffectedObject (New-InspectorAffectedObjectFromSourceObject -SourceObject $applicationSourceObject -FallbackObjectType 'Application' -FallbackObjectId $applicationObjectId -FallbackDisplayName $applicationObjectId) `
                    -EvidenceIds $counterpartCollectionEvidenceIds `
                    -MicrosoftReference 'Microsoft Entra application objects and service principals are separate object types connected by appId.' `
                    -WhyItMatters 'Missing counterpart visibility can affect interpretation of enterprise-app assignments, consent, and service-principal state.' `
                    -Limitations @('This may be expected when the corresponding service principal is not present in the tenant or was not resolved.') `
                    -Recommendation 'Confirm whether a local service principal should exist for the application.' `
                    -Metadata @{ SignalDisposition = 'Review'; EvidenceSupportType = 'DerivedFromTenantCollection'; EvaluationCriterion = 'Tenant application object has no local service-principal counterpart after successful Applications and ServicePrincipals tenant collection.' })
            )
        }

        if (
            [string]::IsNullOrWhiteSpace($applicationObjectId) -and
            -not [string]::IsNullOrWhiteSpace($servicePrincipalObjectId) -and
            $counterpartCollectionEvidenceSucceeded
        ) {
            $servicePrincipalSourceObject = Get-InspectorObservationSourceObject -SourceObjects $sourceObjects -ObjectType 'ServicePrincipal' -ObjectId $servicePrincipalObjectId
            $servicePrincipalMetadata = Get-InspectorObservationProperty -InputObject $servicePrincipalSourceObject -Name 'Metadata'
            $counterpartPublisher = [string](Get-InspectorObservationProperty -InputObject $servicePrincipalMetadata -Name 'PublisherClassification')
            $counterpartOwnership = [string](Get-InspectorObservationProperty -InputObject $servicePrincipalMetadata -Name 'TenantOwnershipClassification')
            $counterpartIsContextual = $counterpartPublisher -in @('MicrosoftPublished', 'ExternalVerified', 'ExternalUnverified', 'ManagedIdentity') -or ($counterpartOwnership -ne 'TenantOwned')
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'ServicePrincipal' `
                    -Title 'Service principal has no discovered application counterpart' `
                    -Description 'The application identity has a service principal but no application object in the normalized identity mapping.' `
                    -Severity $(if ($counterpartIsContextual) { 'Informational' } else { 'Low' }) `
                    -Confidence 'Medium' `
                    -AffectedObject (New-InspectorAffectedObjectFromSourceObject -SourceObject $servicePrincipalSourceObject -FallbackObjectType 'ServicePrincipal' -FallbackObjectId $servicePrincipalObjectId -FallbackDisplayName $servicePrincipalObjectId) `
                    -EvidenceIds $counterpartCollectionEvidenceIds `
                    -MicrosoftReference 'Microsoft Entra application objects and service principals are separate object types connected by appId.' `
                    -WhyItMatters 'A local service principal can represent an application registered in another tenant.' `
                    -Limitations @('This may be expected for multi-tenant or Microsoft-owned applications.') `
                    -Recommendation 'Confirm the app owner organization and whether the service principal is expected.' `
                    -Metadata @{ SignalDisposition = $(if ($counterpartIsContextual) { 'Contextual' } else { 'Review' }); EvidenceSupportType = 'DerivedFromTenantCollection'; PublisherClassification = $counterpartPublisher; TenantOwnershipClassification = $counterpartOwnership; EvaluationCriterion = 'Service principal has no local application counterpart after successful Applications and ServicePrincipals tenant collection; applicability depends on tenant ownership/publisher context.' })
            )
        }
    }

    foreach ($rule in @($ruleResults | Where-Object { $_.RuleId -eq 'APP-OWNERSHIP-001' })) {
        $ownershipMismatchObjectType = if (-not [string]::IsNullOrWhiteSpace($applicationIdentity.ApplicationObjectId)) { 'Application' } else { 'ServicePrincipal' }
        $ownershipMismatchObjectId = if ($ownershipMismatchObjectType -eq 'Application') { [string]$applicationIdentity.ApplicationObjectId } else { [string]$applicationIdentity.ServicePrincipalObjectId }
        if ([string]::IsNullOrWhiteSpace($ownershipMismatchObjectId)) {
            $ownershipMismatchObjectId = [string]$applicationIdentity.AppId
        }

        $observations.Add(
            (New-InspectorSecurityObservation `
                -Category 'ServicePrincipal' `
                -Title 'Application and service principal owners differ' `
                -Description 'The application object and its service principal have different owner sets.' `
                -Severity 'Low' `
                -Confidence 'High' `
                -AffectedObject (New-InspectorAffectedObjectFromSourceObject -SourceObject (Get-InspectorObservationSourceObject -SourceObjects $sourceObjects -ObjectType $ownershipMismatchObjectType -ObjectId $ownershipMismatchObjectId) -FallbackObjectType $ownershipMismatchObjectType -FallbackObjectId $ownershipMismatchObjectId -FallbackDisplayName ([string]$applicationIdentity.AppId)) `
                -EvidenceIds @($rule.EvidenceIds) `
                -MicrosoftReference 'Microsoft Entra separates application objects from service principals; each has its own owners relationship.' `
                -WhyItMatters 'Different ownership can be legitimate, but it should be explainable because app registration and enterprise-app governance may be handled by different people.' `
                -Recommendation 'Validate that both owner sets are intentional and accountable.' `
                -SourceRuleIds @('APP-OWNERSHIP-001'))
        )
    }

    # Consent.
    $delegatedGrants = @(
        $relationships |
        Where-Object { $_.RelationshipType -eq 'DelegatedPermissionGrant' }
    )

    if ($delegatedGrants.Count -gt 0) {
        foreach ($grant in $delegatedGrants) {
            $consentType =
                [string](Get-InspectorObservationMetadataValue `
                    -InputObject $grant `
                    -Name 'ConsentType')

            $grantEvidenceId = [string](Get-InspectorObservationProperty -InputObject $grant -Name 'EvidenceId')
            $grantSourceObject = Get-InspectorObservationSourceObject -SourceObjects $sourceObjects -ObjectType 'ServicePrincipal' -ObjectId ([string]$grant.SourceObjectId)

            if ($consentType -eq 'AllPrincipals') {
                $observations.Add(
                    (New-InspectorSecurityObservation `
                        -Category 'Consent' `
                        -Title 'Tenant-wide delegated consent grant' `
                        -Description 'A delegated permission grant with consentType AllPrincipals was collected.' `
                        -Severity 'Medium' `
                        -Confidence 'High' `
                        -AffectedObject (New-InspectorAffectedObjectFromSourceObject -SourceObject $grantSourceObject -FallbackObjectType 'ServicePrincipal' -FallbackObjectId ([string]$grant.SourceObjectId) -FallbackDisplayName ([string](Get-InspectorObservationProperty -InputObject $grant -Name 'SourceDisplayName'))) `
                        -EvidenceIds @($grantEvidenceId) `
                        -MicrosoftReference $consentReference `
                        -WhyItMatters 'AllPrincipals consent applies tenant-wide rather than to a single principal.' `
                        -Recommendation 'Review tenant-wide delegated consent grants for necessity and scope.' `
                        -Metadata @{
                            ConsentType = $consentType
                            Scope = [string](Get-InspectorObservationMetadataValue -InputObject $grant -Name 'Scope')
                            GrantId = [string](Get-InspectorObservationMetadataValue -InputObject $grant -Name 'GrantId')
                            ClientServicePrincipalId = [string]$grant.SourceObjectId
                            ResourceServicePrincipalId = [string]$grant.TargetObjectId
                            PrincipalId = [string](Get-InspectorObservationMetadataValue -InputObject $grant -Name 'PrincipalId')
                            EvidenceSupportType = 'DerivedFromTenantCollection'
                            ParentEvidenceId = $grantEvidenceId
                        })
                )
            }

            $lastUsed =
                Get-InspectorObservationDate `
                    -Value (Get-InspectorObservationMetadataValue `
                        -InputObject $grant `
                        -Name 'LastUsedDateTime')

            if ($null -ne $lastUsed -and $lastUsed -lt $now.AddDays(-1 * $UnusedConsentDays)) {
                $observations.Add(
                    (New-InspectorSecurityObservation `
                        -Category 'Consent' `
                        -Title 'Delegated consent appears unused' `
                        -Description 'A delegated permission grant has old last-used metadata.' `
                        -Severity 'Low' `
                        -Confidence 'Medium' `
                        -AffectedObject (New-InspectorAffectedObjectFromSourceObject -SourceObject $grantSourceObject -FallbackObjectType 'ServicePrincipal' -FallbackObjectId ([string]$grant.SourceObjectId) -FallbackDisplayName ([string](Get-InspectorObservationProperty -InputObject $grant -Name 'SourceDisplayName'))) `
                        -EvidenceIds @($grantEvidenceId) `
                        -MicrosoftReference $consentReference `
                        -WhyItMatters 'Unused consent grants may represent unnecessary authorization paths.' `
                        -Limitations @('This observation fires only when consent usage metadata is present in ObjectInsight.') `
                        -Recommendation 'Validate whether the delegated consent is still required.' `
                        -Metadata @{
                            LastUsedDateTime = $lastUsed.ToString('o')
                            UnusedConsentDays = $UnusedConsentDays
                        })
                )
            }
        }

        $consentSummarySource = Get-InspectorObservationSourceObject -SourceObjects $sourceObjects -ObjectType 'ServicePrincipal'
        $observations.Add(
            (New-InspectorSecurityObservation `
                -Category 'Consent' `
                -Title 'Delegated consent grants present' `
                -Description "$($delegatedGrants.Count) delegated permission grant relationship(s) were collected." `
                -Severity 'Informational' `
                -Confidence 'High' `
                -AffectedObject (New-InspectorAffectedObjectFromSourceObject -SourceObject $consentSummarySource -FallbackObjectType 'ServicePrincipal' -FallbackObjectId ([string]$ObjectInsight.Input) -FallbackDisplayName ([string]$ObjectInsight.Input)) `
                -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $delegatedGrants) `
                -MicrosoftReference $consentReference `
                -WhyItMatters 'Delegated grants explain what an application can access on behalf of users.' `
                -Recommendation 'Review delegated grants during application access reviews.' `
                -Metadata @{
                    DelegatedGrantCount = $delegatedGrants.Count
                    SignalDisposition = 'Contextual'
                })
        )
    }

    if ($permissionInsights.Count -gt 0) {
        $permissionSummarySource = Get-InspectorObservationSourceObject -SourceObjects $sourceObjects -ObjectType 'ServicePrincipal'
        if ($null -eq $permissionSummarySource) {
            $permissionSummarySource = Get-InspectorObservationSourceObject -SourceObjects $sourceObjects -ObjectType 'Application'
        }
        $observations.Add(
            (New-InspectorSecurityObservation `
                -Category 'Consent' `
                -Title 'Application permissions present' `
                -Description "$($permissionInsights.Count) application permission insight(s) were collected." `
                -Severity 'Informational' `
                -Confidence 'High' `
                -AffectedObject (New-InspectorAffectedObjectFromSourceObject -SourceObject $permissionSummarySource -FallbackObjectType 'ServicePrincipal' -FallbackObjectId ([string]$ObjectInsight.Input) -FallbackDisplayName ([string]$ObjectInsight.Input)) `
                -EvidenceIds @($permissionInsights | ForEach-Object { $_.RelationshipEvidenceId }) `
                -MicrosoftReference 'Microsoft Graph app role assignments represent application permissions granted to a client service principal.' `
                -WhyItMatters 'Application permissions allow app-only access without a signed-in user.' `
                -Recommendation 'Review application permissions for necessity and least privilege.' `
                -Metadata @{
                    ApplicationPermissionCount = $permissionInsights.Count
                    SignalDisposition = 'Contextual'
                })
        )
    }

    # Users.
    foreach ($user in @($sourceObjects | Where-Object { $_.ObjectType -eq 'User' })) {
        $userId = [string]$user.ObjectId
        $displayName = Get-InspectorObservationDisplayName -InputObject $user
        $affectedUser = New-InspectorAffectedObject -ObjectType 'User' -ObjectId $userId -DisplayName $displayName -UserPrincipalName ([string](Get-InspectorObservationProperty -InputObject (Get-InspectorObservationProperty -InputObject $user -Name 'Properties') -Name 'UserPrincipalName'))

        $userRelationships = @(
            Get-InspectorObservationRelationships `
                -ObjectInsight $ObjectInsight `
                -SourceObjectId $userId
        )

        $directoryRoleRelationships = @(
            $userRelationships |
            Where-Object {
                $_.RelationshipType -in @('AssignedDirectoryRole', 'MemberOfDirectoryRole')
            }
        )

        if ($directoryRoleRelationships.Count -gt 0) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Users' `
                    -Title 'User has Microsoft Entra directory role relationship' `
                    -Description "User '$displayName' has $($directoryRoleRelationships.Count) collected directory role relationship(s)." `
                    -Severity 'Informational' `
                    -Confidence 'High' `
                    -AffectedObject $affectedUser `
                    -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $directoryRoleRelationships) `
                    -MicrosoftReference 'Microsoft Graph roleManagement directory role assignments represent Microsoft Entra role assignments.' `
                    -WhyItMatters 'Directory role relationships can grant administrative capability in Microsoft Entra ID.' `
                    -Recommendation 'Confirm the role assignment is still required.' `
                    -Metadata @{
                        DirectoryRoleRelationshipCount = $directoryRoleRelationships.Count
                        ResultState = 'Informational'
                        SignalDisposition = 'Contextual'
                        EvaluationCriterion = 'Collected directory role relationship exists; existence alone is inventory context and does not establish excessive privilege.'
                    })
            )
        }

        if ($userRelationships.Count -ge $HighConnectivityThreshold) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Users' `
                    -Title 'Highly connected user identity' `
                    -Description "User '$displayName' has $($userRelationships.Count) collected relationship(s)." `
                    -Severity 'Low' `
                    -Confidence 'Medium' `
                    -AffectedObject $affectedUser `
                    -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $userRelationships) `
                    -MicrosoftReference 'Microsoft Graph directory relationships expose group, role, ownership, and assignment connections.' `
                    -WhyItMatters 'Highly connected identities can have broader operational influence and should be reviewed carefully.' `
                    -Limitations @('Connectivity is based only on relationships collected in ObjectInsight.') `
                    -Recommendation 'Review the collected relationships for unnecessary access or ownership.' `
                    -Metadata @{
                        RelationshipCount = $userRelationships.Count
                        Threshold = $HighConnectivityThreshold
                    })
            )
        }

        $ownedRelationships = @(
            $userRelationships |
            Where-Object {
                $_.RelationshipType -in @('OwnsApplication', 'OwnsServicePrincipal', 'Owns')
            }
        )

        if ($ownedRelationships.Count -gt 0) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Users' `
                    -Title 'User owns application-related objects' `
                    -Description "User '$displayName' has ownership relationships in collected metadata." `
                    -Severity 'Low' `
                    -Confidence 'Medium' `
                    -AffectedObject $affectedUser `
                    -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $ownedRelationships) `
                    -MicrosoftReference 'Microsoft Entra application ownership allows owners to manage metadata of applications they own.' `
                    -WhyItMatters 'Application ownership can grant administrative influence over app configuration.' `
                    -Limitations @('This observation fires only when user ownership relationships are present in ObjectInsight.') `
                    -Recommendation 'Validate ownership necessity and accountability.' `
                    -Metadata @{
                        OwnedRelationshipCount = $ownedRelationships.Count
                    })
            )

            if ($directoryRoleRelationships.Count -eq 0) {
                $observations.Add(
                    (New-InspectorSecurityObservation `
                        -Category 'Users' `
                        -Title 'User owns applications without collected directory role relationship' `
                        -Description "User '$displayName' owns application-related objects but has no collected directory role relationship in this ObjectInsight." `
                        -Severity 'Informational' `
                        -Confidence 'Low' `
                        -AffectedObject $affectedUser `
                        -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $ownedRelationships) `
                        -MicrosoftReference 'Application owners can manage applications they own even without broad directory roles.' `
                        -WhyItMatters 'Ownership can grant scoped administrative influence independent of tenant-wide roles.' `
                        -Limitations @('Absence of a role relationship here means none was collected for this ObjectInsight, not proof the user has no roles elsewhere.') `
                        -Recommendation 'Review application ownership as part of access governance.' `
                        -Metadata @{
                            OwnedRelationshipCount = $ownedRelationships.Count
                        })
                )
            }
        }
    }

    # Groups.
    foreach ($group in @($sourceObjects | Where-Object { $_.ObjectType -eq 'Group' })) {
        $groupId = [string]$group.ObjectId
        $displayName = Get-InspectorObservationDisplayName -InputObject $group
        $affectedGroup = New-InspectorAffectedObject -ObjectType 'Group' -ObjectId $groupId -DisplayName $displayName -IsAssignableToRole (Get-InspectorObservationProperty -InputObject $group.Properties -Name 'IsAssignableToRole')
        $properties = $group.Properties

        $isAssignableToRole =
            Get-InspectorObservationProperty `
                -InputObject $properties `
                -Name 'IsAssignableToRole'

        $groupRelationships = @(
            Get-InspectorObservationRelationships `
                -ObjectInsight $ObjectInsight `
                -SourceObjectId $groupId
        )

        $memberRelationships = @(
            $groupRelationships |
            Where-Object { $_.RelationshipType -eq 'HasMember' }
        )

        $roleRelationships = @(
            $groupRelationships |
            Where-Object { $_.RelationshipType -eq 'AssignedDirectoryRole' }
        )

        if ($isAssignableToRole -eq $true) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Groups' `
                    -Title 'Role-assignable group' `
                    -Description "Group '$displayName' can be assigned to Microsoft Entra roles." `
                    -Severity 'Medium' `
                    -Confidence 'High' `
                    -AffectedObject $affectedGroup `
                    -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $groupRelationships) `
                    -MicrosoftReference $roleAssignableGroupReference `
                    -WhyItMatters 'Role-assignable groups can carry Microsoft Entra administrative role assignments through group membership.' `
                    -Recommendation 'Review membership and ownership of role-assignable groups regularly.' `
                    -Metadata @{
                        IsAssignableToRole = $true
                    })
            )

            if ($memberRelationships.Count -gt 0) {
                $observations.Add(
                    (New-InspectorSecurityObservation `
                        -Category 'Groups' `
                        -Title 'Role-assignable group has members' `
                        -Description "Role-assignable group '$displayName' has collected member relationships." `
                        -Severity 'Medium' `
                        -Confidence 'High' `
                        -AffectedObject $affectedGroup `
                        -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $memberRelationships) `
                        -MicrosoftReference $roleAssignableGroupReference `
                        -WhyItMatters 'Members of role-assignable groups can inherit role-based administrative capability.' `
                        -Recommendation 'Validate all members of role-assignable groups.' `
                        -Metadata @{
                            MemberCount = $memberRelationships.Count
                        })
                )
            }
        }

        if ($roleRelationships.Count -gt 0 -and $memberRelationships.Count -gt 0) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Groups' `
                    -Title 'Privileged group has members' `
                    -Description "Group '$displayName' has a directory role assignment and collected members." `
                    -Severity 'High' `
                    -Confidence 'High' `
                    -AffectedObject $affectedGroup `
                    -EvidenceIds (Get-InspectorObservationEvidenceIds -Items @($roleRelationships + $memberRelationships)) `
                    -MicrosoftReference $roleAssignableGroupReference `
                    -WhyItMatters 'Group members may receive administrative capabilities through group-based role assignment.' `
                    -Recommendation 'Review group role assignments and membership.' `
                    -Metadata @{
                        MemberCount = $memberRelationships.Count
                        DirectoryRoleRelationshipCount = $roleRelationships.Count
                        DirectoryRoleAssignments = @(
                            $roleRelationships | ForEach-Object {
                                $roleMetadata = Get-InspectorObservationProperty -InputObject $_ -Name 'Metadata'
                                [PSCustomObject][ordered]@{
                                    AssignmentId = [string](Get-InspectorObservationProperty -InputObject $roleMetadata -Name 'AssignmentId')
                                    PrincipalId = [string](Get-InspectorObservationProperty -InputObject $roleMetadata -Name 'PrincipalId')
                                    RoleDefinitionId = [string](Get-InspectorObservationProperty -InputObject $roleMetadata -Name 'RoleDefinitionId')
                                    RoleDisplayName = [string](Get-InspectorObservationProperty -InputObject $roleMetadata -Name 'RoleDisplayName')
                                    DirectoryScopeId = [string](Get-InspectorObservationProperty -InputObject $roleMetadata -Name 'DirectoryScopeId')
                                    EvidenceId = [string](Get-InspectorObservationProperty -InputObject $_ -Name 'EvidenceId')
                                }
                            }
                        )
                        EvaluationCriterion = 'At least one AssignedDirectoryRole relationship exists for the group and the group has at least one collected member.'
                    })
            )
        }

        $nestedPrivilegedParents = @(
            $groupRelationships |
            Where-Object {
                $_.RelationshipType -eq 'MemberOf' -and
                (
                    (Get-InspectorObservationMetadataValue -InputObject $_ -Name 'IsAssignableToRole') -eq $true -or
                    (Get-InspectorObservationMetadataValue -InputObject $_ -Name 'HasDirectoryRoleAssignment') -eq $true
                )
            }
        )

        if ($nestedPrivilegedParents.Count -gt 0) {
            $observations.Add(
                (New-InspectorSecurityObservation `
                    -Category 'Groups' `
                    -Title 'Group is nested into privileged group' `
                    -Description "Group '$displayName' is a member of a privileged or role-assignable group according to collected metadata." `
                    -Severity 'High' `
                    -Confidence 'Medium' `
                    -AffectedObject $affectedGroup `
                    -EvidenceIds (Get-InspectorObservationEvidenceIds -Items $nestedPrivilegedParents) `
                    -MicrosoftReference $roleAssignableGroupReference `
                    -WhyItMatters 'Nested group relationships can indirectly extend privileged access.' `
                    -Limitations @('This observation fires only when parent group privilege metadata is available.') `
                    -Recommendation 'Review nested group paths that lead to role-assignable or role-assigned groups.' `
                    -Metadata @{
                        NestedPrivilegedParentCount = $nestedPrivilegedParents.Count
                    })
            )
        }
    }

    $sortedObservations =
        @(
            $observations |
            Sort-Object Category, Severity, Title, ObservationId
        )

    return [PSCustomObject][ordered]@{
        PSTypeName       = 'EntraObjectInspector.ObservationEngineResult'
        SchemaVersion    = '0.7.0'
        GeneratedAt      = (Get-Date).ToUniversalTime().ToString('o')
        Status           = 'Success'
        ObservationCount = @($sortedObservations).Count
        Observations     = @($sortedObservations)
        GraphCallsIssued = 0
        Limitations      = @(
            'Observation engine evaluates only data already present in ObjectInsight.'
        )
    }
}

