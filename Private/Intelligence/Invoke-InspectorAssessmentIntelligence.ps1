function Invoke-InspectorAssessmentIntelligence {
    <#
    .SYNOPSIS
        Builds deterministic assessment intelligence from existing artifacts.

    .DESCRIPTION
        assessment intelligence & Recommendation Engine.

        This function consumes ObjectInsight, RuleResults, PermissionInsights,
        and SecurityObservations already present in the supplied input. It does
        not call Microsoft Graph, does not rerun discovery, does not create risk
        scores, does not build attack paths, and does not perform remediation.

        Correlations are assessment co-occurrence signals, not exploitability
        claims and not privilege paths.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$InputObject,

        [string]$AssessmentName = 'Entra Object Inspector Assessment'
    )

    $generatedAt = (Get-Date).ToUniversalTime().ToString('o')

    $objectInsights = @(
        Get-InspectorTenantObjectInsights -InputObject $InputObject
    )

    $rawObservations = @(
        Get-InspectorTenantSecurityObservations -InputObject $InputObject
    )

    $dedupedObservations = @(
        Get-InspectorDeduplicatedObservations -Observation $rawObservations
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $recommendations = [System.Collections.Generic.List[object]]::new()
    $correlations = [System.Collections.Generic.List[object]]::new()

    $ownerReference = 'Microsoft recommends proactively monitoring applications in the tenant to ensure that applications have at least two owners where possible.'
    $permissionReference = 'Microsoft Graph permissions reference documents application permissions and highlights authorization-granting permissions such as AppRoleAssignment.ReadWrite.All and RoleManagement.ReadWrite.Directory.'
    $consentReference = 'Microsoft Graph oAuth2PermissionGrant represents delegated permission grants; consentType AllPrincipals indicates tenant-wide consent.'
    $credentialReference = 'Microsoft Graph application and service principal credential resources expose credential validity metadata including startDateTime and endDateTime.'
    $servicePrincipalReference = 'Microsoft Graph servicePrincipal resource exposes accountEnabled and appRoleAssignmentRequired state properties.'
    $roleAssignableGroupReference = 'Microsoft Entra role-assignable groups use isAssignableToRole=true to allow Microsoft Entra role assignment to a group.'
    $overviewReference = 'Assessment intelligence is derived from already-collected Entra Object Inspector observations and Microsoft documentation references attached to those observations.'

    $severitySummary = @(
        $dedupedObservations |
            Group-Object Severity |
            Sort-Object @{ Expression = { Get-InspectorSeverityOrder -Severity $_.Name } }, Name |
            ForEach-Object {
                [PSCustomObject][ordered]@{
                    Severity = $_.Name
                    Count = $_.Count
                }
            }
    )

    $categorySummary = @(
        $dedupedObservations |
            Group-Object Category |
            Sort-Object Name |
            ForEach-Object {
                [PSCustomObject][ordered]@{
                    Category = $_.Name
                    Count = $_.Count
                }
            }
    )

    $confidenceSummary = @(
        $dedupedObservations |
            Group-Object Confidence |
            Sort-Object @{ Expression = { Get-InspectorConfidenceOrder -Confidence $_.Name } }, Name |
            ForEach-Object {
                [PSCustomObject][ordered]@{
                    Confidence = $_.Name
                    Count = $_.Count
                }
            }
    )

    $findingEligibleObservations = @(
        $dedupedObservations |
        Where-Object { Test-InspectorObservationFindingEligibility -Observation $_ }
    )
    $highCount = @($findingEligibleObservations | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = @($findingEligibleObservations | Where-Object { $_.Severity -eq 'Medium' }).Count
    $duplicateObservationCount = [math]::Max(0, @($rawObservations).Count - @($dedupedObservations).Count)

    $postureLabel =
        if ($highCount -gt 0) {
            'AttentionRequired'
        }
        elseif ($mediumCount -gt 0) {
            'ReviewRecommended'
        }
        elseif (@($dedupedObservations).Count -gt 0) {
            'InformationalReview'
        }
        else {
            'NoObservations'
        }

    $postureReason =
        if ($postureLabel -eq 'AttentionRequired') {
            'Attention required because confirmed or review-required high-impact grouped conditions were identified in the inspected scope.'
        }
        elseif ($postureLabel -eq 'ReviewRecommended') {
            'Review recommended because confirmed or review-required medium grouped conditions were identified in the inspected scope.'
        }
        elseif ($postureLabel -eq 'InformationalReview') {
            'Informational review only; collected observations did not produce high or medium grouped conditions.'
        }
        else {
            'No observations were produced from the inspected scope.'
        }

    $severityBasis = if (@($findingEligibleObservations).Count -gt 0) { @($findingEligibleObservations) } else { @($dedupedObservations) }
    $overallSeverity = Join-InspectorSeverity -Severity @($severityBasis | ForEach-Object { $_.Severity })
    $overallConfidence = Join-InspectorConfidence -Confidence @($severityBasis | ForEach-Object { $_.Confidence })

    $identityObservations = @($dedupedObservations | Where-Object { $_.Category -eq 'IdentityGovernance' -and (Test-InspectorObservationFindingEligibility -Observation $_) })
    $credentialObservations = @($dedupedObservations | Where-Object { $_.Category -eq 'Credentials' -and (Test-InspectorObservationFindingEligibility -Observation $_) })
    $permissionObservations = @($dedupedObservations | Where-Object { $_.Category -eq 'Permissions' -and (Test-InspectorObservationFindingEligibility -Observation $_) })
    $servicePrincipalObservations = @($dedupedObservations | Where-Object { $_.Category -eq 'ServicePrincipal' -and (Test-InspectorObservationFindingEligibility -Observation $_) })
    $consentObservations = @($dedupedObservations | Where-Object { $_.Category -eq 'Consent' -and (Test-InspectorObservationFindingEligibility -Observation $_) })
    $userObservations = @($dedupedObservations | Where-Object { $_.Category -eq 'Users' -and (Test-InspectorObservationFindingEligibility -Observation $_) })
    $groupObservations = @($dedupedObservations | Where-Object { $_.Category -eq 'Groups' -and (Test-InspectorObservationFindingEligibility -Observation $_) })

    if (@($identityObservations).Count -gt 0) {
        $findings.Add(
            (New-InspectorAssessmentFinding `
                -Category 'IdentityGovernance' `
                -Title 'Application ownership governance requires review' `
                -Conclusion 'Identity governance observations indicate ownership or accountability gaps across application-related objects.' `
                -Severity (Join-InspectorSeverity -Severity @($identityObservations | ForEach-Object { $_.Severity })) `
                -Confidence (Join-InspectorConfidence -Confidence @($identityObservations | ForEach-Object { $_.Confidence })) `
                -RelatedObservations $identityObservations `
                -Recommendation 'Review application and service principal owners, assign at least two accountable owners where possible, and validate inactive, disabled, or external owners.' `
                -MicrosoftReference $ownerReference `
                -Metadata @{
                    ObservationCount = @($identityObservations).Count
                    NoOwnerCount = @($identityObservations | Where-Object { $_.Title -like '*no owner*' }).Count
                    SingleOwnerCount = @($identityObservations | Where-Object { $_.Title -like '*single owner*' }).Count
                    CriterionSummary = 'Application and service-principal ownership observations are grouped by owner count, owner state, and owner-set consistency.'
                })
        )

        $recommendations.Add(
            (New-InspectorAssessmentRecommendation `
                -Category 'IdentityGovernance' `
                -Title 'Normalize application ownership accountability' `
                -Action 'Assign or validate at least two accountable owners for application and service-principal objects where possible.' `
                -Rationale 'Clear ownership improves accountability for app permissions, credentials, consent, and lifecycle governance.' `
                -MicrosoftReference $ownerReference `
                -RelatedObservations $identityObservations `
                -Confidence (Join-InspectorConfidence -Confidence @($identityObservations | ForEach-Object { $_.Confidence })))
        )
    }

    if (@($credentialObservations).Count -gt 0) {
        $credentialRecommendationParts = [System.Collections.Generic.List[string]]::new()
        if (@($credentialObservations | Where-Object { $_.Title -eq 'Expired credential is still present' }).Count -gt 0) { $credentialRecommendationParts.Add('remove expired credentials after dependency validation') }
        if (@($credentialObservations | Where-Object { $_.Title -eq 'Credential expires soon' }).Count -gt 0) { $credentialRecommendationParts.Add('renew credentials approaching expiration') }
        if (@($credentialObservations | Where-Object { $_.Title -eq 'Long-lived client secret' }).Count -gt 0) { $credentialRecommendationParts.Add('reduce unnecessarily long-lived secret validity') }
        if (@($credentialObservations | Where-Object { $_.Title -eq 'Multiple active client secrets' }).Count -gt 0) { $credentialRecommendationParts.Add('validate whether concurrent active secrets are required') }
        if (@($credentialObservations | Where-Object { $_.Title -eq 'Overlapping credential validity windows' }).Count -gt 0) { $credentialRecommendationParts.Add('confirm overlapping validity is limited to documented rotation windows') }
        $credentialRecommendation =
            if ($credentialRecommendationParts.Count -gt 0) {
                ($credentialRecommendationParts -join '; ') + '.'
            }
            else {
                'Review the detected credential lifecycle conditions and remove unnecessary credential exposure.'
            }

        $findings.Add(
            (New-InspectorAssessmentFinding `
                -Category 'CredentialHygiene' `
                -Title 'Application credential hygiene requires review' `
                -Conclusion 'Credential observations indicate expired, expiring, long-lived, multiple, or overlapping credentials in the inspected scope.' `
                -Severity (Join-InspectorSeverity -Severity @($credentialObservations | ForEach-Object { $_.Severity })) `
                -Confidence (Join-InspectorConfidence -Confidence @($credentialObservations | ForEach-Object { $_.Confidence })) `
                -RelatedObservations $credentialObservations `
                -Recommendation $credentialRecommendation `
                -MicrosoftReference $credentialReference `
                -Metadata @{
                    ObservationCount = @($credentialObservations).Count
                    ExpiredCount = @($credentialObservations | Where-Object { $_.Title -like '*Expired*' }).Count
                    ExpiringCount = @($credentialObservations | Where-Object { $_.Title -like '*expires soon*' }).Count
                    LongLivedCount = @($credentialObservations | Where-Object { $_.Title -like '*Long-lived*' }).Count
                    CriterionSummary = 'Credential conditions are evaluated from collected credential metadata such as startDateTime, endDateTime, credential type, and key identifier.'
                })
        )

        $recommendations.Add(
            (New-InspectorAssessmentRecommendation `
                -Category 'CredentialHygiene' `
                -Title 'Tighten credential lifecycle controls' `
                -Action $credentialRecommendation `
                -Rationale 'Credential hygiene reduces operational risk and limits exposure windows if credentials are leaked.' `
                -MicrosoftReference $credentialReference `
                -RelatedObservations $credentialObservations `
                -Confidence (Join-InspectorConfidence -Confidence @($credentialObservations | ForEach-Object { $_.Confidence })))
        )
    }

    if (@($permissionObservations).Count -gt 0) {
        $permissionNames = @(
            $permissionObservations |
                ForEach-Object {
                    $metadata = Get-InspectorIntelligenceProperty -InputObject $_ -Name 'Metadata'
                    Get-InspectorIntelligenceProperty -InputObject $metadata -Name 'PermissionName'
                } |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                Select-Object -Unique
        )

        $findings.Add(
            (New-InspectorAssessmentFinding `
                -Category 'PermissionExposure' `
                -Title 'High-impact Microsoft Graph permission exposure detected' `
                -Conclusion 'Permission observations indicate high-impact Microsoft Graph application permissions in the inspected scope.' `
                -Severity (Join-InspectorSeverity -Severity @($permissionObservations | ForEach-Object { $_.Severity })) `
                -Confidence (Join-InspectorConfidence -Confidence @($permissionObservations | ForEach-Object { $_.Confidence })) `
                -RelatedObservations $permissionObservations `
                -Recommendation 'Validate business justification, ownership, credential hygiene, and consent posture for each high-impact application permission.' `
                -MicrosoftReference $permissionReference `
                -Metadata @{
                    ObservationCount = @($permissionObservations).Count
                    PermissionNames = @($permissionNames)
                    CriterionSummary = 'Observed application permissions are compared with the local high-impact Microsoft Graph application permission catalog.'
                })
        )

        $recommendations.Add(
            (New-InspectorAssessmentRecommendation `
                -Category 'PermissionExposure' `
                -Title 'Review high-impact application permissions' `
                -Action 'Validate necessity and least privilege for high-impact Microsoft Graph application permissions.' `
                -Rationale 'High-impact application permissions can allow app-only access to sensitive directory, policy, role, or authorization-granting operations.' `
                -MicrosoftReference $permissionReference `
                -RelatedObservations $permissionObservations `
                -Confidence (Join-InspectorConfidence -Confidence @($permissionObservations | ForEach-Object { $_.Confidence })))
        )
    }

    if (@($servicePrincipalObservations).Count -gt 0) {
        $findings.Add(
            (New-InspectorAssessmentFinding `
                -Category 'ServicePrincipalGovernance' `
                -Title 'Service principal governance requires review' `
                -Conclusion 'Service principal observations indicate state, assignment, counterpart, or ownership-difference conditions that should be validated.' `
                -Severity (Join-InspectorSeverity -Severity @($servicePrincipalObservations | ForEach-Object { $_.Severity })) `
                -Confidence (Join-InspectorConfidence -Confidence @($servicePrincipalObservations | ForEach-Object { $_.Confidence })) `
                -RelatedObservations $servicePrincipalObservations `
                -Recommendation 'Validate the specific counterpart and ownership-consistency conditions listed under Conditions detected; routine enabled/assignment state remains contextual inventory.' `
                -MicrosoftReference $servicePrincipalReference `
                -Metadata @{
                    ObservationCount = @($servicePrincipalObservations).Count
                    CriterionSummary = 'Service-principal state observations are treated as contextual inventory unless combined with governance or permission conditions requiring review.'
                })
        )

        $recommendations.Add(
            (New-InspectorAssessmentRecommendation `
                -Category 'ServicePrincipalGovernance' `
                -Title 'Validate service principal access model' `
                -Action 'Validate tenant-relevant counterpart inconsistencies and application/service-principal ownership differences represented by the current finding-eligible conditions.' `
                -Rationale 'Service principal state and assignment settings influence how applications and workloads can be accessed or used.' `
                -MicrosoftReference $servicePrincipalReference `
                -RelatedObservations $servicePrincipalObservations `
                -Confidence (Join-InspectorConfidence -Confidence @($servicePrincipalObservations | ForEach-Object { $_.Confidence })))
        )
    }

    if (@($consentObservations).Count -gt 0) {
        $findings.Add(
            (New-InspectorAssessmentFinding `
                -Category 'ConsentGovernance' `
                -Title 'Application consent posture requires review' `
                -Conclusion 'Consent observations indicate delegated or tenant-wide consent relationships in the inspected scope.' `
                -Severity (Join-InspectorSeverity -Severity @($consentObservations | ForEach-Object { $_.Severity })) `
                -Confidence (Join-InspectorConfidence -Confidence @($consentObservations | ForEach-Object { $_.Confidence })) `
                -RelatedObservations $consentObservations `
                -Recommendation 'Review delegated and tenant-wide consent grants for necessity, scope, and ownership accountability.' `
                -MicrosoftReference $consentReference `
                -Metadata @{
                    ObservationCount = @($consentObservations).Count
                    TenantWideConsentCount = @($consentObservations | Where-Object { $_.Title -like '*Tenant-wide*' }).Count
                    CriterionSummary = 'Delegated and tenant-wide consent grants are grouped for administrator review of scope, necessity, and ownership accountability.'
                })
        )

        $recommendations.Add(
            (New-InspectorAssessmentRecommendation `
                -Category 'ConsentGovernance' `
                -Title 'Review delegated and tenant-wide consent grants' `
                -Action 'Validate whether each delegated or tenant-wide consent grant remains necessary and appropriately scoped.' `
                -Rationale 'Consent grants define what applications can access on behalf of users or across the tenant.' `
                -MicrosoftReference $consentReference `
                -RelatedObservations $consentObservations `
                -Confidence (Join-InspectorConfidence -Confidence @($consentObservations | ForEach-Object { $_.Confidence })))
        )
    }

    if (@($userObservations).Count -gt 0) {
        $findings.Add(
            (New-InspectorAssessmentFinding `
                -Category 'UserGovernance' `
                -Title 'User identity governance signals require review' `
                -Conclusion 'Finding-eligible user observations indicate high-connectivity or application-ownership relationships in the inspected scope; ordinary role relationships remain contextual inventory.' `
                -Severity (Join-InspectorSeverity -Severity @($userObservations | ForEach-Object { $_.Severity })) `
                -Confidence (Join-InspectorConfidence -Confidence @($userObservations | ForEach-Object { $_.Confidence })) `
                -RelatedObservations $userObservations `
                -Recommendation 'Review the high-connectivity and application-ownership conditions listed under Conditions detected for least privilege and accountability.' `
                -MicrosoftReference 'Microsoft Graph role management and directory relationship data support reviewing users with administrative or highly connected relationships.' `
                -Metadata @{
                    ObservationCount = @($userObservations).Count
                    CriterionSummary = 'User governance findings use only finding-eligible high-connectivity and ownership conditions; ordinary directory-role relationship presence remains contextual inventory.'
                })
        )

        $recommendations.Add(
            (New-InspectorAssessmentRecommendation `
                -Category 'UserGovernance' `
                -Title 'Review user governance relationship signals' `
                -Action 'Validate high-connectivity identities and application ownership relationships represented by the current finding-eligible user conditions.' `
                -Rationale 'User relationship signals help administrators review accountability and least-privilege assumptions without inferring sign-in or activity risk.' `
                -MicrosoftReference 'Microsoft Graph role management and directory relationship data support reviewing users with administrative or highly connected relationships.' `
                -RelatedObservations $userObservations `
                -Confidence (Join-InspectorConfidence -Confidence @($userObservations | ForEach-Object { $_.Confidence })))
        )
    }

    if (@($groupObservations).Count -gt 0) {
        $findings.Add(
            (New-InspectorAssessmentFinding `
                -Category 'GroupGovernance' `
                -Title 'Privileged group governance requires review' `
                -Conclusion 'Group observations indicate role-assignable, privileged, or nested privileged group conditions in the inspected scope.' `
                -Severity (Join-InspectorSeverity -Severity @($groupObservations | ForEach-Object { $_.Severity })) `
                -Confidence (Join-InspectorConfidence -Confidence @($groupObservations | ForEach-Object { $_.Confidence })) `
                -RelatedObservations $groupObservations `
                -Recommendation 'Review ownership, membership, and nested membership of role-assignable or privileged groups.' `
                -MicrosoftReference $roleAssignableGroupReference `
                -Metadata @{
                    ObservationCount = @($groupObservations).Count
                    CriterionSummary = 'Group governance observations are grouped around role-assignable, privileged, nested, owner, and membership conditions.'
                })
        )

        $recommendations.Add(
            (New-InspectorAssessmentRecommendation `
                -Category 'GroupGovernance' `
                -Title 'Review role-assignable and privileged groups' `
                -Action 'Validate members, owners, and nested memberships of role-assignable or privileged groups.' `
                -Rationale 'Role-assignable groups can carry Microsoft Entra administrative capabilities through group membership.' `
                -MicrosoftReference $roleAssignableGroupReference `
                -RelatedObservations $groupObservations `
                -Confidence (Join-InspectorConfidence -Confidence @($groupObservations | ForEach-Object { $_.Confidence })))
        )
    }

    if (@($permissionObservations).Count -gt 0 -and @($identityObservations).Count -gt 0) {
        $correlations.Add(
            (New-InspectorAssessmentCorrelation `
                -CorrelationType 'PermissionGovernanceCoOccurrence' `
                -Title 'High-impact permissions co-occur with ownership governance observations' `
                -Description 'The assessment contains both high-impact permission observations and application ownership governance observations.' `
                -RelatedObservations @($permissionObservations + $identityObservations) `
                -Confidence (Join-InspectorConfidence -Confidence @(@($permissionObservations + $identityObservations) | ForEach-Object { $_.Confidence })) `
                -Limitations @('This is a tenant assessment co-occurrence signal, not an attack path or exploitability claim.'))
        )
    }

    if (@($permissionObservations).Count -gt 0 -and @($credentialObservations).Count -gt 0) {
        $correlations.Add(
            (New-InspectorAssessmentCorrelation `
                -CorrelationType 'PermissionCredentialCoOccurrence' `
                -Title 'High-impact permissions co-occur with credential hygiene observations' `
                -Description 'The assessment contains both high-impact permission observations and credential hygiene observations.' `
                -RelatedObservations @($permissionObservations + $credentialObservations) `
                -Confidence (Join-InspectorConfidence -Confidence @(@($permissionObservations + $credentialObservations) | ForEach-Object { $_.Confidence })) `
                -Limitations @('This is a tenant assessment co-occurrence signal, not proof that a credential can exercise the permission.'))
        )
    }

    if (@($permissionObservations).Count -gt 0 -and @($consentObservations).Count -gt 0) {
        $correlations.Add(
            (New-InspectorAssessmentCorrelation `
                -CorrelationType 'PermissionConsentCoOccurrence' `
                -Title 'High-impact permissions co-occur with consent observations' `
                -Description 'The assessment contains both high-impact application permission observations and consent governance observations.' `
                -RelatedObservations @($permissionObservations + $consentObservations) `
                -Confidence (Join-InspectorConfidence -Confidence @(@($permissionObservations + $consentObservations) | ForEach-Object { $_.Confidence })) `
                -Limitations @('This is a governance review signal and does not infer unused access or exploitability.'))
        )
    }

    if (@($groupObservations).Count -gt 0 -and @($userObservations).Count -gt 0) {
        $correlations.Add(
            (New-InspectorAssessmentCorrelation `
                -CorrelationType 'PrivilegedIdentityGovernanceCoOccurrence' `
                -Title 'Privileged group and user governance observations co-occur' `
                -Description 'The assessment contains both group governance observations and user governance observations.' `
                -RelatedObservations @($groupObservations + $userObservations) `
                -Confidence (Join-InspectorConfidence -Confidence @(@($groupObservations + $userObservations) | ForEach-Object { $_.Confidence })) `
                -Limitations @('This is not a nested privilege path calculation.'))
        )
    }

    $limitationItems = [System.Collections.Generic.List[string]]::new()

    foreach ($staticLimitation in @(
        'Assessment intelligence consumes existing artifacts only.',
        'Assessment intelligence does not call Microsoft Graph.',
        'Assessment intelligence does not produce numerical risk scores, exposure scores, attack paths, privilege paths, MITRE mappings, UI, history, or remediation automation.'
    )) {
        if (-not [string]::IsNullOrWhiteSpace([string]$staticLimitation)) {
            $limitationItems.Add([string]$staticLimitation)
        }
    }

    foreach ($sourceLimitation in @(
        Get-InspectorIntelligenceProperty -InputObject $InputObject -Name 'Limitations'
    )) {
        if (-not [string]::IsNullOrWhiteSpace([string]$sourceLimitation)) {
            $limitationItems.Add([string]$sourceLimitation)
        }
    }

    foreach ($sourceItem in @($dedupedObservations + @($findings) + @($correlations))) {
        if ($null -eq $sourceItem) {
            continue
        }

        foreach ($limitation in @(
            Get-InspectorIntelligenceProperty `
                -InputObject $sourceItem `
                -Name 'Limitations'
        )) {
            if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) {
                $limitationItems.Add([string]$limitation)
            }
        }
    }

    $allLimitations = @(
        $limitationItems |
            Sort-Object -Unique
    )

    $objectSummaries = @(
        $objectInsights |
            ForEach-Object {
                $inputValue = [string](Get-InspectorIntelligenceProperty -InputObject $_ -Name 'Input')
                $observationsForObject = @(
                    Get-InspectorIntelligenceProperty -InputObject $_ -Name 'SecurityObservations'
                ) | Where-Object { $null -ne $_ }

                [PSCustomObject][ordered]@{
                    Input = $inputValue
                    Status = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $_ -Name 'Status')
                    ResolutionType = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $_ -Name 'ResolutionType')
                    ObservationCount = @($observationsForObject).Count
                    FindingSignals = @(
                        $observationsForObject |
                            Group-Object Category |
                            Sort-Object Name |
                            ForEach-Object {
                                [PSCustomObject][ordered]@{
                                    Category = $_.Name
                                    Count = $_.Count
                                }
                            }
                    )
                }
            } |
            Sort-Object ResolutionType, Input
    )

    return [PSCustomObject][ordered]@{
        PSTypeName = 'EntraObjectInspector.AssessmentIntelligence'
        SchemaVersion = '0.9.0'
        AssessmentName = $AssessmentName
        GeneratedAt = $generatedAt
        Status = 'Success'
        SourceSchemaVersion = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $InputObject -Name 'SchemaVersion')
        SourceStatus = ConvertTo-InspectorIntelligenceString (Get-InspectorIntelligenceProperty -InputObject $InputObject -Name 'Status')
        GraphCallsIssued = 0
        InputMode = 'ExistingArtifactsOnly'
        RiskScoreProduced = $false
        ExposureScoreProduced = $false
        AttackPathsProduced = $false
        IntelligenceScope = @(
            'Observation correlation',
            'Posture summaries',
            'Category findings',
            'Explainable recommendations',
            'Observation deduplication',
            'Confidence propagation',
            'Limitation aggregation'
        )
        TenantPosture = [PSCustomObject][ordered]@{
            Label = $postureLabel
            HighestSeverity = $overallSeverity
            Confidence = $overallConfidence
            ObservationCount = @($dedupedObservations).Count
            FindingCount = @($findings).Count
            RecommendationCount = @($recommendations).Count
            CorrelationCount = @($correlations).Count
            TenantPostureReason = $postureReason
        }
        Summary = [PSCustomObject][ordered]@{
            ObjectInsightCount = @($objectInsights).Count
            RawObservationCount = @($rawObservations).Count
            DeduplicatedObservationCount = @($dedupedObservations).Count
            DuplicateObservationCount = $duplicateObservationCount
            FindingEligibleObservationCount = @($findingEligibleObservations).Count
            ContextualObservationCount = @($dedupedObservations).Count - @($findingEligibleObservations).Count
            GroupedFindingCount = @($findings).Count
            FindingCount = @($findings).Count
            RecommendationCount = @($recommendations).Count
            CorrelationCount = @($correlations).Count
            LimitationCount = @($allLimitations).Count
        }
        SeveritySummary = @($severitySummary)
        CategorySummary = @($categorySummary)
        ConfidenceSummary = @($confidenceSummary)
        ObjectSummaries = @($objectSummaries)
        DeduplicatedObservations = @($dedupedObservations)
        AssessmentFindings = @($findings | Sort-Object Category, Title, FindingId)
        AssessmentRecommendations = @($recommendations | Sort-Object Category, Title, RecommendationId)
        Correlations = @($correlations | Sort-Object CorrelationType, Title, CorrelationId)
        Limitations = @($allLimitations)
    }
}

