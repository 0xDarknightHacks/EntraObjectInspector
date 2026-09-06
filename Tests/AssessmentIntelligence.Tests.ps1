$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'assessment intelligence' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TestAffectedObject {
                param (
                    [string]$ObjectType = 'Application',
                    [string]$ObjectId = 'app-1',
                    [string]$DisplayName = 'App One'
                )

                [PSCustomObject]@{
                    ObjectType = $ObjectType
                    ObjectId = $ObjectId
                    DisplayName = $DisplayName
                }
            }

            function New-TestObservation {
                param (
                    [string]$ObservationId,
                    [string]$Category,
                    [string]$Title,
                    [string]$Severity = 'Medium',
                    [string]$Confidence = 'High',
                    [string[]]$EvidenceIds = @('ev-1'),
                    [string[]]$Limitations = @(),
                    [hashtable]$Metadata = @{},
                    [object]$AffectedObject = (New-TestAffectedObject)
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.SecurityObservation'
                    SchemaVersion = '0.7.0'
                    ObservationId = $ObservationId
                    Category = $Category
                    Title = $Title
                    Description = 'Description'
                    Severity = $Severity
                    Confidence = $Confidence
                    AffectedObject = $AffectedObject
                    EvidenceIds = @($EvidenceIds)
                    MicrosoftReference = 'Microsoft reference'
                    WhyItMatters = 'Why it matters'
                    Limitations = @($Limitations)
                    Recommendation = 'Review'
                    SourceRuleIds = @()
                    SemanticKey = if ($Metadata.ContainsKey('SemanticKey')) { $Metadata.SemanticKey } else { $null }
                    Metadata = [PSCustomObject]$Metadata
                }
            }

            function New-TestTenantResult {
                param (
                    [object[]]$Observations
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.TenantInspectionResult'
                    SchemaVersion = '0.8.0'
                    Status = 'Success'
                    ObjectInsights = @(
                        [PSCustomObject]@{
                            PSTypeName = 'EntraObjectInspector.ObjectInsight'
                            Input = 'app-1'
                            Status = 'Resolved'
                            ResolutionType = 'ApplicationIdentity'
                            SecurityObservations = @($Observations)
                        }
                    )
                    SecurityObservations = @($Observations)
                    Summary = [PSCustomObject]@{
                        ObjectInsightCount = 1
                        SecurityObservationCount = @($Observations).Count
                    }
                }
            }
        }

        BeforeEach {
            Mock Invoke-InspectorGraphRequest {
                throw 'Assessment intelligence must not call Graph.'
            }
        }

        It 'generates assessment intelligence without Graph calls' {
            $tenant =
                New-TestTenantResult `
                    -Observations @(
                        (New-TestObservation -ObservationId 'OBS-1' -Category 'IdentityGovernance' -Title 'Application has a single owner')
                    )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject $tenant `
                    -AssessmentName 'Unit Test'

            $result.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.AssessmentIntelligence'
            $result.SchemaVersion | Should -Be '0.9.0'
            $result.AssessmentName | Should -Be 'Unit Test'
            $result.GraphCallsIssued | Should -Be 0
            $result.RiskScoreProduced | Should -BeFalse
            $result.ExposureScoreProduced | Should -BeFalse
            $result.AttackPathsProduced | Should -BeFalse

            Should-Invoke Invoke-InspectorGraphRequest -Times 0
        }

        It 'deduplicates observations by ObservationId' {
            $obs1 = New-TestObservation -ObservationId 'OBS-DUP' -Category 'Credentials' -Title 'Credential expires soon'
            $obs2 = New-TestObservation -ObservationId 'OBS-DUP' -Category 'Credentials' -Title 'Credential expires soon'

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations @($obs1, $obs2))

            $result.Summary.RawObservationCount | Should -Be 2
            $result.Summary.DeduplicatedObservationCount | Should -Be 1
            $result.DeduplicatedObservations.Count | Should -Be 1
        }

        It 'builds severity, category, and confidence summaries' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High' -Confidence 'High')
                (New-TestObservation -ObservationId 'OBS-2' -Category 'Credentials' -Title 'Credential expires soon' -Severity 'Medium' -Confidence 'Medium')
                (New-TestObservation -ObservationId 'OBS-3' -Category 'Consent' -Title 'Application permissions present' -Severity 'Informational' -Confidence 'High')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            ($result.SeveritySummary | Where-Object Severity -eq 'High').Count | Should -Be 1
            ($result.SeveritySummary | Where-Object Severity -eq 'Medium').Count | Should -Be 1
            ($result.CategorySummary | Where-Object Category -eq 'Credentials').Count | Should -Be 1
            ($result.ConfidenceSummary | Where-Object Confidence -eq 'High').Count | Should -Be 2
        }

        It 'creates identity governance findings and recommendations' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'IdentityGovernance' -Title 'Application has a single owner' -Severity 'Medium')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.AssessmentFindings.Category | Should -Contain 'IdentityGovernance'
            $result.AssessmentRecommendations.Category | Should -Contain 'IdentityGovernance'
        }

        It 'creates credential hygiene findings and recommendations' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'Credentials' -Title 'Expired credential is still present' -Severity 'High')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.AssessmentFindings.Category | Should -Contain 'CredentialHygiene'
            $result.AssessmentRecommendations.Category | Should -Contain 'CredentialHygiene'
        }

        It 'creates permission exposure findings and recommendations' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High' -Metadata @{ PermissionName = 'Directory.ReadWrite.All' })
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.AssessmentFindings.Category | Should -Contain 'PermissionExposure'
            $result.AssessmentRecommendations.Category | Should -Contain 'PermissionExposure'
            ($result.AssessmentFindings | Where-Object Category -eq 'PermissionExposure').Metadata.PermissionNames |
                Should -Contain 'Directory.ReadWrite.All'
        }

        It 'deduplicates semantically equivalent permission observations without collapsing different objects or grant types' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High' -AffectedObject (New-TestAffectedObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-1') -Metadata @{ SemanticKey = 'ServicePrincipal|sp-1|PERM-GRAPH-HIGH-001|Directory.ReadWrite.All|Application|00000003-0000-0000-c000-000000000000'; PermissionName = 'Directory.ReadWrite.All'; PermissionType = 'Application'; ResourceAppId = '00000003-0000-0000-c000-000000000000' })
                (New-TestObservation -ObservationId 'OBS-2' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High' -AffectedObject (New-TestAffectedObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-1') -Metadata @{ SemanticKey = 'ServicePrincipal|sp-1|PERM-GRAPH-HIGH-001|Directory.ReadWrite.All|Application|00000003-0000-0000-c000-000000000000'; PermissionName = 'Directory.ReadWrite.All'; PermissionType = 'Application'; ResourceAppId = '00000003-0000-0000-c000-000000000000' })
                (New-TestObservation -ObservationId 'OBS-3' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High' -AffectedObject (New-TestAffectedObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-2') -Metadata @{ SemanticKey = 'ServicePrincipal|sp-2|PERM-GRAPH-HIGH-001|Directory.ReadWrite.All|Application|00000003-0000-0000-c000-000000000000'; PermissionName = 'Directory.ReadWrite.All'; PermissionType = 'Application'; ResourceAppId = '00000003-0000-0000-c000-000000000000' })
                (New-TestObservation -ObservationId 'OBS-4' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High' -AffectedObject (New-TestAffectedObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-1') -Metadata @{ SemanticKey = 'ServicePrincipal|sp-1|PERM-GRAPH-HIGH-001|Directory.ReadWrite.All|Delegated|00000003-0000-0000-c000-000000000000'; PermissionName = 'Directory.ReadWrite.All'; PermissionType = 'Delegated'; ResourceAppId = '00000003-0000-0000-c000-000000000000' })
            )

            $result = Invoke-InspectorAssessmentIntelligence -InputObject (New-TestTenantResult -Observations $observations)

            $result.Summary.RawObservationCount | Should -Be 4
            $result.Summary.DeduplicatedObservationCount | Should -Be 3
            $result.Summary.DuplicateObservationCount | Should -Be 1
        }

        It 'adds grouped finding qualification metadata' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High' -Metadata @{ PermissionName = 'Directory.ReadWrite.All' })
            )

            $result = Invoke-InspectorAssessmentIntelligence -InputObject (New-TestTenantResult -Observations $observations)
            $finding = $result.AssessmentFindings | Where-Object Category -eq 'PermissionExposure' | Select-Object -First 1

            $finding.ResultState | Should -BeIn @('Confirmed','ReviewRequired','MoreEvidenceNeeded','Informational')
            $finding.EvidenceLinkStatus | Should -BeIn @('DirectEvidence','Mixed','DerivedFromCollectedState','InsufficientEvidence')
            $finding.CriterionSummary | Should -Not -BeNullOrEmpty
            $finding.SeverityReason | Should -Not -BeNullOrEmpty
            $finding.AffectedObjectCount | Should -Be 1
            @($finding.IssueGroups).Count | Should -BeGreaterThan 0
        }

        It 'creates service principal governance findings' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'ServicePrincipal' -Title 'Service principal does not require assignment' -Severity 'Low')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.AssessmentFindings.Category | Should -Contain 'ServicePrincipalGovernance'
        }

        It 'creates consent governance findings and recommendations' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'Consent' -Title 'Tenant-wide delegated consent grant' -Severity 'Medium')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.AssessmentFindings.Category | Should -Contain 'ConsentGovernance'
            $result.AssessmentRecommendations.Category | Should -Contain 'ConsentGovernance'
        }

        It 'creates user governance findings' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'Users' -Title 'User has Microsoft Entra directory role relationship' -Severity 'Medium')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.AssessmentFindings.Category | Should -Contain 'UserGovernance'
        }

        It 'creates group governance findings and recommendations' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'Groups' -Title 'Role-assignable group' -Severity 'Medium')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.AssessmentFindings.Category | Should -Contain 'GroupGovernance'
            $result.AssessmentRecommendations.Category | Should -Contain 'GroupGovernance'
        }

        It 'correlates high-impact permissions with ownership governance observations' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-PERM' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High')
                (New-TestObservation -ObservationId 'OBS-OWNER' -Category 'IdentityGovernance' -Title 'Application has a single owner' -Severity 'Medium')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.Correlations.CorrelationType | Should -Contain 'PermissionGovernanceCoOccurrence'
            ($result.Correlations | Where-Object CorrelationType -eq 'PermissionGovernanceCoOccurrence').Limitations |
                Should -Contain 'This is a tenant assessment co-occurrence signal, not an attack path or exploitability claim.'
        }

        It 'correlates high-impact permissions with credential hygiene observations' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-PERM' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High')
                (New-TestObservation -ObservationId 'OBS-CRED' -Category 'Credentials' -Title 'Expired credential is still present' -Severity 'High')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.Correlations.CorrelationType | Should -Contain 'PermissionCredentialCoOccurrence'
        }

        It 'correlates high-impact permissions with consent observations' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-PERM' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High')
                (New-TestObservation -ObservationId 'OBS-CONSENT' -Category 'Consent' -Title 'Tenant-wide delegated consent grant' -Severity 'Medium')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.Correlations.CorrelationType | Should -Contain 'PermissionConsentCoOccurrence'
        }

        It 'correlates group and user governance observations without creating a privilege path' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-GROUP' -Category 'Groups' -Title 'Role-assignable group' -Severity 'Medium')
                (New-TestObservation -ObservationId 'OBS-USER' -Category 'Users' -Title 'User has Microsoft Entra directory role relationship' -Severity 'Medium')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.Correlations.CorrelationType | Should -Contain 'PrivilegedIdentityGovernanceCoOccurrence'
            $result.AttackPathsProduced | Should -BeFalse
        }

        It 'propagates confidence conservatively' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'IdentityGovernance' -Title 'Application owner appears inactive' -Severity 'Low' -Confidence 'Medium')
                (New-TestObservation -ObservationId 'OBS-2' -Category 'IdentityGovernance' -Title 'Application owner appears external' -Severity 'Medium' -Confidence 'Low')
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            ($result.AssessmentFindings | Where-Object Category -eq 'IdentityGovernance').Confidence |
                Should -Be 'Low'
        }

        It 'aggregates limitations from observations, findings, and correlations' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All' -Severity 'High' -Limitations @('Observation limitation'))
                (New-TestObservation -ObservationId 'OBS-2' -Category 'Credentials' -Title 'Expired credential is still present' -Severity 'High' -Limitations @('Credential limitation'))
            )

            $result =
                Invoke-InspectorAssessmentIntelligence `
                    -InputObject (New-TestTenantResult -Observations $observations)

            $result.Limitations | Should -Contain 'Observation limitation'
            $result.Limitations | Should -Contain 'Credential limitation'
            $result.Limitations | Should -Contain 'Assessment intelligence does not call Microsoft Graph.'
        }

        It 'supports the public command with pipeline input' {
            $tenant =
                New-TestTenantResult `
                    -Observations @(
                        (New-TestObservation -ObservationId 'OBS-1' -Category 'Consent' -Title 'Application permissions present' -Severity 'Informational')
                    )

            $result =
                $tenant |
                Invoke-EntraAssessmentIntelligence `
                    -AssessmentName 'Pipeline Test'

            $result.AssessmentName | Should -Be 'Pipeline Test'
            $result.GraphCallsIssued | Should -Be 0
        }

        It 'supports PassThru by attaching AssessmentIntelligence to the original object' {
            $tenant =
                New-TestTenantResult `
                    -Observations @(
                        (New-TestObservation -ObservationId 'OBS-1' -Category 'Consent' -Title 'Application permissions present' -Severity 'Informational')
                    )

            $result =
                Invoke-EntraAssessmentIntelligence `
                    -InputObject $tenant `
                    -PassThru

            $result.AssessmentIntelligence | Should -Not -BeNullOrEmpty
            $result.AssessmentIntelligence.GraphCallsIssued | Should -Be 0
        }

        It 'returns the required finding schema fields' {
            $tenant =
                New-TestTenantResult `
                    -Observations @(
                        (New-TestObservation -ObservationId 'OBS-1' -Category 'IdentityGovernance' -Title 'Application has a single owner')
                    )

            $result =
                Invoke-EntraAssessmentIntelligence `
                    -InputObject $tenant

            $finding = @($result.AssessmentFindings)[0]

            $finding.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.AssessmentFinding'
            $finding.PSObject.Properties.Name | Should -Contain 'FindingId'
            $finding.PSObject.Properties.Name | Should -Contain 'Category'
            $finding.PSObject.Properties.Name | Should -Contain 'Conclusion'
            $finding.PSObject.Properties.Name | Should -Contain 'Recommendation'
            $finding.PSObject.Properties.Name | Should -Contain 'ObservationIds'
            $finding.PSObject.Properties.Name | Should -Contain 'EvidenceIds'
            $finding.PSObject.Properties.Name | Should -Contain 'MicrosoftReference'
            $finding.PSObject.Properties.Name | Should -Contain 'Limitations'
        }
    }
}

