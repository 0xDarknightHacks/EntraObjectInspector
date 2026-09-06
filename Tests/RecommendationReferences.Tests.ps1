$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Recommendation authoritative references' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            $requiredReferenceIds = @(
                'MS-APP-SECURITY-BEST-PRACTICES',
                'MS-APP-LEAST-PRIVILEGE',
                'MS-GRAPH-PERMISSIONS-REFERENCE',
                'MS-GRAPH-PERMISSION-BEST-PRACTICES',
                'MS-GRAPH-BEST-PRACTICES',
                'MS-GRAPH-THROTTLING',
                'MS-PERMISSIONS-CONSENT-OVERVIEW',
                'MS-USER-ADMIN-CONSENT',
                'MS-MANAGE-APP-PERMISSIONS',
                'MS-GRANT-TENANT-WIDE-CONSENT',
                'MS-GOVERN-SERVICE-ACCOUNTS',
                'MS-APP-SERVICE-PRINCIPAL-CONCEPTS',
                'MS-APP-CREDENTIALS',
                'MS-RECOMMEND-EXPIRING-APP-CREDENTIALS',
                'MS-RECOMMEND-REMOVE-UNUSED-CREDENTIALS',
                'MS-RECOMMEND-REMOVE-UNUSED-APPS',
                'MS-ENTRA-RBAC-BEST-PRACTICES',
                'MS-PRIVILEGED-ROLES-PERMISSIONS',
                'MS-ROLE-ASSIGNABLE-GROUPS',
                'MS-PIM-FOR-GROUPS',
                'MS-ACCESS-REVIEWS-DEPLOYMENT',
                'MS-ACCESS-REVIEWS-APP-PREPARATION',
                'MS-SECURE-GROUP-ACCESS-CONTROL',
                'MS-ENTRA-AUTH-OPS-GUIDE',
                'MS-ENTRA-SECURE-BEST-PRACTICES',
                'MS-ZERO-TRUST-OVERVIEW',
                'MS-ZERO-TRUST-APP-LEAST-PRIVILEGE',
                'MS-ZERO-TRUST-OVERPRIVILEGED-PERMISSIONS',
                'NIST-CSF-2-PR-AA',
                'CIS-CONTROL-5-ACCOUNT-MANAGEMENT',
                'CIS-CONTROL-6-ACCESS-CONTROL-MANAGEMENT',
                'CIS-M365-FOUNDATIONS-BENCHMARK'
            )

            function New-ReferenceTestObservation {
                param (
                    [string]$Category = 'Permissions',
                    [string]$Title = 'High-impact permission observed'
                )

                [PSCustomObject]@{
                    ObservationId = 'OBS-REF-1'
                    Category = $Category
                    Title = $Title
                    Severity = 'High'
                    Confidence = 'High'
                    AffectedObject = [PSCustomObject]@{
                        ObjectType = 'ServicePrincipal'
                        ObjectId = 'sp-ref-1'
                        DisplayName = 'Reference App'
                    }
                    EvidenceIds = @('ev-ref-1')
                    Metadata = [PSCustomObject]@{ PermissionName = 'Directory.ReadWrite.All' }
                    Limitations = @()
                }
            }

            function New-ReferenceTenantResult {
                $observation = New-ReferenceTestObservation

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.TenantInspectionResult'
                    SchemaVersion = '0.10.0'
                    Status = 'Success'
                    GraphRequestsAtSnapshotCompletion = 0
                    GraphRequestsAtAssessmentCompletion = 0
                    GraphCallsAfterSnapshot = 0
                    ObjectInsights = @(
                        [PSCustomObject]@{
                            Input = 'sp-ref-1'
                            Status = 'Resolved'
                            ResolutionType = 'ServicePrincipal'
                            SecurityObservations = @($observation)
                            Evidence = @(
                                [PSCustomObject]@{
                                    EvidenceId = 'ev-ref-1'
                                    QueryName = 'ReferenceQuery'
                                    RequiredPermission = 'Directory.ReadWrite.All'
                                    Status = 'Success'
                                }
                            )
                        }
                    )
                    SecurityObservations = @($observation)
                    FailedObjects = @()
                    Summary = [PSCustomObject]@{ ObjectInsightCount = 1 }
                }
            }
        }

        It 'exposes a complete static private catalog with valid shape' {
            $catalog = @(Get-InspectorRecommendationReferenceCatalog)

            $catalog.ReferenceId | Should -Be $requiredReferenceIds

            foreach ($referenceId in $requiredReferenceIds) {
                $catalog.ReferenceId | Should -Contain $referenceId
            }

            $catalog.ReferenceId.Count | Should -Be (($catalog.ReferenceId | Select-Object -Unique).Count)
            $catalog.StableId.Count | Should -Be $catalog.Count
            $catalog.StableId.Count | Should -Be (($catalog.StableId | Select-Object -Unique).Count)

            foreach ($reference in $catalog) {
                $reference.ReferenceId | Should -Not -BeNullOrEmpty
                $reference.StableId | Should -Not -BeNullOrEmpty
                $reference.StableId | Should -Match '^[A-Z0-9-]+$'
                $reference.Title | Should -Not -BeNullOrEmpty
                $reference.SourceType | Should -BeIn @('MicrosoftLearn','MicrosoftGraph','MicrosoftZeroTrust','NIST','CIS')
                $reference.Url | Should -Match '^https://'
                @($reference.AppliesTo).Count | Should -BeGreaterThan 0
                $reference.Summary | Should -Not -BeNullOrEmpty
            }
        }

        It 'maps expected categories to authoritative references' {
            $applicationOwnershipReferences = @(Resolve-InspectorRecommendationReferences 'ApplicationOwnership')

            $applicationOwnershipReferences.ReferenceId | Should -Contain 'MS-APP-SECURITY-BEST-PRACTICES'
            $applicationOwnershipReferences.StableId | Should -Contain 'MS-ENTRA-001'
            $applicationOwnershipReferences[0].PSObject.Properties.Name | Should -Contain 'StableId'
            (Resolve-InspectorRecommendationReferences 'CredentialHygiene').ReferenceId | Should -Contain 'MS-APP-CREDENTIALS'
            (Resolve-InspectorRecommendationReferences 'HighImpactPermissions').ReferenceId | Should -Contain 'MS-GRAPH-PERMISSIONS-REFERENCE'
            (Resolve-InspectorRecommendationReferences 'ConsentGovernance').ReferenceId | Should -Contain 'MS-PERMISSIONS-CONSENT-OVERVIEW'
            (Resolve-InspectorRecommendationReferences 'ServicePrincipalGovernance').ReferenceId | Should -Contain 'MS-GOVERN-SERVICE-ACCOUNTS'
            (Resolve-InspectorRecommendationReferences 'DirectoryRoles').ReferenceId | Should -Contain 'MS-ENTRA-RBAC-BEST-PRACTICES'
            (Resolve-InspectorRecommendationReferences 'RoleAssignableGroups').ReferenceId | Should -Contain 'MS-ROLE-ASSIGNABLE-GROUPS'
            (Resolve-InspectorRecommendationReferences 'RuntimeTelemetry').ReferenceId | Should -Contain 'MS-GRAPH-BEST-PRACTICES'
            (Resolve-InspectorRecommendationReferences 'GraphCollection').ReferenceId | Should -Contain 'MS-GRAPH-THROTTLING'
        }

        It 'deduplicates references and returns empty arrays for unknown categories' {
            $references = @(Resolve-InspectorRecommendationReferences 'HighImpactPermissions ApplicationPermissions')

            $references.ReferenceId.Count | Should -Be (($references.ReferenceId | Select-Object -Unique).Count)
            @(Resolve-InspectorRecommendationReferences 'UnmappedThing').Count | Should -Be 0
        }

        It 'enriches assessment recommendations and findings additively' {
            $intelligence = Invoke-InspectorAssessmentIntelligence -InputObject (New-ReferenceTenantResult)

            @($intelligence.AssessmentRecommendations).Count | Should -BeGreaterThan 0
            @($intelligence.AssessmentFindings).Count | Should -BeGreaterThan 0
            @($intelligence.AssessmentRecommendations[0].References).Count | Should -BeGreaterThan 0
            $mappedFinding =
                @($intelligence.AssessmentFindings) |
                    Where-Object Category -eq 'PermissionExposure' |
                    Select-Object -First 1

            @($mappedFinding.References).Count | Should -BeGreaterThan 0
            $intelligence.GraphCallsIssued | Should -Be 0
            $intelligence.RiskScoreProduced | Should -BeFalse
            $intelligence.AttackPathsProduced | Should -BeFalse
        }

        It 'preserves reference metadata in JSON and compact CSV export rows' {
            $tenant = New-ReferenceTenantResult
            $intelligence = Invoke-InspectorAssessmentIntelligence -InputObject $tenant
            $exportModel =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence

            @($exportModel.AssessmentRecommendations[0].References).Count | Should -BeGreaterThan 0
            $mappedFinding =
                @($exportModel.AssessmentFindings) |
                    Where-Object Category -eq 'PermissionExposure' |
                    Select-Object -First 1

            @($mappedFinding.References).Count | Should -BeGreaterThan 0
            $exportModel.AssessmentRecommendationRows[0].ReferenceIds | Should -Match 'MS-'
            (@($exportModel.AssessmentFindingRows) | Where-Object Category -eq 'PermissionExposure' | Select-Object -First 1).ReferenceIds | Should -Match 'MS-'
        }

        It 'renders official reference links without auto-fetching external content' {
            $tenant = New-ReferenceTenantResult
            $intelligence = Invoke-InspectorAssessmentIntelligence -InputObject $tenant
            $model =
                ConvertTo-InspectorReportModel `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Match 'Official references'
            $html | Should -Match 'target="_blank"'
            $html | Should -Match 'rel="noopener noreferrer"'
            $html | Should -Match 'Microsoft Graph'
            $html | Should -Match 'Microsoft Learn'
            $html | Should -Not -Match '<link\s'
            $html | Should -Not -Match '<script\s+src='
            $html | Should -Not -Match 'preload|prefetch'
        }

        It 'keeps report export invariants unchanged' {
            $path = Join-Path $TestDrive 'reference-report.html'
            $tenant = New-ReferenceTenantResult
            $intelligence = Invoke-InspectorAssessmentIntelligence -InputObject $tenant

            $result =
                Export-EntraAssessmentReport `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence `
                    -OutputPath $path `
                    -Force

            $result.GraphCallsIssued | Should -Be 0
            $result.IntelligenceAdded | Should -BeFalse
            $result.NewObservationsAdded | Should -BeFalse
            $result.RiskScoreProduced | Should -BeFalse
            $result.AttackPathsProduced | Should -BeFalse
            $result.SelfContainedHtml | Should -BeTrue
            $result.Printable | Should -BeTrue
        }
    }
}
