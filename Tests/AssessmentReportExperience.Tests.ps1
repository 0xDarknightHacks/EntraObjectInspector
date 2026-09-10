$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'HTML report consultant experience' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TestObservation {
                param (
                    [string]$ObservationId = 'OBS-1',
                    [string]$Category = 'Permissions',
                    [string]$Title = 'High-impact permission: Directory.ReadWrite.All',
                    [string]$Severity = 'High',
                    [string]$ObjectId = 'sp-1',
                    [string]$DisplayName = 'Service Principal One'
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.SecurityObservation'
                    ObservationId = $ObservationId
                    Category = $Category
                    Title = $Title
                    Description = 'Observation description'
                    Severity = $Severity
                    Confidence = 'High'
                    AffectedObject = [PSCustomObject]@{
                        ObjectType = 'ServicePrincipal'
                        ObjectId = $ObjectId
                        DisplayName = $DisplayName
                    }
                    EvidenceIds = @('ev-1')
                    MicrosoftReference = 'Microsoft reference'
                    WhyItMatters = 'Why it matters'
                    Limitations = @()
                    Recommendation = 'Review'
                    SourceRuleIds = @()
                    Metadata = [PSCustomObject]@{}
                }
            }

            function New-TestIntelligence {
                param (
                    [object[]]$Observations
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.AssessmentIntelligence'
                    TenantPosture = [PSCustomObject]@{
                        Label = 'AttentionRequired'
                        HighestSeverity = 'High'
                        Confidence = 'High'
                        ObservationCount = @($Observations).Count
                        FindingCount = 1
                        RecommendationCount = 1
                        CorrelationCount = 1
                    }
                    AssessmentFindings = @(
                        [PSCustomObject]@{
                            Category = 'PermissionExposure'
                            Severity = 'High'
                            Confidence = 'High'
                            Title = 'High-impact Microsoft Graph permission exposure detected'
                            Conclusion = 'Permission observations indicate high-impact permissions.'
                            ObservationIds = @('OBS-1')
                            EvidenceIds = @('ev-1')
                            MicrosoftReference = 'Microsoft reference'
                            Recommendation = 'Review high-impact permissions.'
                            Limitations = @()
                        }
                    )
                    AssessmentRecommendations = @(
                        [PSCustomObject]@{
                            Category = 'PermissionExposure'
                            Confidence = 'High'
                            Title = 'Review high-impact application permissions'
                            Action = 'Validate necessity and least privilege.'
                            Rationale = 'Application permissions can allow app-only access.'
                            ObservationIds = @('OBS-1')
                            EvidenceIds = @('ev-1')
                            MicrosoftReference = 'Microsoft reference'
                            Limitations = @()
                        }
                    )
                    Correlations = @(
                        [PSCustomObject]@{
                            CorrelationType = 'PermissionConsentCoOccurrence'
                            Confidence = 'High'
                            Title = 'High-impact permissions co-occur with consent observations'
                            Description = 'Co-occurrence signal only.'
                            ObservationIds = @('OBS-1')
                            EvidenceIds = @('ev-1')
                            Limitations = @('Not an attack path.')
                        }
                    )
                    Limitations = @('Intelligence limitation')
                }
            }

            function New-TestTenantResult {
                param (
                    [object[]]$Observations,
                    [object]$Intelligence
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.TenantInspectionResult'
                    SchemaVersion = '0.11.0'
                    Status = 'Success'
                    GraphCallsAfterSnapshot = 0
                    ObjectInsights = @(
                        [PSCustomObject]@{
                            Input = 'sp-1'
                            Status = 'Resolved'
                            ResolutionType = 'ApplicationIdentity'
                            SourceObjects = @(
                                [PSCustomObject]@{
                                    ObjectType = 'ServicePrincipal'
                                    ObjectId = 'sp-1'
                                    Properties = [PSCustomObject]@{
                                        DisplayName = 'Friendly Service Principal'
                                    }
                                }
                            )
                            RelationshipCollection = [PSCustomObject]@{
                                Status = 'Success'
                                Completeness = 'Complete'
                                Evidence = @()
                            }
                            SecurityObservations = @($Observations)
                            Evidence = @(
                                [PSCustomObject]@{
                                    EvidenceId = 'ev-1'
                                    QueryName = 'SyntheticQuery'
                                    RequiredPermission = 'Application.Read.All'
                                    Status = 'Success'
                                }
                            )
                        }
                    )
                    SecurityObservations = @($Observations)
                    FailedObjects = @()
                    Summary = [PSCustomObject]@{
                        ObjectInsightCount = 1
                        SecurityObservationCount = @($Observations).Count
                    }
                    AssessmentIntelligence = $Intelligence
                }
            }
        }

        BeforeEach {
            Mock Invoke-InspectorGraphRequest {
                throw 'Report generation must not call Graph.'
            }
        }

        It 'creates an executive narrative from existing findings only' {
            $observations = @(
                New-TestObservation -ObservationId 'OBS-1'
            )
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence

            $model =
                ConvertTo-InspectorReportModel `
                    -InputObject $tenant `
                    -AssessmentName 'UX Test'

            $model.SchemaVersion | Should -Be '0.12.0'
            $model.ExecutiveNarrative.PostureStatement | Should -Match 'AttentionRequired'
            $model.ExecutiveNarrative.KeyConcern | Should -Match 'High-impact Microsoft Graph permission exposure detected'
            $model.GraphCallsIssued | Should -Be 0

            Should-Invoke Invoke-InspectorGraphRequest -Times 0
        }

        It 'groups repeated observations with drill-down source observations' {
            $observations = @(
                (New-TestObservation -ObservationId 'OBS-1' -Title 'ServicePrincipal has no owner' -Category 'IdentityGovernance' -ObjectId 'sp-1' -DisplayName 'SP One')
                (New-TestObservation -ObservationId 'OBS-2' -Title 'ServicePrincipal has no owner' -Category 'IdentityGovernance' -ObjectId 'sp-2' -DisplayName 'SP Two')
            )
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence

            $model = ConvertTo-InspectorReportModel -InputObject $tenant
            $group = $model.ObservationGroups | Where-Object Title -eq 'ServicePrincipal has no owner'

            $group.Count | Should -Be 2
            $group.ObservationIds | Should -Contain 'OBS-1'
            $group.ObservationIds | Should -Contain 'OBS-2'
        }

        It 'renders collapsible report sections' {
            $observations = @((New-TestObservation))
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence
            $model = ConvertTo-InspectorReportModel -InputObject $tenant

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Match '<details'
            $html | Should -Match 'Evidence details'
            $html | Should -Match '<h2>Findings</h2>'
        }

        It 'renders client-side search, filtering, and sorting controls' {
            $observations = @((New-TestObservation))
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence
            $model = ConvertTo-InspectorReportModel -InputObject $tenant

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Match 'globalSearch'
            $html | Should -Match 'severityFilter'
            $html | Should -Not -Match 'categoryFilter'
            $html | Should -Match 'sortTable'
            $html | Should -Match 'data-search'
        }

        It 'renders plain finding evidence identifiers instead of useless self-links' {
            $observations = @((New-TestObservation -ObservationId 'OBS-1'))
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence
            $model = ConvertTo-InspectorReportModel -InputObject $tenant

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Match 'Observation: <span class="pill">OBS-1</span>'
            $html | Should -Match 'Evidence: <span class="pill">ev-1</span>'
            $html | Should -Not -Match 'href="#observation-OBS-1"'
            $html | Should -Not -Match 'href="#evidence-ev-1"'
        }

        It 'prefers friendly display names in object inventory' {
            $observations = @((New-TestObservation))
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence

            $model = ConvertTo-InspectorReportModel -InputObject $tenant

            $model.ObjectIndex[0].DisplayName | Should -Be 'Friendly Service Principal'
            $model.ObjectIndex[0].ObjectType | Should -Be 'ApplicationIdentity'
        }

        It 'renders proper empty state instead of empty table rows' {
            $observations = @((New-TestObservation -Category 'Permissions' -Title 'High-impact permission: Directory.ReadWrite.All'))
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence
            $model = ConvertTo-InspectorReportModel -InputObject $tenant

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Match 'At a glance'
            $html | Should -Not -Match '<td><span class="pill status-default"></span></td>'
        }

        It 'exports UX-enhanced self-contained HTML report' {
            $observations = @((New-TestObservation))
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence

            $result =
                Export-EntraAssessmentReport `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence `
                    -AssessmentName 'HTML Report UX' `
                    -OutputPath (Join-Path $TestDrive 'report-ux.html') `
                    -Force

            $result.SchemaVersion | Should -Be '0.12.0'
            $result.Status | Should -Be 'Success'
            $result.ClientSideInteractivity | Should -BeTrue
            $result.GroupedObservations | Should -BeTrue
            $result.CrossReferencesEnabled | Should -BeTrue
            $result.GraphCallsIssued | Should -Be 0
            $result.IntelligenceAdded | Should -BeFalse
            Test-Path -LiteralPath $result.ReportPath | Should -BeTrue
        }
    }
}

