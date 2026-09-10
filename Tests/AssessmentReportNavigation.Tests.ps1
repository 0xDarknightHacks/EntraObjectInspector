$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'HTML report experience validation' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TestReportObservation {
                param (
                    [string]$ObservationId = 'OBS-HARDEN-1',
                    [string]$Category = 'Permissions',
                    [string]$Title = 'High-impact permission: RoleManagement.ReadWrite.Directory',
                    [string]$Severity = 'High',
                    [string]$EvidenceId = 'ev-harden-1',
                    [string]$DisplayName = 'Demo App'
                )

                [PSCustomObject]@{
                    ObservationId = $ObservationId
                    Category = $Category
                    Title = $Title
                    Description = 'Observation description'
                    Severity = $Severity
                    Confidence = 'High'
                    AffectedObject = [PSCustomObject]@{
                        ObjectType = 'ServicePrincipal'
                        ObjectId = 'sp-harden-1'
                        DisplayName = $DisplayName
                    }
                    EvidenceIds = @($EvidenceId)
                    MicrosoftReference = 'Microsoft reference'
                    WhyItMatters = 'Why it matters'
                    Limitations = @()
                    Recommendation = 'Review'
                    SourceRuleIds = @()
                    Metadata = [PSCustomObject]@{}
                }
            }

            function New-TestReportIntelligence {
                param (
                    [object[]]$Observations
                )

                [PSCustomObject]@{
                    TenantPosture = [PSCustomObject]@{
                        Label = 'AttentionRequired'
                        HighestSeverity = 'High'
                        Confidence = 'High'
                        ObservationCount = @($Observations).Count
                        FindingCount = 1
                        RecommendationCount = 1
                        CorrelationCount = 0
                    }
                    AssessmentFindings = @(
                        [PSCustomObject]@{
                            FindingId = 'FINDING-HARDEN-1'
                            Category = 'PermissionExposure'
                            Severity = 'High'
                            Confidence = 'High'
                            ResultState = 'Confirmed'
                            Title = 'High-impact Microsoft Graph permission exposure detected'
                            Conclusion = 'Permission observations indicate high-impact permissions.'
                            CriterionSummary = 'High-impact application permission is present.'
                            EvidenceSupportStatus = 'Collected'
                            ObservationIds = @('OBS-HARDEN-1')
                            EvidenceIds = @('ev-harden-1')
                            IssueGroups = @(
                                [PSCustomObject]@{
                                    Condition = 'High-impact permission'
                                    Severity = 'High'
                                    Confidence = 'High'
                                    Criterion = 'High-impact application permission is present.'
                                    ObjectCount = 1
                                    ObservationCount = 1
                                }
                            )
                            AffectedObjects = @(
                                [PSCustomObject]@{ ObjectType = 'ServicePrincipal'; ObjectId = 'sp-harden-1'; DisplayName = 'Demo App' }
                            )
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
                            ObservationIds = @('OBS-HARDEN-1')
                            EvidenceIds = @('ev-harden-1')
                            MicrosoftReference = 'Microsoft reference'
                            Limitations = @()
                        }
                    )
                    Correlations = @()
                    Limitations = @('Intelligence limitation')
                }
            }

            function New-TestReportTenantResult {
                param (
                    [object[]]$Observations,
                    [object]$Intelligence
                )

                [PSCustomObject]@{
                    Status = 'Success'
                    GraphCallsAfterSnapshot = 0
                    ObjectInsights = @(
                        [PSCustomObject]@{
                            Input = 'sp-harden-1'
                            Status = 'Resolved'
                            ResolutionType = 'ApplicationIdentity'
                            SourceObjects = @(
                                [PSCustomObject]@{
                                    ObjectType = 'ServicePrincipal'
                                    ObjectId = 'sp-harden-1'
                                    Properties = [PSCustomObject]@{
                                        DisplayName = 'Demo App'
                                    }
                                }
                            )
                            RelationshipCollection = [PSCustomObject]@{
                                Status = 'Success'
                                Completeness = 'Complete'
                                Evidence = @(
                                    [PSCustomObject]@{
                                        EvidenceId = 'ev-harden-1'
                                        QueryName = 'ServicePrincipalOwners'
                                        RequiredPermission = 'Application.Read.All'
                                        Status = 'Success'
                                    }
                                )
                            }
                            SecurityObservations = @($Observations)
                            Evidence = @(
                                [PSCustomObject]@{
                                    EvidenceId = 'ev-harden-1'
                                    QueryName = 'ServicePrincipalOwners'
                                    RequiredPermission = 'Application.Read.All'
                                    Status = 'Success'
                                }
                                [PSCustomObject]@{
                                    EvidenceId = 'ev-harden-1'
                                    QueryName = 'ServicePrincipalOwners'
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
                throw 'Report validation must not call Graph.'
            }
        }

        It 'renders observation and evidence identifiers without useless self-links' {
            $observations = @(
                New-TestReportObservation `
                    -ObservationId 'OBS-HARDEN-1' `
                    -EvidenceId 'ev-harden-1'
            )
            $intelligence = New-TestReportIntelligence -Observations $observations
            $tenant = New-TestReportTenantResult -Observations $observations -Intelligence $intelligence
            $model = ConvertTo-InspectorReportModel -InputObject $tenant

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Match 'Observation: <span class="pill">OBS-HARDEN-1</span>'
            $html | Should -Match 'Evidence: <span class="pill">ev-harden-1</span>'
            $html | Should -Not -Match 'href="#observation-OBS-HARDEN-1"'
            $html | Should -Not -Match 'href="#evidence-ev-harden-1"'
        }

        It 'normalizes report category filter values without changing finding categories' {
            Get-InspectorReportNormalizedCategory -Category 'PermissionExposure' | Should -Be 'Permissions'
            Get-InspectorReportNormalizedCategory -Category 'ConsentGovernance' | Should -Be 'Consent'
            Get-InspectorReportNormalizedCategory -Category 'ServicePrincipalGovernance' | Should -Be 'ServicePrincipal'
            Get-InspectorReportNormalizedCategory -Category 'UserGovernance' | Should -Be 'Users'
        }

        It 'keeps detailed evidence out of the default lightweight HTML view' {
            $observations = @(
                New-TestReportObservation `
                    -ObservationId 'OBS-HARDEN-1' `
                    -EvidenceId 'ev-harden-1'
            )
            $intelligence = New-TestReportIntelligence -Observations $observations
            $tenant = New-TestReportTenantResult -Observations $observations -Intelligence $intelligence
            $model = ConvertTo-InspectorReportModel -InputObject $tenant

            @($model.EvidenceRows).Count | Should -BeGreaterThan 1

            $html = New-InspectorHtmlReport -ReportModel $model
            $evidenceHtml = New-InspectorEvidenceHtmlReport -ReportModel $model

            $html | Should -Not -Match 'Duplicate evidence records are grouped for the HTML view only'
            $html | Should -Not -Match '<th role="button" tabindex="0" data-sort="Count">Count</th>'
            $html | Should -Match 'Evidence: <span class="pill">ev-harden-1</span>'

            $evidenceHtml | Should -Match 'How to Read This Report'
            $evidenceHtml | Should -Match 'Finding → Observation → Evidence'
            $evidenceHtml | Should -Match 'Evidence by Grouped Finding'
            $evidenceHtml | Should -Match 'id="finding-FINDING-HARDEN-1"'
            $evidenceHtml | Should -Match 'Conditions detected'
            $evidenceHtml | Should -Match 'Contributing observations'
            $evidenceHtml | Should -Match 'Evidence used by this finding'
            $evidenceHtml | Should -Match 'href="#evidence-ev-harden-1"'
            $evidenceHtml | Should -Match 'RequiredPermission.*not a permission held by the assessed object'
            $evidenceHtml | Should -Match 'Evidence Record Catalog'
        }

        It 'renders recommendations per finding instead of a global Top Actions section' {
            $observations = @(
                New-TestReportObservation `
                    -ObservationId 'OBS-HARDEN-1' `
                    -EvidenceId 'ev-harden-1'
            )
            $intelligence = New-TestReportIntelligence -Observations $observations
            $tenant = New-TestReportTenantResult -Observations $observations -Intelligence $intelligence
            $model = ConvertTo-InspectorReportModel -InputObject $tenant

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Not -Match 'Top Actions'
            $html | Should -Not -Match 'These actions are rendered from existing assessment recommendations only'
            $html | Should -Match 'Recommended action:</strong> Review high-impact permissions.'
        }

        It 'exports validated single-file HTML without changing architectural invariants' {
            $observations = @(
                New-TestReportObservation `
                    -ObservationId 'OBS-HARDEN-1' `
                    -EvidenceId 'ev-harden-1'
            )
            $intelligence = New-TestReportIntelligence -Observations $observations
            $tenant = New-TestReportTenantResult -Observations $observations -Intelligence $intelligence

            $result =
                Export-EntraAssessmentReport `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence `
                    -AssessmentName 'HTML Report Experience Validation' `
                    -OutputPath (Join-Path $TestDrive 'report-navigation-validation.html') `
                    -Force

            $result.Status | Should -Be 'Success'
            $result.GraphCallsIssued | Should -Be 0
            $result.IntelligenceAdded | Should -BeFalse
            $result.NewObservationsAdded | Should -BeFalse
            $result.RiskScoreProduced | Should -BeFalse
            $result.AttackPathsProduced | Should -BeFalse
            $result.SelfContainedHtml | Should -BeTrue

            $content = Get-Content -LiteralPath $result.ReportPath -Raw
            Test-Path -LiteralPath $result.DiagnosticsReportPath | Should -BeTrue
            Test-Path -LiteralPath $result.EvidenceReportPath | Should -BeTrue
            $content | Should -Match 'Observation: <a class="pill" href="report-navigation-validation-evidence\.html#observation-OBS-HARDEN-1">OBS-HARDEN-1</a>'
            $content | Should -Match 'Evidence: <a class="pill" href="report-navigation-validation-evidence\.html#evidence-ev-harden-1">ev-harden-1</a>'
            $content | Should -Not -Match 'href="#"'
        }

        It 'renders service-principal role and administrative-unit inventory navigation when source identifiers are available' {
            $snapshot = [PSCustomObject]@{
                Collections = [PSCustomObject]@{
                    Users = @()
                    Groups = @()
                    Applications = @()
                    ServicePrincipals = @([PSCustomObject]@{ id='sp-1'; appId='client-1'; displayName='Automation SP' })
                    DirectoryRoleDefinitions = @([PSCustomObject]@{ id='role-1'; displayName='Directory Readers' })
                    DirectoryRoleAssignments = @([PSCustomObject]@{ id='assignment-1'; principalId='sp-1'; roleDefinitionId='role-1'; directoryScopeId='/' })
                    RoleAssignmentScheduleInstances = @()
                    RoleEligibilityScheduleInstances = @()
                    AdministrativeUnits = @([PSCustomObject]@{ id='au-1'; displayName='Tier Zero'; description='Privileged scope'; visibility='Public'; isMemberManagementRestricted=$true })
                    SubscribedSkus = @()
                    RiskyUsers = @()
                }
            }
            $details = ConvertTo-InspectorInventoryDetails -TenantSnapshot $snapshot
            $details.DirectoryRoleAssignments[0].AppId | Should -Be 'client-1'
            $details.AdministrativeUnits[0].ObjectType | Should -Be 'AdministrativeUnit'

            $model = [PSCustomObject]@{
                Summary = [PSCustomObject]@{ TenantId = 'tenant-1' }
                InventoryDetails = $details
            }

            $roleHtml = New-InspectorInventoryDetailHtml -ReportModel $model -PropertyName 'DirectoryRoleAssignments' -Title 'Directory role assignments' -Columns @('Principal','PrincipalType','Role','Scope','AssignmentId')
            $auHtml = New-InspectorInventoryDetailHtml -ReportModel $model -PropertyName 'AdministrativeUnits' -Title 'Administrative units' -Columns @('DisplayName','Description','Visibility','RestrictedManagement')

            $roleHtml | Should -Match 'entra\.microsoft\.com/tenant-1/.+objectId/sp-1/appId/client-1'
            $auHtml | Should -Match 'href="https://entra\.microsoft\.com/tenant-1"'
        }

        It 'renders object-specific Open in Entra links only when identifiers support them' {
            $observations = @(
                New-TestReportObservation `
                    -ObservationId 'OBS-HARDEN-1' `
                    -EvidenceId 'ev-harden-1'
            )
            $intelligence = New-TestReportIntelligence -Observations $observations
            $tenant = New-TestReportTenantResult -Observations $observations -Intelligence $intelligence
            $model = ConvertTo-InspectorReportModel -InputObject $tenant

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Not -Match 'href="#"'
            $html | Should -Not -Match 'onclick="return false"'
            Get-InspectorTenantPortalBaseUrl -TenantId 'tenant-1' | Should -Be 'https://entra.microsoft.com/tenant-1'
            Get-InspectorPortalLink -ObjectType 'User' -ObjectId 'user-1' -TenantId 'tenant-1' | Should -Match 'entra\.microsoft\.com/tenant-1/.+userId/user-1'
            Get-InspectorPortalLink -ObjectType 'Group' -ObjectId 'group-1' -TenantId 'tenant-1' | Should -Match 'entra\.microsoft\.com/tenant-1/.+groupId/group-1'
            Get-InspectorPortalLink -ObjectType 'Application' -ObjectId 'app-object-1' -AppId 'client-1' -TenantId 'tenant-1' | Should -Match 'appId/client-1'
            Get-InspectorPortalLink -ObjectType 'ServicePrincipal' -ObjectId 'sp-1' -AppId 'client-1' -TenantId 'tenant-1' | Should -Match 'objectId/sp-1'
            Get-InspectorPortalLink -ObjectType 'RiskyUser' -ObjectId 'user-1' -TenantId 'tenant-1' | Should -Match 'userId/user-1'
            Get-InspectorPortalLink -ObjectType 'DirectoryRole' -TenantId 'tenant-1' | Should -Match 'RolesManagementMenuBlade'
            Get-InspectorPortalLink -ObjectType 'PimRole' -TenantId 'tenant-1' | Should -Match 'PIMCommon'
            Get-InspectorPortalLink -ObjectType 'AdministrativeUnit' -ObjectId 'au-1' -TenantId 'tenant-1' | Should -Be 'https://entra.microsoft.com/tenant-1'
            Get-InspectorPortalLink -ObjectType 'Application' -ObjectId 'app-object-1' | Should -BeNullOrEmpty
            Get-InspectorPortalLink -ObjectType 'ServicePrincipal' -ObjectId 'sp-1' | Should -BeNullOrEmpty
        }
    }
}


