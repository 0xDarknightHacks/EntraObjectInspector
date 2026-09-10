$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'HTML report lightweight template' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TemplateReportModel {
                param (
                    [switch]$WithoutTelemetry,
                    [switch]$WithoutRecommendations,
                    [switch]$WithoutEvidenceIds,
                    [switch]$WithoutInventoryDetails
                )

            $evidenceIds =
                if ($WithoutEvidenceIds) {
                    @()
                }
                else {
                    @('ev-template-1')
                }

            $observation = [PSCustomObject]@{
                ObservationId = 'OBS-TEMPLATE-1'
                Category = 'Permissions'
                Title = 'Template observation'
                Severity = 'High'
                Confidence = 'High'
                AffectedObject = [PSCustomObject]@{
                    ObjectType = 'ServicePrincipal'
                    ObjectId = 'sp-template-1'
                    AppId = '00000000-1111-2222-3333-444444444444'
                    UserPrincipalName = 'owner@example.com'
                    DisplayName = 'Template App'
                }
                EvidenceIds = $evidenceIds
                WhyItMatters = 'Existing observation rationale.'
                Recommendation = 'Review existing permission assignment.'
            }

            $recommendations =
                if ($WithoutRecommendations) {
                    @()
                }
                else {
                    @(
                        [PSCustomObject]@{
                            Category = 'PermissionExposure'
                            Confidence = 'High'
                            Title = 'Review existing high-impact permission'
                            Action = 'Validate necessity and least privilege.'
                            ObservationIds = @('OBS-TEMPLATE-1')
                            EvidenceIds = $evidenceIds
                        }
                    )
                }

            $tenant = [PSCustomObject]@{
                PSTypeName = 'EntraObjectInspector.TenantInspectionResult'
                SchemaVersion = '0.10.0'
                Status = 'Success'
                GraphRequestsAtSnapshotCompletion = 0
                GraphRequestsAtAssessmentCompletion = 0
                GraphCallsAfterSnapshot = 0
                Summary = [PSCustomObject]@{
                    TenantId = 'tenant-1'
                    TenantDisplayName = 'Tenant One'
                    ObjectInsightCount = 1
                    FailedCount = 0
                    EvidenceRecordCount = 1
                    ScopeInventory = [PSCustomObject]@{
                        UsersDiscovered = 2
                        AppRegistrationsDiscovered = 1
                        ServicePrincipalsDiscovered = 3
                        GroupsDiscovered = 4
                        OAuth2PermissionGrantsDiscovered = 5
                        DirectoryRoleAssignmentsDiscovered = 6
                        EvidenceRecordsCollected = 1
                        FailedObjects = 0
                        CollectionCompleteness = 'Complete'
                        TruncatedCollections = @()
                        MicrosoftPublishedServicePrincipals = 1
                        FirstPartyClassificationConfidence = 'ConservativeMetadata'
                    }
                    SnapshotMode = 'InMemory'
                }
                SecurityObservations = @($observation)
                ObjectInsights = @(
                    [PSCustomObject]@{
                        Input = 'sp-template-1'
                        Status = 'Resolved'
                        ResolutionType = 'ServicePrincipal'
                        SecurityObservations = @($observation)
                        Evidence = @(
                            [PSCustomObject]@{
                            EvidenceId = 'ev-template-1'
                            QueryName = 'TemplateQuery'
                            RequiredPermission = 'Directory.ReadWrite.All'
                            Status = 'Success'
                        }
                        )
                    }
                )
                AssessmentIntelligence = [PSCustomObject]@{
                    TenantPosture = [PSCustomObject]@{
                        Label = 'AttentionRequired'
                        HighestSeverity = 'High'
                        Confidence = 'High'
                    }
                    AssessmentFindings = @(
                        [PSCustomObject]@{
                            Category = 'PermissionExposure'
                            Title = 'High-impact permission finding'
                            Conclusion = 'Existing finding conclusion.'
                            Severity = 'High'
                            Confidence = 'High'
                            ObservationIds = @('OBS-TEMPLATE-1')
                            EvidenceIds = $evidenceIds
                            Recommendation = 'Review existing permission assignment.'
                        }
                        [PSCustomObject]@{
                            Category = 'TenantSummary'
                            Title = 'Tenant assessment observation summary'
                            Conclusion = 'Synthetic rollup finding.'
                            Severity = 'Informational'
                            Confidence = 'High'
                            ObservationIds = @('OBS-TEMPLATE-1')
                            EvidenceIds = $evidenceIds
                            Recommendation = 'Review rollup.'
                        }
                    )
                    AssessmentRecommendations = $recommendations
                    Correlations = @()
                    Limitations = @()
                }
            }

            if (-not $WithoutInventoryDetails) {
                $tenant | Add-Member -NotePropertyName TenantSnapshot -NotePropertyValue ([PSCustomObject]@{
                    Collections = [PSCustomObject]@{
                        Applications = @([PSCustomObject]@{ id='app-object-1'; appId='app-client-1'; displayName='Inventory App' })
                        ServicePrincipals = @([PSCustomObject]@{ id='sp-object-1'; appId='sp-client-1'; displayName='Inventory Enterprise App' })
                        Users = @([PSCustomObject]@{ id='user-risk-1'; displayName='Alice Example'; userPrincipalName='alice@example.com' })
                        Groups = @([PSCustomObject]@{ id='group-privileged-1'; displayName='Privileged Operators'; isAssignableToRole=$true })
                        SubscribedSkus = @([PSCustomObject]@{ skuId='sku-1'; skuPartNumber='SPE_E5'; displayName='Microsoft 365 E5'; capabilityStatus='Enabled' })
                        DirectoryRoleDefinitions = @([PSCustomObject]@{ id='role-def-1'; displayName='Global Reader' })
                        DirectoryRoleAssignments = @([PSCustomObject]@{ id='role-assignment-1'; principalId='user-risk-1'; roleDefinitionId='role-def-1'; directoryScopeId='/' })
                        RoleAssignmentScheduleInstances = @([PSCustomObject]@{ id='pim-active-1'; principalId='user-risk-1'; roleDefinitionId='role-def-1'; directoryScopeId='/administrativeUnits/au-1'; assignmentType='Activated'; roleAssignmentScheduleId='active-schedule-1'; startDateTime='2026-09-01T00:00:00Z'; endDateTime='2026-09-02T00:00:00Z' })
                        RoleEligibilityScheduleInstances = @([PSCustomObject]@{ id='pim-eligible-1'; principalId='user-risk-1'; roleDefinitionId='role-def-1'; directoryScopeId='/administrativeUnits/au-1'; roleEligibilityScheduleId='eligible-schedule-1'; startDateTime='2026-01-01T00:00:00Z'; endDateTime='2026-12-31T00:00:00Z' })
                        AdministrativeUnits = @([PSCustomObject]@{ id='au-1'; displayName='Tier Zero'; description='Privileged administration'; visibility='Public'; isMemberManagementRestricted=$true })
                        RiskyUsers = @([PSCustomObject]@{ id='user-risk-1'; userPrincipalName='alice@example.com'; riskLevel='high'; riskState='atRisk'; riskDetail='adminConfirmedUserCompromised' })
                    }
                })
                $tenant.Summary.ScopeInventory | Add-Member -NotePropertyName SubscribedSkusDiscovered -NotePropertyValue 1
                $tenant.Summary.ScopeInventory | Add-Member -NotePropertyName RoleAssignmentScheduleInstancesDiscovered -NotePropertyValue 1
                $tenant.Summary.ScopeInventory | Add-Member -NotePropertyName RoleEligibilityScheduleInstancesDiscovered -NotePropertyValue 1
                $tenant.Summary.ScopeInventory | Add-Member -NotePropertyName AdministrativeUnitsDiscovered -NotePropertyValue 1
                $tenant.Summary.ScopeInventory | Add-Member -NotePropertyName RiskyUsersDiscovered -NotePropertyValue 1
            }

            if (-not $WithoutTelemetry) {
                $tenant | Add-Member -NotePropertyName RuntimeTelemetry -NotePropertyValue ([PSCustomObject]@{
                    TotalDurationMs = 1234
                    StageSummary = [PSCustomObject]@{
                        TenantSnapshotCollectionDurationMs = 300
                        OfflineProcessingDurationMs = 934
                    }
                    GraphRequestSummary = [PSCustomObject]@{ TotalRequests = 7 }
                    ThrottlingSummary = [PSCustomObject]@{ ThrottledRequests = 0 }
                    RetrySummary = [PSCustomObject]@{ RetriedRequests = 0 }
                    MemorySummary = [PSCustomObject]@{ PeakMemoryMB = 64 }
                    ExternalEndpointSummary = [PSCustomObject]@{ UnexpectedExternalHosts = 0 }
                    RawSnapshotPersisted = $false
                })
            }

                return ConvertTo-InspectorReportModel -InputObject $tenant -AssessmentName 'Template Test'
            }
        }

        It 'renders the selected lightweight administrator report structure' {
            $model = New-TemplateReportModel
            $model.ReportFileName = 'assessment.html'
            $model.EvidenceReportFileName = 'assessment-evidence.html'
            $model.DiagnosticsReportFileName = 'assessment-diagnostics.html'

            $html = New-InspectorHtmlReport -ReportModel $model
            $evidenceHtml = New-InspectorEvidenceHtmlReport -ReportModel $model
            $diagnosticsHtml = New-InspectorDiagnosticsHtmlReport -ReportModel $model

            foreach ($surface in @($html, $evidenceHtml, $diagnosticsHtml)) {
                $surface | Should -Match 'data-eoi-report-shell="1.0"'
                $surface | Should -Match 'class="report-nav"'
                $surface | Should -Match 'assessment.html'
                $surface | Should -Match 'assessment-evidence.html'
                $surface | Should -Match 'assessment-diagnostics.html'
            }

            $stylePattern = '(?s)<style>\s*(.*?)\s*</style>'
            $mainCss = [regex]::Match($html, $stylePattern).Groups[1].Value
            [regex]::Match($evidenceHtml, $stylePattern).Groups[1].Value | Should -Be $mainCss
            [regex]::Match($diagnosticsHtml, $stylePattern).Groups[1].Value | Should -Be $mainCss

            $html | Should -Match 'Entra Object Inspector'
            $html | Should -Match 'id="themeToggle"'
            $html | Should -Match 'Tenant details'
            $html | Should -Match 'tenant-1'
            $html | Should -Match 'Tenant One'
            $html | Should -Match 'Module version'
            $html | Should -Match '<h3>Assessment scope inventory</h3>'
            $html | Should -Match 'id="technical-appendix"'
            $html | Should -Match 'href="#technical-appendix">Technical appendix</a>'
            $html | Should -Match 'Users discovered'
            $html | Should -Match 'Microsoft-published service principals'
            $html | Should -Match '<h2>Findings</h2>'
            $html | Should -Match 'Privileged identity context'
            $html | Should -Not -Match 'Runtime Telemetry'
            $html | Should -Match 'Generated by Entra Object Inspector'
            $html | Should -Match 'Application and permission context'
            $html | Should -Match 'Technical appendix'
            $html | Should -Match 'https://entra.microsoft.com/tenant-1'
            $html | Should -Match '#0f6cbd'
            $html | Should -Match 'Segoe UI'
            $html | Should -Not -Match 'compat-markers'
            $html | Should -Not -Match 'Top Actions / Recommended Next Actions'
            $html | Should -Not -Match 'Boundaries &amp; Trust'
            $html | Should -Not -Match 'Evidence References'
            $html | Should -Match 'Assessment notes and limitations'
            $html.IndexOf('<h2>Findings</h2>') | Should -BeLessThan $html.IndexOf('Privileged identity context')
            $html | Should -Match 'metric-card severity-high'
            $html | Should -Not -Match 'metric-label">Unexpected hosts'
            $html | Should -Not -Match '<h2>Assessment Scope</h2>'
            $html | Should -Not -Match 'id="assessment-scope-statement"'
            $html | Should -Not -Match 'Tenant License Capabilities'
            $html | Should -Not -Match 'tenant-license-capabilities'
            $html | Should -Not -Match 'Assessment Accounting'
            $html | Should -Not -Match 'assessment-accounting'
            $html | Should -Not -Match 'Severity Methodology'
            $html | Should -Not -Match 'severity-methodology'
        }

        It 'renders active licensing and actionable identity inventory without capability booleans' {
            $model = New-TemplateReportModel
            $originalFindings = @($model.AssessmentFindings | ForEach-Object { $_.Title })
            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Match 'Active SKUs'
            $html | Should -Match 'Microsoft 365 E5'
            $html | Should -Match 'Tenant-level discovered licensing'
            $html | Should -Not -Match 'EntraIdP1=True'
            $html | Should -Not -Match 'EntraIdP2=True'
            $html | Should -Not -Match 'EntraSuite=False'
            $html | Should -Match 'Risky users'
            $html | Should -Match 'Alice Example'
            $html | Should -Match 'alice@example.com'
            $html | Should -Match 'adminConfirmedUserCompromised'
            $html | Should -Match 'Active role schedule instances'
            $html | Should -Match 'Eligible role schedule instances'
            $html | Should -Match 'Global Reader'
            $html | Should -Match 'Administrative Unit: Tier Zero'
            $html | Should -Match 'role-assignment-1'
            $html | Should -Match 'Tier Zero'
            $html | Should -Match 'Privileged administration'
            $html | Should -Match 'Open in Entra'
            @($model.AssessmentFindings | ForEach-Object { $_.Title }) | Should -Be $originalFindings
        }

        It 'renders older report models with no inventory detail collections' {
            { New-InspectorHtmlReport -ReportModel (New-TemplateReportModel -WithoutInventoryDetails) } | Should -Not -Throw
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel -WithoutInventoryDetails)
            $html | Should -Match 'Technical appendix'
            $html | Should -Not -Match 'class="evidence inventory-detail"'
        }

        It 'keeps evidence hidden behind native details without a global expand-all control' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Match '<details class="evidence">'
            $html | Should -Match '<summary>Evidence details</summary>'
            $html | Should -Not -Match 'id="toggleEvidence"'
            $html | Should -Not -Match 'Collapse evidence'
        }

        It 'renders severity filtering and dark light theme support without external dependencies' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Match 'data-filter-severity="High"'
            $html | Should -Match 'function applyFindingFilter'
            $html | Should -Match 'data-theme="light"'
            $html | Should -Match '\[data-theme="dark"\]'
            $html | Should -Match 'localStorage'
            $html | Should -Not -Match '<link\s'
            $html | Should -Not -Match '<script\s+src='
            $html | Should -Not -Match '@import'
            $html | Should -Not -Match 'cdn\.'
        }

        It 'renders local investigation filters and result count controls' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Match 'id="findingSearch"'
            $html | Should -Match 'data-filter-severity="High"'
            $html | Should -Not -Match 'id="categoryFilter"'
            $html | Should -Match 'id="objectTypeFilter"'
            $html | Should -Match 'id="clearFindingFilters"'
            $html | Should -Match 'id="findingResultCount"'
            $html | Should -Match 'No findings match the current filters.'
        }

        It 'adds safe searchable data attributes to finding cards' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Match 'class="finding-card"'
            $html | Should -Match 'data-severity="High"'
            $html | Should -Match 'data-category="Permissions"'
            $html | Should -Match 'data-object-type="ServicePrincipal"'
            $html | Should -Match 'data-object-id="sp-template-1"'
            $html | Should -Match 'data-app-id="00000000-1111-2222-3333-444444444444"'
            $html | Should -Match 'data-upn="owner@example.com"'
            $html | Should -Match 'data-display-name="Template App"'
            $html | Should -Match 'data-search="[^"]*template app'
            $html | Should -Match 'data-search="[^"]*sp-template-1'
            $html | Should -Match 'data-search="[^"]*00000000-1111-2222-3333-444444444444'
            $html | Should -Match 'data-search="[^"]*owner@example.com'
            $html | Should -Match 'data-search="[^"]*directory.readwrite.all'
            $html | Should -Not -Match 'data-search="[^"]*Validate necessity and least privilege'
        }

        It 'bounds each finding card search payload' {
            $model = New-TemplateReportModel
            $longRecommendation = 'Review existing permission assignment. ' * 2000
            $model.AssessmentRecommendations[0].Action = $longRecommendation

            $html = New-InspectorHtmlReport -ReportModel $model
            $matches = [regex]::Matches($html, 'data-search="([^"]*)"')

            $matches.Count | Should -BeGreaterThan 0

            foreach ($match in $matches) {
                $match.Groups[1].Value.Length | Should -BeLessOrEqual 9000
            }

            $html | Should -Not -Match ([regex]::Escape($longRecommendation.Trim()))
        }

        It 'keeps filtering inline and avoids live report behavior terminology' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Match 'function applyFindingFilters'
            $html | Should -Match 'matchesSearch && matchesSeverity && matchesObjectType'
            $html | Should -Not -Match '<script\s+src='
            $html | Should -Not -Match '<link\s'
            $html | Should -Not -Match 'Refresh'
            $html | Should -Not -Match 'platform|backend'
        }

        It 'supports local search highlighting without corrupting repeated searches' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Match 'mark\.search-hit'
            $html | Should -Match '--highlight-bg'
            $html | Should -Match '--highlight-text'
            $html | Should -Match '--highlight-border'
            $html | Should -Match 'document.createElement\(''mark''\)'
            $html | Should -Match 'function escapeRegExp'
            $html | Should -Match 'clearSearchHighlights'
            $html | Should -Match 'createTextNode'
            $html | Should -Match 'data-highlight-target'
            $html | Should -Match 'closest\(''pre, code, \.raw-evidence''\)'
            $html | Should -Match 'font-weight:600'
        }

        It 'supports query string prefilled searches without persisting query values' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Match 'new URLSearchParams\(window\.location\.search\)'
            $html | Should -Match "params\.has\('q'\)"
            $html | Should -Match "params\.get\('q'\)"
            $html | Should -Match "params\.get\('object'\)"
            $html | Should -Match 'findingSearch\.value = querySearch'
            $html | Should -Not -Match 'localStorage\.setItem\(''eoi-search'
            $html | Should -Not -Match 'sessionStorage'
        }

        It 'does not render copy controls in finding cards' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Not -Match 'aria-label="Copy object ID"'
            $html | Should -Not -Match 'aria-label="Copy app ID"'
            $html | Should -Not -Match 'aria-label="Copy UPN"'
            $html | Should -Not -Match 'aria-label="Copy permission"'
            $html | Should -Not -Match 'data-copy-value='
            $html | Should -Not -Match 'navigator\.clipboard\.writeText'
            $html | Should -Not -Match 'Copy unavailable'
        }

        It 'debounces search input for larger reports' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Match 'function scheduleFindingFilters'
            $html | Should -Match 'window\.setTimeout\(applyFindingFilters, 125\)'
            $html | Should -Match 'window\.clearTimeout\(findingFilterDebounce\)'
        }

        It 'documents URL encoded report search examples' {
            $readme = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\README.md') -Raw

            $readme | Should -Match 'report\.html\?q=Directory\.ReadWrite\.All'
            $readme | Should -Match 'report\.html\?q=Policy\.ReadWrite\.ConditionalAccess'
            $readme | Should -Match 'report\.html\?q=Finance%20Automation%20App'
            $readme | Should -Match 'report\.html\?object=00000000-0000-0000-0000-000000000000'
            $readme | Should -Match 'report\.html\?object=user%40contoso\.com'
            $readme | Should -Match 'degrade gracefully'
        }

        It 'supports slash keyboard shortcut for focusing report search' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Match "event\.key !== '/'"
            $html | Should -Match 'search\.focus\(\)'
            $html | Should -Match "tagName === 'input'"
            $html | Should -Match 'isContentEditable'
        }

        It 'works without telemetry, recommendations, or evidence identifiers' {
            $html =
                New-InspectorHtmlReport `
                    -ReportModel (New-TemplateReportModel -WithoutTelemetry -WithoutRecommendations -WithoutEvidenceIds)

            $html | Should -Not -Match 'Runtime telemetry was not available for this assessment.'
            $html | Should -Match 'No direct evidence record associated with this observation.'
        }

        It 'renders optional client and consultant report metadata' {
            $model = New-TemplateReportModel
            $model.ClientName = 'Client Test'
            $model.ConsultantName = 'Consultant Test'

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Match 'Client Test'
            $html | Should -Match 'Consultant Test'
        }

        It 'does not render fake links or observation self-links' {
            $html = New-InspectorHtmlReport -ReportModel (New-TemplateReportModel)

            $html | Should -Not -Match 'href="#"'
            $html | Should -Not -Match 'href="#observation-OBS-TEMPLATE-1"'
            $html | Should -Match 'Observation: <span class="pill">OBS-TEMPLATE-1</span>'
        }

        It 'omits synthetic tenant summary from priority findings and caps finding evidence details' {
            $model = New-TemplateReportModel
            $model.AssessmentFindings[0].ObservationIds = 1..12 | ForEach-Object { "OBS-$_" }
            $model.AssessmentFindings[0].EvidenceIds = 1..12 | ForEach-Object { "ev-$_" }

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Match '1 of 1 grouped findings'
            $html | Should -Not -Match 'Synthetic rollup finding'
            $html | Should -Match 'Observation IDs truncated: showing 10 of 12\.'
            $html | Should -Match 'Evidence IDs truncated: showing 10 of 12\.'
        }
    }
}
