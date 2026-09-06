$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'assessment intelligence StrictMode scalar-array regression coverage' {

    InModuleScope EntraObjectInspector {

        BeforeEach {
            Mock Invoke-InspectorGraphRequest {
                throw 'Assessment intelligence must not call Graph.'
            }
        }

        It 'handles a single observation without scalar Count failures' {
            $observation = [PSCustomObject]@{
                PSTypeName = 'EntraObjectInspector.SecurityObservation'
                SchemaVersion = '0.7.0'
                ObservationId = 'OBS-SINGLE'
                Category = 'IdentityGovernance'
                Title = 'Application has a single owner'
                Description = 'Description'
                Severity = 'Medium'
                Confidence = 'High'
                AffectedObject = [PSCustomObject]@{
                    ObjectType = 'Application'
                    ObjectId = 'app-1'
                    DisplayName = 'App One'
                }
                EvidenceIds = @('ev-single')
                MicrosoftReference = 'Microsoft reference'
                WhyItMatters = 'Why it matters'
                Limitations = @()
                Recommendation = 'Review'
                SourceRuleIds = @()
                Metadata = [PSCustomObject]@{}
            }

            $tenant = [PSCustomObject]@{
                PSTypeName = 'EntraObjectInspector.TenantInspectionResult'
                SchemaVersion = '0.8.0'
                Status = 'Success'
                ObjectInsights = @(
                    [PSCustomObject]@{
                        PSTypeName = 'EntraObjectInspector.ObjectInsight'
                        Input = 'app-1'
                        Status = 'Resolved'
                        ResolutionType = 'Application'
                        SecurityObservations = @($observation)
                    }
                )
                SecurityObservations = @($observation)
            }

            {
                $result = Invoke-InspectorAssessmentIntelligence -InputObject $tenant
                $result.GraphCallsIssued | Should -Be 0
                $result.Summary.RawObservationCount | Should -Be 1
                $result.Summary.DeduplicatedObservationCount | Should -Be 1
            } | Should -Not -Throw

            Should-Invoke Invoke-InspectorGraphRequest -Times 0
        }

        It 'handles single confidence and severity values directly' {
            Join-InspectorSeverity -Severity @('High') | Should -Be 'High'
            Join-InspectorConfidence -Confidence @('High') | Should -Be 'High'
            Join-InspectorSeverity -Severity @() | Should -Be 'Informational'
            Join-InspectorConfidence -Confidence @() | Should -Be 'Low'
        }
    }
}

