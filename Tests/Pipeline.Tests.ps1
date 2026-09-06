$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'pipeline orchestration' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TestDiscoveredObject {
                param (
                    [string]$ObjectType,
                    [string]$ObjectId,
                    [string]$InspectionIdentity = $ObjectId
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.DiscoveredObject'
                    ObjectType = $ObjectType
                    ObjectId = $ObjectId
                    InspectionIdentity = $InspectionIdentity
                    ObjectKey = "$ObjectType`:$ObjectId"
                }
            }
        }

        It 'feeds discovered objects through Get-EntraObjectInsight without duplicating pipeline logic' {
            $objects = @(
                (New-TestDiscoveredObject -ObjectType 'Application' -ObjectId 'app-1')
                (New-TestDiscoveredObject -ObjectType 'User' -ObjectId 'user-1' -InspectionIdentity 'user1@contoso.com')
            )

            Mock Get-EntraObjectInsight {
                param($Identity)

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.ObjectInsight'
                    Status = 'Resolved'
                    Identity = $Identity
                }
            }

            $result =
                Invoke-InspectorPipeline `
                    -DiscoveredObject $objects `
                    -BatchSize 1 `
                    -NoProgress

            $result.Status | Should -Be 'Success'
            $result.ProcessedCount | Should -Be 2
            $result.FailedCount | Should -Be 0
            $result.ObjectInsights.Count | Should -Be 2
            $result.ObjectInsights[0].DiscoveryObject | Should -Not -BeNullOrEmpty

            Should-Invoke Get-EntraObjectInsight -Times 2 -Exactly
        }

        It 'retries failed object processing and records final failure' {
            $object =
                New-TestDiscoveredObject `
                    -ObjectType 'Application' `
                    -ObjectId 'app-1'

            Mock Get-EntraObjectInsight {
                throw 'Synthetic processing failure'
            }

            $result =
                Invoke-InspectorPipeline `
                    -DiscoveredObject @($object) `
                    -MaxRetryCount 1 `
                    -NoProgress

            $result.Status | Should -Be 'Failed'
            $result.ProcessedCount | Should -Be 0
            $result.FailedCount | Should -Be 1
            $result.FailedObjects[0].Attempts | Should -Be 2
            $result.Checkpoint.FailedObjectKeys | Should -Contain 'Application:app-1'

            Should-Invoke Get-EntraObjectInsight -Times 2 -Exactly
        }

        It 'supports checkpoint resume by skipping processed object keys' {
            $checkpointPath =
                Join-Path $TestDrive 'checkpoint.json'

            $state = New-InspectorCheckpointState
            Add-InspectorCheckpointObject `
                -State $state `
                -ObjectKey 'Application:app-1'

            Write-InspectorCheckpointState `
                -Path $checkpointPath `
                -State $state

            $objects = @(
                (New-TestDiscoveredObject -ObjectType 'Application' -ObjectId 'app-1')
                (New-TestDiscoveredObject -ObjectType 'Application' -ObjectId 'app-2')
            )

            Mock Get-EntraObjectInsight {
                param($Identity)

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.ObjectInsight'
                    Status = 'Resolved'
                    Identity = $Identity
                }
            }

            $result =
                Invoke-InspectorPipeline `
                    -DiscoveredObject $objects `
                    -CheckpointPath $checkpointPath `
                    -Resume `
                    -NoProgress

            $result.Status | Should -Be 'Success'
            $result.SkippedCount | Should -Be 1
            $result.ProcessedCount | Should -Be 1

            Should-Invoke Get-EntraObjectInsight -Times 1 -Exactly
        }

        It 'writes checkpoint state after successful processing' {
            $checkpointPath =
                Join-Path $TestDrive 'checkpoint-write.json'

            $object =
                New-TestDiscoveredObject `
                    -ObjectType 'Group' `
                    -ObjectId 'group-1'

            Mock Get-EntraObjectInsight {
                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.ObjectInsight'
                    Status = 'Resolved'
                }
            }

            $result =
                Invoke-InspectorPipeline `
                    -DiscoveredObject @($object) `
                    -CheckpointPath $checkpointPath `
                    -NoProgress

            Test-Path -LiteralPath $checkpointPath | Should -BeTrue

            $saved =
                Read-InspectorCheckpointState `
                    -Path $checkpointPath

            $saved.ProcessedObjectKeys | Should -Contain 'Group:group-1'
            $result.Checkpoint.ProcessedObjectKeys | Should -Contain 'Group:group-1'
        }
    }
}

