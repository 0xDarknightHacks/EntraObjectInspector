$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Security Observation Engine' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TestObjectInsight {
                param (
                    [object[]]$SourceObjects = @(),
                    [object[]]$Relationships = @(),
                    [object[]]$Artifacts = @(),
                    [object[]]$Evidence = @(),
                    [object[]]$PermissionInsights = @(),
                    [object[]]$RuleResults = @(),
                    [object]$ApplicationIdentity = $null,
                    [string]$Input = 'test-input'
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.ObjectInsight'
                    Input = $Input
                    SourceObjects = @($SourceObjects)
                    Relationships = @($Relationships)
                    Artifacts = @($Artifacts)
                    Evidence = @($Evidence)
                    PermissionInsights = @($PermissionInsights)
                    RuleResults = @($RuleResults)
                    ApplicationIdentity = $ApplicationIdentity
                }
            }

            function New-TestSourceObject {
                param (
                    [string]$ObjectType,
                    [string]$ObjectId,
                    [hashtable]$Properties = @{}
                )

                [PSCustomObject]@{
                    ObjectType = $ObjectType
                    ObjectId = $ObjectId
                    Properties = [PSCustomObject]$Properties
                }
            }

            function New-TestRelationship {
                param (
                    [string]$RelationshipType,
                    [string]$SourceObjectId,
                    [string]$TargetObjectId = 'target-1',
                    [string]$TargetObjectType = 'User',
                    [string]$TargetDisplayName = 'Target',
                    [hashtable]$Metadata = @{},
                    [string]$EvidenceId = 'ev-rel'
                )

                [PSCustomObject]@{
                    RelationshipType = $RelationshipType
                    SourceObjectId = $SourceObjectId
                    SourceObjectType = 'Application'
                    TargetObjectId = $TargetObjectId
                    TargetObjectType = $TargetObjectType
                    TargetDisplayName = $TargetDisplayName
                    EvidenceId = $EvidenceId
                    Metadata = [PSCustomObject]$Metadata
                }
            }

            function New-TestCredential {
                param (
                    [string]$SourceObjectId = 'app-1',
                    [string]$CredentialType = 'Password',
                    [datetime]$StartDateTime,
                    [datetime]$EndDateTime,
                    [string]$KeyId = 'key-1',
                    [string]$EvidenceId = 'ev-cred'
                )

                [PSCustomObject]@{
                    ArtifactType = 'CredentialMetadata'
                    CredentialType = $CredentialType
                    SourceObjectType = 'Application'
                    SourceObjectId = $SourceObjectId
                    KeyId = $KeyId
                    DisplayName = $KeyId
                    StartDateTime = $StartDateTime.ToUniversalTime().ToString('o')
                    EndDateTime = $EndDateTime.ToUniversalTime().ToString('o')
                    EvidenceId = $EvidenceId
                }
            }

            function Get-ObservationByTitle {
                param (
                    [object]$Result,
                    [string]$Title
                )

                $Result.Observations |
                    Where-Object { $_.Title -eq $Title } |
                    Select-Object -First 1
            }
        }

        BeforeEach {
            Mock Invoke-InspectorGraphRequest {
                throw 'Observation engine must not call Graph.'
            }
        }


        It 'preserves deterministic observation IDs after hash-path optimization' {
            New-InspectorObservationId -Seed 'maturity-hash-compatibility' |
                Should -Be 'OBS-D3F9A73314DF2D07'
        }

        It 'normalizes live DateTimeOffset and portable ISO timestamps to the same UTC instant' {
            $live = [datetimeoffset]::ParseExact(
                '2026-07-29T10:33:58.1234567+02:00',
                'o',
                [System.Globalization.CultureInfo]::InvariantCulture
            )
            $portable = '2026-07-29T08:33:58.1234567Z'

            $liveNormalized = Get-InspectorObservationDate -Value $live
            $portableNormalized = Get-InspectorObservationDate -Value $portable

            $liveNormalized.Kind | Should -Be ([System.DateTimeKind]::Utc)
            $portableNormalized.Kind | Should -Be ([System.DateTimeKind]::Utc)
            $liveNormalized.Ticks | Should -Be $portableNormalized.Ticks
            $liveNormalized.ToString('o') | Should -Be '2026-07-29T08:33:58.1234567Z'
        }

        It 'treats unspecified live Graph DateTime values as UTC rather than host-local time' {
            $liveUnspecified = [datetime]::SpecifyKind(
                [datetime]::ParseExact('2026-07-29T08:33:58.1234567', 'yyyy-MM-ddTHH:mm:ss.fffffff', [System.Globalization.CultureInfo]::InvariantCulture),
                [System.DateTimeKind]::Unspecified
            )
            $portable = '2026-07-29T08:33:58.1234567Z'

            (Get-InspectorObservationDate -Value $liveUnspecified).Ticks |
                Should -Be (Get-InspectorObservationDate -Value $portable).Ticks
        }

        It 'produces identical temporal credential observations for live DateTimeOffset and portable ISO shapes' {
            Mock Get-Date { [datetime]'2026-09-09T09:00:00Z' }

            $source = New-TestSourceObject -ObjectType 'Application' -ObjectId 'app-1' -Properties @{ DisplayName = 'Replay App' }
            $liveArtifacts = @(
                [PSCustomObject]@{
                    ArtifactType='CredentialMetadata'; CredentialType='Password'; SourceObjectType='Application'; SourceObjectId='app-1'; KeyId='key-1'; DisplayName='key-1';
                    StartDateTime=[datetimeoffset]'2026-01-01T02:00:00+02:00'; EndDateTime=[datetimeoffset]'2027-01-01T02:00:00+02:00'; EvidenceId='ev-cred-1'
                },
                [PSCustomObject]@{
                    ArtifactType='CredentialMetadata'; CredentialType='Password'; SourceObjectType='Application'; SourceObjectId='app-1'; KeyId='key-2'; DisplayName='key-2';
                    StartDateTime=[datetimeoffset]'2026-01-15T02:00:00+02:00'; EndDateTime=[datetimeoffset]'2026-12-31T02:00:00+02:00'; EvidenceId='ev-cred-2'
                }
            )
            $portableArtifacts = @(
                [PSCustomObject]@{
                    ArtifactType='CredentialMetadata'; CredentialType='Password'; SourceObjectType='Application'; SourceObjectId='app-1'; KeyId='key-1'; DisplayName='key-1';
                    StartDateTime='2026-01-01T00:00:00.0000000Z'; EndDateTime='2027-01-01T00:00:00.0000000Z'; EvidenceId='ev-cred-1'
                },
                [PSCustomObject]@{
                    ArtifactType='CredentialMetadata'; CredentialType='Password'; SourceObjectType='Application'; SourceObjectId='app-1'; KeyId='key-2'; DisplayName='key-2';
                    StartDateTime='2026-01-15T00:00:00.0000000Z'; EndDateTime='2026-12-31T00:00:00.0000000Z'; EvidenceId='ev-cred-2'
                }
            )

            $liveResult = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($source) -Artifacts $liveArtifacts)
            $portableResult = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($source) -Artifacts $portableArtifacts)
            $titles = @('Multiple active client secrets','Overlapping credential validity windows')
            $liveTemporal = @($liveResult.Observations | Where-Object Title -in $titles | Sort-Object Title)
            $portableTemporal = @($portableResult.Observations | Where-Object Title -in $titles | Sort-Object Title)

            $liveTemporal.Count | Should -Be 2
            $portableTemporal.Count | Should -Be 2
            ($liveTemporal | ConvertTo-Json -Depth 20 -Compress) |
                Should -Be ($portableTemporal | ConvertTo-Json -Depth 20 -Compress)
        }

        It 'returns the required observation engine envelope without Graph calls' {
            $insight = New-TestObjectInsight

            $result = Invoke-InspectorObservationEngine -ObjectInsight $insight

            $result.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.ObservationEngineResult'
            $result.SchemaVersion | Should -Be '0.7.0'
            $result.GraphCallsIssued | Should -Be 0

            Should-Invoke Invoke-InspectorGraphRequest -Times 0
        }

        It 'emits deterministic observation identifiers' {
            $source = New-TestSourceObject -ObjectType 'Application' -ObjectId 'app-1' -Properties @{ DisplayName = 'App' }
            $evidence = [PSCustomObject]@{
                EvidenceId = 'ev-owner-zero'
                QueryName = 'ApplicationOwners:app-1'
                CollectorName = 'ApplicationOwners:app-1'
                Status = 'Success'
                ResultCount = 0
                EvidenceScope = 'ObjectRelationship'
                SubjectObjectType = 'Application'
                SubjectObjectId = 'app-1'
            }
            $insight = New-TestObjectInsight -SourceObjects @($source) -Evidence @($evidence)

            $first = Invoke-InspectorObservationEngine -ObjectInsight $insight
            $second = Invoke-InspectorObservationEngine -ObjectInsight $insight

            @($first.Observations).Count | Should -BeGreaterThan 0
            $first.Observations[0].ObservationId | Should -Be $second.Observations[0].ObservationId
        }

        It 'detects orphaned applications only when owner collection completed successfully' {
            $source = New-TestSourceObject -ObjectType 'Application' -ObjectId 'app-1' -Properties @{ DisplayName = 'Ownerless App' }
            $evidence = [PSCustomObject]@{
                EvidenceId = 'ev-owner-zero'
                QueryName = 'ApplicationOwners:app-1'
                CollectorName = 'ApplicationOwners:app-1'
                Status = 'Success'
                ResultCount = 0
                EvidenceScope = 'ObjectRelationship'
                SubjectObjectType = 'Application'
                SubjectObjectId = 'app-1'
            }
            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($source) -Evidence @($evidence))

            $obs = Get-ObservationByTitle -Result $result -Title 'Application has no owner'

            $obs | Should -Not -BeNullOrEmpty
            $obs.Category | Should -Be 'IdentityGovernance'
            $obs.Severity | Should -Be 'High'
            $obs.EvidenceIds | Should -Contain 'ev-owner-zero'
        }

        It 'maps successful zero-result owner evidence to ownerless observations' {
            $source = New-TestSourceObject -ObjectType 'Application' -ObjectId 'app-1' -Properties @{ DisplayName = 'Ownerless App' }
            $evidence = [PSCustomObject]@{
                EvidenceId = 'ev-owner-zero'
                QueryName = 'ApplicationOwners'
                Status = 'Success'
                ResultCount = 0
                EvidenceScope = 'ObjectRelationship'
                SubjectObjectType = 'Application'
                SubjectObjectId = 'app-1'
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($source) -Evidence @($evidence))
            $obs = Get-ObservationByTitle -Result $result -Title 'Application has no owner'

            $obs | Should -Not -BeNullOrEmpty
            $obs.EvidenceIds | Should -Contain 'ev-owner-zero'
        }

        It 'does not infer ownerless state from a failed owners query' {
            $source = New-TestSourceObject -ObjectType 'Application' -ObjectId 'app-1' -Properties @{ DisplayName = 'Owner Query Failed App' }
            $evidence = [PSCustomObject]@{
                EvidenceId = 'ev-owner-failed'
                QueryName = 'ApplicationOwners'
                Status = 'Failed'
                ResultCount = 0
                EvidenceScope = 'ObjectRelationship'
                SubjectObjectType = 'Application'
                SubjectObjectId = 'app-1'
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($source) -Evidence @($evidence))

            Get-ObservationByTitle -Result $result -Title 'Application has no owner' |
                Should -BeNullOrEmpty
        }

        It 'detects single-owner applications' {
            $source = New-TestSourceObject -ObjectType 'Application' -ObjectId 'app-1' -Properties @{ DisplayName = 'Single Owner App' }
            $owner = New-TestRelationship -RelationshipType 'OwnedBy' -SourceObjectId 'app-1' -EvidenceId 'ev-owner'

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($source) -Relationships @($owner))

            $obs = Get-ObservationByTitle -Result $result -Title 'Application has a single owner'

            $obs | Should -Not -BeNullOrEmpty
            $obs.EvidenceIds | Should -Contain 'ev-owner'
        }

        It 'detects disabled owners when owner account metadata is available' {
            $source = New-TestSourceObject -ObjectType 'Application' -ObjectId 'app-1'
            $owner = New-TestRelationship -RelationshipType 'OwnedBy' -SourceObjectId 'app-1' -Metadata @{ AccountEnabled = $false }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($source) -Relationships @($owner))

            (Get-ObservationByTitle -Result $result -Title 'Application owner is disabled') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects external owners when user type or UPN metadata is available' {
            $source = New-TestSourceObject -ObjectType 'Application' -ObjectId 'app-1'
            $owner = New-TestRelationship -RelationshipType 'OwnedBy' -SourceObjectId 'app-1' -Metadata @{ UserType = 'Guest'; UserPrincipalName = 'guest_contoso.com#EXT#@tenant.onmicrosoft.com' }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($source) -Relationships @($owner))

            (Get-ObservationByTitle -Result $result -Title 'Application owner appears external') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects inactive owners when sign-in metadata is available' {
            $source = New-TestSourceObject -ObjectType 'Application' -ObjectId 'app-1'
            $oldSignIn = (Get-Date).ToUniversalTime().AddDays(-120).ToString('o')
            $owner = New-TestRelationship -RelationshipType 'OwnedBy' -SourceObjectId 'app-1' -Metadata @{ LastSignInDateTime = $oldSignIn }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($source) -Relationships @($owner))

            (Get-ObservationByTitle -Result $result -Title 'Application owner appears inactive') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects expired credentials' {
            $cred = New-TestCredential -StartDateTime ((Get-Date).AddDays(-60)) -EndDateTime ((Get-Date).AddDays(-1))

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -Artifacts @($cred))

            (Get-ObservationByTitle -Result $result -Title 'Expired credential is still present') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects expiring credentials' {
            $cred = New-TestCredential -StartDateTime ((Get-Date).AddDays(-10)) -EndDateTime ((Get-Date).AddDays(10))

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -Artifacts @($cred))

            (Get-ObservationByTitle -Result $result -Title 'Credential expires soon') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects long-lived client secrets' {
            $cred = New-TestCredential -StartDateTime ((Get-Date).AddDays(-10)) -EndDateTime ((Get-Date).AddDays(730))

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -Artifacts @($cred))

            (Get-ObservationByTitle -Result $result -Title 'Long-lived client secret') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects multiple active client secrets' {
            $creds = @(
                (New-TestCredential -SourceObjectId 'app-1' -StartDateTime ((Get-Date).AddDays(-10)) -EndDateTime ((Get-Date).AddDays(90)) -KeyId 'key-1' -EvidenceId 'ev-1')
                (New-TestCredential -SourceObjectId 'app-1' -StartDateTime ((Get-Date).AddDays(-5)) -EndDateTime ((Get-Date).AddDays(120)) -KeyId 'key-2' -EvidenceId 'ev-2')
            )

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -Artifacts $creds)

            (Get-ObservationByTitle -Result $result -Title 'Multiple active client secrets') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects overlapping credential validity windows' {
            $creds = @(
                (New-TestCredential -SourceObjectId 'app-1' -StartDateTime ((Get-Date).AddDays(-10)) -EndDateTime ((Get-Date).AddDays(90)) -KeyId 'key-1' -EvidenceId 'ev-1')
                (New-TestCredential -SourceObjectId 'app-1' -StartDateTime ((Get-Date).AddDays(30)) -EndDateTime ((Get-Date).AddDays(120)) -KeyId 'key-2' -EvidenceId 'ev-2')
            )

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -Artifacts $creds)

            (Get-ObservationByTitle -Result $result -Title 'Overlapping credential validity windows') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects Directory.ReadWrite.All as high-impact permission' {
            $perm = [PSCustomObject]@{
                PermissionName = 'Directory.ReadWrite.All'
                Confidence = 'High'
                SourceObjectId = 'sp-1'
                RelationshipEvidenceId = 'ev-perm'
                AdministrativeImpact = 'Can broadly modify directory objects.'
                PermissionCategory = 'Directory management'
                ImpactLevel = 'High'
                AppRoleId = 'role-id'
                Limitations = @()
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -PermissionInsights @($perm))

            (Get-ObservationByTitle -Result $result -Title 'High-impact permission: Directory.ReadWrite.All') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects RoleManagement.ReadWrite.Directory as high-impact permission' {
            $perm = [PSCustomObject]@{
                PermissionName = 'RoleManagement.ReadWrite.Directory'
                Confidence = 'High'
                SourceObjectId = 'sp-1'
                RelationshipEvidenceId = 'ev-perm'
                AdministrativeImpact = 'Can manage Microsoft Entra role settings.'
                PermissionCategory = 'Directory role management'
                ImpactLevel = 'High'
                AppRoleId = 'role-id'
                Limitations = @()
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -PermissionInsights @($perm))

            (Get-ObservationByTitle -Result $result -Title 'High-impact permission: RoleManagement.ReadWrite.Directory') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects Policy.ReadWrite.ConditionalAccess as high-impact permission' {
            $perm = [PSCustomObject]@{
                PermissionName = 'Policy.ReadWrite.ConditionalAccess'
                Confidence = 'High'
                SourceObjectId = 'sp-1'
                RelationshipEvidenceId = 'ev-perm'
                AdministrativeImpact = 'Can modify Conditional Access policies.'
                PermissionCategory = 'Policy management'
                ImpactLevel = 'High'
                AppRoleId = 'role-id'
                Limitations = @()
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -PermissionInsights @($perm))

            (Get-ObservationByTitle -Result $result -Title 'High-impact permission: Policy.ReadWrite.ConditionalAccess') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects AppRoleAssignment.ReadWrite.All as high-impact permission' {
            $perm = [PSCustomObject]@{
                PermissionName = 'AppRoleAssignment.ReadWrite.All'
                Confidence = 'High'
                SourceObjectId = 'sp-1'
                RelationshipEvidenceId = 'ev-perm'
                AdministrativeImpact = 'Can manage application permission grants and app role assignments.'
                PermissionCategory = 'Authorization grant management'
                ImpactLevel = 'High'
                AppRoleId = 'role-id'
                Limitations = @()
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -PermissionInsights @($perm))

            (Get-ObservationByTitle -Result $result -Title 'High-impact permission: AppRoleAssignment.ReadWrite.All') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects service principals with assignment required disabled' {
            $sp = New-TestSourceObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-1' -Properties @{ DisplayName = 'SP'; AppRoleAssignmentRequired = $false }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($sp))

            (Get-ObservationByTitle -Result $result -Title 'Service principal does not require assignment') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects enabled service principal sign-in state' {
            $sp = New-TestSourceObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-1' -Properties @{ DisplayName = 'SP'; AccountEnabled = $true }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($sp))

            (Get-ObservationByTitle -Result $result -Title 'Service principal sign-in is enabled') |
                Should -Not -BeNullOrEmpty
        }

        It 'emits service principal visibility state when metadata is available' {
            $sp = New-TestSourceObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-1' -Properties @{ DisplayName = 'SP'; VisibleToUsers = $true }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($sp))

            (Get-ObservationByTitle -Result $result -Title 'Service principal visibility state captured') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects missing service principal counterpart' {
            $identity = [PSCustomObject]@{
                AppId = 'client-id'
                ApplicationObjectId = 'app-1'
                ServicePrincipalObjectId = $null
            }
            $evidence = @(
                [PSCustomObject]@{ EvidenceId = 'ev-applications'; QueryName = 'Applications'; Status = 'Success'; EvidenceScope = 'TenantCollection' },
                [PSCustomObject]@{ EvidenceId = 'ev-service-principals'; QueryName = 'ServicePrincipals'; Status = 'Success'; EvidenceScope = 'TenantCollection' }
            )

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -ApplicationIdentity $identity -Evidence $evidence)
            $observation = Get-ObservationByTitle -Result $result -Title 'Application has no discovered service principal counterpart'

            $observation | Should -Not -BeNullOrEmpty
            @($observation.EvidenceIds) | Should -Contain 'ev-applications'
            @($observation.EvidenceIds) | Should -Contain 'ev-service-principals'
            $observation.Metadata.EvidenceSupportType | Should -Be 'DerivedFromTenantCollection'

            $withoutProof = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -ApplicationIdentity $identity)
            (Get-ObservationByTitle -Result $withoutProof -Title 'Application has no discovered service principal counterpart') | Should -BeNullOrEmpty

            $identityOnlyObservation = [PSCustomObject]@{
                EvidenceIds = @()
                AffectedObject = [PSCustomObject]@{ ObjectId = 'app-1' }
                Metadata = [PSCustomObject]@{}
            }
            Get-InspectorObservationEvidenceSupportStatus -Observation $identityOnlyObservation | Should -Be 'Unsupported'
        }

        It 'converts ownership mismatch rules into observations' {
            $identity = [PSCustomObject]@{
                AppId = 'client-id'
                ApplicationObjectId = 'app-1'
                ServicePrincipalObjectId = 'sp-1'
            }

            $rule = [PSCustomObject]@{
                RuleId = 'APP-OWNERSHIP-001'
                EvidenceIds = @('ev-owner-mismatch')
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -ApplicationIdentity $identity -RuleResults @($rule))

            (Get-ObservationByTitle -Result $result -Title 'Application and service principal owners differ') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects tenant-wide delegated consent grants' {
            $grant = New-TestRelationship -RelationshipType 'DelegatedPermissionGrant' -SourceObjectId 'sp-1' -Metadata @{ ConsentType = 'AllPrincipals'; Scope = 'User.Read' } -EvidenceId 'ev-consent'

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -Relationships @($grant))

            (Get-ObservationByTitle -Result $result -Title 'Tenant-wide delegated consent grant') |
                Should -Not -BeNullOrEmpty
        }

        It 'emits delegated consent present observation' {
            $grant = New-TestRelationship -RelationshipType 'DelegatedPermissionGrant' -SourceObjectId 'sp-1' -Metadata @{ ConsentType = 'Principal'; Scope = 'User.Read' } -EvidenceId 'ev-consent'

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -Relationships @($grant))

            (Get-ObservationByTitle -Result $result -Title 'Delegated consent grants present') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects unused delegated consent when usage metadata is available' {
            $oldUse = (Get-Date).ToUniversalTime().AddDays(-120).ToString('o')
            $grant = New-TestRelationship -RelationshipType 'DelegatedPermissionGrant' -SourceObjectId 'sp-1' -Metadata @{ ConsentType = 'Principal'; Scope = 'User.Read'; LastUsedDateTime = $oldUse } -EvidenceId 'ev-consent'

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -Relationships @($grant))

            (Get-ObservationByTitle -Result $result -Title 'Delegated consent appears unused') |
                Should -Not -BeNullOrEmpty
        }

        It 'emits application permissions present observation' {
            $perm = [PSCustomObject]@{
                PermissionName = 'Application.Read.All'
                SourceObjectId = 'sp-1'
                RelationshipEvidenceId = 'ev-perm'
                AdministrativeImpact = 'Can read applications.'
                Confidence = 'High'
                Limitations = @()
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -PermissionInsights @($perm))

            (Get-ObservationByTitle -Result $result -Title 'Application permissions present') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects user directory role relationships' {
            $user = New-TestSourceObject -ObjectType 'User' -ObjectId 'user-1' -Properties @{ DisplayName = 'User' }
            $role = New-TestRelationship -RelationshipType 'AssignedDirectoryRole' -SourceObjectId 'user-1' -TargetObjectType 'DirectoryRole' -TargetDisplayName 'Global Reader' -EvidenceId 'ev-role'

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($user) -Relationships @($role))

            (Get-ObservationByTitle -Result $result -Title 'User has Microsoft Entra directory role relationship') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects highly connected users' {
            $user = New-TestSourceObject -ObjectType 'User' -ObjectId 'user-1' -Properties @{ DisplayName = 'User' }
            $relationships = 1..10 | ForEach-Object {
                New-TestRelationship -RelationshipType 'MemberOfGroup' -SourceObjectId 'user-1' -TargetObjectId "group-$_" -EvidenceId "ev-$_"
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($user) -Relationships @($relationships)) -HighConnectivityThreshold 10

            (Get-ObservationByTitle -Result $result -Title 'Highly connected user identity') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects user ownership relationships when present' {
            $user = New-TestSourceObject -ObjectType 'User' -ObjectId 'user-1' -Properties @{ DisplayName = 'User' }
            $owns = New-TestRelationship -RelationshipType 'OwnsApplication' -SourceObjectId 'user-1' -TargetObjectType 'Application' -TargetObjectId 'app-1' -EvidenceId 'ev-own'

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($user) -Relationships @($owns))

            (Get-ObservationByTitle -Result $result -Title 'User owns application-related objects') |
                Should -Not -BeNullOrEmpty
        }

        It 'emits contextual PIM active and eligible directory role state' {
            $user = New-TestSourceObject -ObjectType 'User' -ObjectId 'user-1' -Properties @{ DisplayName = 'Privileged User' }
            $active = New-TestRelationship -RelationshipType 'ActiveDirectoryRoleScheduleInstance' -SourceObjectId 'user-1' -TargetObjectType 'DirectoryRoleDefinition' -TargetObjectId 'role-def-1' -TargetDisplayName 'Privileged Role' -EvidenceId 'ev-active' -Metadata @{ RoleDefinitionId = 'role-def-1'; RoleDisplayName = 'Privileged Role'; ScopeType = 'Tenant'; ScheduleInstanceId = 'active-1'; StartDateTime = '2026-01-01T00:00:00Z'; EndDateTime = $null; MemberType = 'Direct' }
            $eligible = New-TestRelationship -RelationshipType 'EligibleDirectoryRoleScheduleInstance' -SourceObjectId 'user-1' -TargetObjectType 'DirectoryRoleDefinition' -TargetObjectId 'role-def-1' -TargetDisplayName 'Privileged Role' -EvidenceId 'ev-eligible' -Metadata @{ RoleDefinitionId = 'role-def-1'; RoleDisplayName = 'Privileged Role'; ScopeType = 'Tenant'; ScheduleInstanceId = 'eligible-1'; StartDateTime = '2026-01-01T00:00:00Z'; EndDateTime = '2026-12-31T00:00:00Z'; MemberType = 'Direct' }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($user) -Relationships @($active, $eligible))

            $activeObservation = Get-ObservationByTitle -Result $result -Title 'Principal has active PIM directory role state'
            $eligibleObservation = Get-ObservationByTitle -Result $result -Title 'Principal has eligible PIM directory role state'

            $activeObservation | Should -Not -BeNullOrEmpty
            $activeObservation.FindingEligible | Should -BeFalse
            $activeObservation.Metadata.AssignmentDurationState | Should -Be 'Permanent'
            $activeObservation.EvidenceIds | Should -Contain 'ev-active'
            $eligibleObservation | Should -Not -BeNullOrEmpty
            $eligibleObservation.FindingEligible | Should -BeFalse
            $eligibleObservation.Metadata.AssignmentDurationState | Should -Be 'TimeBound'
            $eligibleObservation.EvidenceIds | Should -Contain 'ev-eligible'
        }

        It 'correlates risky-user state with active privileged context without inferring compromise' {
            $user = New-TestSourceObject -ObjectType 'User' -ObjectId 'user-1' -Properties @{ DisplayName = 'Risky Privileged User' }
            $active = New-TestRelationship -RelationshipType 'ActiveDirectoryRoleScheduleInstance' -SourceObjectId 'user-1' -TargetObjectType 'DirectoryRoleDefinition' -TargetObjectId 'role-def-1' -TargetDisplayName 'Privileged Role' -EvidenceId 'ev-active' -Metadata @{ RoleDefinitionId = 'role-def-1'; RoleDisplayName = 'Privileged Role'; ScopeType = 'Tenant'; ScheduleInstanceId = 'active-1' }
            $risk = [PSCustomObject]@{
                ArtifactType = 'RiskyUserContext'
                SourceObjectType = 'User'
                SourceObjectId = 'user-1'
                RiskLevel = 'high'
                RiskState = 'atRisk'
                RiskDetail = 'adminConfirmedUserCompromised'
                RiskLastUpdatedDateTime = '2026-01-02T00:00:00Z'
                EvidenceId = 'ev-risk'
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($user) -Relationships @($active) -Artifacts @($risk))
            $observation = Get-ObservationByTitle -Result $result -Title 'Risky user has active privileged context'

            $observation | Should -Not -BeNullOrEmpty
            $observation.FindingEligible | Should -BeTrue
            $observation.Severity | Should -Be 'High'
            $observation.EvidenceIds | Should -Contain 'ev-risk'
            $observation.EvidenceIds | Should -Contain 'ev-active'
            $observation.Limitations | Should -Contain 'Risky-user data is licensing and retention dependent, and does not by itself prove compromise.'
        }

        It 'gates privileged risky-user findings on current unresolved riskState' {
            $states = @(
                @{ State = 'atRisk'; Eligible = $true },
                @{ State = 'confirmedCompromised'; Eligible = $true },
                @{ State = 'remediated'; Eligible = $false },
                @{ State = 'dismissed'; Eligible = $false },
                @{ State = 'confirmedSafe'; Eligible = $false },
                @{ State = 'none'; Eligible = $false },
                @{ State = 'unknownFutureValue'; Eligible = $false }
            )

            foreach ($stateCase in $states) {
                $userId = "user-$($stateCase.State)"
                $user = New-TestSourceObject -ObjectType 'User' -ObjectId $userId -Properties @{ DisplayName = $userId }
                $active = New-TestRelationship -RelationshipType 'AssignedDirectoryRole' -SourceObjectId $userId -TargetObjectType 'DirectoryRoleDefinition' -TargetObjectId 'role-def-1' -TargetDisplayName 'Privileged Role' -EvidenceId "ev-role-$userId" -Metadata @{ RoleDefinitionId = 'role-def-1'; RoleDisplayName = 'Privileged Role'; ScopeType = 'Tenant'; EvidenceIds = @("ev-role-$userId", "ev-active-$userId") }
                $risk = [PSCustomObject]@{
                    ArtifactType = 'RiskyUserContext'
                    SourceObjectType = 'User'
                    SourceObjectId = $userId
                    RiskLevel = 'high'
                    RiskState = $stateCase.State
                    RiskDetail = 'test'
                    EvidenceId = "ev-risk-$userId"
                }

                $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($user) -Relationships @($active) -Artifacts @($risk))
                $riskObservation = @($result.Observations | Where-Object { (Get-InspectorObservationMetadataValue -InputObject $_ -Name 'RelationshipType') -eq 'RiskyUserContext' -and $_.AffectedObject.ObjectId -eq $userId })[0]

                $riskObservation.FindingEligible | Should -Be ([bool]$stateCase.Eligible)
                $riskObservation.Metadata.CurrentRiskStateActionable | Should -Be ([bool]$stateCase.Eligible)
                $riskObservation.EvidenceIds | Should -Contain "ev-risk-$userId"
                $riskObservation.EvidenceIds | Should -Contain "ev-active-$userId"
            }
        }

        It 'keeps risky-user context non-actionable without active privilege' {
            $user = New-TestSourceObject -ObjectType 'User' -ObjectId 'user-risk-only' -Properties @{ DisplayName = 'Risk Only' }
            $risk = [PSCustomObject]@{
                ArtifactType = 'RiskyUserContext'
                SourceObjectType = 'User'
                SourceObjectId = 'user-risk-only'
                RiskLevel = 'high'
                RiskState = 'atRisk'
                EvidenceId = 'ev-risk-only'
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($user) -Artifacts @($risk))
            $riskObservation = @($result.Observations | Where-Object { (Get-InspectorObservationMetadataValue -InputObject $_ -Name 'RelationshipType') -eq 'RiskyUserContext' })[0]

            $riskObservation.FindingEligible | Should -BeFalse
            $riskObservation.Metadata.SignalDisposition | Should -Be 'Contextual'
        }

        It 'detects role-assignable groups' {
            $group = New-TestSourceObject -ObjectType 'Group' -ObjectId 'group-1' -Properties @{ DisplayName = 'Role Group'; IsAssignableToRole = $true }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($group))

            (Get-ObservationByTitle -Result $result -Title 'Role-assignable group') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects role-assignable groups with members' {
            $group = New-TestSourceObject -ObjectType 'Group' -ObjectId 'group-1' -Properties @{ DisplayName = 'Role Group'; IsAssignableToRole = $true }
            $member = New-TestRelationship -RelationshipType 'HasMember' -SourceObjectId 'group-1' -TargetObjectType 'User' -TargetObjectId 'user-1' -EvidenceId 'ev-member'

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($group) -Relationships @($member))

            (Get-ObservationByTitle -Result $result -Title 'Role-assignable group has members') |
                Should -Not -BeNullOrEmpty
        }

        It 'detects privileged groups with members and preserves matching role assignment proof' {
            $group = New-TestSourceObject -ObjectType 'Group' -ObjectId 'group-1' -Properties @{ DisplayName = 'Privileged Group' }
            $member = New-TestRelationship -RelationshipType 'HasMember' -SourceObjectId 'group-1' -TargetObjectType 'User' -TargetObjectId 'user-1' -EvidenceId 'ev-member'
            $role = New-TestRelationship -RelationshipType 'AssignedDirectoryRole' -SourceObjectId 'group-1' -TargetObjectType 'DirectoryRoleDefinition' -TargetObjectId 'role-1' -EvidenceId 'ev-role' -Metadata @{ AssignmentId = 'assignment-1'; PrincipalId = 'group-1'; RoleDefinitionId = 'role-1'; RoleDisplayName = 'Global Reader'; DirectoryScopeId = '/' }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($group) -Relationships @($member, $role))
            $observation = Get-ObservationByTitle -Result $result -Title 'Privileged group has members'

            $observation | Should -Not -BeNullOrEmpty
            $observation.Metadata.DirectoryRoleRelationshipCount | Should -Be 1
            @($observation.Metadata.DirectoryRoleAssignments).Count | Should -Be 1
            $observation.Metadata.DirectoryRoleAssignments[0].AssignmentId | Should -Be 'assignment-1'
            $observation.Metadata.DirectoryRoleAssignments[0].PrincipalId | Should -Be 'group-1'
            $observation.Metadata.DirectoryRoleAssignments[0].EvidenceId | Should -Be 'ev-role'
        }

        It 'does not treat membership relationships as directory role assignments for privileged group detection' {
            $group = New-TestSourceObject -ObjectType 'Group' -ObjectId 'group-1' -Properties @{ DisplayName = 'Role Assignable Group'; IsAssignableToRole = $true }
            $relationships = @(
                New-TestRelationship -RelationshipType 'HasMember' -SourceObjectId 'group-1' -TargetObjectType 'User' -TargetObjectId 'user-1'
                New-TestRelationship -RelationshipType 'HasMember' -SourceObjectId 'group-1' -TargetObjectType 'User' -TargetObjectId 'user-2'
                New-TestRelationship -RelationshipType 'HasMember' -SourceObjectId 'group-1' -TargetObjectType 'User' -TargetObjectId 'user-3'
                1..11 | ForEach-Object {
                    New-TestRelationship -RelationshipType 'MemberOf' -SourceObjectId 'group-1' -TargetObjectType 'Group' -TargetObjectId "parent-$_"
                }
            )

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($group) -Relationships $relationships)

            Get-ObservationByTitle -Result $result -Title 'Role-assignable group' |
                Should -Not -BeNullOrEmpty
            Get-ObservationByTitle -Result $result -Title 'Role-assignable group has members' |
                Should -Not -BeNullOrEmpty
            Get-ObservationByTitle -Result $result -Title 'Privileged group has members' |
                Should -BeNullOrEmpty
        }

        It 'detects nested privileged group relationships when parent metadata is available' {
            $group = New-TestSourceObject -ObjectType 'Group' -ObjectId 'group-1' -Properties @{ DisplayName = 'Nested Group' }
            $parent = New-TestRelationship -RelationshipType 'MemberOf' -SourceObjectId 'group-1' -TargetObjectType 'Group' -TargetObjectId 'parent-1' -EvidenceId 'ev-parent' -Metadata @{ IsAssignableToRole = $true }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($group) -Relationships @($parent))

            (Get-ObservationByTitle -Result $result -Title 'Group is nested into privileged group') |
                Should -Not -BeNullOrEmpty
        }

        It 'preserves late-source relationship observations when relationship volume is high' {
            $groups = 1..25 | ForEach-Object {
                New-TestSourceObject -ObjectType 'Group' -ObjectId "group-$_" -Properties @{ DisplayName = "Group $_"; IsAssignableToRole = $false }
            }
            $relationships = foreach ($index in 1..25) {
                foreach ($memberIndex in 1..20) {
                    New-TestRelationship -RelationshipType 'HasMember' -SourceObjectId "group-$index" -TargetObjectType 'User' -TargetObjectId "user-$memberIndex" -EvidenceId "ev-member-$index-$memberIndex"
                }
            }
            $relationships += New-TestRelationship -RelationshipType 'AssignedDirectoryRole' -SourceObjectId 'group-25' -TargetObjectType 'DirectoryRoleDefinition' -TargetObjectId 'role-25' -EvidenceId 'ev-role-25' -Metadata @{ AssignmentId = 'assignment-25'; PrincipalId = 'group-25'; RoleDefinitionId = 'role-25'; RoleDisplayName = 'Privileged Role'; DirectoryScopeId = '/' }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects $groups -Relationships $relationships)
            $observation = @($result.Observations | Where-Object { $_.Title -eq 'Privileged group has members' -and $_.AffectedObject.ObjectId -eq 'group-25' })[0]

            $observation | Should -Not -BeNullOrEmpty
            $observation.Metadata.MemberCount | Should -Be 20
            $observation.Metadata.DirectoryRoleRelationshipCount | Should -Be 1
            @($observation.EvidenceIds) | Should -Contain 'ev-role-25'
            @($observation.EvidenceIds) | Should -Contain 'ev-member-25-20'
        }

        It 'returns observations with the required schema fields' {
            $source = New-TestSourceObject -ObjectType 'Application' -ObjectId 'app-1'
            $evidence = [PSCustomObject]@{
                EvidenceId = 'ev-owner-zero'
                QueryName = 'ApplicationOwners:app-1'
                CollectorName = 'ApplicationOwners:app-1'
                Status = 'Success'
                ResultCount = 0
                EvidenceScope = 'ObjectRelationship'
                SubjectObjectType = 'Application'
                SubjectObjectId = 'app-1'
            }
            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-TestObjectInsight -SourceObjects @($source) -Evidence @($evidence))
            $obs = @($result.Observations)[0]

            $obs.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.SecurityObservation'
            $obs.PSObject.Properties.Name | Should -Contain 'ObservationId'
            $obs.PSObject.Properties.Name | Should -Contain 'Category'
            $obs.PSObject.Properties.Name | Should -Contain 'Title'
            $obs.PSObject.Properties.Name | Should -Contain 'Description'
            $obs.PSObject.Properties.Name | Should -Contain 'Severity'
            $obs.PSObject.Properties.Name | Should -Contain 'Confidence'
            $obs.PSObject.Properties.Name | Should -Contain 'AffectedObject'
            $obs.PSObject.Properties.Name | Should -Contain 'EvidenceIds'
            $obs.PSObject.Properties.Name | Should -Contain 'MicrosoftReference'
            $obs.PSObject.Properties.Name | Should -Contain 'WhyItMatters'
            $obs.PSObject.Properties.Name | Should -Contain 'Limitations'
            $obs.PSObject.Properties.Name | Should -Contain 'Recommendation'
        }
    }
}

