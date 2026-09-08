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

