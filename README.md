# Entra Object Inspector

Entra Object Inspector is a read-only PowerShell tool for assessing Microsoft Entra ID objects and relationships through Microsoft Graph. It inspects users, groups, applications, and service principals, preserves supporting evidence, generates assessment findings, and exports structured artifacts and self-contained HTML reports.

**GitHub:** https://github.com/0xDarknightHacks

## Scope

The tool supports:

- Users
- Groups
- Application registrations
- Service principals / enterprise applications
- Correlated application identities
- Ownership, membership, permission, and app-role relationship evidence
- Tenant-wide assessment
- JSON, CSV, Markdown, and static HTML reporting

Entra Object Inspector is assessment-only. It does **not** remediate, modify tenant configuration, perform risk/exposure scoring, or execute attack/privilege-path analysis.

Tenant-wide assessments use a snapshot-first model. Microsoft Graph is used to collect the required tenant data; subsequent resolution, relationship processing, observations, assessment intelligence, exports, and reports operate offline against the collected data.

## Requirements

- PowerShell 7.6 LTS or later
- Microsoft Entra application registration
- App-only Microsoft Graph authentication using a client secret
- Required Microsoft Graph application permissions with admin consent

Release-validated dependencies:

| Dependency | Version |
| --- | ---: |
| `Microsoft.Graph.Authentication` | 2.39.0 |
| `Microsoft.PowerShell.SecretManagement` | 1.1.2 |
| `Microsoft.PowerShell.SecretStore` | 1.0.6 |
| `Pester` (development only) | 6.1.0 |

### Microsoft Graph permissions

Permissions depend on the objects and relationships being assessed. The collection logic uses:

- `Application.Read.All`
- `User.Read.All`
- `GroupMember.Read.All`
- `Member.Read.Hidden` when hidden group membership is in scope
- `Directory.Read.All`
- `RoleManagement.Read.Directory`

`Organization.Read.All` is optional and is used only for organization metadata in reports.

Use the least-privilege permission set appropriate for the intended assessment scope.

## Installation

```powershell
git clone https://github.com/0xDarknightHacks/EntraObjectInspector.git
cd .\EntraObjectInspector

Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretManagement -RequiredVersion 1.1.2 -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretStore -RequiredVersion 1.0.6 -Scope CurrentUser

Import-Module .\EntraObjectInspector.psd1 -Force
```

Validate the local runtime and module requirements:

```powershell
.\Scripts\Test-EntraObjectInspectorRequirements.ps1
```

## Configuration

Create the local configuration file:

```powershell
New-Item -ItemType Directory -Path "$HOME\.entra-object-inspector" -Force

@{
    TenantId = "<tenant-id>"
    ClientId = "<application-client-id>"
} | ConvertTo-Json | Set-Content "$HOME\.entra-object-inspector\config.json"
```

Store the application client secret with PowerShell SecretManagement:

```powershell
Register-SecretVault `
    -Name EntraInspectorVault `
    -ModuleName Microsoft.PowerShell.SecretStore

Set-Secret `
    -Name InspectorGraphClientSecret `
    -Vault EntraInspectorVault `
    -Secret "<client-secret>"
```

Do not commit tenant identifiers, credentials, local configuration, assessment exports, reports, or diagnostics.

## Run an Assessment

For a complete tenant assessment:

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Contoso Entra Assessment" `
    -OutputDirectory ".\EntraObjectInspector-Exports"
```

To specify the report path and open it after generation:

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Contoso Entra Assessment" `
    -OutputDirectory ".\EntraObjectInspector-Exports" `
    -ReportPath ".\EntraObjectInspector-Reports\contoso-assessment.html" `
    -OpenReport
```

The command performs authentication, snapshot collection, tenant inspection, assessment intelligence, structured export, and HTML report generation.

## Public Commands

The module exposes seven public commands:

```text
Connect-InspectorGraph
Get-EntraObjectInsight
Invoke-EntraTenantInspection
Export-EntraTenantInspection
Invoke-EntraAssessmentIntelligence
Export-EntraAssessmentReport
Invoke-EntraSecurityAssessment
```

For object-specific inspection:

```powershell
Connect-InspectorGraph
Get-EntraObjectInsight -Identity "<object-id-or-upn-or-app-id>"
```

For manual pipeline execution:

```powershell
$tenantResult = Invoke-EntraTenantInspection `
    -ObjectType Application, ServicePrincipal, User, Group `
    -MaxObjectsPerType 0 `
    -BatchSize 25

$intelligence = Invoke-EntraAssessmentIntelligence `
    -InputObject $tenantResult `
    -AssessmentName "Example Assessment"

$export = Export-EntraTenantInspection `
    -InputObject $tenantResult `
    -AssessmentIntelligence $intelligence `
    -OutputDirectory ".\EntraObjectInspector-Exports" `
    -AssessmentName "Example Assessment"

Export-EntraAssessmentReport `
    -InputObject $tenantResult `
    -AssessmentIntelligence $intelligence `
    -AssessmentName "Example Assessment" `
    -OutputPath ".\EntraObjectInspector-Reports\example-assessment.html" `
    -Force
```

## Output

A tenant assessment produces structured JSON/CSV artifacts, a Markdown summary, diagnostics, and three self-contained HTML reports:

- main assessment report
- evidence report
- diagnostics report

The export package includes the assessment manifest, summary, observations, object/evidence indexes, findings, recommendations, correlations, limitations, failed-object records, execution data, and assessment intelligence.

Generated outputs may contain sensitive tenant metadata. Store and share them accordingly.

## Security Model

Entra Object Inspector is designed to remain read-only. Logical tenant operations use Microsoft Graph `GET` requests. Selected high-volume independent reads may use Microsoft Graph JSON batching; the outer `$batch` request uses `POST`, while its individual subrequests remain read-only `GET` operations.

Post-snapshot assessment intelligence, exports, and report generation do not require Microsoft Graph calls.

## Testing

Run the full Pester suite:

```powershell
Invoke-Pester -Path .\Tests -Output Detailed
```

The v1.0.0 release baseline contains **276 tests** and requires **276 passed / 0 failed / 0 skipped**.

For a broader local validation:

```powershell
.\Scripts\Test-EntraObjectInspectorRequirements.ps1 -RunTests
```

## Repository Structure

```text
Public/      Exported PowerShell commands
Private/     Internal assessment implementation
Scripts/     Local validation/operator helpers
Tests/       Pester test suite
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development, testing, and release guidance.

Contributions should preserve the read-only Microsoft Graph boundary and evidence/provenance behavior.

## License

Licensed under the [MIT License](LICENSE).
