# Entra Object Inspector

**Current release: v1.0.3**

Entra Object Inspector is a read-only PowerShell assessment tool for Microsoft Entra ID. It collects tenant data through Microsoft Graph, builds a deterministic snapshot, correlates identities and relationships, and produces evidence-backed findings and self-contained HTML reports.

It is designed for assessment and investigation only. It does **not** remediate tenant configuration, calculate numerical risk scores, or execute attack/privilege paths.

## What it covers

- Users and groups
- Application registrations and service principals
- Ownership, membership, permissions, and app-role relationships
- Directory roles and privileged / role-assignable groups
- Active and eligible PIM role schedule instances
- Administrative Unit scope
- Risky-user privilege correlation
- Cross-object security observations
- Portable offline snapshots
- Snapshot comparison / drift assessment
- Targeted assessments
- Rule packs and accepted-condition baselines
- JSON, CSV, Markdown, diagnostics, evidence, and HTML reporting

## Screenshots

> **Screenshot placeholder — CLI assessment summary**  
> Suggested image: a successful `Invoke-EntraSecurityAssessment` run showing mode, Graph statistics, package status, and report path.  
> Suggested path: `docs/images/cli-assessment-summary.png`

<!-- ![CLI assessment summary](docs/images/cli-assessment-summary.png) -->

> **Screenshot placeholder — main HTML report**  
> Suggested image: the report overview showing severity metrics, grouped findings, and tenant context.  
> Suggested path: `docs/images/report-overview.png`

<!-- ![Main HTML report](docs/images/report-overview.png) -->

> **Screenshot placeholder — finding evidence drill-down**  
> Suggested image: one grouped finding showing affected objects, why it matters, supporting evidence, and Entra navigation.  
> Suggested path: `docs/images/finding-evidence.png`

<!-- ![Finding evidence drill-down](docs/images/finding-evidence.png) -->

## Requirements

- PowerShell 7.6 LTS or later
- Microsoft Entra application registration
- App-only Microsoft Graph authentication using a client secret
- Microsoft Graph application permissions appropriate to the assessment scope

Release-validated module dependencies:

| Dependency | Version |
| --- | ---: |
| `Microsoft.Graph.Authentication` | 2.39.0 |
| `Microsoft.PowerShell.SecretManagement` | 1.1.2 |
| `Microsoft.PowerShell.SecretStore` | 1.0.6 |

The full tenant-wide feature set can require permissions including `Application.Read.All`, `User.Read.All`, `GroupMember.Read.All`, `Directory.Read.All`, PIM schedule read permissions, `AdministrativeUnit.Read.All`, and `IdentityRiskyUser.Read.All`. `Member.Read.Hidden` is needed when hidden membership is in scope.

Use the least-privilege permission set appropriate to the assessment you intend to run.

## Install

```powershell
git clone https://github.com/0xDarknightHacks/EntraObjectInspector.git
cd .\EntraObjectInspector

Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretManagement -RequiredVersion 1.1.2 -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretStore -RequiredVersion 1.0.6 -Scope CurrentUser

Import-Module .\EntraObjectInspector.psd1 -Force
```

Validate the local environment:

```powershell
.\Scripts\Test-EntraObjectInspectorRequirements.ps1
```

## Configure authentication

Create the local configuration file:

```powershell
New-Item -ItemType Directory -Path "$HOME\.entra-object-inspector" -Force

@{
    TenantId = "<tenant-id>"
    ClientId = "<application-client-id>"
} | ConvertTo-Json | Set-Content "$HOME\.entra-object-inspector\config.json"
```

Store the client secret with PowerShell SecretManagement:

```powershell
Register-SecretVault `
    -Name EntraInspectorVault `
    -ModuleName Microsoft.PowerShell.SecretStore

Set-Secret `
    -Name InspectorGraphClientSecret `
    -Vault EntraInspectorVault `
    -Secret "<client-secret>"
```

Do not commit tenant identifiers, secrets, snapshots, reports, diagnostics, or exported assessment data.

## Run an assessment

### Live tenant assessment

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Tenant Assessment" `
    -OutputDirectory ".\EntraObjectInspector-Exports"
```

### Live assessment and save a portable snapshot

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Tenant Assessment" `
    -SaveSnapshotPath ".\snapshots\tenant.json"
```

### Offline assessment from a snapshot

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Offline Assessment" `
    -SnapshotPath ".\snapshots\tenant.json"
```

Portable offline mode performs **zero Microsoft Graph requests**.

### Compare two snapshots

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Drift Review" `
    -SnapshotPath ".\snapshots\current.json" `
    -CompareToSnapshotPath ".\snapshots\previous.json"
```

### Target specific objects

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Targeted Review" `
    -Target "Application|<object-id>","ServicePrincipal|<object-id>"
```

For additional workflows, including rule packs, baselines, advanced options, and manual pipeline commands:

```powershell
Get-Help Invoke-EntraSecurityAssessment -Examples
Get-Help Invoke-EntraSecurityAssessment -Full
```

## Output

Each assessment produces a timestamped package containing structured artifacts and three self-contained HTML reports:

- main assessment report
- evidence report
- diagnostics report

The package also includes the manifest, observations, grouped findings, object/evidence indexes, correlations, limitations, recommendations, execution metadata, and assessment intelligence.

Generated output may contain sensitive tenant information and should be stored and shared accordingly.

## Security model

Entra Object Inspector remains read-only. Tenant operations use Microsoft Graph `GET` requests. High-volume collection can use Microsoft Graph JSON batching, where the outer `$batch` request is `POST` but contained tenant operations remain read-only `GET` requests.

After snapshot collection, assessment intelligence, correlation, exports, and report generation operate offline. `GraphCallsAfterSnapshot` is used as a release boundary check.

## Validation

The v1.0.3 release was validated with:

- **349/349 Pester tests passing**
- successful tenant-wide live assessment
- successful portable offline assessment
- zero failed objects in the validated live and offline runs
- `PackageValidationStatus = Success`
- `ReleaseEligible = True`
- `GraphCallsAfterSnapshot = 0`
- zero Graph requests during portable offline analysis

Run the test suite with:

```powershell
Invoke-Pester -Path .\Tests -Output Detailed
```

## Repository structure

```text
Public/      Exported PowerShell commands
Private/     Internal assessment implementation
Scripts/     Validation and operator helpers
Schemas/     Rule-pack, baseline, and artifact schemas
Tests/       Pester test suite
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance and [SECURITY.md](SECURITY.md) for security reporting.

Contributions should preserve the read-only Microsoft Graph boundary, deterministic snapshot behavior, evidence provenance, and fail-closed coverage semantics.

## License

Licensed under the [MIT License](LICENSE).
