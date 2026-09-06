# Entra Object Inspector

Entra Object Inspector is a read-only Microsoft Entra security assessment tool built in PowerShell. It resolves Entra objects, collects relationships through Microsoft Graph, enriches permission evidence with a local catalog, produces explainable security observations, generates assessment intelligence, exports structured artifacts, and creates a static HTML report.

**GitHub:** https://github.com/0xDarknightHacks

The tool is intended for Microsoft Entra administrators, Microsoft 365 security administrators, identity and security consultants, security engineers, and open-source contributors who need evidence-backed inspection of Entra objects and tenant relationships.

## What It Does

- Resolves users, groups, applications, and service principals.
- Collects relationship and ownership evidence from Microsoft Graph.
- Preserves evidence records for review and export.
- Enriches Microsoft Graph permission grants using a local catalog.
- Produces explainable security observations.
- Generates assessment-level findings, recommendations, correlations, and limitations.
- Exports JSON, CSV, Markdown, and self-contained static HTML reports.
- Supports tenant-wide inspection.

## What It Does Not Do

- No remediation.
- No write actions.
- No risk scoring.
- No exposure scoring.
- No attack graph.
- No privilege path analysis.
- No MITRE mapping.
- No dashboard or web server.
- No historical comparison.
- No automated changes to the tenant.

## Architecture

```text
Authentication
    -> Tenant Snapshot Collection
    -> Offline Resolution
    -> Offline Relationship Building
    -> Normalization
    -> Permission Intelligence
    -> Observation Engine
    -> Assessment Intelligence
    -> JSON/CSV Export
    -> HTML Report + Diagnostics/Evidence Sidecars
```

Authentication uses Microsoft Graph app-only authentication with local configuration and SecretManagement. Tenant-wide assessments use a snapshot-first model: Microsoft Graph is used during the initial ingestion stage to build an in-memory tenant snapshot, and the remaining pipeline runs offline against that snapshot. Offline resolution maps input identifiers to Entra users, groups, applications, and service principals. Offline relationship building projects snapshot data into the relationship/evidence model. Normalization builds ObjectInsight records. Permission intelligence enriches collected grants with the local Microsoft Graph permission catalog. The observation engine produces explainable security observations from collected evidence. Assessment intelligence derives assessment-level findings, recommendations, correlations, and limitations from existing results. The export layer writes JSON, CSV, and Markdown artifacts. The report layer renders a static main assessment report plus diagnostics and evidence sidecar reports.

The raw tenant snapshot is temporary by default and is not exported unless explicitly returned for debugging or integration. Snapshot data and generated outputs may contain sensitive tenant metadata.

## Supported Object Types

- User
- Group
- Application registration
- Service principal / enterprise application
- Application identity when an application registration and service principal are correlated

## Requirements

- PowerShell 7.6 LTS or later. The current release was validated with PowerShell **7.6.4** (Core, x64).
- Runtime module minimums are declared in `EntraObjectInspector.psd1`. The current release baseline is:

  | Dependency | Minimum supported | Exact version used for release validation |
  | --- | ---: | ---: |
  | `Microsoft.Graph.Authentication` | 2.39.0 | 2.39.0 |
  | `Microsoft.PowerShell.SecretManagement` | 1.1.2 | 1.1.2 |
  | `Microsoft.PowerShell.SecretStore` | 1.0.6 | 1.0.6 |
  | `Pester` (development/test only) | n/a | 6.1.0 |

  The minimums intentionally equal the first versions validated for this public release; support for older module versions is not claimed. Runtime users may use newer compatible versions, while CI installs the exact tested baseline so release validation is reproducible.
- App-only Microsoft Graph authentication.
- A registered Microsoft Entra application using client-secret authentication.
- Microsoft Graph application permissions required by the collectors you run.

### Permissions Used By Collection Logic

The collection logic references the following Microsoft Graph application permissions, depending on the inspected object types and enabled collectors:

- `Application.Read.All`
- `User.Read.All`
- `GroupMember.Read.All`
- `Member.Read.Hidden` when any in-scope group uses `HiddenMembership` visibility; without it, member evidence for that group is intentionally marked partial and the assessment fails release eligibility closed.
- `Directory.Read.All`
- `RoleManagement.Read.Directory`

These permissions must be granted and admin-consented to the assessment application as required for the intended inspection scope. Use the least privilege set that covers the object types and relationships you intend to inspect. Microsoft Graph v1.0 documents [`GET /oauth2PermissionGrants`](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0) with `Directory.Read.All` as the least-privileged application permission; the collector and evidence metadata use the same requirement.

`Organization.Read.All` is an optional reporting-metadata application permission used only for tenant and organization details in reports; it is not part of assessment-required evidence coverage, and absence or failure of `/organization` metadata collection does not invalidate assessment correctness or release eligibility.

### Permissions Recognized By The Local Permission Catalog

The local permission catalog may describe additional Microsoft Graph permissions observed on inspected applications, including high-impact permissions such as `Directory.Read.All`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, and related application permissions.

These catalog entries are used to explain observed grants. They are not automatically required to run the tool.

## Installation

Clone the repository and import the module from the local path:

```powershell
git clone https://github.com/0xDarknightHacks/EntraObjectInspector.git
cd .\EntraObjectInspector

# Reproduce the dependency baseline used for this release.
Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Scope CurrentUser -Repository PSGallery
Install-Module Microsoft.PowerShell.SecretManagement -RequiredVersion 1.1.2 -Scope CurrentUser -Repository PSGallery
Install-Module Microsoft.PowerShell.SecretStore -RequiredVersion 1.0.6 -Scope CurrentUser -Repository PSGallery

Remove-Module EntraObjectInspector -Force -ErrorAction SilentlyContinue
Import-Module .\EntraObjectInspector.psd1 -Force
```

You can validate local runtime, project structure, module prerequisites, local module import, and the public command surface before configuration:

```powershell
.\Scripts\Test-EntraObjectInspectorRequirements.ps1
```

Optional full validation also runs the Pester suite and writes detailed test output to a local log:

```powershell
.\Scripts\Test-EntraObjectInspectorRequirements.ps1 -RunTests
```

The requirements helper does not connect to Microsoft Graph, validate tenant credentials, or run an assessment. Use `-ShowManualCommands` to print install commands, or `-InstallMissing` to install missing modules from PSGallery when explicitly requested.

## Configuration

Create the configuration file expected by the current authentication implementation:

```powershell
New-Item -ItemType Directory -Path "$HOME\.entra-object-inspector" -Force
@{
    TenantId = "<tenant-id>"
    ClientId = "<application-client-id>"
} | ConvertTo-Json | Set-Content "$HOME\.entra-object-inspector\config.json"
```

Store the application client secret in SecretManagement:

```powershell
Register-SecretVault -Name EntraInspectorVault -ModuleName Microsoft.PowerShell.SecretStore
Set-Secret -Name InspectorGraphClientSecret -Vault EntraInspectorVault -Secret "<client-secret>"
```

Do not commit tenant identifiers, client secrets, exported assessment data, generated reports, logs, transcripts, or local configuration files.

When the SecretStore vault is password protected, `Connect-InspectorGraph` allows up to three password attempts while retrieving `InspectorGraphClientSecret`. Password/unlock failures are retried; unrelated vault failures are not. After the third rejected password the command stops with a concise recovery message. If needed, unlock the vault explicitly with `Unlock-SecretStore` and rerun the assessment.

## CLI Experience

`Invoke-EntraSecurityAssessment` presents a compact ASCII identity banner in interactive terminals, keeps the existing seven-stage progress model, and prints a concise completion summary with package status and output locations. Decorative output is suppressed when standard output is redirected, while stage information remains available for logs and automation. Color is used sparingly and is disabled when `NO_COLOR` is set or `TERM=dumb`. Host decoration is display-only and does not alter the structured pipeline result.

## Quick Start

Use `Invoke-EntraSecurityAssessment` for the fastest end-to-end run after installation and configuration:

```powershell
Import-Module .\EntraObjectInspector.psd1 -Force

Invoke-EntraSecurityAssessment `
    -AssessmentName "Contoso Entra Assessment" `
    -OutputDirectory ".\EntraObjectInspector-Exports"
```

This performs connection, tenant inspection, assessment intelligence, structured JSON/CSV/Markdown export, and static HTML report generation. Full orchestration telemetry distinguishes tenant inspection duration from export, report generation, and total command runtime.

Diagnostics logs are written locally under the output directory by default and help identify failed orchestration stages and object-processing failures. Logs are intended for operator troubleshooting and do not intentionally include secrets, tokens, passwords, client secrets, certificate material, authorization headers, or raw tenant snapshots. Higher Graph request counts are expected in larger tenants because relationship collection is object-dependent.

To open the generated HTML report automatically after successful report generation:

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Validation Assessment" `
    -OutputDirectory ".\EntraObjectInspector-Exports" `
    -ReportPath ".\EntraObjectInspector-Reports\validation-assessment.html" `
    -OpenReport
```

`Invoke-EntraSecurityAssessment` disconnects the Microsoft Graph session by default when it created the session. Use `-KeepGraphSession` only when intentionally preserving that session. When `-SkipConnect` is used, the caller owns the existing session and the command does not disconnect it by default.

Use the individual commands when debugging, integrating, testing, or customizing a pipeline.

## Run The Pipeline Manually

Connect to Microsoft Graph:

```powershell
Connect-InspectorGraph
```

Inspect a single object:

```powershell
$objectInsight = Get-EntraObjectInsight -Identity "<object-id-or-upn-or-app-id>"
```

Run tenant inspection:

```powershell
$tenantResult = Invoke-EntraTenantInspection `
    -ObjectType Application, ServicePrincipal, User, Group `
    -MaxObjectsPerType 0 `
    -BatchSize 25
```

`Invoke-EntraTenantInspection` builds a temporary in-memory tenant snapshot first. After snapshot collection completes, resolution, relationship building, normalization, permission intelligence, rules, and observations run offline from the snapshot.

Generate assessment intelligence:

```powershell
$intelligence = Invoke-EntraAssessmentIntelligence `
    -InputObject $tenantResult `
    -AssessmentName "Example Assessment"
```

Export structured artifacts:

```powershell
$export = Export-EntraTenantInspection `
    -InputObject $tenantResult `
    -AssessmentIntelligence $intelligence `
    -OutputDirectory ".\EntraObjectInspector-Exports" `
    -AssessmentName "Example Assessment"
```

Generate an HTML report:

```powershell
$report = Export-EntraAssessmentReport `
    -InputObject $tenantResult `
    -AssessmentIntelligence $intelligence `
    -AssessmentName "Example Assessment" `
    -ClientName "Contoso" `
    -ConsultantName "Consultant Name" `
    -OutputPath ".\EntraObjectInspector-Reports\example-assessment.html" `
    -Force
```

You can also generate a report from an existing export directory:

```powershell
$report = Export-EntraAssessmentReport `
    -ExportDirectory $export.ExportDirectory `
    -AssessmentName "Example Assessment" `
    -OutputPath ".\EntraObjectInspector-Reports\example-assessment.html" `
    -Force
```

Assessment intelligence, structured export, and HTML report generation consume existing in-memory or exported artifacts and do not call Microsoft Graph. The main HTML report is intentionally lightweight: detailed evidence is available in JSON/CSV exports and the evidence sidecar, while the main report shows concise per-finding evidence links and recommendations. Best-effort Open in Entra links are rendered per affected object only when the required identifiers are available.

## Output Artifacts

`Export-EntraTenantInspection` writes a run-specific export directory containing:

- `assessment-manifest.json`
- `assessment-summary.json`
- `security-observations.json`
- `security-observations.csv`
- `object-index.json`
- `object-index.csv`
- `evidence-index.json`
- `evidence-index.csv`
- `failed-objects.json`
- `failed-objects.csv`
- `execution-log.json`
- `execution-log.csv`
- `assessment-intelligence.json`
- `tenant-posture.json`
- `assessment-findings.json`
- `assessment-findings.csv`
- `assessment-recommendations.json`
- `assessment-recommendations.csv`
- `assessment-correlations.json`
- `assessment-correlations.csv`
- `assessment-limitations.json`
- `assessment-limitations.csv`

Full object insights can be exported explicitly with `-IncludeFullObjectInsights`.
- `assessment-summary.md`

The object index includes direct evidence counts only when evidence can be mapped to the object by subject metadata or directly referenced observation evidence IDs. Tenant-wide collection evidence is not treated as direct evidence for every object. Evidence rows may include `EvidenceScope`, `SubjectObjectType`, and `SubjectObjectId` to support this mapping.

`Export-EntraAssessmentReport` writes three self-contained HTML files: the main assessment report, a diagnostics sidecar, and an evidence sidecar. The returned result includes `ReportPath`, `DiagnosticsReportPath`, and `EvidenceReportPath`.

## HTML Report

The main HTML report is designed as a lightweight administrator triage report. It shows scope inventory, summary metrics, findings by category, priority findings, affected objects, recommended actions, and expandable evidence links. It is self-contained, offline-compatible, printable, searchable, and supports light/dark mode.

The diagnostics sidecar contains operational metadata such as Run ID, Report ID, command status, tenant inspection status, authoritative assessment coverage, expected-versus-collected evidence-plan reconciliation, stage durations, Graph request summary, failed-object details, diagnostics log path, and artifact records. Runtime telemetry is intentionally kept out of the main report.

The evidence sidecar is built from the authoritative deduplicated evidence index and canonical security observation list. Its primary view follows Finding → Observation → Evidence so administrators can review the proof supporting each grouped finding without starting from the raw evidence catalog. The complete observation/evidence catalogs remain available as secondary drill-down provenance.

Report search and filtering are local to the generated HTML file. Administrators can paste an object ID, appId/clientId, UPN, display name, permission name, category, severity, object type, or finding keyword into the finding search box to search the assessment content already embedded in the report.

The HTML report is an immutable report artifact. It does not refresh tenant data, query Microsoft Graph, or perform remediation. To refresh findings, run a new assessment:

```powershell
Invoke-EntraSecurityAssessment
```

For object-specific live inspection from the CLI, use:

```powershell
Get-EntraObjectInsight -Identity <object-id-or-upn-or-appId>
```

Single-object inspection is CLI functionality, not a live HTML report feature.

Search can also be prefilled with local report links. Query values may be URL-encoded and are decoded locally by the browser:

```text
report.html?q=Directory.ReadWrite.All
report.html?q=Policy.ReadWrite.ConditionalAccess
report.html?q=Finance%20Automation%20App
report.html?object=00000000-0000-0000-0000-000000000000
report.html?object=user%40contoso.com
```

Matching visible finding text is highlighted in the browser, and search features degrade gracefully when optional browser capabilities are unavailable. The `/` shortcut focuses the report search box. The shared report toolbar includes `Toggle theme`; sidecar reports use the same self-contained theme behavior. These features only inspect the static report content and perform no tenant queries.

The main report displays both Run ID and Report ID when available. Run ID represents the assessment orchestration run; Report ID identifies the rendered report artifact.

The release gate is fail-closed on assessment coverage. The snapshot builds an expected evidence plan independently from the evidence rows: required tenant collections plus the required per-object owner/member/app-role relationship queries for the collected scope. `ReleaseEligible` can be true only when that expected plan exactly matches the exported required evidence and every expected query completed successfully.


Recommendations and findings include authoritative references where applicable. Primary links point to Microsoft Learn and Microsoft Graph documentation; broader governance context may include Microsoft Zero Trust, NIST CSF 2.0, and CIS Controls. Each reference also has a short stable ID for maintenance and traceability. Reference links are static hyperlinks provided for transparency and validation. The report does not fetch external content automatically. The CIS Microsoft 365 Benchmark is referenced only at benchmark-family level unless specific licensed benchmark content is provided.

## Security Model

Entra Object Inspector is designed as a read-only assessment tool. Every logical tenant operation is a Microsoft Graph GET. High-volume independent relationship GETs may be transported through the Microsoft Graph v1.0 JSON `$batch` endpoint; the outer transport uses POST only as the batch envelope and every subrequest is hard-coded to GET. The module preserves one logical evidence/telemetry operation per subrequest and does not modify tenant state. Use least-privilege application permissions, protect client secrets, and avoid committing local configuration. Exported outputs may contain sensitive tenant metadata and should be stored, shared, and retained accordingly. Generated output folders such as `EntraObjectInspector-Exports/`, `EntraObjectInspector-Reports/`, `exports/`, and `reports/` should not be committed. Public release archives should likewise exclude generated assessment exports/reports and diagnostics logs; those artifacts can contain tenant-specific metadata even when no secrets are present.

## Performance Notes

Tenant-wide assessment loads selected Entra metadata into memory temporarily. Memory usage depends on the number of applications, service principals, users, groups, memberships, assignments, and grants. The snapshot-first model reduces repeated Graph latency and throttling exposure by collecting tenant data in a bounded ingestion stage, then processing offline.

Runtime telemetry summarizes stage duration, logical Graph request count, physical HTTP transport count, retry/throttling behavior, throughput, memory footprint, output artifact sizes, and expected external hosts. `GraphRequestSummary` remains the logical request/evidence view, while `GraphTransportSummary` distinguishes wrapper-issued single-request HTTP calls from JSON batch envelopes and records batch subrequest executions, including pagination or retry replays. Telemetry is intended for local operator visibility, diagnostics sidecar review, and run-summary review; it is not rendered as a dedicated main-report section. The collector uses `$select`, pagination, retry/throttling handling, bounded collection, and small read-only JSON batches for the highest-volume application/service-principal relationship GETs. For very large tenants, run from a machine with sufficient RAM and stable network connectivity. Do not persist raw snapshots unless needed for debugging, because they may contain sensitive tenant metadata.

## Reproducing Release Validation

For a clean-machine release check, use PowerShell 7.6 or later and install the exact release-validation dependency set:

```powershell
Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
Install-Module Microsoft.PowerShell.SecretManagement -RequiredVersion 1.1.2 -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
Install-Module Microsoft.PowerShell.SecretStore -RequiredVersion 1.0.6 -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
Install-Module Pester -RequiredVersion 6.1.0 -Scope CurrentUser -Repository PSGallery -Force -AllowClobber

./Scripts/Test-EntraObjectInspectorRequirements.ps1 -NonInteractive -SkipGalleryReachability

# Explicit imports ensure the validation session uses the tested versions even if
# other versions are also installed on the machine.
Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Force
Import-Module Microsoft.PowerShell.SecretManagement -RequiredVersion 1.1.2 -Force
Import-Module Microsoft.PowerShell.SecretStore -RequiredVersion 1.0.6 -Force
Import-Module Pester -RequiredVersion 6.1.0 -Force

Remove-Module EntraObjectInspector -Force -ErrorAction SilentlyContinue
Import-Module ./EntraObjectInspector.psd1 -Force
if (@(Get-Command -Module EntraObjectInspector -CommandType Function).Count -ne 7) {
    throw 'Expected exactly seven public commands.'
}

$result = Invoke-Pester -Path ./Tests -Output Detailed -PassThru
if ($result.FailedCount -gt 0) {
    throw "Pester failed: $($result.FailedCount) failing test(s)."
}
```

The current suite contains **276 Pester test cases** and the release gate requires **276 passed / 0 failed / 0 skipped**. CI performs the same dependency pinning, requirements validation, module-surface check, test run, and source-release hygiene gate. CI intentionally performs no live Microsoft Graph authentication or tenant assessment.

Generated tenant assessments, reports, diagnostics, logs, local configuration, temporary archives, test output, and release-inventory output are not source-release content and are covered by `.gitignore` and/or the CI hygiene gate. Before publishing from a real Git clone, verify `git status --short` and `git ls-files` so ignored local files are not mistaken for tracked content.

## Testing

Run parser/import validation:

```powershell
Remove-Module EntraObjectInspector -Force -ErrorAction SilentlyContinue
Import-Module .\EntraObjectInspector.psd1 -Force
```

Run the complete Pester suite:

```powershell
Invoke-Pester `
    -Path .\Tests `
    -Output Detailed
```

The project includes a Pester test suite covering:

- module import/export surface
- authentication wrapper behavior
- GET-only logical Graph operations, including the read-only JSON batch transport envelope
- object resolution
- relationship collection
- normalization
- rule evaluation
- permission intelligence
- security observations
- tenant orchestration
- tenant snapshot collection
- offline pipeline boundary behavior
- assessment intelligence
- structured exports
- HTML report generation
- diagnostics and evidence sidecar report generation
- client-side report navigation/cross-reference behavior
- authoritative recommendation reference catalog
- StrictMode regression coverage
- runtime telemetry

The current release baseline contains 276 Pester test cases and requires 276 passed / 0 failed / 0 skipped before release.

## Repository Structure

- `Public` - exported PowerShell commands.
- `Private` - internal implementation.
- `Private/Collectors` - object relationship collectors.
- `Private/Discovery` - tenant object discovery.
- `Private/Normalize` - ObjectInsight normalization.
- `Private/Permissions` - Microsoft Graph permission catalog and enrichment.
- `Private/References` - authoritative recommendation reference catalog.
- `Private/Rules` - baseline rule evaluation.
- `Private/Observations` - security observation generation.
- `Private/Snapshot` - temporary tenant snapshot collection and offline lookup.
- `Private/Pipeline` - deprecated pre-snapshot compatibility helper retained for regression coverage only; supported production retry/resume behavior lives in `Invoke-EntraTenantInspection`.
- `Private/Telemetry` - local runtime telemetry helpers.
- `Private/Intelligence` - assessment-level intelligence.
- `Private/Export` - JSON, CSV, and summary export.
- `Private/Reporting` - HTML report model and renderer.
- `Scripts` - optional local operator and maintainer helper scripts.
- `Tests` - Pester tests.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.

Open issues for bugs, proposed improvements, and design discussion. Submit pull requests with focused changes and tests. Preserve the read-only boundary, do not add Microsoft Graph write calls, and keep evidence-preserving behavior intact. Changes that affect output contracts should include corresponding test updates. Risk scoring, exposure scoring, attack-path features, remediation, and similar assessment semantics should be discussed before implementation.

## Roadmap

- More permission catalog coverage.
- Additional report templates.
- More object relationship coverage where Microsoft Graph supports it.
- Optional PowerShell Gallery packaging.
- More sample datasets.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
