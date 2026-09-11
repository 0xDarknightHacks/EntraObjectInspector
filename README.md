<div align="center">

# Entra Object Inspector

**Evidence-driven identity inspection for Microsoft Entra ID**

[![Release](https://img.shields.io/badge/release-v1.0.3-blue)](#)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.6%20LTS%2B-5391FE?logo=powershell)](#requirements)
[![Tests](https://img.shields.io/badge/tests-349%2F349%20passing-brightgreen)](#validation)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Entra Object Inspector captures Microsoft Entra identity state into a deterministic snapshot, reconstructs security-relevant relationships, and produces traceable observations backed by the evidence that caused them.

**Collect once. Inspect offline. Compare over time. Trace every observation to evidence.**

[Quick start](#quick-start) · [What it is](#what-it-is) · [Requirements](#requirements) · [Permissions](#permissions) · [Docs](#usage) · [Security model](#security-model)

</div>

---

## Table of contents

- [What it is](#what-it-is)
- [Screenshots](#screenshots)
- [Requirements](#requirements)
- [Permissions](#permissions)
- [Quick start](#quick-start)
  - [1. Install](#1-install)
  - [2. Configure authentication](#2-configure-authentication)
  - [3. Run an assessment](#3-run-an-assessment)
- [Usage](#usage)
  - [Live tenant assessment](#live-tenant-assessment)
  - [Live assessment with a saved snapshot](#live-assessment-with-a-saved-snapshot)
  - [Offline assessment from a snapshot](#offline-assessment-from-a-snapshot)
  - [Compare two snapshots](#compare-two-snapshots)
  - [Target specific objects](#target-specific-objects)
- [Output](#output)
- [Security model](#security-model)
- [Validation](#validation)
- [Repository structure](#repository-structure)
- [Contributing & security reporting](#contributing--security-reporting)
- [License](#license)

---

## What it is

Entra Object Inspector is an **evidence-driven Microsoft Entra identity inspection engine**.

It is built around the tenant's identity state and relationships rather than a checklist of configuration controls. The engine collects identity data once, preserves it as a portable snapshot, correlates relationships across objects and privilege, and explains security-relevant observations with their supporting evidence.

### Inspect → Correlate → Explain

| Capability | What it provides |
|---|---|
| Inspect | Deterministic identity-state snapshots covering users, groups, applications, service principals, permissions, directory roles, PIM, Administrative Units, and relevant risk context |
| Correlate | Cross-object analysis of ownership, membership, application permissions, app-role assignments, privilege, scope, and risky-identity relationships |
| Explain | Traceable observations identifying what was observed, why it matters, which objects contributed, and which collected evidence supports it |
| Re-analyze | Portable offline inspection with zero Microsoft Graph requests after snapshot collection |
| Compare | Snapshot-to-snapshot drift analysis for security-relevant identity changes |
| Focus | Targeted object inspection, rule packs, and accepted-condition baselines without changing the core engine |

> **Not another posture scanner.** Entra Object Inspector does not model its primary output as a compliance score or a catalogue of configuration failures. It reconstructs Microsoft Entra identity state and relationships so security observations remain inspectable, reproducible, and evidence-backed.

The tool remains strictly **read-only**. It does not remediate tenant configuration, calculate numerical risk scores, or execute attack paths.

## Screenshots

<details>
<summary><b>CLI assessment invoke</b></summary>

![CLI assessment summary](assets/images/cli-assessment.png)
</details>

<details>
<summary><b>Main HTML report overview</b></summary>

![Main HTML report](assets/images/report-overview.png)
</details>

<details>
<summary><b>Finding evidence drill-down</b></summary>

![Finding evidence drill-down](assets/images/finding-evidence.png)
</details>

<details>
<summary><b>Privileged identity overview</b></summary>

![Privileged identity overview](assets/images/privileged-identity.png)
</details>

<details>
<summary><b>Evidence report overview</b></summary>

![Evidence report overview](assets/images/evidence.png)
</details>

<details>
<summary><b>Diagnostics report overview</b></summary>

![Diagnostics report overview](assets/images/diagnostics.png)
</details>

## Requirements

- PowerShell 7.6 LTS or later
- A Microsoft Entra application registration
- App-only Microsoft Graph authentication using a client secret

**Release-validated module dependencies**

| Dependency | Version |
|---|---:|
| `Microsoft.Graph.Authentication` | 2.39.0 |
| `Microsoft.PowerShell.SecretManagement` | 1.1.2 |
| `Microsoft.PowerShell.SecretStore` | 1.0.6 |

## Permissions

Use the **least-privilege permission set appropriate to the assessment you intend to run** — not every permission below is needed for every assessment.

| Scope | Permission |
|---|---|
| Applications | `Application.Read.All` |
| Users | `User.Read.All` |
| Groups | `GroupMember.Read.All` |
| Directory objects | `Directory.Read.All` |
| PIM | PIM schedule read permissions |
| Administrative Units | `AdministrativeUnit.Read.All` |
| Risky users | `IdentityRiskyUser.Read.All` |
| Hidden membership *(if in scope)* | `Member.Read.Hidden` |

## Quick start

### 1. Install

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

### 2. Configure authentication

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

> ⚠️ **Never commit** tenant identifiers, secrets, snapshots, reports, diagnostics, or exported assessment data.

### 3. Run an inspection

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Tenant Assessment" `
    -OutputDirectory ".\EntraObjectInspector-Exports"
```

See [Usage](#usage) below for snapshots, offline mode, drift comparison, and targeted inspection.

## Usage

### Live tenant inspection

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Tenant Assessment" `
    -OutputDirectory ".\EntraObjectInspector-Exports"
```

### Live inspection with a saved snapshot

```powershell
Invoke-EntraSecurityAssessment `
    -AssessmentName "Tenant Assessment" `
    -SaveSnapshotPath ".\snapshots\tenant.json"
```

### Offline inspection from a snapshot

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

For rule packs, baselines, advanced options, and manual pipeline commands:

```powershell
Get-Help Invoke-EntraSecurityAssessment -Examples
Get-Help Invoke-EntraSecurityAssessment -Full
```

## Output

Each run produces a timestamped evidence package containing:

- **Three self-contained HTML reports** — main inspection, evidence, and diagnostics
- Manifest, observations, grouped findings, object/evidence indexes, correlations, limitations, recommendations, and execution metadata
- Inspection intelligence summary

> Generated output may contain sensitive tenant information — store and share it accordingly.

The main report supports URL-encoded local search and object filters. For example:

```text
report.html?q=Directory.ReadWrite.All
report.html?q=Policy.ReadWrite.ConditionalAccess
report.html?q=Finance%20Automation%20App
report.html?object=00000000-0000-0000-0000-000000000000
report.html?object=user%40contoso.com
```

Invalid or unsupported filter values degrade gracefully to the normal local report view.

## Security model

- Entra Object Inspector is **read-only end to end**. Tenant operations use Microsoft Graph `GET` requests.
- High-volume collection may use Graph JSON batching (`$batch`), where the outer request is `POST` but every contained operation remains a read-only `GET`.
- After snapshot collection, all inspection intelligence, correlation, export, and report generation run **offline** — no further Graph calls. `GraphCallsAfterSnapshot` is used as a release boundary check.

## Validation

The v1.0.3 release was validated with:

- ✅ 349/349 Pester tests passing
- ✅ Successful tenant-wide live assessment
- ✅ Successful portable offline assessment
- ✅ Zero failed objects in validated live and offline runs
- ✅ `PackageValidationStatus = Success`, `ReleaseEligible = True`
- ✅ `GraphCallsAfterSnapshot = 0`, zero Graph requests during offline analysis

Run the test suite yourself:

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

## Contributing & security reporting

- Development guidance: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security reporting: [SECURITY.md](SECURITY.md)

Contributions should preserve the read-only Microsoft Graph boundary, deterministic snapshot behavior, evidence provenance, and fail-closed coverage semantics.

## License

Licensed under the [MIT License](LICENSE).
