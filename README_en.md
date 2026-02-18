# Outlook GPO & Registry Audit — Pre-Migration Assessment

A PowerShell-based scanner and reference toolkit for identifying Outlook/Exchange GPO settings, registry Altlasten, and migration blockers before Exchange Online (M365) migrations.

## Problem

Enterprise environments accumulate years of Outlook GPO policies, direct registry tweaks, and legacy Office 2010/2013 remnants. During Exchange migrations, these hidden settings cause:

- **AutoDiscover failures** — `PreferLocalXML`, `ExcludeHttpsAutoDiscoverDomain` silently override cloud routing
- **Authentication blocks** — `EnableADAL = 0` prevents Modern Auth, making M365 unreachable
- **Protocol downgrades** — `MapiHttpDisabled = 1` forces RPC/HTTP fallback with degraded performance
- **Hardcoded servers** — `ProxyServer` values pointing to decommissioned infrastructure
- **Proxy/WPAD conflicts** — machine-wide proxy enforcement blocking M365 Optimize endpoints

This tool finds them all before they find you.

## What It Does

```
HKCU:\Software\Microsoft\Office\16.0\Outlook\*          ← User direct
HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\* ← GPO user config
HKCU:\Software\Microsoft\Exchange\*                      ← Exchange client
HKLM:\Software\Microsoft\Office\16.0\Outlook\*          ← Machine direct
HKLM:\Software\Policies\Microsoft\Office\16.0\Outlook\* ← GPO computer config
HKLM:\Software\Policies\Microsoft\Exchange\*             ← Exchange machine policy
Office 14.0 / 15.0 equivalents                          ← Legacy Altlasten
WPAD / Internet Settings / WinHTTP                       ← Proxy enforcement
```

Every finding is:
- **Mapped to its ADMX policy name** (what the GPO editor shows vs what's in the registry)
- **Severity-rated** (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- **Annotated with migration impact** and remediation recommendation
- **Tagged** as GPO-enforced, direct, or legacy

## Quick Start

```powershell
# Basic local scan
.\Get-OutlookGPOAudit.ps1

# Full scan with WPAD and GPO object analysis
.\Get-OutlookGPOAudit.ps1 -IncludeWPAD -GPOAnalysis

# Remote scan
.\Get-OutlookGPOAudit.ps1 -ComputerName DC01,WS001,WS002

# Custom output path
.\Get-OutlookGPOAudit.ps1 -ExportPath C:\Migration\Audit -IncludeWPAD
```

## Output

```
OutlookGPOAudit_20250218_143022/
├── OutlookGPO_FullInventory.csv        # Every registry value found
├── OutlookGPO_MigrationBlockers.csv    # CRITICAL + HIGH items only
├── OutlookGPO_AuditReport.html         # Visual report with severity highlighting
└── OutlookGPO_PolicyObjects.csv        # GPO objects (if -GPOAnalysis used)
```

The HTML report includes:
- Summary dashboard (total findings, critical/high/medium counts, legacy count)
- Migration blockers table with recommendations
- Complete registry inventory with ADMX policy cross-reference
- GPO object listing with link/scope info
- WPAD documentation and M365 endpoint bypass reference
- Pre-migration checklist

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ComputerName` | String[] | localhost | Target computer(s) for scanning |
| `-ExportPath` | String | `.\OutlookGPOAudit_<timestamp>` | Output folder |
| `-IncludeWPAD` | Switch | off | Scan WPAD/proxy/WinHTTP keys |
| `-GPOAnalysis` | Switch | off | Parse GPO objects via `Get-GPO` (requires RSAT) |

## ADMX Mapping

The core value of this tool is the registry-to-ADMX rosetta stone. The GPO editor shows friendly names like *"Disable AutoDiscover"* but writes to registry paths that are non-obvious during troubleshooting.

| GPO Editor Shows | Registry Value | Why It Matters |
|---|---|---|
| Exclude the query for the AutoDiscover domain | `ExcludeHttpsAutoDiscoverDomain` | Blocks HTTPS AutoDiscover — M365 depends on this |
| Prefer local XML AutoDiscover | `PreferLocalXML` | Local XML overrides ALL. Blocks migration entirely. |
| Disable Zero Config Exchange | `ZeroConfigExchange` | Prevents automatic profile creation |
| Enable Modern Authentication | `EnableADAL` | **Required** for M365. 0 = cannot connect. |
| Disable MAPI/HTTP | `MapiHttpDisabled` | THE protocol for M365. Disabling = degraded. |
| Do not allow an OST file | `NoOST` | Online-only. Severe performance hit with M365. |
| RPC Proxy Server Name | `ProxyServer` | Hardcoded server WILL break post-migration |

Full mapping of 30+ policies included in the script's `$ADMXMappings` hashtable.

## Severity Classification

| Level | Meaning | Example |
|-------|---------|---------|
| **CRITICAL** | Will break M365 connectivity | `EnableADAL=0`, `MapiHttpDisabled=1`, `NoOST=1` |
| **HIGH** | Will cause significant issues | AutoDiscover exclusions, hardcoded proxy servers |
| **MEDIUM** | Should be reviewed | Cached mode settings, OST size limits, sync windows |
| **LOW** | Informational / cleanup | Roaming signatures, attachment blocking, legacy keys |

## Pre-Migration Checklist

1. ☐ Enable Modern Auth (`EnableADAL = 1`) via GPO
2. ☐ Remove hardcoded RPC `ProxyServer` values
3. ☐ Ensure MAPI/HTTP enabled (`MapiHttpDisabled` = 0 or absent)
4. ☐ Enable Cached Mode (`NoOST` = 0 or absent)
5. ☐ Remove `PreferLocalXML` AutoDiscover overrides
6. ☐ Review AutoDiscover exclusion policies
7. ☐ Ensure `ZeroConfigExchange` enabled
8. ☐ Set Cached Mode Sync Window (12 months recommended)
9. ☐ Remove legacy Office 2010/2013 GPO remnants
10. ☐ Verify proxy/WPAD allows M365 Optimize endpoints

## Citrix vs. Fat-Client Comparison

In Citrix published app environments, Outlook GPOs come from **two different sources** that most admins forget to cross-check:

```
Fat Client:    User OU GPO  ──→  HKCU on endpoint     ──→  Outlook
Citrix VDA:    Server OU GPO ──→  HKCU via loopback    ──→  Outlook (published app)
                                  + UPM/FSLogix layering
```

The result: a user running Outlook locally gets different settings than the same user running Outlook as a Citrix published app. Classic migration blindspot.

### Usage

```powershell
# Auto-detect if running on/in Citrix
.\Get-CitrixOutlookGPO.ps1 -AutoDetect

# Explicit comparison
.\Get-CitrixOutlookGPO.ps1 -CitrixVDAServers CTX01,CTX02 -CompareWithClient WS001

# Recommended workflow
# Step 1: Run base audit on VDA
.\Get-OutlookGPOAudit.ps1 -ExportPath C:\ctx_audit -IncludeWPAD    # on Citrix server
# Step 2: Run base audit on fat client
.\Get-OutlookGPOAudit.ps1 -ExportPath C:\cli_audit -IncludeWPAD    # on endpoint
# Step 3: Compare
.\Get-CitrixOutlookGPO.ps1 -CitrixVDAServers CTX01 -CompareWithClient WS001
```

### What It Detects

| Finding | Risk | Why |
|---------|------|-----|
| **Value conflicts** | Settings with different values on VDA vs. client | User gets inconsistent Outlook behavior |
| **Citrix-only settings** | GPO applied to VDA OU but not endpoint OU | Published-app users get settings fat-client users don't |
| **Client-only settings** | GPO applied to endpoint OU but not VDA OU | Fat-client users get settings Citrix users miss |
| **UPM exclusions stripping Outlook keys** | UPM registry exclusion list drops Outlook settings | Settings vanish between Citrix sessions |
| **OST on non-persistent storage** | Cached Mode enabled but no FSLogix/persistent disk | Full OST rebuild on every Citrix logon |
| **Modern Auth without Citrix FAS** | EnableADAL=1 but no FAS/SSO passthrough | Auth popups fail or loop in published apps |
| **Proxy divergence** | VDA routes through datacenter proxy, client through local | M365 connectivity works locally but fails in Citrix |

### Citrix-Specific Registry Paths

In addition to standard Outlook paths, the Citrix module scans:

```
HKLM:\Software\Policies\Citrix\UserProfileManager\*     ← UPM sync/exclusion lists
HKLM:\Software\FSLogix\Profiles                          ← FSLogix profile container
HKLM:\Software\Policies\FSLogix\ODFC                     ← FSLogix Office container
HKLM:\Software\Citrix\VirtualDesktopAgent                ← VDA detection
HKLM:\Software\Citrix\CtxHook\AppInit_DLLs\Outlook       ← Citrix Outlook hooks
HKLM:\Software\Citrix\...\Authentication                 ← Citrix SSO/FAS config
```

### GPO Loopback Processing

This is the core of the Citrix GPO problem. When loopback is enabled (standard in Citrix):

- **Replace mode**: User Configuration from VDA server OU *replaces* the user's normal policy entirely
- **Merge mode**: VDA server OU User Configuration *merges* with user's OU policy (VDA wins on conflict)

Check with: `gpresult /scope computer /v | findstr Loopback`

## Requirements

- PowerShell 5.1+
- Local admin (for HKLM reads)
- RSAT Group Policy module (optional, for `-GPOAnalysis`)
- WinRM enabled on targets (for remote `-ComputerName`)

## Files

```
├── Get-OutlookGPOAudit.ps1             # Main scanner script
├── Get-CitrixOutlookGPO.ps1            # Citrix vs. fat-client comparison
├── OutlookGPO_AuditReference.docx      # Full documentation (printable)
├── README.md                            # English
└── README.de.md                         # Deutsch
```

## License

MIT

## Author

Jan Hübener
