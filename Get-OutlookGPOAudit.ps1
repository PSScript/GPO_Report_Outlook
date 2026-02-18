#Requires -Version 5.1
<#
.SYNOPSIS
    Outlook GPO & Registry Audit for Pre-Migration Assessment
    
.DESCRIPTION
    Scans HKLM and HKCU for all Outlook/Exchange-related GPO settings,
    compares against known ADMX template policies, and identifies
    migration blockers ("Altlasten") for Exchange/Outlook migrations.
    
    Covers:
    - HKCU:\Software\Microsoft\Office\16.0\Outlook\*
    - HKCU:\Software\Microsoft\Exchange\*
    - HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\*
    - HKLM:\Software\Microsoft\Office\16.0\Outlook\*
    - HKLM:\Software\Policies\Microsoft\Office\16.0\Outlook\*
    - HKLM:\Software\Policies\Microsoft\Exchange\*
    - WPAD/Proxy enforcement keys
    
.PARAMETER ComputerName
    Target computer(s). Default: localhost.
    
.PARAMETER ExportPath
    Output folder for CSV/HTML reports.
    
.PARAMETER IncludeWPAD
    Include WPAD/Proxy enforcement documentation.
    
.PARAMETER GPOAnalysis
    Also parse GPO objects via Get-GPO (requires RSAT).
    
.EXAMPLE
    .\Get-OutlookGPOAudit.ps1 -ExportPath C:\Reports -IncludeWPAD
    
.EXAMPLE
    .\Get-OutlookGPOAudit.ps1 -ComputerName SRV01,SRV02 -GPOAnalysis
    
.NOTES
    Author:  Jan Hübener / DATAGROUP SE
    Version: 1.0.0
    Date:    2025-02-18
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    
    [Parameter()]
    [string]$ExportPath = ".\OutlookGPOAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    
    [switch]$IncludeWPAD,
    [switch]$GPOAnalysis
)

#region ======== CONFIGURATION ========

$script:AuditTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$script:Results = [System.Collections.Generic.List[PSObject]]::new()
$script:MigrationBlockers = [System.Collections.Generic.List[PSObject]]::new()

# ── Registry paths to scan ──
$RegistryPaths = @(
    # HKCU - User settings (direct)
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Office\16.0\Outlook'; Scope = 'User-Direct'; Category = 'Outlook' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Office\16.0\Outlook\AutoDiscover'; Scope = 'User-Direct'; Category = 'AutoDiscover' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Office\16.0\Outlook\RPC'; Scope = 'User-Direct'; Category = 'RPC/HTTP' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Office\16.0\Outlook\Cached Mode'; Scope = 'User-Direct'; Category = 'CachedMode' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Office\16.0\Outlook\OST'; Scope = 'User-Direct'; Category = 'OST' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Office\16.0\Outlook\Preferences'; Scope = 'User-Direct'; Category = 'Preferences' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Office\16.0\Outlook\Security'; Scope = 'User-Direct'; Category = 'Security' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Office\16.0\Outlook\Setup'; Scope = 'User-Direct'; Category = 'Setup' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Exchange'; Scope = 'User-Direct'; Category = 'Exchange' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Exchange\Client\Options'; Scope = 'User-Direct'; Category = 'Exchange-Client' }
    
    # HKCU - Policy-enforced (GPO User Config)
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook'; Scope = 'GPO-User'; Category = 'Outlook-Policy' }
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover'; Scope = 'GPO-User'; Category = 'AutoDiscover-Policy' }
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook\RPC'; Scope = 'GPO-User'; Category = 'RPC-Policy' }
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode'; Scope = 'GPO-User'; Category = 'CachedMode-Policy' }
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook\OST'; Scope = 'GPO-User'; Category = 'OST-Policy' }
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook\Preferences'; Scope = 'GPO-User'; Category = 'Preferences-Policy' }
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook\Security'; Scope = 'GPO-User'; Category = 'Security-Policy' }
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook\Setup'; Scope = 'GPO-User'; Category = 'Setup-Policy' }
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Exchange'; Scope = 'GPO-User'; Category = 'Exchange-Policy' }
    
    # HKLM - Machine settings (direct)
    @{ Hive = 'HKLM'; Path = 'Software\Microsoft\Office\16.0\Outlook'; Scope = 'Machine-Direct'; Category = 'Outlook-Machine' }
    @{ Hive = 'HKLM'; Path = 'Software\Microsoft\Office\16.0\Outlook\AutoDiscover'; Scope = 'Machine-Direct'; Category = 'AutoDiscover-Machine' }
    @{ Hive = 'HKLM'; Path = 'Software\Microsoft\Office\16.0\Outlook\RPC'; Scope = 'Machine-Direct'; Category = 'RPC-Machine' }
    @{ Hive = 'HKLM'; Path = 'Software\Microsoft\Office\16.0\Outlook\Security'; Scope = 'Machine-Direct'; Category = 'Security-Machine' }
    @{ Hive = 'HKLM'; Path = 'Software\Microsoft\Office\16.0\Outlook\Setup'; Scope = 'Machine-Direct'; Category = 'Setup-Machine' }
    @{ Hive = 'HKLM'; Path = 'Software\Microsoft\Exchange'; Scope = 'Machine-Direct'; Category = 'Exchange-Machine' }
    
    # HKLM - Policy-enforced (GPO Computer Config)
    @{ Hive = 'HKLM'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook'; Scope = 'GPO-Machine'; Category = 'Outlook-MachinePolicy' }
    @{ Hive = 'HKLM'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover'; Scope = 'GPO-Machine'; Category = 'AutoDiscover-MachinePolicy' }
    @{ Hive = 'HKLM'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook\RPC'; Scope = 'GPO-Machine'; Category = 'RPC-MachinePolicy' }
    @{ Hive = 'HKLM'; Path = 'Software\Policies\Microsoft\Office\16.0\Outlook\Security'; Scope = 'GPO-Machine'; Category = 'Security-MachinePolicy' }
    @{ Hive = 'HKLM'; Path = 'Software\Policies\Microsoft\Exchange'; Scope = 'GPO-Machine'; Category = 'Exchange-MachinePolicy' }
    
    # Older Office versions (legacy Altlasten)
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Office\15.0\Outlook'; Scope = 'Legacy-2013'; Category = 'Outlook-Legacy15' }
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Office\15.0\Outlook'; Scope = 'Legacy-2013-GPO'; Category = 'Outlook-Legacy15-Policy' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Office\14.0\Outlook'; Scope = 'Legacy-2010'; Category = 'Outlook-Legacy14' }
    @{ Hive = 'HKCU'; Path = 'Software\Policies\Microsoft\Office\14.0\Outlook'; Scope = 'Legacy-2010-GPO'; Category = 'Outlook-Legacy14-Policy' }
    @{ Hive = 'HKLM'; Path = 'Software\Policies\Microsoft\Office\15.0\Outlook'; Scope = 'Legacy-2013-GPO-Machine'; Category = 'Outlook-Legacy15-MachinePolicy' }
    @{ Hive = 'HKLM'; Path = 'Software\Policies\Microsoft\Office\14.0\Outlook'; Scope = 'Legacy-2010-GPO-Machine'; Category = 'Outlook-Legacy14-MachinePolicy' }
)

# WPAD/Proxy paths
$WPADPaths = @(
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Scope = 'User-Proxy'; Category = 'WPAD-InternetSettings' }
    @{ Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'; Scope = 'User-Proxy'; Category = 'WPAD-Connections' }
    @{ Hive = 'HKLM'; Path = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Scope = 'Machine-Proxy'; Category = 'WPAD-Machine' }
    @{ Hive = 'HKLM'; Path = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'; Scope = 'GPO-Proxy'; Category = 'WPAD-Policy' }
    @{ Hive = 'HKLM'; Path = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'; Scope = 'Machine-WinHTTP'; Category = 'WPAD-WinHTTP' }
    @{ Hive = 'HKLM'; Path = 'SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc'; Scope = 'Machine-Service'; Category = 'WPAD-Service' }
)

if ($IncludeWPAD) {
    $RegistryPaths += $WPADPaths
}

#endregion

#region ======== KNOWN ADMX TEMPLATE MAPPINGS ========

# Maps registry values to their ADMX policy names (outlk16.admx / outlk.admx)
# This is the "rosetta stone" — what the GPO editor shows vs what's in the registry
$ADMXMappings = @{
    # ── AutoDiscover ──
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ExcludeHttpsAutoDiscoverDomain' = @{
        PolicyName = 'Exclude the query for the AutoDiscover domain'
        ADMXFile = 'outlk16.admx'
        Severity = 'HIGH'
        MigrationImpact = 'AutoDiscover may fail in new environment if this blocks HTTPS lookup'
        Recommendation = 'Review: May need to be DISABLED for M365 migration'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ExcludeHttpRedirect' = @{
        PolicyName = 'Exclude the HTTP redirect method'
        ADMXFile = 'outlk16.admx'
        Severity = 'HIGH'
        MigrationImpact = 'Blocks HTTP redirect AutoDiscover — critical for hybrid coexistence'
        Recommendation = 'Must be 0 (disabled) during M365 migration'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ExcludeScpLookup' = @{
        PolicyName = 'Exclude the SCP object lookup'
        ADMXFile = 'outlk16.admx'
        Severity = 'MEDIUM'
        MigrationImpact = 'SCP disabled = no AD-based AutoDiscover. OK for cloud-only, problem for hybrid'
        Recommendation = 'Keep enabled during hybrid coexistence phase'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ExcludeSrvRecord' = @{
        PolicyName = 'Exclude the SRV record lookup'
        ADMXFile = 'outlk16.admx'
        Severity = 'LOW'
        MigrationImpact = 'SRV rarely used. Low impact.'
        Recommendation = 'Can remain as-is'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ExcludeLastKnownGoodURL' = @{
        PolicyName = 'Exclude the last known good URL'
        ADMXFile = 'outlk16.admx'
        Severity = 'MEDIUM'
        MigrationImpact = 'Cached URL may point to old server after migration'
        Recommendation = 'Consider enabling exclusion during cutover to force fresh lookup'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\PreferLocalXML' = @{
        PolicyName = 'Prefer local XML AutoDiscover'
        ADMXFile = 'outlk16.admx'
        Severity = 'HIGH'
        MigrationImpact = 'Local XML overrides all. Will BLOCK migration if pointing to old server.'
        Recommendation = 'REMOVE before migration. Highest priority Altlast.'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ZeroConfigExchange' = @{
        PolicyName = 'Disable Zero Config Exchange'
        ADMXFile = 'outlk16.admx'
        Severity = 'HIGH'
        MigrationImpact = 'Disables automatic profile configuration via AutoDiscover'
        Recommendation = 'Must be 0 for M365. Critical blocker if set to 1.'
    }
    
    # ── Cached Mode ──
    'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode\Enable' = @{
        PolicyName = 'Use Cached Exchange Mode'
        ADMXFile = 'outlk16.admx'
        Severity = 'MEDIUM'
        MigrationImpact = 'Forced online mode may cause performance issues with M365'
        Recommendation = 'Enable Cached Mode for M365. Performance critical.'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode\SyncWindowSetting' = @{
        PolicyName = 'Cached Exchange Mode Sync Window'
        ADMXFile = 'outlk16.admx'
        Severity = 'MEDIUM'
        MigrationImpact = 'Sync window affects initial OST population time and bandwidth'
        Recommendation = 'Set to 12 months (value 6) for M365. Reduce for bandwidth-constrained sites.'
        ValueMap = @{ 0 = 'All'; 1 = '1 month'; 3 = '3 months'; 6 = '6 months'; 12 = '12 months'; 24 = '24 months' }
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode\SyncWindowSettingDays' = @{
        PolicyName = 'Cached Mode Sync Window (Days)'
        ADMXFile = 'outlk16.admx'
        Severity = 'LOW'
        MigrationImpact = 'Fine-grained sync window. Overrides SyncWindowSetting.'
        Recommendation = 'Verify alignment with SyncWindowSetting'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode\DownloadSharedFolders' = @{
        PolicyName = 'Download Shared Folders'
        ADMXFile = 'outlk16.admx'
        Severity = 'MEDIUM'
        MigrationImpact = 'Shared folder caching increases OST size significantly in M365'
        Recommendation = 'Consider disabling for M365 to reduce OST bloat'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode\DownloadPublicFolderFavorites' = @{
        PolicyName = 'Download Public Folder Favorites'
        ADMXFile = 'outlk16.admx'
        Severity = 'LOW'
        MigrationImpact = 'Public folders may not exist in target environment'
        Recommendation = 'Disable if PF migration not planned'
    }
    
    # ── RPC/HTTP (Outlook Anywhere) ──
    'Software\Policies\Microsoft\Office\16.0\Outlook\RPC\ProxyServer' = @{
        PolicyName = 'RPC Proxy Server Name'
        ADMXFile = 'outlk16.admx'
        Severity = 'CRITICAL'
        MigrationImpact = 'Hardcoded proxy server WILL break after migration'
        Recommendation = 'REMOVE before migration. Let AutoDiscover handle this.'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\RPC\ProxyServerFlags' = @{
        PolicyName = 'RPC Proxy Server Flags'
        ADMXFile = 'outlk16.admx'
        Severity = 'HIGH'
        MigrationImpact = 'Controls NTLM/Negotiate auth for RPC proxy'
        Recommendation = 'Remove — M365 uses Modern Auth, not RPC'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\RPC\EnableRPCEncryption' = @{
        PolicyName = 'Enable RPC Encryption'
        ADMXFile = 'outlk16.admx'
        Severity = 'LOW'
        MigrationImpact = 'Moot for MAPI/HTTP and M365'
        Recommendation = 'Can remain, no impact on M365'
    }
    
    # ── OST Management ──
    'Software\Policies\Microsoft\Office\16.0\Outlook\OST\NoOST' = @{
        PolicyName = 'Do not allow an OST file'
        ADMXFile = 'outlk16.admx'
        Severity = 'CRITICAL'
        MigrationImpact = 'No OST = Online Mode only. Severe performance degradation with M365.'
        Recommendation = 'MUST be removed for M365 migration.'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\OST\MaxOSTSize' = @{
        PolicyName = 'Maximum OST file size'
        ADMXFile = 'outlk16.admx'
        Severity = 'MEDIUM'
        MigrationImpact = 'May truncate large M365 mailboxes. Default 50GB is usually fine.'
        Recommendation = 'Remove or set to 50GB+ for M365'
    }
    
    # ── Security ──
    'Software\Policies\Microsoft\Office\16.0\Outlook\Security\EnableADAL' = @{
        PolicyName = 'Enable Modern Authentication'
        ADMXFile = 'outlk16.admx'
        Severity = 'CRITICAL'
        MigrationImpact = 'ADAL/Modern Auth required for M365. If disabled = cannot connect.'
        Recommendation = 'MUST be 1 for M365. Top priority migration prerequisite.'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Security\AlwaysUseMSOAuthForAutoDiscover' = @{
        PolicyName = 'Always use Modern Auth for AutoDiscover'
        ADMXFile = 'outlk16.admx'
        Severity = 'HIGH'
        MigrationImpact = 'Forces OAuth for AutoDiscover. Required for M365.'
        Recommendation = 'Set to 1 for M365'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Security\AdminSecurityMode' = @{
        PolicyName = 'Outlook Security Mode'
        ADMXFile = 'outlk16.admx'
        Severity = 'MEDIUM'
        MigrationImpact = 'Controls whether Outlook uses group policy security settings'
        Recommendation = 'Review — may need adjustment for M365 security baseline'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Security\Level1Remove' = @{
        PolicyName = 'Remove file types from Level 1 block'
        ADMXFile = 'outlk16.admx'
        Severity = 'MEDIUM'
        MigrationImpact = 'Attachment blocking exceptions. May conflict with Defender policies.'
        Recommendation = 'Document and compare with M365 ATP/Defender attachment policies'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Security\Level1Add' = @{
        PolicyName = 'Add file types to Level 1 block'
        ADMXFile = 'outlk16.admx'
        Severity = 'LOW'
        MigrationImpact = 'Additional blocking — carries over fine'
        Recommendation = 'Document for reference'
    }
    
    # ── Setup / Profile ──
    'Software\Policies\Microsoft\Office\16.0\Outlook\Setup\DisableRoamingSignatures' = @{
        PolicyName = 'Disable Roaming Signatures'
        ADMXFile = 'outlk16.admx'
        Severity = 'LOW'
        MigrationImpact = 'M365 now supports roaming signatures natively'
        Recommendation = 'Consider enabling roaming for M365'
    }
    
    # ── Exchange General ──
    'Software\Policies\Microsoft\Exchange\MapiHttpDisabled' = @{
        PolicyName = 'Disable MAPI/HTTP'
        ADMXFile = 'N/A (direct registry)'
        Severity = 'CRITICAL'
        MigrationImpact = 'MAPI/HTTP is THE protocol for M365. Disabling = RPC/HTTP fallback = degraded.'
        Recommendation = 'MUST be 0 or absent for M365.'
    }
    
    # ── Preferences ──
    'Software\Policies\Microsoft\Office\16.0\Outlook\Preferences\DelegateSentItemsStyle' = @{
        PolicyName = 'Save sent items in delegators Sent Items'
        ADMXFile = 'outlk16.admx'
        Severity = 'LOW'
        MigrationImpact = 'Behavioral. No migration impact.'
        Recommendation = 'Document for user communication'
    }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Preferences\HideNewOutlookToggle' = @{
        PolicyName = 'Hide New Outlook toggle'
        ADMXFile = 'outlk16.admx'
        Severity = 'LOW'
        MigrationImpact = 'Controls visibility of New Outlook toggle'
        Recommendation = 'Review based on New Outlook rollout plan'
    }
}

# Known migration blocker patterns (registry value names)
$BlockerPatterns = @(
    @{ Pattern = 'ProxyServer'; Reason = 'Hardcoded RPC proxy — will break post-migration'; Severity = 'CRITICAL' }
    @{ Pattern = 'NoOST'; Reason = 'OST disabled — M365 requires cached mode'; Severity = 'CRITICAL' }
    @{ Pattern = 'MapiHttpDisabled'; Reason = 'MAPI/HTTP disabled — primary M365 protocol'; Severity = 'CRITICAL' }
    @{ Pattern = 'EnableADAL'; Reason = 'Modern Auth control — must be enabled for M365'; Severity = 'CRITICAL' }
    @{ Pattern = 'ZeroConfigExchange'; Reason = 'AutoDiscover disabled — profile creation blocked'; Severity = 'HIGH' }
    @{ Pattern = 'PreferLocalXML'; Reason = 'Local AutoDiscover XML override — stale config risk'; Severity = 'HIGH' }
    @{ Pattern = 'ForceAutoDiscoverForOnPrem'; Reason = 'Forced on-prem AutoDiscover — blocks cloud routing'; Severity = 'HIGH' }
    @{ Pattern = 'ExcludeHttpsAutoDiscoverDomain'; Reason = 'HTTPS AutoDiscover excluded — M365 depends on this'; Severity = 'HIGH' }
    @{ Pattern = 'ExcludeHttpRedirect'; Reason = 'HTTP redirect blocked — hybrid coexistence needs this'; Severity = 'HIGH' }
    @{ Pattern = 'DefaultProfile'; Reason = 'Hardcoded profile name — may cause dual-profile issues'; Severity = 'MEDIUM' }
    @{ Pattern = 'NoModifyProfiles'; Reason = 'Profile modification locked — users cannot fix issues'; Severity = 'MEDIUM' }
    @{ Pattern = 'ForcePSTPath'; Reason = 'Forced PST location — review for cloud migration'; Severity = 'MEDIUM' }
    @{ Pattern = 'DisableRoamingSignatures'; Reason = 'Roaming signatures disabled — M365 feature'; Severity = 'LOW' }
)

#endregion

#region ======== FUNCTIONS ========

function Get-RegistryValues {
    [CmdletBinding()]
    param(
        [string]$Computer,
        [string]$Hive,
        [string]$Path,
        [string]$Scope,
        [string]$Category
    )
    
    $fullPath = "${Hive}:\${Path}"
    $results = [System.Collections.Generic.List[PSObject]]::new()
    
    try {
        if ($Computer -eq $env:COMPUTERNAME) {
            # Local scan
            $regKeys = @()
            if (Test-Path $fullPath) {
                $regKeys += $fullPath
                # Recurse one level for subkeys
                Get-ChildItem -Path $fullPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $regKeys += $_.PSPath
                    # And one more level
                    Get-ChildItem -Path $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $regKeys += $_.PSPath
                    }
                }
            }
            
            foreach ($key in $regKeys) {
                try {
                    $item = Get-Item -Path $key -ErrorAction Stop
                    $relativePath = $key -replace [regex]::Escape("${Hive}:\"), ''
                    
                    foreach ($valueName in $item.GetValueNames()) {
                        if ([string]::IsNullOrEmpty($valueName)) { continue }
                        
                        $value = $item.GetValue($valueName)
                        $valueKind = $item.GetValueKind($valueName)
                        
                        # Check ADMX mapping
                        $admxKey = "$relativePath\$valueName"
                        $admxInfo = $ADMXMappings[$admxKey]
                        
                        # Check blocker patterns
                        $blocker = $BlockerPatterns | Where-Object { $valueName -match $_.Pattern } | Select-Object -First 1
                        
                        $obj = [PSCustomObject]@{
                            Computer      = $Computer
                            Timestamp     = $script:AuditTimestamp
                            Hive          = $Hive
                            Path          = $relativePath
                            ValueName     = $valueName
                            Value         = if ($value -is [byte[]]) { ($value | ForEach-Object { '{0:X2}' -f $_ }) -join ' ' } else { $value }
                            ValueType     = $valueKind.ToString()
                            Scope         = $Scope
                            Category      = $Category
                            IsPolicy      = ($relativePath -like '*Policies*')
                            IsLegacy      = ($relativePath -match '\\(14|15)\.0\\')
                            PolicyName    = if ($admxInfo) { $admxInfo.PolicyName } else { '' }
                            ADMXFile      = if ($admxInfo) { $admxInfo.ADMXFile } else { '' }
                            Severity      = if ($blocker) { $blocker.Severity } elseif ($admxInfo) { $admxInfo.Severity } else { 'INFO' }
                            MigrationNote = if ($admxInfo) { $admxInfo.MigrationImpact } elseif ($blocker) { $blocker.Reason } else { '' }
                            Recommendation= if ($admxInfo) { $admxInfo.Recommendation } else { '' }
                        }
                        
                        $results.Add($obj)
                        
                        if ($blocker -or ($admxInfo -and $admxInfo.Severity -in @('CRITICAL','HIGH'))) {
                            $script:MigrationBlockers.Add($obj)
                        }
                    }
                } catch {
                    Write-Verbose "Cannot read $key : $_"
                }
            }
        }
        else {
            # Remote scan via Invoke-Command
            $scriptBlock = {
                param($H, $P, $S, $C)
                $fp = "${H}:\${P}"
                $out = @()
                if (Test-Path $fp) {
                    $keys = @($fp)
                    Get-ChildItem -Path $fp -Recurse -Depth 2 -EA SilentlyContinue | ForEach-Object { $keys += $_.PSPath }
                    foreach ($k in $keys) {
                        try {
                            $item = Get-Item $k -EA Stop
                            $rp = $k -replace [regex]::Escape("${H}:\"), ''
                            foreach ($vn in $item.GetValueNames()) {
                                if ([string]::IsNullOrEmpty($vn)) { continue }
                                $out += [PSCustomObject]@{
                                    Path = $rp; ValueName = $vn
                                    Value = $item.GetValue($vn)
                                    ValueType = $item.GetValueKind($vn).ToString()
                                }
                            }
                        } catch {}
                    }
                }
                $out
            }
            
            $remoteResults = Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Hive, $Path, $Scope, $Category -ErrorAction SilentlyContinue
            foreach ($r in $remoteResults) {
                $admxKey = "$($r.Path)\$($r.ValueName)"
                $admxInfo = $ADMXMappings[$admxKey]
                $blocker = $BlockerPatterns | Where-Object { $r.ValueName -match $_.Pattern } | Select-Object -First 1
                
                $obj = [PSCustomObject]@{
                    Computer      = $Computer
                    Timestamp     = $script:AuditTimestamp
                    Hive          = $Hive
                    Path          = $r.Path
                    ValueName     = $r.ValueName
                    Value         = $r.Value
                    ValueType     = $r.ValueType
                    Scope         = $Scope
                    Category      = $Category
                    IsPolicy      = ($r.Path -like '*Policies*')
                    IsLegacy      = ($r.Path -match '\\(14|15)\.0\\')
                    PolicyName    = if ($admxInfo) { $admxInfo.PolicyName } else { '' }
                    ADMXFile      = if ($admxInfo) { $admxInfo.ADMXFile } else { '' }
                    Severity      = if ($blocker) { $blocker.Severity } elseif ($admxInfo) { $admxInfo.Severity } else { 'INFO' }
                    MigrationNote = if ($admxInfo) { $admxInfo.MigrationImpact } elseif ($blocker) { $blocker.Reason } else { '' }
                    Recommendation= if ($admxInfo) { $admxInfo.Recommendation } else { '' }
                }
                $results.Add($obj)
                if ($blocker -or ($admxInfo -and $admxInfo.Severity -in @('CRITICAL','HIGH'))) {
                    $script:MigrationBlockers.Add($obj)
                }
            }
        }
    } catch {
        Write-Warning "Error scanning $fullPath on ${Computer}: $_"
    }
    
    return $results
}

function Get-GPOOutlookPolicies {
    [CmdletBinding()]
    param()
    
    $gpoResults = [System.Collections.Generic.List[PSObject]]::new()
    
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        
        $allGPOs = Get-GPO -All -ErrorAction Stop
        
        foreach ($gpo in $allGPOs) {
            try {
                [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType XML -ErrorAction Stop
                
                $ns = @{ q = 'http://www.microsoft.com/GroupPolicy/Settings/Registry' }
                $regSettings = $report.SelectNodes('//q:RegistrySetting', $ns) 2>$null
                
                foreach ($setting in $regSettings) {
                    $keyPath = $setting.KeyPath
                    if ($keyPath -match 'Outlook|Exchange') {
                        $gpoResults.Add([PSCustomObject]@{
                            GPOName      = $gpo.DisplayName
                            GPOId        = $gpo.Id.ToString()
                            GPOStatus    = $gpo.GpoStatus
                            WMIFilter    = $gpo.WmiFilter.Name
                            KeyPath      = $keyPath
                            ValueName    = $setting.Value.Name
                            Value        = $setting.Value.InnerText
                            LinkedTo     = ($report.GPO.LinksTo.SOMPath | Select-Object -First 3) -join '; '
                        })
                    }
                }
            } catch {
                Write-Verbose "Cannot process GPO $($gpo.DisplayName): $_"
            }
        }
    } catch {
        Write-Warning "Group Policy module not available. Skipping GPO analysis. Install RSAT to enable."
    }
    
    return $gpoResults
}

function Export-HTMLReport {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[PSObject]]$AllResults,
        [System.Collections.Generic.List[PSObject]]$Blockers,
        [PSObject[]]$GPOResults,
        [string]$OutputPath,
        [bool]$WithWPAD
    )
    
    $severityOrder = @{ 'CRITICAL' = 0; 'HIGH' = 1; 'MEDIUM' = 2; 'LOW' = 3; 'INFO' = 4 }
    $sortedBlockers = $Blockers | Sort-Object { $severityOrder[$_.Severity] }
    
    $blockerRows = foreach ($b in $sortedBlockers) {
        $sevClass = switch ($b.Severity) {
            'CRITICAL' { 'sev-critical' }
            'HIGH'     { 'sev-high' }
            'MEDIUM'   { 'sev-medium' }
            default    { 'sev-low' }
        }
        @"
        <tr class="$sevClass">
            <td>$($b.Severity)</td>
            <td>$($b.Computer)</td>
            <td>$($b.Hive)</td>
            <td><code>$($b.Path)\$($b.ValueName)</code></td>
            <td>$($b.Value)</td>
            <td>$(if($b.PolicyName){$b.PolicyName}else{'(Direct Registry)'})</td>
            <td>$($b.MigrationNote)</td>
            <td>$($b.Recommendation)</td>
        </tr>
"@
    }
    
    $allRows = foreach ($r in ($AllResults | Sort-Object Hive, Path, ValueName)) {
        $sevClass = switch ($r.Severity) {
            'CRITICAL' { 'sev-critical' }
            'HIGH'     { 'sev-high' }
            'MEDIUM'   { 'sev-medium' }
            'LOW'      { 'sev-low' }
            default    { '' }
        }
        $policyBadge = if ($r.IsPolicy) { '<span class="badge policy">GPO</span>' } else { '' }
        $legacyBadge = if ($r.IsLegacy) { '<span class="badge legacy">LEGACY</span>' } else { '' }
        @"
        <tr class="$sevClass">
            <td>$($r.Severity)</td>
            <td>$($r.Computer)</td>
            <td>$($r.Hive)</td>
            <td><code>$($r.Path)</code></td>
            <td>$($r.ValueName)</td>
            <td>$($r.Value)</td>
            <td>$($r.ValueType)</td>
            <td>$($r.Scope) $policyBadge $legacyBadge</td>
            <td>$(if($r.PolicyName){$r.PolicyName}else{'-'})</td>
            <td>$($r.MigrationNote)</td>
        </tr>
"@
    }
    
    $gpoSection = ''
    if ($GPOResults -and $GPOResults.Count -gt 0) {
        $gpoRows = foreach ($g in $GPOResults) {
            @"
            <tr>
                <td>$($g.GPOName)</td>
                <td>$($g.GPOStatus)</td>
                <td><code>$($g.KeyPath)</code></td>
                <td>$($g.ValueName)</td>
                <td>$($g.Value)</td>
                <td>$($g.LinkedTo)</td>
            </tr>
"@
        }
        $gpoSection = @"
    <h2>GPO Objects with Outlook/Exchange Settings</h2>
    <table>
        <tr><th>GPO Name</th><th>Status</th><th>Key Path</th><th>Value</th><th>Data</th><th>Linked To</th></tr>
        $($gpoRows -join "`n")
    </table>
"@
    }
    
    $wpadSection = ''
    if ($WithWPAD) {
        $wpadSection = @"
    <h2>WPAD / Proxy Enforcement Documentation</h2>
    <div class="wpad-doc">
        <h3>WPAD Impact on Outlook/Exchange Connectivity</h3>
        <p>WPAD (Web Proxy Auto-Discovery) settings directly affect Outlook's ability to connect to Exchange Online. 
        Misconfigured proxy settings are among the <strong>top 3 causes</strong> of Outlook connectivity failures during M365 migrations.</p>
        
        <h3>Critical Registry Keys</h3>
        <table>
            <tr><th>Key</th><th>Value</th><th>Impact</th><th>Recommendation</th></tr>
            <tr>
                <td><code>HKCU\...\Internet Settings\ProxyEnable</code></td>
                <td>0/1</td>
                <td>Enables manual proxy. If 1 and proxy doesn't route to M365 = blocked.</td>
                <td>Ensure proxy allows *.outlook.com, *.office365.com, *.microsoftonline.com</td>
            </tr>
            <tr>
                <td><code>HKCU\...\Internet Settings\AutoConfigURL</code></td>
                <td>PAC URL</td>
                <td>PAC file controls routing. Must route M365 traffic correctly.</td>
                <td>Verify PAC file includes M365 endpoint bypass rules per MS URL/IP service</td>
            </tr>
            <tr>
                <td><code>HKCU\...\Internet Settings\ProxyServer</code></td>
                <td>server:port</td>
                <td>Static proxy. Must support M365 protocols and Modern Auth.</td>
                <td>Configure proxy exceptions for M365 "Optimize" category endpoints</td>
            </tr>
            <tr>
                <td><code>HKLM\...\WinHttp\WinHttpAutoProxyOptions</code></td>
                <td>Various</td>
                <td>WinHTTP proxy affects system-level M365 connectivity (AutoDiscover, EWS).</td>
                <td>Run <code>netsh winhttp show proxy</code> to verify</td>
            </tr>
            <tr>
                <td><code>HKLM\...\Internet Settings\ProxySettingsPerUser</code></td>
                <td>0/1</td>
                <td>If 0: machine-wide proxy overrides user settings.</td>
                <td>Set to 1 unless centralized proxy management required</td>
            </tr>
            <tr class="sev-high">
                <td><code>HKLM\Software\Policies\...\Internet Settings\ProxySettingsPerUser</code></td>
                <td>0</td>
                <td><strong>GPO-enforced machine proxy</strong> — users cannot override. Common Altlast.</td>
                <td>Review GPO. May need exception for M365 endpoints.</td>
            </tr>
        </table>

        <h3>M365 Endpoints That Must Bypass Proxy</h3>
        <p>Per Microsoft's connectivity principles, the following "Optimize" category endpoints should bypass proxy inspection:</p>
        <table>
            <tr><th>Service</th><th>URLs</th><th>Protocol</th></tr>
            <tr><td>Exchange Online</td><td>outlook.office.com, outlook.office365.com</td><td>TCP 443</td></tr>
            <tr><td>AutoDiscover</td><td>autodiscover.outlook.com (redirected from on-prem)</td><td>TCP 443</td></tr>
            <tr><td>Auth</td><td>login.microsoftonline.com, login.windows.net</td><td>TCP 443</td></tr>
            <tr><td>MAPI/HTTP</td><td>outlook.office.com/mapi/*</td><td>TCP 443</td></tr>
            <tr><td>EWS</td><td>outlook.office.com/ews/*</td><td>TCP 443</td></tr>
        </table>

        <h3>Diagnostic Commands</h3>
        <pre>
# Show current WinHTTP proxy
netsh winhttp show proxy

# Show IE/WinINET proxy settings  
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL

# Test AutoDiscover connectivity through proxy
Test-NetConnection outlook.office365.com -Port 443
Resolve-DnsName autodiscover.outlook.com

# Check WPAD DNS (should resolve if WPAD in use)
Resolve-DnsName wpad.$env:USERDNSDOMAIN

# M365 connectivity test
Test-OutlookWebServices -Identity user@domain.com  # requires Exchange tools
        </pre>
    </div>
"@
    }
    
    # Summary stats
    $totalFindings = $AllResults.Count
    $criticalCount = ($AllResults | Where-Object Severity -eq 'CRITICAL').Count
    $highCount = ($AllResults | Where-Object Severity -eq 'HIGH').Count
    $mediumCount = ($AllResults | Where-Object Severity -eq 'MEDIUM').Count
    $policyCount = ($AllResults | Where-Object IsPolicy).Count
    $legacyCount = ($AllResults | Where-Object IsLegacy).Count
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Outlook GPO Audit Report — Pre-Migration Assessment</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f5f5f5; color: #333; padding: 20px; font-size: 13px; }
        h1 { color: #1a1a2e; margin-bottom: 5px; font-size: 22px; }
        h2 { color: #16213e; margin: 30px 0 15px; border-bottom: 2px solid #0f3460; padding-bottom: 5px; font-size: 16px; }
        h3 { color: #0f3460; margin: 15px 0 8px; font-size: 14px; }
        .subtitle { color: #666; margin-bottom: 20px; font-size: 12px; }
        .summary { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }
        .stat-card { background: white; border-radius: 8px; padding: 15px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); min-width: 120px; text-align: center; }
        .stat-card .number { font-size: 28px; font-weight: bold; }
        .stat-card .label { font-size: 11px; color: #666; text-transform: uppercase; }
        .stat-card.critical .number { color: #dc3545; }
        .stat-card.high .number { color: #fd7e14; }
        .stat-card.medium .number { color: #ffc107; }
        .stat-card.legacy .number { color: #6f42c1; }
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; font-size: 12px; }
        th { background: #1a1a2e; color: white; padding: 8px 10px; text-align: left; font-weight: 600; white-space: nowrap; }
        td { padding: 6px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
        tr:hover { background: #f8f9fa; }
        code { background: #e9ecef; padding: 1px 5px; border-radius: 3px; font-size: 11px; word-break: break-all; }
        .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; margin-left: 4px; }
        .badge.policy { background: #0d6efd; color: white; }
        .badge.legacy { background: #6f42c1; color: white; }
        .sev-critical { background: #fff5f5 !important; border-left: 4px solid #dc3545; }
        .sev-high { background: #fff8f0 !important; border-left: 4px solid #fd7e14; }
        .sev-medium { background: #fffde7 !important; border-left: 4px solid #ffc107; }
        .sev-low { border-left: 4px solid #28a745; }
        .wpad-doc { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .wpad-doc pre { background: #1a1a2e; color: #00ff88; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 12px; margin: 10px 0; }
        .wpad-doc p { margin: 8px 0; line-height: 1.5; }
        @media print { body { padding: 0; font-size: 10px; } .stat-card { page-break-inside: avoid; } }
    </style>
</head>
<body>
    <h1>Outlook GPO &amp; Registry Audit Report</h1>
    <p class="subtitle">Pre-Migration Assessment — Generated $($script:AuditTimestamp) — Computers: $($ComputerName -join ', ')</p>
    
    <div class="summary">
        <div class="stat-card"><div class="number">$totalFindings</div><div class="label">Total Findings</div></div>
        <div class="stat-card critical"><div class="number">$criticalCount</div><div class="label">Critical</div></div>
        <div class="stat-card high"><div class="number">$highCount</div><div class="label">High</div></div>
        <div class="stat-card medium"><div class="number">$mediumCount</div><div class="label">Medium</div></div>
        <div class="stat-card"><div class="number">$policyCount</div><div class="label">GPO-Enforced</div></div>
        <div class="stat-card legacy"><div class="number">$legacyCount</div><div class="label">Legacy (2010/2013)</div></div>
    </div>

    <h2>⚠ Migration Blockers &amp; Risk Items</h2>
    $(if ($sortedBlockers.Count -gt 0) {
    @"
    <table>
        <tr><th>Severity</th><th>Computer</th><th>Hive</th><th>Registry Path</th><th>Value</th><th>ADMX Policy</th><th>Migration Impact</th><th>Recommendation</th></tr>
        $($blockerRows -join "`n")
    </table>
"@
    } else {
        '<p style="color:#28a745;font-weight:bold;">✓ No critical migration blockers detected.</p>'
    })
    
    <h2>Complete Registry Inventory</h2>
    <table>
        <tr><th>Sev</th><th>Computer</th><th>Hive</th><th>Path</th><th>Value Name</th><th>Data</th><th>Type</th><th>Scope</th><th>ADMX Policy</th><th>Note</th></tr>
        $($allRows -join "`n")
    </table>
    
    $gpoSection
    
    $wpadSection
    
    <h2>ADMX Template Reference</h2>
    <p>The following ADMX templates contain Outlook/Exchange policies. Ensure these are loaded in your Central Store:</p>
    <table>
        <tr><th>Template</th><th>File</th><th>Scope</th><th>Key Policies</th></tr>
        <tr><td>Microsoft Outlook 2016/365</td><td>outlk16.admx / outlk16.adml</td><td>User &amp; Computer</td><td>AutoDiscover, Cached Mode, RPC, Security, OST, Profiles</td></tr>
        <tr><td>Microsoft Office 2016/365</td><td>office16.admx</td><td>User &amp; Computer</td><td>Update channels, Telemetry, Privacy, Trust Center</td></tr>
        <tr><td>Microsoft Office Common</td><td>officecommon16.admx</td><td>User</td><td>Signing, Encryption, Smart Card auth</td></tr>
        <tr><td>Microsoft Exchange (direct reg)</td><td>N/A</td><td>Machine</td><td>MapiHttpDisabled, RPC encryption</td></tr>
    </table>
    <p style="margin-top:10px;color:#666;font-size:11px;">
        Download latest ADMX: 
        <code>https://www.microsoft.com/en-us/download/details.aspx?id=49030</code> (Office 2016/365) &mdash;
        For M365 Apps: Use the ADMX from your Office deployment or Microsoft 365 Apps admin templates.
    </p>
    
    <h2>Pre-Migration Checklist</h2>
    <table>
        <tr><th>#</th><th>Action</th><th>Priority</th><th>Status</th></tr>
        <tr class="sev-critical"><td>1</td><td>Enable Modern Auth (EnableADAL = 1) via GPO</td><td>CRITICAL</td><td>☐</td></tr>
        <tr class="sev-critical"><td>2</td><td>Remove hardcoded RPC ProxyServer values</td><td>CRITICAL</td><td>☐</td></tr>
        <tr class="sev-critical"><td>3</td><td>Ensure MAPI/HTTP is NOT disabled (MapiHttpDisabled = 0 or absent)</td><td>CRITICAL</td><td>☐</td></tr>
        <tr class="sev-critical"><td>4</td><td>Enable OST/Cached Mode (NoOST must be 0 or absent)</td><td>CRITICAL</td><td>☐</td></tr>
        <tr class="sev-high"><td>5</td><td>Remove PreferLocalXML AutoDiscover overrides</td><td>HIGH</td><td>☐</td></tr>
        <tr class="sev-high"><td>6</td><td>Review AutoDiscover exclusion policies (ExcludeHttps*, ExcludeHttp*)</td><td>HIGH</td><td>☐</td></tr>
        <tr class="sev-high"><td>7</td><td>Ensure ZeroConfigExchange is enabled (0 or absent)</td><td>HIGH</td><td>☐</td></tr>
        <tr class="sev-medium"><td>8</td><td>Set Cached Mode Sync Window to 12 months</td><td>MEDIUM</td><td>☐</td></tr>
        <tr class="sev-medium"><td>9</td><td>Review and remove legacy Office 2010/2013 GPO remnants</td><td>MEDIUM</td><td>☐</td></tr>
        <tr class="sev-medium"><td>10</td><td>Verify proxy/WPAD allows M365 "Optimize" endpoints</td><td>MEDIUM</td><td>☐</td></tr>
        <tr><td>11</td><td>Document attachment blocking (Level1Add/Remove) for Defender ATP comparison</td><td>LOW</td><td>☐</td></tr>
        <tr><td>12</td><td>Plan roaming signatures enablement</td><td>LOW</td><td>☐</td></tr>
    </table>
    
    <p style="margin-top:30px;color:#999;font-size:10px;">
        Generated by Get-OutlookGPOAudit.ps1 v1.0 — DATAGROUP SE — Pre-Migration Assessment Tool
    </p>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "HTML report: $OutputPath" -ForegroundColor Green
}

#endregion

#region ======== MAIN EXECUTION ========

Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Outlook GPO & Registry Audit — Pre-Migration Scanner   ║" -ForegroundColor Cyan
Write-Host "║  DATAGROUP SE                                           ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Create output directory
if (-not (Test-Path $ExportPath)) {
    New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
}

# Scan all computers
foreach ($computer in $ComputerName) {
    Write-Host "Scanning $computer ..." -ForegroundColor Yellow
    
    foreach ($regDef in $RegistryPaths) {
        Write-Verbose "  $($regDef.Hive):\$($regDef.Path)"
        $findings = Get-RegistryValues -Computer $computer -Hive $regDef.Hive -Path $regDef.Path -Scope $regDef.Scope -Category $regDef.Category
        foreach ($f in $findings) {
            $script:Results.Add($f)
        }
    }
}

# GPO Analysis (optional)
$gpoData = @()
if ($GPOAnalysis) {
    Write-Host "Analyzing Group Policy Objects ..." -ForegroundColor Yellow
    $gpoData = Get-GPOOutlookPolicies
    Write-Host "  Found $($gpoData.Count) Outlook/Exchange GPO settings" -ForegroundColor Gray
}

# Export results
Write-Host "`nExporting reports ..." -ForegroundColor Yellow

# CSV - full inventory
$csvPath = Join-Path $ExportPath 'OutlookGPO_FullInventory.csv'
$script:Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "  CSV: $csvPath" -ForegroundColor Gray

# CSV - blockers only
$blockerCsvPath = Join-Path $ExportPath 'OutlookGPO_MigrationBlockers.csv'
$script:MigrationBlockers | Export-Csv -Path $blockerCsvPath -NoTypeInformation -Encoding UTF8
Write-Host "  CSV: $blockerCsvPath" -ForegroundColor Gray

# HTML report
$htmlPath = Join-Path $ExportPath 'OutlookGPO_AuditReport.html'
Export-HTMLReport -AllResults $script:Results -Blockers $script:MigrationBlockers -GPOResults $gpoData -OutputPath $htmlPath -WithWPAD:$IncludeWPAD

# GPO data if available
if ($gpoData.Count -gt 0) {
    $gpoCsvPath = Join-Path $ExportPath 'OutlookGPO_PolicyObjects.csv'
    $gpoData | Export-Csv -Path $gpoCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV: $gpoCsvPath" -ForegroundColor Gray
}

# Summary
Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  AUDIT COMPLETE                                         ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Total findings:     $($script:Results.Count.ToString().PadLeft(5))                              ║" -ForegroundColor White
Write-Host "║  CRITICAL blockers:  $((($script:Results | Where-Object Severity -eq 'CRITICAL').Count).ToString().PadLeft(5))                              ║" -ForegroundColor Red
Write-Host "║  HIGH risk:          $((($script:Results | Where-Object Severity -eq 'HIGH').Count).ToString().PadLeft(5))                              ║" -ForegroundColor Yellow
Write-Host "║  Legacy remnants:    $((($script:Results | Where-Object IsLegacy).Count).ToString().PadLeft(5))                              ║" -ForegroundColor Magenta
Write-Host "║  GPO-enforced:       $((($script:Results | Where-Object IsPolicy).Count).ToString().PadLeft(5))                              ║" -ForegroundColor Blue
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

#endregion