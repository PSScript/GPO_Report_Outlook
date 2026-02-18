#Requires -Version 5.1
<#
.SYNOPSIS
    Citrix vs. Fat-Client Outlook GPO Comparison v1.1
.DESCRIPTION
    Two modes:
    Mode 1 - LIVE SCAN: Scans Citrix VDA and client via WinRM
    Mode 2 - CSV COMPARE: Compares CSVs from Get-OutlookGPOAudit.ps1
.PARAMETER CitrixVDAServers
    VDA server names to scan.
.PARAMETER CompareWithClient
    Client machine name(s).
.PARAMETER CitrixCSV
    CSV from Get-OutlookGPOAudit.ps1 run on VDA (offline mode).
.PARAMETER ClientCSV
    CSV from Get-OutlookGPOAudit.ps1 run on client (offline mode).
.PARAMETER ExportPath
    Output folder.
.PARAMETER IncludeWPAD
    Include WPAD/Proxy keys.
.PARAMETER AutoDetect
    Auto-detect Citrix from current session.
.EXAMPLE
    .\Get-CitrixOutlookGPO.ps1 -CitrixVDAServers CTX01 -CompareWithClient WS001
.EXAMPLE
    .\Get-CitrixOutlookGPO.ps1 -CitrixCSV C:\ctx\FullInventory.csv -ClientCSV C:\cli\FullInventory.csv
.NOTES
    Author:  Jan Hübener
    Version: 1.1.0
#>

[CmdletBinding(DefaultParameterSetName = 'LiveScan')]
param(
    [Parameter(ParameterSetName = 'LiveScan')][string[]]$CitrixVDAServers,
    [Parameter(ParameterSetName = 'LiveScan')][string[]]$CompareWithClient = @($env:COMPUTERNAME),
    [Parameter(ParameterSetName = 'CSVCompare', Mandatory)][ValidateScript({ Test-Path $_ })][string]$CitrixCSV,
    [Parameter(ParameterSetName = 'CSVCompare', Mandatory)][ValidateScript({ Test-Path $_ })][string]$ClientCSV,
    [string]$ExportPath = ".\CitrixOutlookGPO_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$IncludeWPAD,
    [switch]$AutoDetect
)

$ErrorActionPreference = 'Continue'
$script:AuditTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

#region ======== ADMX MAPPINGS ========
$ADMXMappings = @{
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ExcludeHttpsAutoDiscoverDomain' = @{ PolicyName='Exclude HTTPS AutoDiscover domain'; Severity='HIGH'; MigrationImpact='Blocks HTTPS AutoDiscover' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ExcludeHttpRedirect' = @{ PolicyName='Exclude HTTP redirect'; Severity='HIGH'; MigrationImpact='Blocks HTTP redirect — hybrid needs this' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ExcludeScpLookup' = @{ PolicyName='Exclude SCP lookup'; Severity='MEDIUM'; MigrationImpact='No AD-based AutoDiscover' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ExcludeSrvRecord' = @{ PolicyName='Exclude SRV record'; Severity='LOW'; MigrationImpact='SRV rarely used' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ExcludeLastKnownGoodURL' = @{ PolicyName='Exclude last known URL'; Severity='MEDIUM'; MigrationImpact='Cached URL may point to old server' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\PreferLocalXML' = @{ PolicyName='Prefer local XML'; Severity='CRITICAL'; MigrationImpact='BLOCKS migration — overrides all' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover\ZeroConfigExchange' = @{ PolicyName='Disable Zero Config'; Severity='HIGH'; MigrationImpact='Disables auto profile config' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode\Enable' = @{ PolicyName='Use Cached Mode'; Severity='MEDIUM'; MigrationImpact='Forced online = poor M365 perf' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode\SyncWindowSetting' = @{ PolicyName='Sync Window'; Severity='MEDIUM'; MigrationImpact='Controls OST sync depth' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode\DownloadSharedFolders' = @{ PolicyName='Download Shared Folders'; Severity='MEDIUM'; MigrationImpact='Increases OST size' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode\DownloadPublicFolderFavorites' = @{ PolicyName='Download PF Favorites'; Severity='LOW'; MigrationImpact='PF may not exist in target' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\RPC\ProxyServer' = @{ PolicyName='RPC Proxy Server'; Severity='CRITICAL'; MigrationImpact='Hardcoded proxy WILL break' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\RPC\ProxyServerFlags' = @{ PolicyName='RPC Proxy Flags'; Severity='HIGH'; MigrationImpact='Auth flags — moot for M365' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\RPC\EnableRPCEncryption' = @{ PolicyName='RPC Encryption'; Severity='LOW'; MigrationImpact='Moot for MAPI/HTTP' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Security\EnableADAL' = @{ PolicyName='Enable Modern Auth'; Severity='CRITICAL'; MigrationImpact='REQUIRED for M365' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Security\AlwaysUseMSOAuthForAutoDiscover' = @{ PolicyName='OAuth for AutoDiscover'; Severity='HIGH'; MigrationImpact='Forces OAuth for M365' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Security\AdminSecurityMode' = @{ PolicyName='Security Mode'; Severity='MEDIUM'; MigrationImpact='Controls GPO security model' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\Security\Level1Remove' = @{ PolicyName='Remove Level 1 block'; Severity='MEDIUM'; MigrationImpact='Attachment exceptions' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\OST\NoOST' = @{ PolicyName='Disallow OST'; Severity='CRITICAL'; MigrationImpact='Online-only = severe degradation' }
    'Software\Policies\Microsoft\Office\16.0\Outlook\OST\MaxOSTSize' = @{ PolicyName='Max OST size'; Severity='MEDIUM'; MigrationImpact='May truncate large mailboxes' }
    'Software\Policies\Microsoft\Exchange\MapiHttpDisabled' = @{ PolicyName='Disable MAPI/HTTP'; Severity='CRITICAL'; MigrationImpact='THE protocol for M365' }
}
$BlockerPatterns = @(
    @{ Pattern='ProxyServer'; Reason='Hardcoded RPC proxy'; Severity='CRITICAL' }
    @{ Pattern='NoOST'; Reason='OST disabled'; Severity='CRITICAL' }
    @{ Pattern='MapiHttpDisabled'; Reason='MAPI/HTTP disabled'; Severity='CRITICAL' }
    @{ Pattern='EnableADAL'; Reason='Modern Auth control'; Severity='CRITICAL' }
    @{ Pattern='ZeroConfigExchange'; Reason='AutoDiscover disabled'; Severity='HIGH' }
    @{ Pattern='PreferLocalXML'; Reason='Local XML override'; Severity='HIGH' }
    @{ Pattern='ExcludeHttpsAutoDiscoverDomain'; Reason='HTTPS AutoDiscover excluded'; Severity='HIGH' }
    @{ Pattern='ExcludeHttpRedirect'; Reason='HTTP redirect blocked'; Severity='HIGH' }
)
#endregion

#region ======== REGISTRY PATHS ========
$OutlookRegistryPaths = @(
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Office\16.0\Outlook'; Scope='GPO-User'; Category='Outlook-Policy' }
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover'; Scope='GPO-User'; Category='AutoDiscover-Policy' }
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Office\16.0\Outlook\RPC'; Scope='GPO-User'; Category='RPC-Policy' }
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode'; Scope='GPO-User'; Category='CachedMode-Policy' }
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Office\16.0\Outlook\OST'; Scope='GPO-User'; Category='OST-Policy' }
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Office\16.0\Outlook\Preferences'; Scope='GPO-User'; Category='Preferences-Policy' }
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Office\16.0\Outlook\Security'; Scope='GPO-User'; Category='Security-Policy' }
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Office\16.0\Outlook\Setup'; Scope='GPO-User'; Category='Setup-Policy' }
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Exchange'; Scope='GPO-User'; Category='Exchange-Policy' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Office\16.0\Outlook'; Scope='User-Direct'; Category='Outlook' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Office\16.0\Outlook\AutoDiscover'; Scope='User-Direct'; Category='AutoDiscover' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Office\16.0\Outlook\RPC'; Scope='User-Direct'; Category='RPC' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Office\16.0\Outlook\Cached Mode'; Scope='User-Direct'; Category='CachedMode' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Office\16.0\Outlook\OST'; Scope='User-Direct'; Category='OST' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Office\16.0\Outlook\Preferences'; Scope='User-Direct'; Category='Preferences' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Office\16.0\Outlook\Security'; Scope='User-Direct'; Category='Security' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Office\16.0\Outlook\Setup'; Scope='User-Direct'; Category='Setup' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Exchange'; Scope='User-Direct'; Category='Exchange' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Exchange\Client\Options'; Scope='User-Direct'; Category='Exchange-Client' }
    @{ Hive='HKLM'; Path='Software\Policies\Microsoft\Office\16.0\Outlook'; Scope='GPO-Machine'; Category='Outlook-MachinePolicy' }
    @{ Hive='HKLM'; Path='Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover'; Scope='GPO-Machine'; Category='AutoDiscover-MachinePolicy' }
    @{ Hive='HKLM'; Path='Software\Policies\Microsoft\Office\16.0\Outlook\RPC'; Scope='GPO-Machine'; Category='RPC-MachinePolicy' }
    @{ Hive='HKLM'; Path='Software\Policies\Microsoft\Office\16.0\Outlook\Security'; Scope='GPO-Machine'; Category='Security-MachinePolicy' }
    @{ Hive='HKLM'; Path='Software\Policies\Microsoft\Exchange'; Scope='GPO-Machine'; Category='Exchange-MachinePolicy' }
    @{ Hive='HKLM'; Path='Software\Microsoft\Office\16.0\Outlook'; Scope='Machine-Direct'; Category='Outlook-Machine' }
    @{ Hive='HKLM'; Path='Software\Microsoft\Office\16.0\Outlook\AutoDiscover'; Scope='Machine-Direct'; Category='AutoDiscover-Machine' }
    @{ Hive='HKLM'; Path='Software\Microsoft\Office\16.0\Outlook\Setup'; Scope='Machine-Direct'; Category='Setup-Machine' }
    @{ Hive='HKLM'; Path='Software\Microsoft\Exchange'; Scope='Machine-Direct'; Category='Exchange-Machine' }
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Office\15.0\Outlook'; Scope='Legacy-2013-GPO'; Category='Legacy15-Policy' }
    @{ Hive='HKCU'; Path='Software\Policies\Microsoft\Office\14.0\Outlook'; Scope='Legacy-2010-GPO'; Category='Legacy14-Policy' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Office\15.0\Outlook'; Scope='Legacy-2013'; Category='Legacy15' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Office\14.0\Outlook'; Scope='Legacy-2010'; Category='Legacy14' }
)
$WPADRegistryPaths = @(
    @{ Hive='HKCU'; Path='Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Scope='User-Proxy'; Category='WPAD-InternetSettings' }
    @{ Hive='HKCU'; Path='Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'; Scope='User-Proxy'; Category='WPAD-Connections' }
    @{ Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Scope='Machine-Proxy'; Category='WPAD-Machine' }
    @{ Hive='HKLM'; Path='Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'; Scope='GPO-Proxy'; Category='WPAD-Policy' }
    @{ Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'; Scope='Machine-WinHTTP'; Category='WPAD-WinHTTP' }
)
$CitrixRegistryPaths = @(
    @{ Hive='HKLM'; Path='Software\Policies\Citrix\UserProfileManager'; Scope='Citrix-UPM'; Category='UPM-Config' }
    @{ Hive='HKLM'; Path='Software\Policies\Citrix\UserProfileManager\SyncDirList'; Scope='Citrix-UPM'; Category='UPM-SyncDirs' }
    @{ Hive='HKLM'; Path='Software\Policies\Citrix\UserProfileManager\SyncExclusionListDir'; Scope='Citrix-UPM'; Category='UPM-ExcludeDirs' }
    @{ Hive='HKLM'; Path='Software\Policies\Citrix\UserProfileManager\SyncExclusionListRegistry'; Scope='Citrix-UPM'; Category='UPM-ExcludeReg' }
    @{ Hive='HKLM'; Path='Software\Policies\Citrix\UserProfileManager\MirrorFoldersList'; Scope='Citrix-UPM'; Category='UPM-Mirror' }
    @{ Hive='HKLM'; Path='Software\Policies\Citrix\UserProfileManager\LargeFileHandlingList'; Scope='Citrix-UPM'; Category='UPM-LargeFiles' }
    @{ Hive='HKLM'; Path='Software\FSLogix\Profiles'; Scope='FSLogix'; Category='FSLogix-Profiles' }
    @{ Hive='HKLM'; Path='Software\Policies\FSLogix\ODFC'; Scope='FSLogix'; Category='FSLogix-ODFC' }
    @{ Hive='HKLM'; Path='Software\Citrix\VirtualDesktopAgent'; Scope='Citrix-VDA'; Category='VDA-Config' }
    @{ Hive='HKLM'; Path='Software\Citrix\VirtualDesktopAgent\Authentication'; Scope='Citrix-VDA'; Category='VDA-Auth' }
    @{ Hive='HKLM'; Path='Software\Citrix\CtxHook\AppInit_DLLs\Outlook'; Scope='Citrix-Hook'; Category='CtxHook-Outlook' }
    @{ Hive='HKLM'; Path='Software\Citrix\ICA Client'; Scope='Citrix-ICA'; Category='ICA-Machine' }
    @{ Hive='HKCU'; Path='Software\Citrix\ICA Client'; Scope='Citrix-ICA'; Category='ICA-User' }
    @{ Hive='HKLM'; Path='Software\Policies\Citrix\PortICA'; Scope='Citrix-Policy'; Category='PortICA' }
)
if ($IncludeWPAD) { $OutlookRegistryPaths += $WPADRegistryPaths }
#endregion

#region ======== CITRIX CONFLICT DEFINITIONS ========
$CitrixConflicts = @(
    @{ Pattern='OST|ost|NoOST'; Component='OST File Location'; Risk='HIGH'; Description='OST in non-persistent VDI lost on logoff. UPM/FSLogix must handle persistence.'; Check='Verify OST on persistent disk or FSLogix ODFC container.' }
    @{ Pattern='SyncExclusionListRegistry'; Component='UPM Registry Exclusion'; Risk='HIGH'; Description='UPM may exclude Outlook reg keys from roaming. Settings lost between sessions.'; Check='Review UPM registry exclusion list for Outlook paths.' }
    @{ Pattern='SyncExclusionListDir'; Component='UPM Folder Exclusion'; Risk='HIGH'; Description='UPM folder exclusions may drop Outlook local data (NK2, sigs, rules).'; Check='Ensure AppData\Local\Microsoft\Outlook handled by FSLogix ODFC or UPM mirror.' }
    @{ Pattern='EnableADAL'; Component='Modern Auth in Citrix'; Risk='CRITICAL'; Description='Modern Auth popups may fail without Citrix FAS or SSO passthrough.'; Check='Verify Citrix FAS or SSO passthrough configured.' }
    @{ Pattern='ProxyEnable|AutoConfigURL|ProxyServer'; Component='Proxy Divergence'; Risk='HIGH'; Description='VDA uses SERVER proxy, not client. Published-app routes through datacenter proxy.'; Check='Ensure Citrix server proxy allows M365 Optimize endpoints.' }
    @{ Pattern='Cached Mode|CachedMode|SyncWindowSetting'; Component='Cached Mode in Citrix'; Risk='MEDIUM'; Description='Cached Mode in non-persistent VDI needs persistent OST storage.'; Check='Use FSLogix ODFC or redirect OST to persistent disk.' }
    @{ Pattern='MapiHttpDisabled'; Component='MAPI/HTTP in Citrix'; Risk='CRITICAL'; Description='MAPI/HTTP disabled on VDA = ALL published Outlook users affected.'; Check='Ensure MapiHttpDisabled=0 or absent on all VDAs.' }
)
#endregion

#region ======== CORE: Registry Scanner ========
function Get-RegistryValuesFromTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][hashtable[]]$Paths,
        [string]$Environment = 'Unknown'
    )
    $results = [System.Collections.Generic.List[PSObject]]::new()
    $isLocal = ($Computer -eq $env:COMPUTERNAME)
    foreach ($regDef in $Paths) {
        $hive = $regDef.Hive; $path = $regDef.Path; $scope = $regDef.Scope; $category = $regDef.Category
        $fullPath = "${hive}:\${path}"
        try {
            if ($isLocal) {
                $regKeys = [System.Collections.Generic.List[string]]::new()
                if (Test-Path $fullPath) {
                    $regKeys.Add($fullPath)
                    Get-ChildItem -Path $fullPath -Recurse -Depth 2 -EA SilentlyContinue | ForEach-Object { $regKeys.Add($_.PSPath) }
                }
                foreach ($key in $regKeys) {
                    try {
                        $item = Get-Item -Path $key -EA Stop
                        $relativePath = ($key -replace '^Microsoft\.PowerShell\.Core\\Registry::', '') -replace "^${hive}:\\", ''
                        foreach ($valueName in $item.GetValueNames()) {
                            if ([string]::IsNullOrEmpty($valueName)) { continue }
                            $value = $item.GetValue($valueName)
                            $valueKind = $item.GetValueKind($valueName)
                            $admxKey = "$relativePath\$valueName"
                            $admxInfo = $ADMXMappings[$admxKey]
                            $blocker = $BlockerPatterns | Where-Object { $valueName -match $_.Pattern } | Select-Object -First 1
                            $results.Add([PSCustomObject]@{
                                Computer=$Computer; Environment=$Environment; Hive=$hive; Path=$relativePath
                                ValueName=$valueName
                                Value = if ($value -is [byte[]]) { ($value | ForEach-Object { '{0:X2}' -f $_ }) -join ' ' } else { "$value" }
                                ValueType=$valueKind.ToString(); Scope=$scope; Category=$category
                                IsPolicy=($relativePath -like '*Policies*'); IsLegacy=($relativePath -match '\\(14|15)\.0\\')
                                PolicyName = if ($admxInfo) { $admxInfo.PolicyName } else { '' }
                                Severity = if ($blocker) { $blocker.Severity } elseif ($admxInfo) { $admxInfo.Severity } else { 'INFO' }
                                MigrationNote = if ($admxInfo) { $admxInfo.MigrationImpact } elseif ($blocker) { $blocker.Reason } else { '' }
                            })
                        }
                    } catch { Write-Verbose "  Cannot read: $key ($_)" }
                }
            } else {
                $remoteResults = Invoke-Command -ComputerName $Computer -EA Stop -ScriptBlock {
                    param($H, $P)
                    $fp = "${H}:\${P}"; $out = @()
                    if (Test-Path $fp) {
                        $keys = @($fp)
                        Get-ChildItem -Path $fp -Recurse -Depth 2 -EA SilentlyContinue | ForEach-Object { $keys += $_.PSPath }
                        foreach ($k in $keys) {
                            try {
                                $item = Get-Item $k -EA Stop
                                $rp = ($k -replace '^Microsoft\.PowerShell\.Core\\Registry::', '') -replace "^${H}:\\", ''
                                foreach ($vn in $item.GetValueNames()) {
                                    if ([string]::IsNullOrEmpty($vn)) { continue }
                                    $v = $item.GetValue($vn)
                                    $out += [PSCustomObject]@{
                                        Path=$rp; ValueName=$vn
                                        Value = if ($v -is [byte[]]) { ($v | ForEach-Object { '{0:X2}' -f $_ }) -join ' ' } else { "$v" }
                                        ValueType = $item.GetValueKind($vn).ToString()
                                    }
                                }
                            } catch {}
                        }
                    }
                    $out
                } -ArgumentList $hive, $path
                foreach ($r in $remoteResults) {
                    $admxKey = "$($r.Path)\$($r.ValueName)"
                    $admxInfo = $ADMXMappings[$admxKey]
                    $blocker = $BlockerPatterns | Where-Object { $r.ValueName -match $_.Pattern } | Select-Object -First 1
                    $results.Add([PSCustomObject]@{
                        Computer=$Computer; Environment=$Environment; Hive=$hive
                        Path=$r.Path; ValueName=$r.ValueName; Value=$r.Value; ValueType=$r.ValueType
                        Scope=$scope; Category=$category
                        IsPolicy=($r.Path -like '*Policies*'); IsLegacy=($r.Path -match '\\(14|15)\.0\\')
                        PolicyName = if ($admxInfo) { $admxInfo.PolicyName } else { '' }
                        Severity = if ($blocker) { $blocker.Severity } elseif ($admxInfo) { $admxInfo.Severity } else { 'INFO' }
                        MigrationNote = if ($admxInfo) { $admxInfo.MigrationImpact } elseif ($blocker) { $blocker.Reason } else { '' }
                    })
                }
            }
        } catch { Write-Warning "  Failed: $fullPath on ${Computer}: $_" }
    }
    return $results
}
#endregion

#region ======== CORE: Citrix Detection ========
function Test-CitrixEnvironment {
    [CmdletBinding()]
    param([string]$Computer = $env:COMPUTERNAME)
    $scriptBlock = {
        $r = @{}
        $vda = Get-ItemProperty -Path 'HKLM:\Software\Citrix\VirtualDesktopAgent' -EA SilentlyContinue
        $r.IsCitrixVDA = [bool]$vda
        $r.VDAVersion = if ($vda) { $vda.ProductVersion } else { '' }
        $r.DeliveryController = if ($vda) { $vda.ListOfDDCs } else { '' }
        $ctxSvc = Get-Service -Name 'BrokerAgent','CtxProfile','picaSvc2' -EA SilentlyContinue | Where-Object Status -eq 'Running'
        if ($ctxSvc -and -not $r.IsCitrixVDA) { $r.IsCitrixVDA = $true }
        $r.SessionType = if ($env:SESSIONNAME -match '^ICA') { 'ICA (Published)' }
                         elseif ($env:SESSIONNAME -match '^RDP') { 'RDP' }
                         elseif ($env:SESSIONNAME -eq 'Console') { 'Console' } else { $env:SESSIONNAME }
        $upm = Get-ItemProperty -Path 'HKLM:\Software\Policies\Citrix\UserProfileManager' -EA SilentlyContinue
        $r.UPMActive = ($upm -and $upm.ServiceActive -eq 1)
        $fsl = Get-ItemProperty -Path 'HKLM:\Software\FSLogix\Profiles' -EA SilentlyContinue
        $r.FSLogixActive = ($fsl -and $fsl.Enabled -eq 1)
        $odfc = Get-ItemProperty -Path 'HKLM:\Software\Policies\FSLogix\ODFC' -EA SilentlyContinue
        $r.ODFCEnabled = ($odfc -and $odfc.Enabled -eq 1)
        $r.ProfileSolution = if ($r.FSLogixActive -and $r.UPMActive) { 'FSLogix + UPM (CONFLICT!)' }
                             elseif ($r.FSLogixActive) { if ($r.ODFCEnabled) { 'FSLogix (Profile + ODFC)' } else { 'FSLogix (NO ODFC!)' } }
                             elseif ($r.UPMActive) { 'Citrix UPM' } else { 'None / Local' }
        try {
            $lb = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -Name 'UserPolicyMode' -EA Stop
            $r.LoopbackProcessing = switch ($lb.UserPolicyMode) { 1 { 'Replace' }; 2 { 'Merge' }; default { "Value: $($lb.UserPolicyMode)" } }
        } catch { $r.LoopbackProcessing = 'Not configured' }
        $r.ClientName = if ($env:CLIENTNAME) { $env:CLIENTNAME } else { 'N/A' }
        try {
            $wmi = Get-CimInstance -Namespace 'Root\Citrix\DesktopInformation' -ClassName 'Citrix_VirtualDesktopInfo' -EA Stop
            $r.MachineCatalog = $wmi.CatalogName; $r.DesktopGroup = $wmi.DesktopGroupName
        } catch { $r.MachineCatalog = 'N/A'; $r.DesktopGroup = 'N/A' }
        $r
    }
    $info = [ordered]@{
        Computer=$Computer; IsCitrixVDA=$false; VDAVersion=''; SessionType='Unknown'
        ProfileSolution='Unknown'; UPMActive=$false; FSLogixActive=$false; ODFCEnabled=$false
        LoopbackProcessing='Unknown'; DeliveryController=''; MachineCatalog=''; DesktopGroup=''; ClientName=''
    }
    try {
        $data = if ($Computer -eq $env:COMPUTERNAME) { & $scriptBlock } else { Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -EA Stop }
        foreach ($key in $data.Keys) { if ($info.Contains($key)) { $info[$key] = $data[$key] } }
    } catch { Write-Warning "Citrix detection failed on ${Computer}: $_" }
    [PSCustomObject]$info
}
#endregion

#region ======== CORE: Compare ========
function Compare-RegistryResults {
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSObject[]]$CitrixResults, [Parameter(Mandatory)][PSObject[]]$ClientResults)
    $comparison = [System.Collections.Generic.List[PSObject]]::new()
    $ctxLookup = @{}; $clientLookup = @{}
    foreach ($c in $CitrixResults) { $ctxLookup["$($c.Hive)|$($c.Path)|$($c.ValueName)"] = $c }
    foreach ($c in $ClientResults) { $clientLookup["$($c.Hive)|$($c.Path)|$($c.ValueName)"] = $c }
    $allKeys = @($ctxLookup.Keys) + @($clientLookup.Keys) | Sort-Object -Unique
    foreach ($key in $allKeys) {
        $ctx = $ctxLookup[$key]; $cli = $clientLookup[$key]
        $status = if ($ctx -and $cli) { if ("$($ctx.Value)" -eq "$($cli.Value)") { 'MATCH' } else { 'CONFLICT' } }
                  elseif ($ctx) { 'CITRIX_ONLY' } else { 'CLIENT_ONLY' }
        $ref = if ($ctx) { $ctx } else { $cli }
        $comparison.Add([PSCustomObject]@{
            Status=$status; Hive=$ref.Hive; Path=$ref.Path; ValueName=$ref.ValueName
            CitrixValue = if ($ctx) { $ctx.Value } else { '(not set)' }
            ClientValue = if ($cli) { $cli.Value } else { '(not set)' }
            CitrixScope = if ($ctx) { $ctx.Scope } else { '-' }
            ClientScope = if ($cli) { $cli.Scope } else { '-' }
            IsPolicy=$ref.IsPolicy; Severity=$ref.Severity
            PolicyName=$ref.PolicyName; MigrationNote=$ref.MigrationNote; Category=$ref.Category
        })
    }
    return ($comparison | Sort-Object @{E={ switch ($_.Status) { 'CONFLICT'{0}; 'CITRIX_ONLY'{1}; 'CLIENT_ONLY'{2}; default{3} } }}, Path, ValueName)
}
#endregion

#region ======== CORE: Citrix Conflict Finder ========
function Find-CitrixConflicts {
    [CmdletBinding()]
    param([PSObject[]]$CitrixResults, [PSObject[]]$Comparison, [PSObject]$CitrixInfo)
    $found = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($conflict in $CitrixConflicts) {
        $matched = $false; $evidence = @()
        $matchEntries = @($CitrixResults | Where-Object { $_.ValueName -match $conflict.Pattern -or $_.Category -match $conflict.Pattern -or $_.Path -match $conflict.Pattern })
        if ($matchEntries) { $matched = $true; $evidence += $matchEntries | Select-Object -First 3 | ForEach-Object { "$($_.Path)\$($_.ValueName) = $($_.Value)" } }
        $conflictEntries = @($Comparison | Where-Object { $_.Status -eq 'CONFLICT' -and ($_.ValueName -match $conflict.Pattern -or $_.Path -match $conflict.Pattern) })
        if ($conflictEntries) { $matched = $true; $evidence += $conflictEntries | ForEach-Object { "CONFLICT: CTX=$($_.CitrixValue) vs CLI=$($_.ClientValue) at $($_.ValueName)" } }
        if ($conflict.Component -eq 'OST File Location' -and $CitrixInfo -and (-not $CitrixInfo.FSLogixActive -or -not $CitrixInfo.ODFCEnabled)) {
            $matched = $true; $evidence += "No FSLogix ODFC — OST at risk on non-persistent VDI"
        }
        if ($conflict.Component -eq 'Modern Auth in Citrix') {
            $fasCheck = @($CitrixResults | Where-Object { $_.Category -eq 'VDA-Auth' })
            if (-not $fasCheck) { $evidence += "No Citrix FAS/Auth config found in VDA registry" }
        }
        if ($matched) {
            $found.Add([PSCustomObject]@{ Component=$conflict.Component; Risk=$conflict.Risk; Description=$conflict.Description; Check=$conflict.Check; Evidence=($evidence -join '; ') })
        }
    }
    return $found
}
#endregion

#region ======== HTML EXPORT ========
function Export-ComparisonHTML {
    [CmdletBinding()]
    param(
        [PSObject[]]$Comparison, [PSObject]$CitrixInfo, [PSObject[]]$ConflictsFound,
        [string]$CitrixSource, [string]$ClientSource, [string]$OutputPath
    )
    $conflicts = @($Comparison | Where-Object Status -eq 'CONFLICT')
    $ctxOnly   = @($Comparison | Where-Object Status -eq 'CITRIX_ONLY')
    $cliOnly   = @($Comparison | Where-Object Status -eq 'CLIENT_ONLY')
    $matches   = @($Comparison | Where-Object Status -eq 'MATCH')

    function Build-TableRows { param([PSObject[]]$Items, [string]$Label)
        $sb = [System.Text.StringBuilder]::new()
        foreach ($item in $Items) {
            $sev = switch ($item.Severity) { 'CRITICAL' { 'font-weight:bold;color:#cc0000;' }; 'HIGH' { 'color:#cc6600;' }; default { '' } }
            [void]$sb.AppendLine("<tr><td>$Label</td><td style=`"$sev`">$($item.Severity)</td>")
            [void]$sb.AppendLine("<td><code>$($item.Hive)\$($item.Path)\$($item.ValueName)</code></td>")
            [void]$sb.AppendLine("<td class=`"ctx-val`">$($item.CitrixValue)</td><td class=`"cli-val`">$($item.ClientValue)</td>")
            [void]$sb.AppendLine("<td>$(if($item.PolicyName){$item.PolicyName}else{'-'})</td><td>$($item.MigrationNote)</td></tr>")
        }
        return $sb.ToString()
    }

    $warnHtml = ''
    if ($ConflictsFound.Count -gt 0) {
        $warnHtml = '<div class="warning-box"><h3>Citrix-Specific Risks Detected</h3>'
        foreach ($cf in $ConflictsFound) {
            $rc = switch ($cf.Risk) { 'CRITICAL' { '#cc0000' }; 'HIGH' { '#cc6600' }; default { '#856404' } }
            $warnHtml += "<div class='risk-item'><strong style='color:$rc'>[$($cf.Risk)] $($cf.Component)</strong><br/>$($cf.Description)<br/><em>Check: $($cf.Check)</em>"
            if ($cf.Evidence) { $warnHtml += "<br/><code style='font-size:11px;'>$($cf.Evidence)</code>" }
            $warnHtml += "</div>"
        }
        $warnHtml += '</div>'
    }

    $ctxCard = ''
    if ($CitrixInfo) {
        $pc = if ($CitrixInfo.ProfileSolution -match 'CONFLICT|None') { 'color:#cc0000;' } else { 'color:#27ae60;' }
        $lc = if ($CitrixInfo.LoopbackProcessing -eq 'Replace') { 'color:#cc0000;font-weight:bold;' } elseif ($CitrixInfo.LoopbackProcessing -eq 'Merge') { 'color:#cc6600;' } else { '' }
        $ctxCard = @"
        <div class="env-card citrix"><h3>Citrix VDA: $($CitrixInfo.Computer)</h3>
        <div class="d"><strong>VDA:</strong> $($CitrixInfo.VDAVersion)</div>
        <div class="d"><strong>Session:</strong> $($CitrixInfo.SessionType)</div>
        <div class="d" style="$pc"><strong>Profile:</strong> $($CitrixInfo.ProfileSolution)</div>
        <div class="d"><strong>UPM:</strong> $($CitrixInfo.UPMActive) | <strong>FSLogix:</strong> $($CitrixInfo.FSLogixActive) | <strong>ODFC:</strong> $($CitrixInfo.ODFCEnabled)</div>
        <div class="d" style="$lc"><strong>Loopback:</strong> $($CitrixInfo.LoopbackProcessing)</div>
        <div class="d"><strong>DDC:</strong> $($CitrixInfo.DeliveryController)</div>
        <div class="d"><strong>Catalog:</strong> $($CitrixInfo.MachineCatalog) | <strong>Group:</strong> $($CitrixInfo.DesktopGroup)</div></div>
"@
    }

    $thdr = '<tr><th>Status</th><th>Severity</th><th>Registry Path</th><th>Citrix</th><th>Client</th><th>ADMX Policy</th><th>Note</th></tr>'

    $html = @"
<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Citrix vs Client - Outlook GPO</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#f5f5f5;padding:20px;font-size:13px;color:#333}
h1{color:#1a1a2e;font-size:22px;margin-bottom:5px}
h2{color:#0f3460;font-size:16px;margin:25px 0 12px;border-bottom:2px solid #0f3460;padding-bottom:5px}
.sub{color:#666;font-size:12px;margin-bottom:20px}
.cards{display:flex;gap:20px;margin:20px 0;flex-wrap:wrap}
.env-card{flex:1;min-width:280px;background:#fff;border-radius:8px;padding:15px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.env-card h3{font-size:14px;margin-bottom:10px}
.env-card.citrix{border-left:4px solid #e74c3c}
.env-card.client{border-left:4px solid #3498db}
.d{font-size:12px;color:#555;margin:4px 0}
.d strong{color:#333;min-width:100px;display:inline-block}
.stats{display:flex;gap:15px;margin:20px 0;flex-wrap:wrap}
.st{background:#fff;border-radius:8px;padding:12px 20px;box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center;min-width:100px}
.st .n{font-size:28px;font-weight:bold}
.st .l{font-size:10px;color:#666;text-transform:uppercase}
.st.c .n{color:#e74c3c} .st.x .n{color:#e67e22} .st.b .n{color:#3498db} .st.m .n{color:#27ae60}
table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px;font-size:12px}
th{background:#1a1a2e;color:#fff;padding:8px 10px;text-align:left}
td{padding:6px 8px;border-bottom:1px solid #eee;vertical-align:top}
code{background:#e9ecef;padding:1px 5px;border-radius:3px;font-size:11px;word-break:break-all}
.ctx-val{color:#c0392b;font-weight:600}
.cli-val{color:#2980b9;font-weight:600}
.warning-box{background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:15px;margin:15px 0}
.warning-box h3{color:#856404;margin-bottom:10px}
.risk-item{margin:10px 0;padding:8px 0;border-bottom:1px solid rgba(0,0,0,.1);font-size:12px}
.info-box{background:#eaf2f8;border:1px solid #3498db;border-radius:8px;padding:15px;margin:15px 0;font-size:12px}
.info-box h3{color:#2c3e50;margin-bottom:8px}
.info-box p{color:#2c3e50;margin:4px 0;line-height:1.5}
</style></head><body>
<h1>Citrix vs. Fat-Client - Outlook GPO Comparison</h1>
<p class="sub">Generated: $($script:AuditTimestamp) | Citrix: $CitrixSource | Client: $ClientSource</p>
<div class="cards">$ctxCard
<div class="env-card client"><h3>Fat Client: $ClientSource</h3>
<div class="d"><strong>Session:</strong> Direct (local Outlook)</div>
<div class="d"><strong>GPO Source:</strong> Endpoint OU policies</div></div></div>
<div class="stats">
<div class="st c"><div class="n">$($conflicts.Count)</div><div class="l">Conflicts</div></div>
<div class="st x"><div class="n">$($ctxOnly.Count)</div><div class="l">Citrix Only</div></div>
<div class="st b"><div class="n">$($cliOnly.Count)</div><div class="l">Client Only</div></div>
<div class="st m"><div class="n">$($matches.Count)</div><div class="l">Matching</div></div>
</div>
$warnHtml
<h2>Conflicts - Same Key, Different Value ($($conflicts.Count))</h2>
<p style="margin-bottom:10px;color:#666;font-size:12px;">Users get different Outlook behavior depending on launch location.</p>
$(if ($conflicts.Count -gt 0) { "<table>$thdr$(Build-TableRows -Items $conflicts -Label 'CONFLICT')</table>" } else { '<p style="color:#27ae60;font-weight:bold;">No value conflicts detected.</p>' })
<h2>Citrix Only - Not on Client ($($ctxOnly.Count))</h2>
<p style="margin-bottom:10px;color:#666;font-size:12px;">Published-app users get these, local users do not.</p>
$(if ($ctxOnly.Count -gt 0) { "<table>$thdr$(Build-TableRows -Items $ctxOnly -Label 'CTX ONLY')</table>" } else { '<p>No Citrix-only settings.</p>' })
<h2>Client Only - Not on Citrix ($($cliOnly.Count))</h2>
<p style="margin-bottom:10px;color:#666;font-size:12px;">Local users get these, published-app users do not.</p>
$(if ($cliOnly.Count -gt 0) { "<table>$thdr$(Build-TableRows -Items $cliOnly -Label 'CLIENT ONLY')</table>" } else { '<p>No client-only settings.</p>' })
<h2>Matching ($($matches.Count))</h2>
$(if ($matches.Count -gt 0) { "<details><summary style='cursor:pointer;color:#27ae60;font-weight:bold;'>Expand $($matches.Count) matching</summary><table>$thdr$(Build-TableRows -Items $matches -Label 'MATCH')</table></details>" } else { '<p>None.</p>' })
<div class="info-box"><h3>GPO Precedence in Citrix Published Apps</h3>
<p><strong>1.</strong> HKLM from <strong>VDA server OU</strong> (Computer Config)</p>
<p><strong>2.</strong> HKCU from <strong>user OU</strong> (User Config) - modified by loopback</p>
<p><strong>3.</strong> Citrix Studio policies</p>
<p><strong>4.</strong> UPM/FSLogix profile layering</p>
<p style="margin-top:8px"><strong>Loopback Replace:</strong> Server OU User Config <em>replaces</em> user policy entirely.</p>
<p><strong>Loopback Merge:</strong> Server OU merges with user OU. Server wins on conflict.</p>
<p style="margin-top:8px"><strong>Key:</strong> GPO linked to endpoint OU but NOT Citrix server OU = published-app users get <em>different settings</em>.</p>
<p style="margin-top:8px"><code>gpresult /scope computer /v | findstr Loopback</code></p></div>
<p style="margin-top:30px;color:#999;font-size:10px;">Get-CitrixOutlookGPO.ps1 v1.1 - Jan Huebener</p>
</body></html>
"@
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "  HTML: $OutputPath" -ForegroundColor Green
}
#endregion

#region ======== MAIN EXECUTION ========
Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "  Citrix vs. Client - Outlook GPO Comparison v1.1" -ForegroundColor Cyan
Write-Host "=====================================================`n" -ForegroundColor Cyan

if (-not (Test-Path $ExportPath)) { New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null }

$ctxResults = $null; $cliResults = $null; $ctxInfo = $null; $ctxSource = ''; $cliSource = ''

# ── MODE: CSV COMPARE ──
if ($PSCmdlet.ParameterSetName -eq 'CSVCompare') {
    Write-Host "Mode: CSV Comparison (offline)" -ForegroundColor Yellow
    Write-Host "  Citrix CSV: $CitrixCSV" -ForegroundColor Gray
    Write-Host "  Client CSV: $ClientCSV" -ForegroundColor Gray
    $ctxResults = Import-Csv -Path $CitrixCSV -Encoding UTF8
    $cliResults = Import-Csv -Path $ClientCSV -Encoding UTF8
    $ctxSource = ($ctxResults | Select-Object -First 1).Computer
    $cliSource = ($cliResults | Select-Object -First 1).Computer
    if (-not $ctxSource) { $ctxSource = "CSV: $(Split-Path $CitrixCSV -Leaf)" }
    if (-not $cliSource) { $cliSource = "CSV: $(Split-Path $ClientCSV -Leaf)" }
    Write-Host "  Citrix entries: $($ctxResults.Count) | Client entries: $($cliResults.Count)" -ForegroundColor Gray
}
# ── MODE: LIVE SCAN ──
else {
    if ($AutoDetect -and -not $CitrixVDAServers) {
        Write-Host "Auto-detecting Citrix environment ..." -ForegroundColor Yellow
        $localCtx = Test-CitrixEnvironment
        if ($localCtx.IsCitrixVDA) {
            Write-Host "  Running ON Citrix VDA (v$($localCtx.VDAVersion))" -ForegroundColor Green
            $CitrixVDAServers = @($env:COMPUTERNAME)
        } elseif ($localCtx.SessionType -match 'ICA') {
            Write-Host "  Running IN Citrix session (client: $($localCtx.ClientName))" -ForegroundColor Green
            $CitrixVDAServers = @($env:COMPUTERNAME)
        } else {
            Write-Warning "Not a Citrix environment. Use -CitrixVDAServers to specify."
            Write-Warning "Current: VDA=$($localCtx.IsCitrixVDA), Session=$($localCtx.SessionType)"
            return
        }
    }
    if (-not $CitrixVDAServers) { Write-Error "No VDA servers specified. Use -CitrixVDAServers or -AutoDetect."; return }

    $ctxSource = $CitrixVDAServers[0]; $cliSource = $CompareWithClient[0]

    # Detect Citrix environment
    Write-Host "Detecting Citrix on $ctxSource ..." -ForegroundColor Yellow
    $ctxInfo = Test-CitrixEnvironment -Computer $ctxSource
    Write-Host "  VDA:      $($ctxInfo.IsCitrixVDA) (v$($ctxInfo.VDAVersion))" -ForegroundColor Gray
    Write-Host "  Profile:  $($ctxInfo.ProfileSolution)" -ForegroundColor $(if ($ctxInfo.ProfileSolution -match 'CONFLICT|None') { 'Red' } else { 'Gray' })
    Write-Host "  Loopback: $($ctxInfo.LoopbackProcessing)" -ForegroundColor $(if ($ctxInfo.LoopbackProcessing -eq 'Replace') { 'Red' } elseif ($ctxInfo.LoopbackProcessing -eq 'Merge') { 'Yellow' } else { 'Gray' })
    Write-Host "  Catalog:  $($ctxInfo.MachineCatalog) | DDC: $($ctxInfo.DeliveryController)" -ForegroundColor Gray

    # Scan VDA (Outlook + Citrix paths)
    Write-Host "`nScanning Citrix VDA: $ctxSource ..." -ForegroundColor Yellow
    $allCtxPaths = $OutlookRegistryPaths + $CitrixRegistryPaths
    $ctxResults = Get-RegistryValuesFromTarget -Computer $ctxSource -Paths $allCtxPaths -Environment 'Citrix'
    Write-Host "  Found $($ctxResults.Count) registry values" -ForegroundColor Gray

    # Scan fat client (Outlook paths only)
    Write-Host "Scanning fat client: $cliSource ..." -ForegroundColor Yellow
    $cliResults = Get-RegistryValuesFromTarget -Computer $cliSource -Paths $OutlookRegistryPaths -Environment 'Client'
    Write-Host "  Found $($cliResults.Count) registry values" -ForegroundColor Gray
}

# ── COMPARE ──
Write-Host "`nComparing ..." -ForegroundColor Yellow
$ctxOutlookOnly = @($ctxResults | Where-Object { $_.Category -notmatch '^(UPM|FSLogix|VDA|CtxHook|ICA|PortICA)' })
$comparison = Compare-RegistryResults -CitrixResults $ctxOutlookOnly -ClientResults $cliResults

$conflicts = @($comparison | Where-Object Status -eq 'CONFLICT')
$ctxOnly   = @($comparison | Where-Object Status -eq 'CITRIX_ONLY')
$cliOnly   = @($comparison | Where-Object Status -eq 'CLIENT_ONLY')
$matches   = @($comparison | Where-Object Status -eq 'MATCH')

Write-Host "  Conflicts:    $($conflicts.Count)" -ForegroundColor $(if ($conflicts.Count) { 'Red' } else { 'Green' })
Write-Host "  Citrix only:  $($ctxOnly.Count)" -ForegroundColor $(if ($ctxOnly.Count) { 'Yellow' } else { 'Gray' })
Write-Host "  Client only:  $($cliOnly.Count)" -ForegroundColor $(if ($cliOnly.Count) { 'Yellow' } else { 'Gray' })
Write-Host "  Matching:     $($matches.Count)" -ForegroundColor Green

# Citrix-specific risk check
Write-Host "`nChecking Citrix-specific risks ..." -ForegroundColor Yellow
$ctxConflictsFound = Find-CitrixConflicts -CitrixResults $ctxResults -Comparison $comparison -CitrixInfo $ctxInfo
foreach ($cf in $ctxConflictsFound) {
    $color = switch ($cf.Risk) { 'CRITICAL' { 'Red' }; 'HIGH' { 'Yellow' }; default { 'Gray' } }
    Write-Host "  [$($cf.Risk)] $($cf.Component)" -ForegroundColor $color
}

# ── EXPORT ──
Write-Host "`nExporting ..." -ForegroundColor Yellow

# CSV - full comparison
$comparison | Export-Csv -Path (Join-Path $ExportPath 'CitrixVsClient_Comparison.csv') -NoTypeInformation -Encoding UTF8
Write-Host "  CSV (all):       CitrixVsClient_Comparison.csv" -ForegroundColor Gray

# CSV - conflicts only
$conflicts | Export-Csv -Path (Join-Path $ExportPath 'CitrixVsClient_Conflicts.csv') -NoTypeInformation -Encoding UTF8
Write-Host "  CSV (conflicts): CitrixVsClient_Conflicts.csv" -ForegroundColor Gray

# CSV - Citrix-specific (UPM, FSLogix, VDA)
$ctxSpecific = @($ctxResults | Where-Object { $_.Category -match '^(UPM|FSLogix|VDA|CtxHook|ICA|PortICA)' })
if ($ctxSpecific.Count -gt 0) {
    $ctxSpecific | Export-Csv -Path (Join-Path $ExportPath 'CitrixSpecific_Registry.csv') -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV (Citrix):    CitrixSpecific_Registry.csv" -ForegroundColor Gray
}

# CSV - environment info
if ($ctxInfo) {
    $ctxInfo | Export-Csv -Path (Join-Path $ExportPath 'CitrixEnvironment_Info.csv') -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV (env):       CitrixEnvironment_Info.csv" -ForegroundColor Gray
}

# HTML report
$htmlPath = Join-Path $ExportPath 'CitrixVsClient_OutlookGPO.html'
Export-ComparisonHTML -Comparison $comparison -CitrixInfo $ctxInfo -ConflictsFound $ctxConflictsFound `
    -CitrixSource $ctxSource -ClientSource $cliSource -OutputPath $htmlPath

# ── SUMMARY ──
Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "  COMPARISON COMPLETE" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Citrix VDA:     $ctxSource" -ForegroundColor White
Write-Host "  Fat Client:     $cliSource" -ForegroundColor White
Write-Host "  ---" -ForegroundColor DarkGray
Write-Host "  Conflicts:      $($conflicts.Count)" -ForegroundColor $(if ($conflicts.Count) { 'Red' } else { 'Green' })
Write-Host "  Citrix only:    $($ctxOnly.Count)" -ForegroundColor Yellow
Write-Host "  Client only:    $($cliOnly.Count)" -ForegroundColor Blue
Write-Host "  Matching:       $($matches.Count)" -ForegroundColor Green
Write-Host "  ---" -ForegroundColor DarkGray
Write-Host "  Citrix risks:   $($ctxConflictsFound.Count)" -ForegroundColor $(if ($ctxConflictsFound.Count) { 'Red' } else { 'Green' })
if ($ctxInfo) {
    Write-Host "  Profile:        $($ctxInfo.ProfileSolution)" -ForegroundColor $(if ($ctxInfo.ProfileSolution -match 'CONFLICT|None') { 'Red' } else { 'White' })
    Write-Host "  Loopback:       $($ctxInfo.LoopbackProcessing)" -ForegroundColor $(if ($ctxInfo.LoopbackProcessing -eq 'Replace') { 'Red' } elseif ($ctxInfo.LoopbackProcessing -eq 'Merge') { 'Yellow' } else { 'White' })
}
Write-Host "  ---" -ForegroundColor DarkGray
Write-Host "  Output:         $ExportPath" -ForegroundColor Gray
Write-Host "=====================================================" -ForegroundColor Cyan
#endregion
