<#
.SYNOPSIS
    Analyzer - An HP Business System Update Detection and Update Tool

.DESCRIPTION
    This PowerShell script analyzes HP business PCs to detect available BIOS, driver, and software updates
    using HP Client Management Script Library (CMSL). It provides comprehensive scanning capabilities
    with options to download, install, or create repositories of available updates.

    The script performs the following operations:
    - Scans the system for platform identification
    - Categorizes updates by type (BIOS, Driver, Software, Utility)
    - Provides detailed analysis with version comparisons
    - Generates comprehensive logs and reports in multiple formats
    - Enables automated update management workflows

.DISCLAIMER
    This script is provided "as-is" without warranty of any kind. confers no rights, and is not supported by HP.

.PARAMETER Action
    Specifies the action to perform. Valid options:
    - Scan: Analyze system and display available updates (default)
    - Download: Download available updates to specified location
    - Install: Download and install updates (requires elevated privileges)
    - CreateRepo: Create a local repository of updates for use by HP Image Assistant

.PARAMETER ActionPath
    Specifies the path for download/repository operations.
    Default: $env:TEMP\HPAnalyzer

.PARAMETER Category
    Limits analysis to specific categories. Valid options:
    - BIOS: System firmware updates
    - Driver: Hardware driver updates
    Default: All categories (BIOS, Driver, Software, Utility)

.PARAMETER ReferenceFile
    Specifies an XML reference file to use for analysis.
    The file must have a .xml extension and contain HP SoftPaq information.
    The file is validated to ensure it exists and has the correct extension.
    Example: "C:\HP\Reference\platform_x64_10.0.19045.xml"

.PARAMETER SubCategory
    Filters driver updates by subcategory. Valid options:
    - Audio: Audio device drivers
    - Chipset: Chipset and system drivers
    - Graphics: Display and graphics drivers
    - Network: Network adapter drivers
    - Video: Video capture and display drivers

.EXAMPLE
    .\Analyzer.ps1
    Performs a basic scan of the system for all available updates.

.EXAMPLE
    .\Analyzer.ps1 -Action Download -ActionPath "C:\HPUpdates"
    Downloads all available updates to the specified directory.

.EXAMPLE
    .\Analyzer.ps1 -Action Scan -Category BIOS,Driver -Verbose
    Scans for BIOS and driver updates only with verbose output.

.EXAMPLE
    .\Analyzer.ps1 -Action Install -Category Driver -SubCategory Graphics
    Downloads and installs available graphics driver updates.

.EXAMPLE
    .\Analyzer.ps1 -Action Scan -ReferenceFile "C:\HP\EliteBook_850_G8_x64_10.0.19045.xml"
    Performs a scan using a specific XML reference file for comparison.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    Returns the number of available updates found.
    
    Generated files:
    - Log file: Analyzer-[timestamp].txt
    - CSV report: Analyzer-[timestamp].csv
    - JSON report: Analyzer-[timestamp].json
    - Debug log: Analyzer-[timestamp]-Debug.log (when -Debug is used)

.NOTES
    File Name      : Analyzer2.05.05.ps1
    Author         : HP Inc.
    Version        : 2.05.05
    Date Created   : [Original Creation Date]
    Last Modified  : August 29, 2025

    Prerequisites:
    - Windows PowerShell 5.1 or PowerShell 7+
    - HP Client Management Script Library (CMSL) module
    - Supported HP business PC platform
    - Internet connectivity for update queries
    - Administrative privileges (required for Install action only)
    
    System Requirements:
    - HP Business PCs with supported hardware configurations
    - HP Client Management Script Library (CMSL) installed
    - Internet access for update queries and downloads

    Error Codes:
    - 0: Success, updates available or scan completed
    - -1: Softpaq not installed
    - -2: Detail file not found
    - -3: Driver not found in PnP list
    - -4: UWP application not found
    - 10+: Update available codes (various types)

.LINK
    https://developers.hp.com/hp-client-management/doc/client-management-script-library

.LINK
    https://support.hp.com/us-en/document/c05832395

.COMPONENT
    HP Client Management Script Library (CMSL)

.ROLE
    System Administration, for Updates

.FUNCTIONALITY
    System Analysis, Update Detection

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)] [ValidateSet('Scan', 'Download', 'Install', 'CreateRepo')]
        [string]$Action = 'Scan',
    [Parameter(Mandatory = $false)]
        [string]$ActionPath = "$env:TEMP\HPAnalyzer",
    [Parameter(Mandatory = $false)] [ValidateSet('BIOS', 'Driver')]
        [string[]]$Category,
    [Parameter(Mandatory = $false)] [ValidateScript({
        if (-not (Test-Path -Path $_ -PathType Leaf)) { throw "File '$_' does not exist." }
        if ([System.IO.Path]::GetExtension($_) -ne '.xml') { throw "File '$_' must have a .xml extension." }
        return $true })]
        [string]$ReferenceFile,
    [Parameter(Mandatory = $false)] [ValidateSet('Audio', 'Chipset', 'Graphics', 'Network', 'Video')]
        [string[]]$SubCategory
) # param

#region Script Initialization and Metadata

# Script metadata
$ScriptVersion = '2.05.05'
$ScriptName = 'Analyzer'
$ScriptAuthor = 'Dan Felman, HP Inc.'
$ScriptLastModified = '2025-08-29'

# Performance tracking
$Script:StartTime = Get-Date
$Script:ExecutionId = (Get-Date).ToString('yyyyMMdd-HHmmss')

Write-Verbose "Starting execution - Version: $ScriptVersion"
Write-Verbose "Execution ID: $ExecutionId"
Write-Verbose "Parameters: Action=$Action, ActionPath=$ActionPath"
if ($Category) { Write-Verbose "Category filter: $($Category -join ', ')" }
if ($SubCategory) { Write-Verbose "SubCategory filter: $($SubCategory -join ', ')" }

#endregion

# Legacy Help Display (maintained for backward compatibility)
if ( $Help ) {
    'Analyzer scans a supported HP business PC and displays BIOS/Driver/Software updates available for a platform - requires HP CMSL'
    'It returns the number of Softpaqs available for updates'
    'Runtime options:'
    'Analyzer.exe [options]                                 # defaults to ''Scan'''
        '  [-Action <Scan|Download|CreateRepo|Install>]     # What action to take, defaults to ''Scan'''
        '       NOTE: Install action requires elevated rights'
        '  [-ActionPath <path>]                             # where to download/create repository'
        '               defaults to $env:TEMP\HPAnalyzer'
        '  [-Category <BIOS,Driver>]                        # Limit analysis to these categories: BIOS and/or Driver'
        '               defaults to All categories (select from: ''Audio'', ''Chipset'', ''Graphics'', ''Network'', ''Video'')'
        '  [-Debug]                                         # Output additional script debugging information'
        '  [-Help]                                          # Display this help message'
        '  [-ReferenceFile <path to .xml file>]             # Use a local XML reference file for analysis'
        '  [-SubCategory <Audio,Chipset,Graphics,Network,Video>]     # Filter by driver types'
        '               assumes -category Driver'
        '  [-Verbose]                                       # Output additional script verbose information'
    return 0
} # if ( $Help )

#region Script Configuration and Debugging Setup
# ============================================================================
# Configure script execution environment and debugging
# ============================================================================

# Configure verbose and debug preferences based on parameters
if ( $PSBoundParameters.Verbose  ) { $Script:Verbose = $true }
$Script:DebugPreference = if ($PSBoundParameters['Debug']) { 'Continue' } else { 'SilentlyContinue' }
$Script:VerbosePreference = if ($PSBoundParameters['Verbose']) { 'Continue' } else { 'SilentlyContinue' }

# Initialize debug logging with timestamp
$Script:DebugLogEnabled = $PSBoundParameters['Debug']

#endregion

#region Application Configuration and Constants
# ============================================================================
# Define script configuration, constants, and system mappings
# ============================================================================

# Initialize comprehensive configuration object
$Script:Config = @{
    Constants = @{
        SPQNOTINSTALLED = -1
        SPQDETAILFILENOTFOUND = -2          # means not updated via Softpaq
        SPQDRIVERNOTFOUND = -3           # this driver not in the PnP driver list        
        SPQUWPNOTFOUND = -4

        SPQUPTODATE = 0
        SPQDETAILFILEUPTODATE = 1
        SPQDRIVERUPTODATE = 2
        SPQUWPUPTODATE = 3
        
        SPQUPDATEAVAILABLE = 10
        SPQDETAILFILEUPDATEAVAILABLE = 11
        SPQDRIVERUPDATEAVAILABLE = 12
        SPQUWPUPDATEAVAILABLE = 13
    }
    Paths = @{   
        LogFile = "$($PSScriptRoot)\Analyzer-$((Get-Date).ToString('yyyyMMdd-HHmm')).txt"
        DebugFile = "$($PSScriptRoot)\Analyzer-$((Get-Date).ToString('yyyyMMdd-HHmm'))-Debug.log"
        CsvFile = "$($PSScriptRoot)\Analyzer-$((Get-Date).ToString('yyyyMMdd-HHmm')).csv"
        JsonFile = "$($PSScriptRoot)\Analyzer-$((Get-Date).ToString('yyyyMMdd-HHmm')).json"
    }
    OSVersionMap = @{
        '18363' = '1909'; '19041' = '2004'; '19042' = '2009'
        '19043' = '21H1'; '19044' = '21H2'; '19045' = '22H2'
        '22000' = '21H2'; '22621' = '22H2'; '22631' = '23H2'
        '26100' = '24H2'
    }
    CVAPathTokens = @{
        '<DRIVERS>' = "C:\Windows\System32\drivers"
        '<PROGRAMFILES>' = "C:\Program Files"
        '<PROGRAMFILESDIR>' = "C:\Program Files"
        '<PROGRAMFILESDIRX86>' = "C:\Program Files (x86)"
        '<WINDIR>' = "C:\Windows"
        '<WINSYSDIR>' = "C:\Windows\System32"
        '<WINSYSDIRX86>' = "C:\WINDOWS\SYSWOW64"
        '<WINDISK>' = (Get-CimInstance -ClassName CIM_OperatingSystem).SystemDrive
        '<WINSYSDISK>' = ($env:windir).split('\')[0]
    }
    
} # $Script:Config

Write-Verbose "Configuration of constants initialized"
Write-Debug "Log file: $($Script:Config.Paths.LogFile)"
Write-Debug "CSV file: $($Script:Config.Paths.CsvFile)"
Write-Debug "JSON file: $($Script:Config.Paths.JsonFile)"

Write-Debug "Debug logging enabled: $DebugLogEnabled"
if ($DebugLogEnabled) { Write-Verbose "Debug log path: $($Script:Config.Paths.DebugFile)" }

#endregion

#region Utility Functions
# ============================================================================
# Core utility functions for logging, file operations, and data management
# ============================================================================

Function Add-ToLog {
    [CmdletBinding()]param( [Parameter(Mandatory = $true)][string]$Message )    
    write-host $Message                 # first say it to the console    
    Add-LogFile -Message $Message       # next write it to the log file
} # Add-ToLog()

Function Add-LogFile {
    [CmdletBinding()]param( [Parameter(Mandatory = $true)][string]$Message )
    $al_msg = "$((Get-Date).ToString('yyyyMMdd-HH:mm')) - $Message"
    $al_msg | Out-File -FilePath $Script:Config.Paths.LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
} # Add-LogFile()

Function Add-DebugOut {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message
    )    
    if ($Script:DebugLogEnabled) {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $debugMessage = "[$timestamp] $Message"
        # Log to debug file if enabled
        $debugMessage | Out-File -FilePath $Script:Config.Paths.DebugFile -Append -Encoding UTF8
    } # if ($Script:DebugLogEnabled)
} # Add-DebugOut

Function Add-Verbose {
    [CmdletBinding()]param(
        [Parameter(Mandatory = $true)][string]$Message
    )
    $debugMessage = if ($Component) { "[$Component] $Message" } else { $Message }
    if ( $Verbose ) {       # only write verbose output if the verbose flag (-Verbose) is set
        Write-Verbose -Message $debugMessage             # to console
        Add-LogFile -Message $debugMessage               # to log file
    } # if ( $Verbose )
    if ($Script:DebugLogEnabled) { Add-DebugOut -Message $debugMessage }

} # Add-Verbose()

Add-Verbose -Message "Analyzer: $($ScriptVersion) -- $($startTime)" 
Add-Verbose -Message "Invokation command line: $($MyInvocation.Line)"

<#####################################################################################
    Initialize the environment
    This function initializes the environment, checks for CMSL, and retrieves Softpaq list
    It returns a hash table with the following keys:
    - PlatformID            # the HP Device Product ID
    - PlatformName          # the HP Device Model Name
    - OS                    # the OS version (win10 or win11)
    - OSVer                 # the OS version string (e.g., 22H2, 24H2)
    - SoftpaqList           # the list of Softpaq updates
    - XMLFile               # path to the XML file containing Softpaq list
    - XmlContent            # the XML content from the XML file
    - CacheDir              # the cache directory for XML file
#####################################################################################>
function Initialize-Environment {
    [CmdletBinding()]param( $pAction, $pActionPath )

    #requires -Modules @{ ModuleName='HPCMSL'; ModuleVersion='1.8.1' }
    Add-DebugOut -Message "Initializing environment for Action:$($pAction) at ActionPath:$($pActionPath)"
    $ie_env = @{}

    # obtain the system's OS information
    $ie_WindowsOS = Get-CimInstance win32_operatingsystem        # 'win'+$ie_WindowsOS.version.split('.')[0]
    $ie_env.OS = if ($ie_WindowsOS.BuildNumber -lt 22000) { 'win10' } else { 'win11' }
    $ie_env.OSVer = $Script:Config.OSVersionMap[$ie_WindowsOS.BuildNumber]
    $ie_env.architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture

    # next, check if HP CMSL is installed while obtaining the platform information
    Try {
        $ie_env.PlatformID = Get-HPDeviceProductID
        $ie_env.PlatformName = Get-HPDeviceModel        
        $ie_env.fileName = "$($ie_env.PlatformID)_$($ie_env.architecture)_$($ie_env.OS.Substring(3)).0.$($ie_env.OSVer).xml"
        Add-Verbose -Message "Analyzing platform: [$($ie_env.PlatformID)] $($ie_env.PlatformName) -- OS: $($ie_env.OS)/$($ie_env.OSVer)"
    } catch {
        Add-DebugOut -Message "Failed to get HP Device Product ID or Model Name. Ensure HP CMSL is installed and the device is supported."
        throw "Failed to get HP Device Product ID or Model Name. Ensure HP CMSL is installed and the device is supported."
    } # Try-catch

    # finally, obtain the Softpaq list for the platform and OS
    Add-Verbose -Message "Retrieving Softpaq List from Reference File"
    try {
        $ie_env.CacheDir = $PSScriptRoot
        if ( $Script:ReferenceFile ) {
            # Get-SoftpaqList requires the xml file to be available as a cab file in a specific path
            $ie_env.XMLFilePath = $Script:ReferenceFile
            $ie_NewXMLFolderPathName = (Split-Path -Path $ie_env.XMLFilePath -Leaf).replace('xml','cab.dir')
            $ie_env.SoftpaqList = Get-SoftpaqList -CacheDir $ie_env.CacheDir -Overwrite 'Yes' -ErrorAction Stop
            $ie_destinationXMLpath = Join-Path -Path $ie_env.CacheDir -ChildPath "cache\$ie_NewXMLFolderPathName"
            Add-Verbose -Message "Copying XML file to: $ie_destinationXMLpath to enable use of argument -ReferenceFile"
            Copy-Item -Path $ie_env.XMLFilePath -Destination $ie_destinationXMLpath -Force
        } else {
            $ie_env.SoftpaqList = Get-SoftpaqList -CacheDir $ie_env.CacheDir -Overwrite 'Yes' -ErrorAction Stop
        } # else if ( $Script:ReferenceFile )

        $ie_env.XMLFilePath = Get-ChildItem -Path "$($ie_env.CacheDir)\cache" -Include "*.xml" -Recurse -File | 
                Where-Object { $_.Name -match $ie_env.PlatformID } 

        Add-Verbose -Message "Working File: $($ie_env.XMLFilePath)"
        $ie_env.XmlContent = [xml](Get-Content -Path $ie_env.XMLFilePath)
    } catch {
        throw "Failed to retrieve Softpaq list or XML file. Ensure HP CMSL is installed and the device is supported."   
    } # Try-catch 

    $ie_env.Links = @{
        'InstalledApps' = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')
        'InstalledPackages' = (Get-ChildItem 'HKLM:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\')
        'InstalledWOWApps' = (Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        'InstalledAppxApps' = (Get-AppxPackage)
        'XMLRefFileSolutions' = $ie_env.XmlContent.SelectNodes("ImagePal/Solutions")
        'XMLRefFileDevices' = $ie_env.XmlContent.SelectNodes("ImagePal/Devices")
        'XMLRefFileUWPApps' = $ie_env.XmlContent.SelectNodes("ImagePal/SystemInfo/UWPApps/UWPApp")
    } # $Links
    
    Add-Verbose -Message "Obtaining system's PnP driver list"
    $ie_env.PnpSignedDrivers = Get-CimInstance win32_PnpSignedDriver | 
        Where-Object { $_.DriverVersion -and `
            ($_.DriverProviderName -ne 'Microsoft') -and `
            (-not $_.DeviceID.StartsWith("{")) -and `
            ($_.DeviceClass -ne 'SOFTWARECOMPONENT')
        } # Where-Object

    # finally, initialize for the specific actions

    switch ($pAction) {
        'Download' {
            $Script:ActionPath = initialize-DownloadFolder $pActionPath
        } # 'Download'
        'Install' {
            if (-not (Test-AdminRights)) {
                Throw "This script requires elevated rights to install Softpaqs"
            }
            $Script:ActionPath = initialize-DownloadFolder $pActionPath
        } # 'Install'
        'CreateRepo' {
            $Script:ActionPath = initialize-DownloadFolder $pActionPath
            if (-not (initialize-HPIArepository $pActionPath $ie_env.PlatformID $ie_env.OS $ie_env.OSVer) ) {
                Throw "Failed to initialize HP Image Assistant Repository "
            } # if (-not (initialize-HPIArepository $pActionPath) )
        } # 'CreateRepo'
    } # switch ( $Action )

    Resolve-OptionConflicts         # resolve options conflicts
if ( $ie_env.OS -eq 'win10') { $ie_env.OS = 'WT64' } else { $ie_env.OS = 'W11' }
    return $ie_env
} # Function Initialize-Environment

Function Test-CategoryFilter {
    [CmdletBinding()] param( $pTest, $pCategory )

    if ( -not $pCategory -or ($pCategory -match $pTest) ) {
        return $true
    }
    return $false
} # Function Test-CategoryFilter()

function Resolve-BIOS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$pSoftpaqEntry,
        [Parameter(Mandatory)]$pSoftpaq
    )
    $rb_InstalledBIOS = (Get-HPBIOSSettingValue 'System BIOS Version').split(' ')
    $rb_InstalledBIOSVersion = $rb_InstalledBIOS[2]  # ex. 'Q70 Ver. 01.19.20  03/21/2022'
    $rb_InstalledBIOSDate = $rb_InstalledBIOS[-1]

    $rb_SoftpaqBIOS = $pSoftpaq.Version
    # handle Softpaq BIOS version that do NOT start with '0' (e.g. '01.19.20')
    if ( $rb_InstalledBIOSVersion -match "^0" -and ($rb_SoftpaqBIOS -notmatch "^0") ) { $rb_SoftpaqBIOS =  '0'+$rb_SoftpaqBIOS }
    if ( $rb_InstalledBIOSVersion -lt $rb_SoftpaqBIOS  ) {
        $rb_Status = $Script:Config.Constants.SPQUPDATEAVAILABLE     # '1'     # "-- BIOS UPDATE AVAILABLE"
    } else {
        $rb_Status = $Script:Config.Constants.SPQUPTODATE            # '0'     # "-- BIOS UP TO DATE"
    } # else if ( $rb_InstalledBIOSVersion -lt $rb_SoftpaqBIOS  )

    $pSoftpaqEntry.InstalledVersion = $rb_InstalledBIOSVersion
    $pSoftpaqEntry.InstallDate = $rb_InstalledBIOSDate
    $pSoftpaqEntry.SoftpaqStatus = $rb_Status

    return $pSoftpaqEntry
} # function Resolve-BIOS()

function Test-StringContainsArrayItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$pInputString,
        [Parameter(Mandatory = $true)][array]$pSearchArray
    )
    foreach ( $item in $pSearchArray ) {
        $ts_contains = $pInputString.ToLower().Contains($item.ToLower())
        if ( $ts_contains ) { return $true } # foreach ($item in $SearchArray)
    } # foreach ($item in $SearchArray)

    return $false
} # function Test-StringContainsArrayItems()

function Expand-CVAPath {
    [CmdletBinding()]
    param([string]$pDriverPath)
    
    $ec_token = $pDriverPath.split('\')[0]
    if ($ec_token.contains(',')) { $ec_token = $pDriverPath.split(',')[0] }

    $ec_expandedPath = $Script:Config.CVAPathTokens[$ec_token]
    if ($ec_expandedPath) {
        $pDriverPath = $pDriverPath.replace($ec_token, $ec_expandedPath)
    }

    return $pDriverPath
} # Function Expand-CVAPath()

Function Get-UWPAppsFromRefFile {
    [CmdletBinding()] param( $pSoftpaq, $pLists )

    $gu_UWPAppxList = @()

    $pLists.XMLRefFileUWPApps | Where-Object { $_.Solutions.UpdateInfo.IdRef -eq $pSoftpaq.ID } | ForEach-Object {
        $gu_UWPAppxList += @{ 
            RefFileUWPName = $_.Name.split('.')[1] 
            RefFileUWPVersion = $_.Version
        } # @{ RefFileUWPName = $_.Name.split('.')[1] ...
    } # foreach ( $_ in $pLists.XMLRefFileUWPApps )

    return $gu_UWPAppxList

} # Function Get-UWPAppsFromRefFile()

Function Get-File_PropertyVersion {
    [CmdletBinding()] param( $pFileDetailPath )

    # get the driver file version from the file propery entry, Use ProductVersion, or FileVersion as a backup

    # get the file 'version info tab' from the file properties
    $gf_FileVersionInfo = (Get-Item $pFileDetailPath).VersionInfo

    # handle version formatting (issues with some drivers deliverables)
    $gf_FileVersion = (($gf_FileVersionInfo.ProductVersion.Replace(',','.')).replace(' ','')).split(' ')[0]

    if ( -not ($gf_FileVersion -as [version]) ) { $gf_FileVersion = $gf_FileVersionInfo.FileVersion }

    $gf_FileVersion = $gf_FileVersion.split(' ')[0]         # some drivers have a date at the end following a space char

    return [PSCustomObject]@{ FullPath = $pFileDetailPath ; ProductVersion = $gf_FileVersion }

} # Function Get-File_PropertyVersion()

Function Get-InstalledDetailFileInfo {
    [CmdletBinding()] param( $pFileDetail )

    $gi_InstalledFileInfo = @{
        FullPath = $null
        ProductVersion = $null
    } # gi_InstalledFileInfo

    $gi_ExpandedPath = Expand-CVAPath $pFileDetail.Directory    
    $gi_FullFilePath = Join-Path -Path $gi_ExpandedPath -ChildPath $pFileDetail.FileName  

    if ( Test-Path $gi_FullFilePath ) {    
        $gi_InstalledFileInfo =  (Get-File_PropertyVersion $gi_FullFilePath)
    } else {
        # search for the driver file from the parent path, in case the location is updated for every version
        $gi_FileName = $pFileDetail.FileName
        $gi_parentFolder = Split-Path $gi_ExpandedPath -Parent
        if ( $gi_ExpandedPath -match 'x64$' ) { $gi_parentFolder = Split-Path $gi_parentFolder -Parent }                
        
        $gi_FullFilePaths = Get-ChildItem -Path $gi_parentFolder -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $gi_FileName }
        
        # if there are multiple files matching the name starting with the parent folder
        # try to sort by ProductVersion if populated and return the most recent
        if ( $gi_FullFilePaths.Count -gt 0 ) {
            # get all entries found                
            $gi_fileDetails = foreach ($gifile in $gi_FullFilePaths) {
                $gi_fileInfo = Get-Item $gifile.FullName
                if ( $gi_fileInfo.VersionInfo.ProductVersion -match '_\d+\.\d+\.\d+\.\d+$' ) {
                    [PSCustomObject]@{ FullPath = $gi_fileInfo.FullName ; ProductVersion = $gi_fileInfo.VersionInfo.ProductVersion }                                   
                } else {
                    [PSCustomObject]@{ FullPath = $gi_fileInfo.FullName ; ProductVersion = $gi_fileInfo.VersionInfo.FileVersion }
                }
            } # foreach ($file in $gi_FullFilePaths)
            
            # Try to sort by ProductVersion if populated
            $gi_InstalledFileInfo = $gi_fileDetails | Sort-Object -Property @{
                Expression = { 
                    if ([string]::IsNullOrEmpty($_.ProductVersion)) { [System.Version]"0.0.0.0" } else { try { [System.Version]$_.ProductVersion } catch { [System.Version]"0.0.0.0" } }
                }
                Descending = $true
            #}, -LastWriteTime -Descending | Select-Object -First 1
            #}, -Descending | Select-Object -First 1
            } | Select-Object -First 1

        } # if ($gi_InstalledFileInfo.Count -gt 0)

    } # else if ( Test-Path $gi_FullFilePath )

    return $gi_InstalledFileInfo          

} # Function Get-InstalledDetailFileInfo

Function Get-DetailFileVersions {
    [CmdletBinding()] param( $pSolution, $pOS , $pOSVer )

    Add-DebugOut -Message "     > Get-DetailFileVersions()" 
    $gd_DetailFile = [ordered]@{
        DetailFileVersion = $null
        DetailFileInstalledVersion = $null
        DetailFileStatus = $Script:Config.Constants.SPQDETAILFILENOTFOUND
        SoftpaqStatus = $Script:Config.Constants.SPQNOTINSTALLED
    } # $gd_DetailFile

    # Find the entry with a matching OS version entry in the Reference File <DetailFileInformation> section of a Solution (aka Softpaq)
    <# Reference File DetailFile Information example:
        <FileDetail>
          <FileName>igdkmdn64.sys</FileName>
          <Directory>&lt;WINSYSDIR&gt;\DriverStore\FileRepository\iigd_dch.inf_amd64_e35423a455e0d784\</Directory>
          <Version>32.0.101.6651</Version>
          <OS>W11_24H2</OS>
        </FileDetail>  #>    
    [array]$gd_RefFile_FileDetailEntry = $pSolution.DetailFileInformation.FileDetail | Where-Object {$_.OS -eq "$($pOS)_$($pOSVer)"}
    if ( -not $gd_RefFile_FileDetailEntry ) {
        # try to find a matching OS entry without the OS version (e.g., W11 instead of W11_24H2)
        $gd_RefFile_FileDetailEntry = $pSolution.DetailFileInformation.FileDetail | Where-Object {$_.OS -eq "$($pOS)"}
    } # if ( -not $gd_RefFile_FileDetailEntry )

    if ( $gd_RefFile_FileDetailEntry.Count -gt 0 ) {
        $gd_RefFile_FileDetailEntry | ForEach-Object {
            $gd_InstalledDetailFileinfo = Get-InstalledDetailFileInfo $_        
            <# returns the top matching entry
                @{
                    FullPath = $null
                    ProductVersion = $null
                }  #>
            $gd_DetailFile.FullPath = ($gd_InstalledDetailFileinfo.FullPath)
            $gd_DetailFile.DetailFileInstalledVersion = ($gd_InstalledDetailFileinfo.ProductVersion)
            $gd_DetailFile.DetailFileVersion = $_.Version            
        } # ForEach-Object

        if ( $gd_DetailFile.DetailFileInstalledVersion -and $gd_DetailFile.DetailFileVersion ) {
            if ( [version]$gd_DetailFile.DetailFileInstalledVersion -lt [version]$gd_DetailFile.DetailFileVersion ) {
                $gd_DetailFile.DetailFileStatus = $Script:Config.Constants.SPQDETAILFILEUPDATEAVAILABLE
                $gd_DetailFile.SoftpaqStatus = $Script:Config.Constants.SPQUPDATEAVAILABLE
            } else {
                $gd_DetailFile.DetailFileStatus = $Script:Config.Constants.SPQDETAILFILEUPTODATE
                $gd_DetailFile.SoftpaqStatus = $Script:Config.Constants.SPQUPTODATE
            } # else if ( [version]$gd_DetailFile.DetailFileInstalledVersion -lt [version]$gd_DetailFile.DetailFileVersion )
        } # if ( $gd_DetailFile.DetailFileInstalledVersion -and $gd_DetailFile.DetailFileVersion )
    } # if ( $gd_RefFile_FileDetailEntry.Count -gt 0 )

    Add-DebugOut -Message "       $($gd_DetailFile.FullPath): Reference/Installed Version=$($gd_DetailFile.DetailFileVersion)/$($gd_DetailFile.DetailFileInstalledVersion)" 
    Add-DebugOut -Message "     < Get-DetailFileVersions() DetailFile Status: $($gd_DetailFile.DetailFileStatus)" 
    return $gd_DetailFile

} # Function Get-DetailFileVersions

Function Initialize-Driver {
    return [ordered]@{
        DeviceID = $null
        HardwareType = $null
        HardwareVENDEV = $null
        PnPDriverVersion = $null
        PnpDriverDate = $null
        PnpDriverClass = $null
        SoftpaqID = $null
        RefFileDriverVersion = $null
        RefFileDriverDate = $null
        Driverstatus = $Script:Config.Constants.SPQDRIVERNOTFOUND
    } # return [ordered]@{ ...
} # Function Initialize-Driver()

Function Find-Driver {
    [CmdletBinding()] param( $pSoftpaqID, $pLists, $pInstalledDrivers )
    
    Add-DebugOut -Message "   > Find-Driver()"
                
    $fd_MatchedDriverList = @()     # initialize the hardware list to return
    $fd_Driver = [ordered]@{}
    # get the list of devices from the XML Reference File <Devices> section. Limit the scope
    $fd_MatchedXMLDeviceList =  $pLists.XMLRefFileDevices.Device | 
        Where-Object  { $_.Solutions.UpdateInfo.IdRef -like $pSoftpaqID `
            -and ($_.ClassName -notlike 'Extension') `
            -and $_.ClassName -notlike 'SoftwareComponent' }

    ###########################################################################################
    # Let's start by finding the hardware ID in the Reference file [Devices] section
    # and check if the driver is installed in the system, otherwise the list will be empty (no deviceID match)
    
    # Get all Softpaq matching devices from the XML Reference File <Devices> section
    foreach ($Entry in $fd_MatchedXMLDeviceList) {

        # $Entry.DeviceID  example:         DeviceId       : PCI\VEN_14C3&DEV_4D75&SUBSYS_14C34D75
        $fd_XMLDeviceHash = $Entry.DeviceID.split('\')
        $fd_XMLEntryType = $fd_XMLDeviceHash[0]

        $fd_XMLDeviceVENDEV = $fd_XMLDeviceHash[1] -replace '.*?(VEN_)', '$1' # obtain the VEN&PID|DEV string
        $fd_XMLEntryVENDEV = ($fd_XMLDeviceVENDEV -split '&')[0..1] -join '&' # ensure we only have VEN&PID string to match

        if ($fd_XMLDeviceVENDEV -match '(&REV_[^&\\]+)') { $fd_XMLEntryREV = $matches[1].TrimStart('&') } else { $fd_XMLEntryREV = $null }

        foreach ( $PnPDriver in $pInstalledDrivers ) {
            $fd_PnPDriverHash = $PnPDriver.DeviceID.split('\')
            $fd_PnPDriverType = $fd_PnPDriverHash[0]                    # obtain the DeviceID driver Type
            $fd_PnPDriverEntry = $fd_PnPDriverHash[1]            
            $fd_PnPDriverVENDEV = ($fd_PnPDriverEntry -split '&')[0..1] -join '&'  # get only the VEN&DEV string

            #if ( $fd_PnPDriverVENDEV -match '^DEVTYPE') { continue }        # handle entry from Realtek HD Audio Driver
            if ( ($fd_PnPDriverType -eq $fd_XMLEntryType) -and ($fd_PnPDriverEntry -match $fd_XMLEntryVENDEV) ) {
                # Match DeviceID revision versions REV_xyz
                if ($fd_PnPDriverEntry -match '(&REV_[^&\\]+)') { $fd_PnPDriverEntryREV = $matches[1].TrimStart('&') }
                if ( $fd_PnPDriverEntryREV -and ($fd_PnPDriverEntryREV -notmatch $fd_XMLEntryREV) ) { continue }
                $fd_Driver = Initialize-Driver

                $fd_Driver.DeviceID = $fd_PnPDriverVENDEV
                $fd_Driver.HardwareType = $fd_XMLEntryType
                $fd_Driver.HardwareVENDEV = $fd_XMLEntryVENDEV       # added in 2.04.03
                $fd_Driver.PnPDriverVersion = $PnPDriver.DriverVersion
                $fd_Driver.PnpDriverDate = $PnPDriver.DriverDate.ToString("MM-dd-yyyy")
                $fd_Driver.PnpDriverClass = $PnPDriver.DeviceClass
                if ( [version]$fd_Driver.PnPDriverVersion -lt $Entry.DriverVersion ) {
                    $fd_Driver.Driverstatus = $Script:Config.Constants.SPQDRIVERUPDATEAVAILABLE
                } else {
                    $fd_Driver.Driverstatus = $Script:Config.Constants.SPQDRIVERUPTODATE
                } # if ( [version]$fd_Driver.PnPDriverVersion -lt $Entry.DriverVersion )

                # confirm the driver is not already in the matched list - so we add it only once
                $fd_RegexMatch = "^$($fd_XMLEntryType).*?$($fd_XMLEntryVENDEV)"

                $fd_EntryInList = $fd_MatchedDriverList | Where-Object { $_.CVAHWID -match $fd_RegexMatch }

                if ( -not $fd_EntryInList ) {
           
                    $fd_Driver.SoftpaqID = $pSoftpaqID
                    $fd_Driver.CVAHWID = $Entry.DeviceID
                    $fd_Driver.RefFileDriverVersion = $Entry.DriverVersion
                    $fd_Driver.RefFileDriverDate = $Entry.DriverDate
                    $fd_MatchedDriverList += $fd_Driver     # add this driver to the return list
                    Add-DebugOut -Message "       Matched Installed DeviceID: $($fd_Driver.DeviceID) - Available/Installed Versions: $($fd_Driver.RefFileDriverVersion)($($fd_Driver.RefFileDriverDate))/$($fd_Driver.PnPDriverVersion)($($fd_Driver.PnpDriverDate)) Status: $($fd_Driver.Driverstatus)" 
                } # if ( -not $fd_EntryInList )

            } # if ( ($fd_PnPDriverID -match $fd_XMLEntryVENDEV) -and ($fd_XMLEntryType -match $fd_PnPDriverType) )
        } # foreach ( $PnPDriver in $pInstalledDrivers )

    } # foreach ($Entry in $fd_MatchedXMLDeviceList)

    Add-DebugOut -Message "   < Find-Driver()" 

    return $fd_MatchedDriverList   #$fd_DriverEntry
    
} # Function Find-Driver

Function Resolve-Driver {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$pSoftpaqEntry,
        [Parameter(Mandatory)]$pSoftpaq,
        [Parameter(Mandatory)]$pLinks,
        [Parameter(Mandatory)]$pDriversList
    )
    Add-DebugOut -Message "   > Resolve-Driver()" 

    #$rd_OS = $Script:AnalyzerEnv.OS

    #if ( $rd_OS -eq 'win10') { $rd_OS = 'WT64' } else { $rd_OS = 'W11' }      # how CVA shows Windows 10/64 bit support

    # first, find the Solution <Softpaq> entry in the reference file to get the Detail File information
    $rd_Solution =  $pLinks.XMLRefFileSolutions.UpdateInfo | Where-Object {$_.id -eq $pSoftpaq.Id }
    $rd_DetailFileVersions = Get-DetailFileVersions $rd_Solution $Script:AnalyzerEnv.OS $Script:AnalyzerEnv.OSVer
    <# returns @{
            DetailFileVersion = $null
            DetailFileInstalledVersion = $null
            DetailFileStatus = $Script:Config.Constants.SPQDETAILFILENOTFOUND
            SoftpaqStatus = $Script:Config.Constants.SPQNOTINSTALLED
        }  #> 
    $pSoftpaqEntry.DetailFileVersion = $rd_DetailFileVersions.DetailFileVersion
    $pSoftpaqEntry.DetailFileInstalledVersion = $rd_DetailFileVersions.DetailFileInstalledVersion
    $pSoftpaqEntry.DetailFileStatus = $rd_DetailFileVersions.DetailFileStatus
    $pSoftpaqEntry.SoftpaqStatus = $rd_DetailFileVersions.SoftpaqStatus

    $pSoftpaqEntry.Drivers = Find-Driver $pSoftpaq.Id $pLinks $pDriversList

    <# Find-Driver() returns a list of matched PnP drivers entries containing the following keys:
        @{
            DeviceID                       HPIC000C
            HardwareType            ACPI
            HardwareVENDEV          HPIC000C
            PnPDriverVersion               1.66.3710.0
            PnpDriverDate                  03-27-2024
            PnpDriverClass                 SYSTEM
            SoftpaqID                      sp160438
            RefFileDriverVersion           1.66.3710.0
            RefFileDriverDate              03/28/2024
            Status                         2
            CVAHWID                        ACPI\HPIC000C
        } #>
    
    if ( $pSoftpaqEntry.Drivers.Count -eq 0 ) {         
        $pSoftpaqEntry.SoftpaqStatus = $Script:Config.Constants.SPQNOTINSTALLED   # No drivers found
    } else {
        $rd_AllDriversUpdated = $true
        $pSoftpaqEntry.Drivers | ForEach-Object {
            if ( $_.DriverStatus -eq $Script:Config.Constants.SPQDRIVERUPDATEAVAILABLE ) {
                $rd_AllDriversUpdated = $false
            } # if ( $_.DriverStatus -eq $Script:Config.Constants.SPQDRIVERUPDATEAVAILABLE )
        } #  $pSoftpaqEntry.Drivers | ForEach-Object
        if ( $rd_AllDriversUpdated ) {
            $pSoftpaqEntry.SoftpaqStatus = $Script:Config.Constants.SPQUPTODATE
        } else {
            $pSoftpaqEntry.SoftpaqStatus = $Script:Config.Constants.SPQUPDATEAVAILABLE
        }
    } # else ( $pSoftpaqEntry.Drivers.Count -eq 0 )

    # check if the Softpaq is installed as a Software UWP app
    $rd_UWPAppxs = Get-UWP $pSoftpaq $pLinks

    # in case the Softpaq has > 1 UWP/Appx applications, check each one for updates
    foreach ( $i_UWP in $rd_UWPAppxs ) { 
        $pSoftpaqEntry.UWPName = $i_UWP.RefFileUWPName
        $pSoftpaqEntry.UWPVersion = $i_UWP.RefFileUWPVersion
        $pSoftpaqEntry.UWPInstallVersion = $i_UWP.InstalledUWPVersion
        $pSoftpaqEntry.UWPStatus = $i_UWP.UWPStatus
        if ( $pSoftpaqEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPUPDATEAVAILABLE ) { 
            Add-DebugOut -Message "       UWPP Appx: $($pSoftpaqEntry.UWPName) $($pSoftpaqEntry.UWPVersion) is installed, but update available: $($pSoftpaqEntry.UWPInstallVersion)"
            $pSoftpaqEntry.SoftpaqStatus = $Script:Config.Constants.SPQUPDATEAVAILABLE
            break   
        } # if ( $pSoftpaqEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPUPDATEAVAILABLE )
    } # foreach ( $i_UWP in $a_UWPAppxInfo )

    Add-DebugOut -Message "   < Resolve-Driver() - returning SoftpaqStatus: $($pSoftpaqEntry.SoftpaqStatus)"
    return $pSoftpaqEntry
} # function Resolve-Driver()

Function Get-UWPAppx {
    [CmdletBinding()] param( [string]$pUWPName, $pLists ) 
 
    $gu_MatchedRefFileUWPEntry = @{
        InstalledUWPName = $null
        InstalledUWPVersion = $null
    }

    #  find a matching installed Appx: ex. AD2F1837.HPProgrammableKey_1.0.17.0_x64__v10z8vjag6ke6
    $gu_InstalledAppx = $pLists.InstalledAppxApps | where { $_ -match $pUWPName } | Select-Object -First 1

    if ( $gu_InstalledAppx ) {
        $gu_MatchedRefFileUWPEntry.InstalledUWPName = $gu_InstalledAppx.Name
        $gu_MatchedRefFileUWPEntry.InstalledUWPVersion = $gu_InstalledAppx.Version
    } else {
        ########################################################################
        # additional check for 2.04.00
        # add check for Easy Clean, Power Manager, etc., installed as local packages
        # 'InstalledPackages' = (Get-ChildItem 'HKLM:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages')

        # find installed UWP as local packages from registry
        $gu_InstalledPackage = $pLists.InstalledPackages | Where-Object { $_.PSChildName -match "$($pUWPName)" } | Select-Object PSChildName -First 1
        if ( $gu_InstalledPackage ) {
            $gu_MatchedRefFileUWPEntry.InstalledUWPName =$gu_InstalledPackage.PSChildName.split('_')[0]
            $gu_MatchedRefFileUWPEntry.InstalledUWPVersion = $gu_InstalledPackage.PSChildName.split('_')[1]                    
        } # if ( $gu_InstalledPackage )

    } # else if ( $gu_InstalledAppx )

    return $gu_MatchedRefFileUWPEntry

} # Function Get-UWPAppx

Function Get-UWPasApp {
    [CmdletBinding()] param( $pSoftpaqName, $pLists )

    $gu_UWPInfo = [ordered]@{
        InstalledUWPName = $null
        InstalledUWPVersion = $null
    } # $gu_UWPInfo

    # search WoW Uninstall entries for matching Software, list obtained with 'Get-ItemProperty'
    # Combine both search loops for efficiency
    $fu_AllInstalledApps = @($pLists.InstalledWOWApps) + @($pLists.InstalledApps)

    foreach ( $iInst in $fu_AllInstalledApps ) {   
        if ( $iInst.DisplayName -match $pSoftpaqName ) {      
            $gu_UWPInfo.InstalledUWPName = $iInst.DisplayName
            $gu_UWPInfo.InstalledUWPVersion = $iInst.DisplayVersion.split(' ')[0]
            break
        } # if ( $iInst.DisplayName -match $pSoftpaq.name )
    } # foreach ( $iInst in $fu_AllInstalledApps )

    return $gu_UWPInfo

} # Function Get-UWPasApp()

Function Get-UWP {
    [CmdletBinding()] param( $pSoftpaq, $pLists )

    Add-DebugOut -Message "       > Get-UWP()" 
    $gu_UWPList = @()  # initialize the list of UWP entries from the Reference File
    
    # find UWP entries in the Reference File for this Softpaq from <UWPApps> section
    $gu_RefFileUWPList = @()  # initialize the list of UWP entries from the Reference File
    $gu_RefFileUWPList = Get-UWPAppsFromRefFile $pSoftpaq $pLists
    <# returns a list of UWP entries from the Reference File
        @{ RefFileUWPName = 'HPProgrammableKey' ; RefFileUWPVersion = ' }
    #>   

    $gu_RefFileUWPList | ForEach-Object {
        $gu_RefFileVersion = $_.RefFileUWPVersion           # cache for reuse in loop
        $gu_status = $Script:Config.Constants.SPQUWPNOTFOUND

        $gu_UWPInfoSoftware = Get-UWPAppx  $_.RefFileUWPName $pLists
        <# returns @{
                InstalledUWPName = $null
                InstalledUWPVersion = $null
            }  #>
        if ( $gu_UWPInfoSoftware.InstalledUWPVersion ) {
            if ( [version]$gu_UWPInfoSoftware.InstalledUWPVersion -lt [version]$gu_RefFileVersion ) {
                $gu_status = $Script:Config.Constants.SPQUWPUPDATEAVAILABLE
                Add-DebugOut -Message "         Found UWP Appx: $($gu_UWPInfoSoftware.InstalledUWPName) Available/Installed Versions: $($gu_RefFileVersion)/$($gu_UWPInfoSoftware.InstalledUWPVersion)"
            } else {
                $gu_status = $Script:Config.Constants.SPQUWPUPTODATE    
            } # else if ( [version]$gu_UWPInfoSoftware.InstalledUWPVersion -lt [version]$gu_RefFileVersion )
        } # if ( $gu_UWPInfoSoftware.InstalledUWPVersion )

        $gu_UWPList += [ordered]@{
            RefFileUWPName = $_.RefFileUWPName
            RefFileUWPVersion = $gu_RefFileVersion
            InstalledUWPName = $gu_UWPInfoSoftware.InstalledUWPName
            InstalledUWPVersion = $gu_UWPInfoSoftware.InstalledUWPVersion
            UWPStatus = $gu_status
        } # $gu_UWPList
        
        if ( $null -eq $gu_UWPInfoSoftware.InstalledUWPVersion ) {

            # see if Softpaq ins installed as an app
            $gu_uwp = Get-UWPasApp $pSoftpaq.Name $pLists
            <# returns @{
                    InstalledUWPName = $null
                    InstalledUWPVersion = $null
                }  #>
            if ( $gu_uwp.InstalledUWPVersion ) {
                if ( $gu_uwp.InstalledUWPVersion -and $gu_uwp.InstalledUWPVersion -lt $gu_RefFileVersion ) {
                    Add-DebugOut -Message "         Found UWP App: $($gu_uwp.InstalledUWPName) Available/Installed Versions: $($gu_RefFileVersion)/$($gu_uwp.InstalledUWPVersion)"
                    $gu_status = $Script:Config.Constants.SPQUWPUPDATEAVAILABLE
                } else {
                    $gu_status = $Script:Config.Constants.SPQUWPUPTODATE    
                }
                $gu_UWPList += [ordered]@{
                    RefFileUWPName = $_.RefFileUWPName
                    RefFileUWPVersion = $gu_RefFileVersion
                    InstalledUWPName = $gu_uwp.InstalledUWPName
                    InstalledUWPVersion = $gu_uwp.InstalledUWPVersion
                    UWPStatus = $gu_status
                    } # $gu_UWPList
                $gu_UWP.UWPName = $gu_uwp.InstalledUWPName
                $gu_UWP.UWPInstallVersion = $gu_uwp.InstalledUWPVersion
           } # if ( $gu_uwp.InstalledUWPVersion )
        } # if ( $null -eq $gu_UWPInfoSoftware.InstalledUWPVersion )
    } # $gu_RefFileUWPList | ForEach-Object {}

    Add-DebugOut -Message "       < Get-UWP()"

    return $gu_UWPList # | Select-Object -First 1

} # Function Get-UWP()

Function initialize-HPIArepository {
    [CmdletBinding()]
	param( $pRepoFolder, $pPlatformID, $pOS, $pOSVer )

    Add-DebugOut -Message "  > initialize-HPIArepository()"
    $ir_CurrentLoc = Get-Location                   # Save the current location to return later

    Set-Location $pRepoFolder   # Change to the repository folder for initialization - required by the repository cmdlets
   
    Try {
        # Attempt to get repository info to check if it's already initialized
        Get-RepositoryInfo -ErrorAction Stop | Out-Null
        Add-DebugOut -Message "  ... repository already initialized"
    } Catch {
        # Catch block will handle the case where Get-RepositoryInfo fails, indicating it's not initialized               
        (Initialize-Repository) 6>&1
        Add-DebugOut -Message  "  .. repository initialized"
        Set-RepositoryConfiguration -setting OfflineCacheMode -cachevalue Enable 6>&1 
        Set-RepositoryConfiguration -setting RepositoryReport -Format csv 6>&1
        Add-DebugOut -Message  "  ... repository configuration set to OfflineCacheMode: Enable, RepositoryReport: csv"
        $ih_addFilter = Add-RepositoryFilter -Platform $pPlatformID -OS $pOS -OSVer $pOSVer -Category BIOS 6>&1
        Add-DebugOut -Message  "  ... repository filter added for Category: BIOS - will remove Softpaq once 1st sync completes"
        $ih_repoSync = Invoke-RepositorySync -ErrorAction Stop 6>&1
        Add-DebugOut -Message  "  ... repository created"
    } # Try/Catch block for Get-RepositoryInfo

    # cleanup the repository folder from any previous Softpaq files 
    # This is to ensure the repository is clean before any new Softpaq files are downloaded
    Add-DebugOut -Message "  ... cleaning up repository folder: $pRepoFolder"
    Get-ChildItem -Path $pRepoFolder -Recurse | 
        Where-Object { $_.Name -match '^sp\d{6}\.(exe|cva|html)$'-or ($_.Name -match '^.+\.(mark|csv)$') } |
        ForEach-Object { Remove-Item -Path $_.FullName }

    Add-DebugOut -Message "  < initialize-HPIArepository()"

    Set-Location $ir_CurrentLoc

    return $true
} # Function initialize-HPIArepository()

Function initialize-DownloadFolder {
    [CmdletBinding()] param( $pDownloadFolder )

    Add-DebugOut -Message "  > initialize-DownloadFolder() checking download folder: $($pDownloadFolder)"
    if ( -not (Test-Path $pDownloadFolder) ) {    
        Try {
            New-Item -Path $pDownloadFolder -ItemType directory | Out-Null
            Add-DebugOut -Message "  ... Download path was not found, created: $($pDownloadFolder)"
        } Catch {
            Throw "  ... problem: $($_)"        # Throw an error to exit if the folder cannot be created
        } # try/catch block for New-Item
    } # if ( -not (Test-Path $pRepoFolder) )

    return Resolve-Path $pDownloadFolder

} # Function initialize-DownloadFolder()

Function Invoke-SoftpaqInstall {
    [CmdletBinding()] param( $pSoftpaqObj, $pFolderPath )

    Add-DebugOut -Message "      > Invoke-SoftpaqInstall() - Softpaq: $($pSoftpaqObj.SoftpaqID)"

    $is_ExtractFolder = $pFolderPath+'\'+$pSoftpaqObj.SoftpaqID
    if (-not (Test-Path $is_ExtractFolder)) { New-Item -ItemType Directory -Path $is_ExtractFolder -Force }

    $is_returnCode = 1001           # something happened during installation!!!
    Try {
        $Error.Clear()
        # get the softpaq and extract it to the specified folder
        $null = (Get-Softpaq $pSoftpaqObj.SoftpaqID -Extract -DestinationPath "$($is_ExtractFolder)" -Overwrite skip) 6>&1
        Add-DebugOut -Message "`t  Extracted Softpaq $($pSoftpaqObj.SoftpaqID) to $($is_ExtractFolder)"

        # separate the installer executable from the silent install command options (it may not have any)
        # make "HpFirmwareUpdRec64.exe" look like HpFirmwareUpdRec64.exe --- no double quotes
        $is_installer = $pSoftpaqObj.SilentInstall.split(' ')[0].replace('"','')          # get the first part of the silent install command
        $is_installerArgs = $pSoftpaqObj.SilentInstall.split(' ')[1..$pSoftpaqObj.SilentInstall.split(' ').Count] -join ' '  # get the remaining parts of the silent install command
        $is_installerFullPath = $is_ExtractFolder + '\' + $is_installer                   # the path to the installer executable
        # Start the installer process with the silent install command
        # change to the extraction folder to make sure the installer can find the files it needs
        Set-Location $is_ExtractFolder
        if ( $is_installerArgs ) {
            Add-DebugOut -Message "`t  Installer: $($is_installerFullPath) args: ''$($is_installerArgs)''"
            $is_process = Start-Process -FilePath "$($is_installerFullPath)" -ArgumentList "$($is_installerArgs)" -Wait -PassThru -NoNewWindow -ErrorAction Stop
        } else {
            Add-DebugOut -Message "`t  Installer: $($is_installerFullPath)" 
            $is_process = Start-Process -FilePath "$($is_installerFullPath)" -Wait -PassThru -NoNewWindow -ErrorAction Stop
        } # else if ( $is_installerArgs )
        $is_returnCode = $is_process.ExitCode
        Add-DebugOut -Message "     ... done"
    } Catch {
        Add-DebugOut -Message "     ... failed to download/Install: $($_.Exception.Message)"
    } # Try/Catch block for Get-Softpaq Install
    switch ($is_returnCode) {
        0 { Add-DebugOut -Message "     ... installation succeeded" }
        1001 { Add-DebugOut -Message "     ... installation failed" }
        3010 { Add-DebugOut -Message "     ... installation succeeded. Reboot required." }
        default { Add-DebugOut -Message "     ... unknown return code: $($is_returnCode)" }
    }
    Add-DebugOut -Message "      < Invoke-SoftpaqInstall() - return code: $($is_process.ExitCode)" 

    return $is_returnCode

} # Function Invoke-SoftpaqInstall()

Function Get-SoftpaqCVAFile {
    [CmdletBinding()] param( $pSoftpaqID, $pFolderPath )

    Add-DebugOut -Message "    > Get-SoftpaqCVAFile() - Softpaq: $pSoftpaqID"

    $gs_DownloadSuccess = $false
    
    Try {
        Add-DebugOut -Message "    ... downloading CVA file for Softpaq: $pSoftpaqID"
        $null = Get-SoftpaqMetadataFile $pSoftpaqID -Overwrite 'Yes' -ErrorAction Stop 6>&1
        Add-DebugOut -Message "    ... done"
        $gs_DownloadSuccess = $true
    } Catch {
        Add-DebugOut -Message "    ... failed to download: $($Error[2])"
    } # Try/Catch block for Get-SoftpaqMetadata

    Add-DebugOut -Message "    < Get-SoftpaqCVAFile()"

    return $gs_DownloadSuccess
} # Function Get-SoftpaqCVAFile()

Function Get-SoftpaqReadmeFile {
    [CmdletBinding()] param( $pSoftpaqID, $pSoftpaqURL, $pFolderPath )

    Add-DebugOut -Message "    > Get-SoftpaqReadmeFile() - Softpaq: $pSoftpaqID - $($pFolderPath)"

    $gs_DownloadSuccess = $false

    Try {
        Add-DebugOut -Message "    ... downloading HTML file for Softpaq: $pSoftpaqID" 
        $gs_SoftpaqHtml = "$pFolderPath\$pSoftpaqID.html"
        $null = Invoke-WebRequest -UseBasicParsing -Uri "$($pSoftpaqURL)" -OutFile $gs_SoftpaqHtml
        Add-DebugOut -Message "    ... done" 
        $gs_DownloadSuccess = $true
    } Catch {
        Add-DebugOut -Message "    ... failed to download: $($_)" 
    } # Try/Catch block for Invoke-WebRequest

    Add-DebugOut -Message "    < Get-SoftpaqReadmeFile()"

    return $gs_DownloadSuccess
} # Function Get-SoftpaqReadmeFile()
Function Get-SoftpaqFiles {
    param( $pSoftpaqObj, $pFolderPath )

    Add-DebugOut -Message "    > Get-SoftpaqFiles() ($($pSoftpaqObj.SoftpaqID))"

    $gs_StartLocation = Get-Location
    Set-Location $pFolderPath

    $gs_SoftpaqExePath = "$pFolderPath\$($pSoftpaqObj.SoftpaqID).exe"

    Add-DebugOut -Message "    ... Softpaq $($pSoftpaqObj.SoftpaqID) --> $($pSoftpaqObj.SoftpaqName)"

    if ( Test-Path $gs_SoftpaqExePath ) {
        Add-DebugOut -Message "`t$($pSoftpaqObj.SoftpaqID) already downloaded - $($pSoftpaqObj.SoftpaqName)"
    } else {
        Try {
            $Error.Clear()
            Add-DebugOut -Message "`t  downloading "
            $null = (Get-Softpaq $pSoftpaqObj.SoftpaqID -DestinationPath "$($pFolderPath)") 6>&1
            Add-DebugOut -Message " ... done"
            $pSoftpaqObj.ActionReturnCode = 0
        } Catch {
            Add-DebugOut -Message " ... failed to download: $($Error[2])"
            $pSoftpaqObj.ActionReturnCode = -1
        } # Try/Catch block for Get-Softpaq
    } # else if ( Test-Path $gs_SoftpaqExePath )

    $null = Get-SoftpaqCVAFile $pSoftpaqObj.SoftpaqID $pFolderPath
    
    $null = Get-SoftpaqReadmeFile $pSoftpaqObj.SoftpaqID $pSoftpaqObj.url.replace('exe','html') $pFolderPath

    Add-DebugOut -Message "    < Get-SoftpaqFiles()"

    Set-Location $gs_StartLocation

    return $pSoftpaqObj.ActionReturnCode

} # Function Get-SoftpaqFiles

function Resolve-Software {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$pSoftpaqEntry,
        [Parameter(Mandatory)]$pSoftpaq,
        [Parameter(Mandatory)]$pLinks
    )

    Add-DebugOut -Message "   > Resolve-Software()"
    # handle exceptions in names between installed app and CVA Title name
    if ( $pSoftpaq.name -match 'BIOS Config Utility' ) { $pSoftpaq.name = 'HP BIOS Configuration Utility' }
    if ( $pSoftpaq.name -match 'Cloud Recovery' ) { $pSoftpaq.name = 'HP Cloud Recovery' }    
    $rs_Solution =  $pLinks.XMLRefFileSolutions.UpdateInfo | Where-Object {$_.id -eq $pSoftpaq.id}
    $rs_DetailFileInfo = Get-DetailFileVersions $rs_Solution $Script:AnalyzerEnv.OS $Script:AnalyzerEnv.OSVer
    <# returns @{
            DetailFileSoftpaqVersion = $null
            DetailFileInstalledVersion = $null
            DetailFileStatus = $Script:Config.Constants.SPQDETAILFILENOTFOUND
            SoftpaqStatus = $Script:Config.Constants.SPQNOTINSTALLED
        }  #>
    $pSoftpaqEntry.DetailFileVersion = $rs_DetailFileInfo.DetailFileVersion
    $pSoftpaqEntry.DetailFileInstalledVersion = $rs_DetailFileInfo.DetailFileInstalledVersion
    $pSoftpaqEntry.DetailFileStatus = $rs_DetailFileInfo.DetailFileStatus
    $pSoftpaqEntry.SoftpaqStatus = $rs_DetailFileInfo.SoftpaqStatus

    # Get UWP (Universal Windows Platform) app information related to the Softpaq - if any
    $rs_uwp = Get-UWP $pSoftpaq $pLinks
        <# returns [ordered]@{
                RefFileUWPName = $null
                RefFileUWPVersion = $null
                InstalledUWPName = $null
                InstalledUWPVersion = $null
            } # end of returned hash table
        #>
    if ($rs_uwp) {
        $pSoftpaqEntry.UWPName = $rs_uwp.InstalledUWPName
        $pSoftpaqEntry.UWPVersion = $rs_uwp.RefFileUWPVersion
        $pSoftpaqEntry.UWPInstallVersion = $rs_uwp.InstalledUWPVersion
        $pSoftpaqEntry.UWPStatus = $rs_uwp.UWPStatus
        if ( $pSoftpaqEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPUPDATEAVAILABLE ) {
            $pSoftpaqEntry.UWP = $true
            $pSoftpaqEntry.SoftpaqStatus = $Script:Config.Constants.SPQUPDATEAVAILABLE
        } # if ( $pSoftpaqEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPUPDATEAVAILABLE )
    } # if ($rs_uwp)

    Add-DebugOut -Message "   < Resolve-Software() - returning SoftpaqStatus: $($pSoftpaqEntry.SoftpaqStatus)" 
    return $pSoftpaqEntry

} # function Resolve-Software()
function Resolve-Diagnostics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$pSoftpaqEntry,
        [Parameter(Mandatory)]$pSoftpaq,
        [Parameter(Mandatory)]$pLinks
    )
    Add-DebugOut -Message "   > Resolve-Diagnostics()" 
    $rd_Solution =  $pLinks.XMLRefFileSolutions.UpdateInfo | Where-Object {$_.id -eq $pSoftpaq.id}

    $rd_DetailFileInfo = Get-DetailFileVersions $rd_Solution $Script:AnalyzerEnv.OS $Script:AnalyzerEnv.OSVer
    <# returns Softpaq and Installed Detail File versions
        @{
            DetailFileVersion = $null
            DetailFileInstalledVersion = $null
            DetailFileStatus = $Script:Config.Constants.SPQDETAILFILENOTFOUND
            SoftpaqStatus = $Script:Config.Constants.SPQNOTINSTALLED
        }  #>  
    $pSoftpaqEntry.DetailFileVersion = $rd_DetailFileInfo.DetailFileVersion
    $pSoftpaqEntry.DetailFileInstalledVersion = $rd_DetailFileInfo.DetailFileInstalledVersion
    $pSoftpaqEntry.DetailFileStatus = $rd_DetailFileInfo.DetailFileStatus
    $pSoftpaqEntry.SoftpaqStatus = $rd_DetailFileInfo.SoftpaqStatus

    Add-DebugOut -Message "   < Resolve-Diagnostics() - returning SoftpaqStatus: $($pSoftpaqEntry.SoftpaqStatus)" 
    return $pSoftpaqEntry
} # function Resolve-Diagnostics()

function Initialize-SoftpaqEntry {
    [CmdletBinding()]
    param( [Parameter(Mandatory)]$pSoftpaq )    
    return [ordered]@{
        SoftpaqID = $pSoftpaq.id
        SoftpaqName = $pSoftpaq.name
        SoftpaqVersion = $pSoftpaq.Version
        SoftpaqCategory = $pSoftpaq.Category
        SoftpaqStatus = $Script:Config.Constants.SPQNOTINSTALLED
        Category = $null                      # set later to 'BIOS', 'Driver', 'Software', 'Diagnostic'
        SoftpaqDate = $pSoftpaq.ReleaseDate
        ReleaseType = $pSoftpaq.ReleaseType
        URL = $pSoftpaq.url
        InstalledVersion = $null
        DetailFileVersion = $null
        DetailFileInstalledVersion = $null
        DetailFileStatus = $null
        Action = $Action
        ActionReturnCode = 0
        SilentInstall = $null
        Drivers = @()                                       # the Driver list
        UWP = $false
        UWPName = $null
        UWPVersion = $null
        UWPStatus = $Script:Config.Constants.SPQUWPNOTFOUND
    }
} # Function Initialize-SoftpaqEntry()

Function Test-AdminRights {

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
        $isAdmin = $principal.IsInRole($adminRole)
        
        # Additional validation - try to write to a protected location
        if ($isAdmin) {
            $testPath = "$env:SystemRoot\System32\test.txt"
            New-Item -Path $testPath -ItemType File -ErrorAction Stop | Remove-Item -ErrorAction Stop
        }
        
        return $isAdmin
    }
    catch {
        Add-DebugOut -Message "Failed to verify admin rights: $($_.Exception.Message)"
        return $false
    }

} # Test-AdminRights()

Function Resolve-OptionConflicts {

    # If the Subcategory was specified, set the Category to 'Driver' if not  already passed as argument
    # e.g., only select driver Softpaqs for reporting (that match the Subcategory argument)

    if ( $Script:SubCategory ) { 
        if ( $Script:Category -and ('driver' -notin $Script:Category) -and $Script:SubCategory ) {
            throw "Option -SubCategory conflicts with -Category 'bios' (no subcategories for BIOS Softpaqs)"
        } # if ( $Script:Category -and ('driver' -notin $Script:Category) -and $Script:SubCategory )
        if ( -not $Script:Category ) { 
            # If the Category is not set, set it to 'Driver' for reporting
            # This is needed for the case where the user specifies a SubCategory, but does not specify a Category
            Add-Verbose -Message "-- SubCategory specified with no -Category option. Setting Category to 'Driver' for reporting"
            $Script:Category = 'Driver'
        } # if ( -not $Script:Category )
    } # if ( $Script:SubCategory )

    # Category and RecommendedSoftware are mutually exclusive (currently -Category only allows 'Bios','Driver')
    if ( ($Script:Category -or $Script:SubCategory) -and $Script:RecommendedSoftware ) { 
        throw "Option -Category|-SubCategory conflicts with -RecommendedSoftware" 
    } # if ( ($Script:Category -or $Script:SubCategory) -and $Script:RecommendedSoftware )

} # Function Resolve-OptionConflicts()

Function Invoke-SoftpaqAnalysis {
    [CmdletBinding()] param( $pSoftpaq, $pDriversList, $pLists, $pCategory, $pSubCategory )

    Add-DebugOut -Message " > Invoke-SoftpaqAnalysis()"
    $is_Softpaq = Initialize-SoftpaqEntry $pSoftpaq            # initialize the Softpaq object
    # Find the silent install command - entry is in the Reference File Solutions section for the Softpaq
    $is_Softpaq.SilentInstall = ($pLists.XMLRefFileSolutions.UpdateInfo | 
        Where-Object { $_.id -eq $pSoftpaq.id }).SilentInstall
    Add-DebugOut -Message "     -- Silent Install Command: $($is_Softpaq.SilentInstall)"

    switch -regex ( $pSoftpaq.Category) {
        'bios' {
            if ( Test-CategoryFilter 'bios' $pCategory ) {
                $is_Softpaq.Category = 'BIOS'                  # set the category to BIOS
                $is_Softpaq = Resolve-BIOS $is_Softpaq $pSoftpaq
            } # if ( Test-CategoryFilter 'bios' $pCategory )
        } # 'bios'

        '^driver|^dock' {           # assume category 'dock' is a driver Softpaq - if firmware it would have been skipped
            if ( Test-CategoryFilter 'driver' $pCategory ) {
                # if SubCategory is set, check if the Softpaq category matches the SubCategory option from the command line
                if ( $Script:SubCategory ) {
                    $is_SubTest = Test-StringContainsArrayItems -pInputString $pSoftpaq.category -pSearchArray $Script:SubCategory
                    if ( -not $is_SubTest ) {
                        Add-DebugOut -Message "     -- Does NOT meet Category and SubCategory filters"
                        continue
                    } # if ( -not $is_SubTest )
                } # if ( $Script:SubCategory )
                Add-DebugOut -Message "     -- Softpaq meets Category and SubCategory filters" 
                $is_Softpaq.Category = 'Driver'                     # set the category to Driver
                $is_Softpaq = Resolve-Driver $is_Softpaq $pSoftpaq $pLists $pDriversList
            } # if ( Test-CategoryFilter 'driver' $pCategory )

        } # 'driver|utility'

        'software|utility' {
            if ( -not $pCategory ) {
                $is_Softpaq.Category = 'Software'                  # set the category to Software
                $is_Softpaq = Resolve-Software $is_Softpaq $pSoftpaq $pLists
            } # if ( -not $pCategory )
        } # 'software'

        'diagnostic' {
            if ( -not $pCategory ) {
                $is_Softpaq.Category = 'Diagnostic'                # set the category to Diagnostic
                $is_Softpaq = Resolve-Diagnostics $is_Softpaq $pSoftpaq $pLists
            } # if ( -not $pCategory )
        } # 'diagnostic'
       
    } # switch -wildcard ( $pSoftpaq.Category)
    Add-DebugOut -Message " < Invoke-SoftpaqAnalysis() - returning SoftpaqStatus: $($is_Softpaq.SoftpaqStatus)" 
    return $is_Softpaq
} # Function Invoke-SoftpaqAnalysis

Function ConvertTo-CsvLine {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$pSoftpaqEntry)
    
    # Format driver information if present
    $driverInfo = if ($pSoftpaqEntry.Drivers) {
        ($pSoftpaqEntry.Drivers | ForEach-Object {
            "$($_.DeviceID);$($_.PnPDriverVersion)/$($_.RefFileDriverVersion)"
        }) -join '|'
    } else { "" }

    # Create CSV line with essential fields
    [PSCustomObject]@{
        SoftpaqID = $pSoftpaqEntry.SoftpaqID
        Name = $pSoftpaqEntry.SoftpaqName
        SubCategory = $pSoftpaqEntry.SoftpaqCategory
        Status = $pSoftpaqEntry.SoftpaqStatus
        CurrentVersion = $pSoftpaqEntry.DetailFileInstalledVersion
        AvailableVersion = $pSoftpaqEntry.DetailFileVersion 
        ReleaseDate = $pSoftpaqEntry.SoftpaqDate
        UWPName = $pSoftpaqEntry.UWPName
        UWPVersion = $pSoftpaqEntry.UWPInstallVersion
        UWPAvailableVersion = $pSoftpaqEntry.UWPVersion
        Drivers = $driverInfo
        SilentInstall = $pSoftpaqEntry.SilentInstall
        URL = $pSoftpaqEntry.URL        
    }
} # Function ConvertTo-CsvLine()

Function New-JsonItem {
    [CmdletBinding()] param ( $pSoftpaqEntry )

    # Format driver information if present
    $driverInfo = if ($pSoftpaqEntry.Drivers) {
        ($pSoftpaqEntry.Drivers | ForEach-Object {
           [ordered]@{
               DeviceID = $_.CVAHWID
               RefFileDriverVersion = $_.RefFileDriverVersion
               PnPDriverVersion = $_.PnPDriverVersion
               DriverClass = $_.PnPDriverClass
           }
        })
    } else { $null }

    $nj_item = [ordered]@{
        SoftpaqID = $pSoftpaqEntry.SoftpaqID
        SoftpaqName = $pSoftpaqEntry.SoftpaqName
        Category = $pSoftpaqEntry.SoftpaqCategory
        SoftpaqVersion = $pSoftpaqEntry.SoftpaqVersion
        SoftpaqDate = $pSoftpaqEntry.SoftpaqDate
        InstalledVersion = $pSoftpaqEntry.InstalledVersion
        DetailFileVersion = $pSoftpaqEntry.DetailFileVersion
        DetailFileInstalledVersion = $pSoftpaqEntry.DetailFileInstalledVersion
        SilentInstall = $pSoftpaqEntry.SilentInstall
        URL = $pSoftpaqEntry.URL
        ReleaseType = $pSoftpaqEntry.ReleaseType
        Drivers = if ($driverInfo -ne "") { $driverInfo } else { $null }
        ActionReturnCode = $pSoftpaqEntry.ActionReturnCode
    }
    if ( $null -eq $nj_item.Drivers ) { $nj_item.Remove('Drivers') }  # remove empty Drivers entry
    if ( $null -eq $nj_item.InstalledVersion ) { $nj_item.Remove('InstalledVersion') }  # remove empty InstalledVersion entry
    if ( $null -eq $nj_item.DetailFileInstalledVersion ) { $nj_item.Remove('DetailFileInstalledVersion') }  # remove empty DetailFileInstalledVersion entry
    if ( $null -eq $nj_item.DetailFileVersion ) { $nj_item.Remove('DetailFileVersion') }  # remove empty DetailFileVersion entry
    
    return $nj_item

} # Function New-JsonItem()

#####################################################################################
# Start of Script
#####################################################################################

$CurrLocation = Get-location

#Resolve-OptionConflicts         # resolve options conflicts

# set up the environment for the action
$Script:AnalyzerEnv = Initialize-Environment $Script:Action $Script:ActionPath

$SoftpaqsUpdateList = @()                   # List of Softpaqs that have updates
$SoftpaqsNOUpdateList = @()                 # list of Softpaqs that do NOT require updates
$SoftpaqsNOTInstalledList = @()             # list of Softpaqs that are NOT installed
#>
# -----------------------------------------------------------------------------------

# Pre-filter Softpaqs to avoid processing unsupported ones
$FilteredSoftpaqs = $AnalyzerEnv.SoftpaqList | Where-Object {
    $_.Category -notmatch '^Manageability' -and
    -not ($_.Category -match '^Dock' -and $_.Name -notmatch '^All Docks') -and  # this includes dock drivers
    $_.name -notmatch '^HP Wolf|^HP Sure|^HP Services Scan|^MyHP' -and
    $_.name -notmatch 'HP Support Assistant'
} # Where-Object
Add-Verbose -Message "Filtered out certain Softpaqs - Manageability, Dock (excluding 'All Docks' drivers), and specific HP utilities"

# Process each Softpaq in the filtered list
$FilteredSoftpaqs | ForEach-Object {

    Add-Verbose -Message "=> $($_.Id)/$($_.Name) / $($_.Category) / Version:$($_.Version)"

    $SoftpaqEntry = Invoke-SoftpaqAnalysis $_ $Script:AnalyzerEnv.PnpSignedDrivers $AnalyzerEnv.Links $Category $SubCategory

    if ( $SoftpaqEntry.SoftpaqStatus -eq $Script:Config.Constants.SPQUPDATEAVAILABLE ) {

        switch ( $Action ) {
            'Scan' {
                # Analysis is done below after the switch
                break
            }
            'Download' {
                Add-Verbose -Message "-- Downloading Softpaqs to Folder: $($Script:ActionPath)"
                $SoftpaqEntry.ActionReturnCode = Get-SoftpaqFiles -pSoftpaqObj $SoftpaqEntry -pFolderPath $($Script:ActionPath)
                break
            }
            'CreateRepo' {
                Add-Verbose -Message "-- Creating repository, downloading Softpaqs to Folder: $($Script:ActionPath)"
                $SoftpaqEntry.ActionReturnCode = Get-SoftpaqFiles -pSoftpaqObj $SoftpaqEntry -pFolderPath $($Script:ActionPath)
                break
            }
            'Install' {
                Add-Verbose -Message "-- Installing Softpaq $($SoftpaqEntry.SoftpaqID) - $($SoftpaqEntry.SoftpaqName) version: $($SoftpaqEntry.SoftpaqVersion).."
                $SoftpaqEntry.ActionReturnCode = Invoke-SoftpaqInstall $SoftpaqEntry -pFolderPath $Script:ActionPath

                if ( $SoftpaqEntry.ActionReturnCode -eq 0 ) {
                    Add-Verbose -Message " Installer run successfully (0)" 
                } else {
                    Add-Verbose -Message " Installer return code: $($SoftpaqEntry.ActionReturnCode)" 
                } # else if ( $SoftpaqEntry.ActionReturnCode -eq 0 )

            } # 'Install'
            default {
                Add-Verbose -Message "Unknown action: $Action"
                break
            }
        }
        $SoftpaqsUpdateList += $SoftpaqEntry
    } # if ( $SoftpaqEntry.SoftpaqStatus -eq $Script:Config.Constants.SPQUPDATEAVAILABLE )

} # $FilteredSoftpaqs | ForEach-Object {}

# Line up Device information in the JSON output
$JsonOut = [Ordered]@{
    "PlatformName" = $AnalyzerEnv.PlatformName
    "PlatformID" = $AnalyzerEnv.PlatformID
    "Analyzer Version" = $ScriptVersion
    "OS" = $AnalyzerEnv.OS
    "OSVer" = $AnalyzerEnv.OSVer    
    "DateTime" = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    "Action" = $Action
    "Remediations" = @()
} # $JsonOut

# Process the list of Softpaqs that have updates for output
$SoftpaqsUpdateList | ForEach-Object {
    $msg = "$($_.SoftpaqID) - $($_.SoftpaqName) <$($_.SoftpaqCategory)> - $($_.SoftpaqVersion) [DetailFile/installed:$($_.DetailFileVersion)/$($_.DetailFileInstalledVersion)]"
    Add-ToLog -Message $msg

    # Export to  CSV and set-up JSON output
    $softpaqData = ConvertTo-CsvLine -pSoftpaqEntry $_
    $softpaqData | Export-Csv -Path $Script:Config.Paths.CsvFile -NoTypeInformation -Append

    $JsonOut.Remediations += New-JsonItem $_
} # $SoftpaqsUpdateList | ForEach-Object {}

# After processing all Softpaqs, export the aggregated JSON data
$JsonOut | ConvertTo-Json -Depth 10 | 
    ForEach-Object { $_.Replace('\u0026', '&').Replace('\\', '\') } | 
    Set-Content -Path $Script:Config.Paths.JsonFile -Encoding UTF8

# -----------------------------------------------------------------------------------

# Restore the current location
Set-location $CurrLocation


