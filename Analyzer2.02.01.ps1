<#
.Name
    Analyzer.ps1

.Synopsis
    Analyzer displays possible Softpaq updates available for a platform

.DESCRIPTION
    Analyzer finds 'BIOS', 'Driver', 'Software' Softpaqs that can update the current system

.Notes  
    Author: Dan Felman/HP Inc
                               
.Dependencies
    Requires HP Client Management Script Library
    HP Business class devices (as supported by HPIA and HP CMSL)
    Internet access. Analyzer downloads content from Internet

.Parameters
    -Action    <Scan|Download|CreateRepo> -- [string] what action to take, defaults to 'Scan'
        'Scan'      - check current device for updates
        'Download'  - download Softpaqs to ActionPath designed path after a scan completes - defaults to $env:TEMP\HPAnalyzer
        'CreateRepo' - create a repository in the specified path, and download Softpaq updates to repository
        -CleanOutput            -- [switch] only show Softpaqs that require action, not other output    
        -ActionPath <path>      -- [string] path to download Softpaqs to, defaults to $env:TEMP\HPAnalyzer
        This is the path where Softpaqs will be downloaded or repository created
        If the path does not exist, it will be created
    -Category <BIOS,Driver> -- [string[]] list of categories to check ONLY for certain updates
    -DebugOut               -- [switch] add debugging info to output
        This will output additional debugging information to the log file
        If -Silent is specified, it will only output to the log file
    -NoDots                 -- [switch] avoid output of '.' while looping thru Softpaqs (useful when logging output)
    -RecommendedSoftware    -- [switch] include HP Software HP recommends
        This will include HP software recommendations in the analysis:
        HP Notifications, HP Power Manager, HP Smart Health, HP Programmable Key
        HP Auto Lock and Awake, System Default Settings
        NOTE: DOES NOT apply with option: -Category
    -ShowHWID               -- [switch] list Hardware ID matched for each driver
    -Silent                 -- [switch] suppress all output to console - just outputs to log files
    -SubCategory <'Audio','Chipset','Graphics','Network','Video'> -- string[] applies only to 'Driver' category
        This will filter the driver updates by specific subcategories
        If not specified, all drivers will be checked
        If specified, only the drivers in the specified subcategories will be checked
        NOTE: -Category 'Driver' will be enabled even if not specified
    -Help                   -- [switch] describe available options

.Examples
    # check current device for updates
    Analyzer.ps1
    Analyzer.ps1 -NoDots            # check current device, avoid output of '.' while looping thru Softpaqs
    Analyzer.ps1 -ShowHWID -RecommendedSoftware     # check current platform, show matching Hardware IDs, include info on recommended HP software
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)] [ValidateSet('Scan', 'Download', 'CreateRepo')]
        [string]$Action = 'Scan',
    [Parameter(Mandatory = $false)]
        [string]$ActionPath = "$env:TEMP\HPAnalyzer",
    [Parameter(Mandatory = $false)] [ValidateSet('BIOS', 'Driver')]
        [string[]]$Category,
    [Parameter(Mandatory = $false)] 
        [switch]$CleanOutput,
    [Parameter(Mandatory = $false)] 
        [switch]$DebugOut,
    [Parameter(Mandatory = $false)]
        [switch]$NoDots,
    [Parameter(Mandatory = $false)]
        [switch]$RecommendedSoftware,
    [Parameter(Mandatory = $false)]
        [switch]$ShowHWID,
    [Parameter(Mandatory = $false)]
        [switch]$Silent,
    [Parameter(Mandatory = $false)] [ValidateSet('Audio', 'Chipset', 'Graphics', 'Network', 'Video')]
        [string[]]$SubCategory,
    [Parameter(Mandatory = $false)]
        [switch]$Help
) # param

if ( $Help ) {
    'Analyzer scans a supported HP business PC and displays BIOS/Driver/Software updates available for a platform - requires HP CMSL'
    'It returns the number of Softpaqs available for updates'
    'Runtime options:'
    'Analyzer.exe [-ShowHWID] [-noDots] ...'
    'Analyzer.exe [-S] [-n] ...'
        '  [-Action <Scan|Download|CreateRepo>]    # What action to take, defaults to ''Scan'''
        '  [-ActionPath <path>]         # where to download/create repository - defaults to $env:TEMP\HPAnalyzer'
        '  [-Category <BIOS,Driver>]    # ONLY check these categories for updates - Only BIOS and/or Driver categories ae allowed'
        '  [-CleanOutput]               # Only show Softpaqs that require action, not other output'
        '  [-DebugOut]                  # Output additional script debugging information'
        '  [-Help]                      # Display this help message'
        '  [-noDots]                    # Avoid displaying dot/Softpaq to console while running'
        '  [-RecommendedSoftware]       # Add HP software recommendations to analysis:'
        '                HP Notifications, HP Power Manager, HP Smart Health, HP Programmable Key'
        '                HP Auto Lock and Awake, System Default Settings'
        '                NOTE: DOES NOT apply with option: -Category'
        '  [-ShowHWID]                  # Display matching PnP hardware ID'
        '  [-Silent]                    # Suppress all output to console'
        '  [-SubCategory <Audio,Chipset,Video,Network>]     # Filter by specific driver subcategories'
    return 0
} # if ( $Help )

$startTime = (Get-Date).DateTime

$ScriptVersion = '2.02.01'

# Initialize configuration variables
$Script:Config = @{
    Constants = @{
        SPQNOTINSTALLED = -1
        SPQUPTODATE = 0
        SPQUPDATEAVAILABLE = 1
        SPQUWPNOTINSTALLED = -11
        SPQUWPUPTODATE = 10
        SPQUWPUPDATEAVAILABLE = 11
    }
    Paths = @{   
        LogFile = "$($PSScriptRoot)\Analyzer-$((Get-Date).ToString('yyyyMMdd-HHmm')).txt"
        DebugFile = "$($PSScriptRoot)\Analyzer-Debug-$((Get-Date).ToString('yyyyMMdd-HHmm')).log"
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
    RecommendedSWList = @(
        'HP Notifications', 'HP Power Manager', 'HP Smart Health', 'HP Programmable Key', 
        'HP Programmable Key (SA)', 'HP Auto Lock and Awake', 'System Default Settings'
    ) # RecommendedSWList
    
} # $Script:Config

# error codes for color coding, etc.
$TypeError = -1 ; $TypeNorm = 1 ; $TypeWarn = 2 ; $TypeDebug = 4 ; $TypeSuccess = 5 ; $TypeNoNewline = 10

function TraceLog {
	[CmdletBinding()] param( 
        [Parameter(Mandatory = $true)]$Message, 
        [Parameter(Mandatory = $false)][int]$Type ) 

	if ( $null -eq $Type ) { $Type = $TypeNorm }
    if ( $Type -eq $TypeError ) { $Message = "ERROR: $Message" }

    if ( $Message -ne '.') {
        $Message | Out-File -Append -Encoding UTF8 -FilePath $Script:Config.Paths.LogFile
    }
    if ( -not $Script:Silent ) {
        if ( $Type -eq $TypeNoNewline ) { Write-Host $Message -NoNewline } else { Write-Host $Message }
    } 
} # function TraceLog

if ( -not $CleanOutput ) { TraceLog -Message "Analyzer: $($ScriptVersion) -- $($startTime)" $TypeNorm  }
# Log the command line
if ( $DebugOut ) { TraceLog -Message "-- Script executed as: $($MyInvocation.Line)" $TypeNorm }

<######################################################################################
    Function Resolve-OptionConflicts
    This function resolves conflicts between the options specified in the command line arguments
    It checks for conflicts between -Category, -SubCategory, and -RecommendedSoftware options
#>#####################################################################################
Function Resolve-OptionConflicts {

    # If the Subcategory was specified, set the Category to 'Driver' if not  already passed as argument
    # e.g., only select driver Softpaqs for reporting (that match the Subcategory argument)

    if ( $SubCategory ) { 
        if ( $Category -and ('driver' -notin $Category) -and $SubCategory ) {
            throw "Option -SubCategory conflicts with -Category 'bios' (no subcategories for BIOS Softpaqs)"
        } # if ( $Category -and ('driver' -notin $Category) -and $SubCategory )
        if ( -not $Category ) { 
            # If the Category is not set, set it to 'Driver' for reporting
            # This is needed for the case where the user specifies a SubCategory, but does not specify a Category
            if ( -not $CleanOutput ) { TraceLog -Message "-- SubCategory specified with no -Category option. Setting Category to 'Driver' for reporting" $TypeNorm }
            $Category = 'Driver'
        } # if ( -not $Category )
    } # if ( $SubCategory )

    # Category and RecommendedSoftware are mutually exclusive (currently -Category only allows 'Bios','Driver')
    if ( ($Category -or $SubCategory) -and $RecommendedSoftware ) { 
        throw "Option -Category|-SubCategory conflicts with -RecommendedSoftware" 
    } # if ( ($Category -or $SubCategory) -and $RecommendedSoftware )

} # Function Resolve-OptionConflicts()

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

    $ie_env = @{}

    # obtain the system's OS information
    $ie_WinOS = Get-CimInstance win32_operatingsystem        # 'win'+$ie_WinOS.version.split('.')[0]
    $ie_env.OS = if ($ie_WinOS.BuildNumber -lt 22000) { 'win10' } else { 'win11' }
    $ie_env.OSVer = $Script:Config.OSVersionMap[$ie_WinOS.BuildNumber]
    $ie_env.architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture

    # next, check if HP CMSL is installed while obtaining the platform information
    Try {
        $ie_env.PlatformID = Get-HPDeviceProductID
        $ie_env.PlatformName = Get-HPDeviceModel
        if ( -not $CleanOutput ) { TraceLog -Message "-- Analyzing platform: [$($ie_env.PlatformID)] $($ie_env.PlatformName) -- OS: $($ie_env.OS)/$($ie_env.OSVer)" $TypeNorm }
        $ie_env.fileName = "$($ie_env.PlatformID)_$($ie_env.architecture)_$($ie_env.OS.Substring(3)).0.$($ie_env.OSVer).xml"
    } catch {
        throw "Failed to get HP Device Product ID or Model Name. Ensure HP CMSL is installed and the device is supported."
    } # Try-catch

    # finally, obtain the Softpaq list for the platform and OS
    try {
        if ( -not $CleanOutput ) { TraceLog -Message "-- Obtaining Softpaq List" $false }
        $ie_env.CacheDir =  $PSScriptRoot+"\cache"            # set cache path to script location
        $ie_env.SoftpaqList = Get-SoftpaqList -CacheDir "$($ie_env.CacheDir)" -ErrorAction Stop
        $ie_env.XMLFilePath = Get-ChildItem -Path "$($ie_env.CacheDir)" -Include "*.xml" -Recurse -File | 
            Where-Object { $_.Name -match $ie_env.PlatformID }        
        $ie_env.XmlContent = [xml](Get-Content -Path $ie_env.XMLFilePath)
        if ( -not $CleanOutput ) { TraceLog -Message "-- Working File: $($ie_env.XMLFilePath)" $TypeNorm}
    } catch {
        throw "Failed to retrieve Softpaq list or XML file. Ensure HP CMSL is installed and the device is supported."   
    } # Try-catch 

    $ie_env.Links = @{
        'InstalledApps' = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')
        'InstalledWOWApps' = (Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        'InstalledAppxApps' = (Get-AppxPackage)
        'XMLRefFileSolutions' = $ie_env.XmlContent.SelectNodes("ImagePal/Solutions")
        'XMLRefFileDevices' = $ie_env.XmlContent.SelectNodes("ImagePal/Devices")
        'XMLRefFileUWPApps' = $ie_env.XmlContent.SelectNodes("ImagePal/SystemInfo/UWPApps/UWPApp")
    } # $Links

    if ( -not $CleanOutput ) { TraceLog -Message '-- Obtaining PnP Driver list ...' $TypeNorm }
    $ie_env.PnpSignedDrivers = Get-CimInstance win32_PnpSignedDriver | 
        Where-Object { $_.DriverVersion -and `
            ($_.DriverProviderName -ne 'Microsoft') -and `
            (-not $_.DeviceID.StartsWith("{")) -and `
            ($_.DeviceClass -ne 'SOFTWARECOMPONENT')
        } # Where-Object

    # finally, initialize for the specific actions
    
    switch ($pAction) {
        'Scan' {
            if ( -not $CleanOutput ) { TraceLog -Message "-- Analyzing device and generating Report in $($pActionPath)" $TypeNorm }
        } # 'Scan'
        'Download' {
            if ( -not $CleanOutput ) { TraceLog -Message "-- Initializing Softpaq Download Folder: $($pActionPath)" $TypeNorm }
            initialize-DownloadFolder $pActionPath
        } # 'Download'        
        'CreateRepo' {
            if ( -not $CleanOutput ) { TraceLog -Message "-- Initializing HP Image Assistant Repository at $($pActionPath)" $TypeNorm }
            if (-not (initialize-HPIArepository $pActionPath) ) {
                Throw "Failed to initialize HP Image Assistant Repository "
            } # if (-not (initialize-HPIArepository $Script:ActionPath) )
        } # 'CreateRepo'
    } # switch ( $Action )

    return $ie_env
} # Function Initialize-Environment

#####################################################################################
# End of initialization
#####################################################################################

<######################################################################################
    Function Get-ReferenceFileDeviceDriverInfo
    retrieves an associated Device entry from a Reference File <Devices> section
    parm: $pSoftpaqID               Softpaq ID to match in the Reference File
          $pXMLRefFileDevices       list of devices in the Reference File
          $pDeviceToMatch           device to match in the Reference File
    return: $gr_RefernceFileDeviceDriverInfo = @{
            HardwareID=$null
            RefFileDriverVersion=$null
            RefFileDriverDate=$null
######################################################################################>
Function Get-ReferenceFileDeviceDriverInfo {
    [CmdletBinding()] param( $pSoftpaqID, $pXMLRefFileDevices, $pDeviceToMatch )

    if ( $DebugOut ) { TraceLog -Message "      > Get-ReferenceFileDeviceDriverInfo() - Search <Devices> for a match to:$($pDeviceToMatch)" $TypeNorm }

    $gr_RefernceFileDeviceDriverInfo = @{       # setup the return hash table defaults
        HardwareID=$null
        RefFileDriverVersion=$null
        RefFileDriverDate=$null
    } # $gr_RefernceFileDeviceDriverInfo

    # The information to return is in the Reference File <Devices> section
    foreach ( $gr_iDevice in $pXMLRefFileDevices.Device ) {

        if ( $gr_iDevice.Solutions.UpdateInfo.IdRef -match $pSoftpaqID ) {  # we have the Softpaq matched in <Devices><Device> entry

            $gr_DevType = $pDeviceToMatch.split('\')[0]                     # get the device type to match 
            $gr_DevPID = $pDeviceToMatch.split('&')[1]                      # get the PID string

            $gr_pattern = "^(?=.*$($gr_DevType))(?=.*$($gr_DevPID))"

            #if ( ($gr_iDevice.DeviceID -match "^$($gr_DevType)") -and ($gr_iDevice.DeviceID -match "$($gr_DevPID)" ) ) {
            if ( $gr_iDevice.DeviceID -match $gr_pattern ) {
                $gr_RefernceFileDeviceDriverInfo.HardwareID = $gr_iDevice.DeviceID
                $gr_RefernceFileDeviceDriverInfo.RefFileDriverVersion = $gr_iDevice.DriverVersion
                $gr_RefernceFileDeviceDriverInfo.RefFileDriverDate = $gr_iDevice.DriverDate
                break
            } # if ( ($gr_iDevice.DeviceID -match "^$($gr_DevType)") -and ($gr_iDevice.DeviceID -match "$($gr_DevPID)" ) )

        } # if ( $gr_iDevice.Solutions.UpdateInfo.IdRef -match $pSoftpaqID )

    } # foreach ( $gr_iDevice in $pXMLRefFileDevices.Device )

    # if the <Devices> section does not have this entry, check in <Solutions> next for the Softpaq Version
    if ( $null -eq $gr_RefernceFileDeviceDriverInfo.RefFileDriverVersion ) { 
        foreach ( $gr_iXMLRefFileSolution in $Script:XMLRefFileSolutions.UpdateInfo ) {
            if ( $gr_iXMLRefFileSolution.ID -like $pSoftpaqID ) {
                $gr_RefernceFileDeviceDriverInfo.RefFileDriverVersion = $gr_iXMLRefFileSolution.Version
                $gr_RefernceFileDeviceDriverInfo.RefFileDriverDate = $gr_iXMLRefFileSolution.DateReleased
                if ( $DebugOut ) { TraceLog -Message "      <XML Reference File <Solution> - Found matching driver version" } $TypeNorm 
                break
            } # if ( $gr_iXMLRefFileSolution.ID -like $pSoftpaqID )
        } # foreach ( $gr_iXMLRefFileSolution in $Script:XMLRefFileSolutions.UpdateInfo )
    } # if ( $null -eq $gr_iXMLRefFileSolution.Version )
    
    if ( $DebugOut ) { TraceLog -Message "      < Get-ReferenceFileDeviceDriverInfo() - matched $($gr_RefernceFileDeviceDriverInfo.HardwareID)/$($gr_RefernceFileDeviceDriverInfo.RefFileDriverVersion)" $TypeNorm  }

    return $gr_RefernceFileDeviceDriverInfo

} # Function Get-ReferenceFileDeviceDriverInfo

<######################################################################################
    Function Get-HardwareMatch
        This function checks for a Softpaq's supported Hardware ID in [Devices] section
        It returns information on a matching PnPDriver 
    parm:   $pSoftpaqID
            $pXMLDevicesList        list of devices in the Reference File
            $pPnPDrivers            list of installed PnP drivers
    return  HardwareID
            RefFileDriverVersion
            PnPDiverVersion
            PnpDriverDate
            PnpDriverClass
#>#####################################################################################
Function Get-HardwareMatch {
    [CmdletBinding()] param( $pSoftpaqID, $pXMLDevicesList, $pPnPDrivers )

    if ( $DebugOut ) { TraceLog -Message '   > Get-HardwareMatch() - Search PnP Drivers for a match' }$TypeNorm 

    # The information to return
    $gh_HardwareInfo = @{
        HardwareID=$null
        PnPDiverVersion=$null
        PnpDriverDate=$null
        PnpDriverClass=$null
    } # $gh_HardwareInfo

    # Get all Softpaq matching devices from the XML Reference File <Devices> section
    $gh_MatchedRefFileDeviceList =  $pXMLDevicesList.Device | Where-Object {$_.Solutions.UpdateInfo.IdRef -like $pSoftpaqID }

    foreach ($gh_iEntry in $gh_MatchedRefFileDeviceList) {                    

        $gh_DevHash = $gh_iEntry.DeviceID.split('\')
        $gh_DevType = $gh_DevHash[0]                                    # get the device type to match 
        # handle deviceID without VEN_PID identities (typically HP drivers of some kind - like Hotkeys)
        $gh_DevPID = $gh_DevHash[1]                                     # get the PID string
        if ( $gh_DevPID.contains('&') ) { $gh_DevPID = $gh_DevPID.split('&')[1] }     

        $gh_pattern = "^(?=.*$($gh_DevType))(?=.*$($gh_DevPID))"

        foreach ( $gh_iPnPDriver in $pPnPDrivers ) {
            if ( $gh_iPnPDriver.DriverProviderName -like 'Microsoft*' ) { continue } # skip Microsoft drivers
            if ( $null -eq $gh_iPnPDriver.DeviceID ) { continue }
            if ( $gh_iPnPDriver.DeviceID -match "$gh_pattern" ) {
                if ( $DebugOut ) { TraceLog -Message "      matching $($gh_iEntry.DeviceID) with this pattern: {$($gh_pattern)}" $TypeNorm  }   
                if ( $DebugOut ) { TraceLog -Message "      matched PnP DeviceID $($gh_iPnPDriver.DeviceID) - $($gh_iPnPDriver.DriverVersion)" $TypeNorm  }                    
                $gh_HardwareInfo.HardwareID = $gh_iEntry.DeviceID
                $gh_HardwareInfo.PnPDriverVersion = $gh_iPnPDriver.DriverVersion
                $gh_HardwareInfo.PnpDriverDate = $gh_iPnPDriver.DriverDate
                $gh_HardwareInfo.PnpDriverClass = $gh_iPnPDriver.DeviceClass
                # convert DriverDate to appropriate string
                if ( $gh_HardwareInfo.DriverDate ) { $gh_HardwareInfo.DriverDate = $gh_HardwareInfo.DriverDate.ToString("MM-dd-yyyy") }
                break
            } # if ( $gh_iPnPDriver.DeviceID -match "$gh_pattern" )
        } # foreach ( $gh_iPnPDriver in $pPnPDrivers )
        if ( $gh_HardwareInfo.HardwareID ) { break }
    } # foreach ($gh_iEntry in $gh_MatchedRefFileDeviceList)

    if ( $DebugOut ) {
        if ( $gh_HardwareInfo.HardwareID ) {
            TraceLog -Message "   < Get-HardwareMatch() - returning"  $TypeNorm 
            TraceLog -Message "   ... PnP HWID matched: $($gh_HardwareInfo.HardwareID)" $TypeNorm 
            TraceLog -Message "   ... PnP Driver version: $($gh_HardwareInfo.PnPDriverVersion)" $TypeNorm 
            TraceLog -Message "   ... PnP Driver Date: $($gh_HardwareInfo.PnpDriverDate)" $TypeNorm 
            TraceLog -Message "   ... PnP Driver Class: $($gh_HardwareInfo.PnpDriverClass)" $TypeNorm 
        } else {
            TraceLog -Message '   < Get-HardwareMatch() PnP driver NOT matched' $TypeNorm 
        } # else if ( $gh_HardwareInfo.HardwareID )
    } # if ( $DebugOut )

    return $gh_HardwareInfo
} # Function Get-HardwareMatch

<######################################################################################
Function Expand-CVAPath
    This function expands the CVA path tokens in the driver path
    parm: $pDriverPath   the driver path to expand
    return: $pDriverPath  the expanded driver path
    example: <WINSYSDIR>\DriverStore\FileRepository\iigd_dch.inf_amd64_e35423a455e0d784\igdkmdn64.sys
            becomes C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_e35423a455e0d784\igdkmdn64.sys   
#>#####################################################################################
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

Function Get-DetailFilePropertyVersion {
    [CmdletBinding()] param( $pFileDetailPath )

    #$gd_FileVersion = [version]"0.0.0.0" 

     # get the driver file version from the file propery entry
    # Use ProductVersion or FileVersion as a backup
    $gd_FileVersionInfo = (Get-Item $pFileDetailPath).VersionInfo

    $gd_FileVersion = $gd_FileVersionInfo.ProductVersion

    if ( $gd_FileVersion -notmatch '_\d+\.\d+\.\d+\.\d+$' ) { $gd_FileVersion = $gd_FileVersionInfo.FileVersion}

    $gd_FileVersion = $gd_FileVersion.split(' ').replace(',','.')       # handle bad File Version entry, and using , instead of . as separator
    $gd_FileVersion = $gd_FileVersion.split('+')[0]                     # issue with ibtusb.sys: ProductVersion entry includes addition info
    if ( $DebugOut ) { TraceLog -Message "       < Get-SingleDetailFile() [DetailFile] file found: $($pFileDetailPath)/$($gd_FileVersion)" }

    return [PSCustomObject]@{ FullPath = $pFileDetailPath ; ProductVersion = $gd_FileVersion } 

} # Function Get-DetailFilePropertyVersion()

<######################################################################################
Function Get-InstalledDetailFileInfo
    This function returns the full path and version of the driver file
    parm: $pFileDetail   Entry frmo Reference File Solutions DetailFile section
    return: $gf_FileInfo = @{
            FullPath = $null
            ProductVersion = $null
    } # $gf_FileInfo
#>#####################################################################################
Function Get-InstalledDetailFileInfo {
    [CmdletBinding()] param( $pFileDetail )
    <# argument example
        <FileDetail>
          <FileName>igdkmdn64.sys</FileName>
          <Directory>&lt;WINSYSDIR&gt;\DriverStore\FileRepository\iigd_dch.inf_amd64_e35423a455e0d784\</Directory>
          <Version>32.0.101.6651</Version>
          <OS>W11_24H2</OS>
        </FileDetail>
    #>
    if ( $DebugOut ) { TraceLog -Message "     > Get-InstalledDetailFileInfo() - search for $($pFileDetail.FileName)" $TypeNorm  }

    $gi_InstalledFileInfo = @{
        FullPath = $null
        ProductVersion = $null
    } # gi_InstalledFileInfo
  
    # there may be multiple entries in the [DetailFileInformation] section that match the OS
    $pFileDetail | ForEach-Object {

        $gi_ExpandedPath = Expand-CVAPath $_.Directory
        $gi_FilePath = Join-Path -Path $gi_ExpandedPath -ChildPath $_.FileName
        $gi_FileName = $_.FileName

        if ( Test-Path $gi_FilePath ) {    

            $gi_InstalledFileInfo =  (Get-DetailFilePropertyVersion $gi_FilePath)

        } else {
            # search for the driver file from the parent path, in case the location is updated for every version
            $gi_parentFolder = Split-Path $gi_ExpandedPath -Parent
            $gi_FolderName = Split-Path -Path $gi_parentFolder -Leaf
            $gi_appName = $gi_FolderName.split('.')[0]
            if ( $gi_ExpandedPath -match 'x64$' ) { $gi_parentFolder = Split-Path $gi_parentFolder -Parent }                   
            
            if ( $DebugOut ) { TraceLog -Message "       Searching for $($gi_FileName) from parent folder $($gi_parentFolder)" $TypeNorm  }        
            
            $gi_FilePaths = Get-ChildItem -Path $gi_parentFolder -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -eq $gi_FileName }
            
            if ( $DebugOut ) { TraceLog -Message "       There are $($gi_FilePaths.Count) files matching $($gi_FileName) in parent folder $($gi_parentFolder)" $TypeNorm }    

            # if there are multiple files matching the name starting with the parent folder
            # try to sort by ProductVersion if populated and return the most recent
            if ( $gi_FilePaths.Count -gt 0 ) {

                # get all entries found                
                $gi_fileDetails = foreach ($gifile in $gi_FilePaths) {
                    $gi_fileInfo = Get-Item $gifile.FullName
                    if ( $gi_fileInfo.VersionInfo.ProductVersion -match '_\d+\.\d+\.\d+\.\d+$' ) {
                        [PSCustomObject]@{ FullPath = $gi_fileInfo.FullName ; ProductVersion = $gi_fileInfo.VersionInfo.ProductVersion }                                   
                    } else {
                        [PSCustomObject]@{ FullPath = $gi_fileInfo.FullName ; ProductVersion = $gi_fileInfo.VersionInfo.FileVersion }
                    }
                } # foreach ($file in $gi_FilePaths)
                
                # Try to sort by ProductVersion if populated
                $gi_InstalledFileInfo = $gi_fileDetails | Sort-Object -Property @{
                    Expression = { 
                        if ([string]::IsNullOrEmpty($_.ProductVersion)) { [version]"0.0.0.0" } else { try { [version]$_.ProductVersion } catch { [version]"0.0.0.0" } }
                    }
                    Descending = $true
                }, LastWriteTime -Descending | Select-Object -First 1

            } # if ($gi_InstalledFileInfo.Count -gt 0)    

            if ( $DebugOut ) { TraceLog -Message "       [DetailFile] file found: $($gi_InstalledFileInfo.FullPath)/$($gi_InstalledFileInfo.ProductVersion)" $TypeNorm  }

        } # else if ( Test-Path $gi_FilePath )

    } # $pFileDetail | ForEach-Object

    if ( $DebugOut ) { TraceLog -Message "     < Get-InstalledDetailFileInfo()" $TypeNorm  }    

    return $gi_InstalledFileInfo          

} # Function Get-InstalledDetailFileInfo

<######################################################################################
    Function Get-SolutionDetailFileDriverInfo
    This function returns the driver version string from the CVA file's <Solution> [DetailFileInformation] section
    It relies on the CVA file's [DetailFileInformation] section from the driver file,
        matching the OS version being analyzed or the generic 'WT64'
    Each [DetailFileInformation] entry has the DriverName=<...> syntax where the '='
        separates the location of the driver file from the version string and OS support
    example:
        ptf.dll=<WINSYSDIR>\DriverStore\FileRepository\dptf_cpu.inf_amd64_897ea327b3fe52f7\,0x0008,0x0007,0x29CC,0x57E6,WT64_2004
    parm: $pSolution      the Softpaq solution from the reference file to check
          $pOS            the OS version to check against
          $pOSVer         the OS version to check against
    return: $gd_DetailFileHash = @{
            DetailFileSoftpaqVersion = $null
            DetailFileInstalledVersion = $null }
######################################################################################>
Function Get-SolutionDetailFileDriverInfo {
    [CmdletBinding()] param( $pSolution, $pOS , $pOSVer )

    if ( $DebugOut ) { TraceLog -Message "   > Get-SolutionDetailFileDriverInfo() - searching for $($pSolution.Id)" $TypeNorm  }

    $gd_DetailFileHash = @{
        DetailFileSoftpaqVersion = $null
        DetailFileInstalledVersion = "0.0.0.0"
    } # $gd_DetailFileHash

    # Find the matching OS version entry in the Reference File <DetailFileInformation> section of a Solution (aka Softpaq)
    <# Reference File DetailFile Information example:
        <FileDetail>
          <FileName>igdkmdn64.sys</FileName>
          <Directory>&lt;WINSYSDIR&gt;\DriverStore\FileRepository\iigd_dch.inf_amd64_e35423a455e0d784\</Directory>
          <Version>32.0.101.6651</Version>
          <OS>W11_24H2</OS>
        </FileDetail>
    #>
    [array]$gd_RefFile_FileDetailEntry = $pSolution.DetailFileInformation.FileDetail | Where-Object {$_.OS -eq "$($pOS)_$($pOSVer)"}
    if ( $DebugOut ) { TraceLog -Message "   ... search in: $($gd_RefFile_FileDetailEntry.Directory) for $($gd_RefFile_FileDetailEntry.FileName)/$($gd_RefFile_FileDetailEntry.Version)" $TypeNorm  }

    if ( $gd_RefFile_FileDetailEntry.count -gt 0 ) {
        # default to first entry found - assume all entries would have the same version
        $gd_DetailFileHash.DetailFileSoftpaqVersion = $gd_RefFile_FileDetailEntry[0].Version    # we assumed an array returned
        <# Get-InstalledDetailFileInfo() returns the top matching entry
            $gi_InstalledFileInfo = @{
                FullPath = $null
                ProductVersion = $null
            } # gi_InstalledFileInfo
        #>
        $gd_DetailFileinfo = Get-InstalledDetailFileInfo $gd_RefFile_FileDetailEntry        
        $gd_DetailFileHash.DetailFileInstalledVersion = ($gd_DetailFileinfo.ProductVersion)
    } # if ( $null -ne $gd_RefFile_FileDetailEntry )

    if ( $DebugOut ) {
        TraceLog -Message "   < Get-SolutionDetailFileDriverInfo()" $TypeNorm 
        TraceLog -Message "     ... DetailFile path $($gd_DetailFileinfo.FullPath)" $TypeNorm 
        TraceLog -Message "     ... DetailFile Softpaq Version/Installed Version $($gd_DetailFileHash.DetailFileSoftpaqVersion)/$($gd_DetailFileHash.DetailFileInstalledVersion)" $TypeNorm 
    } # if ( $DebugOut )

    return $gd_DetailFileHash

} # Function Get-SolutionDetailFileDriverInfo

<######################################################################################
    Function Get-UWPInfoFromRefFile
        This functions determines if the Softpaq has a UWP requirement and if it is installed
        It returns a list of UWP entries from the Reference File that match the installed appx
    parm: $pSoftpaq         Softpaq object returned from Get-SoftpaqList
            $pLists         list of registry and Reference file entry lists
    return: $gu_MatchedRefFileUWPList = @(
        RefFileUWPName = $null
        RefFileUWPVersion = $null
        InstalledUWPName = $null
        InstalledUWPVersion = $null
        Status = $Script:Config.Constants.SPQUWPNOTINSTALLED
    ) # $gu_MatchedRefFileUWPList
#>#####################################################################################
Function Get-UWPInfoFromRefFile {
    [CmdletBinding()] param( $pSoftpaq, $pLists ) 
 
    $gu_MatchedRefFileUWPEntry = @{
        RefFileUWPName = $null
        RefFileUWPVersion = $null
        InstalledUWPName = $null
        InstalledUWPVersion = $null
        Status = $Script:Config.Constants.SPQUWPNOTINSTALLED
    }
    $gu_MatchedRefFileUWPList = @()

    if ( $DebugOut ) { TraceLog -Message "   > Get-UWPInfoFromRefFile(): $($pSoftpaq.ID) - Checking for UWP appx" $TypeNorm  }

    # Scan every UWP entry in the Reference file for matching installed appx
    foreach ( $iUWPEntry in $pLists.XMLRefFileUWPApps ) {
        # see if that entry is installed in this system... Use Softpaq ID to match
        # match the reference file UWP entry to the current Softpaq (there may be more than 1)
        if ( $pSoftpaq.ID -like $iUWPEntry.Solutions.UpdateInfo.IdRef ) {    
            if ( $DebugOut ) { TraceLog -Message "   .. Get-UWPInfoFromRefFile(): matched $($pSoftpaq.ID)" $TypeNorm }

            #  find a matching installed Appx: ex. AD2F1837.HPProgrammableKey_1.0.17.0_x64__v10z8vjag6ke6

            $gu_InstalledAppx = $pLists.InstalledAppxApps | ForEach-Object {
                 if ( $_ -match $iUWPEntry.Name ) { return $_ }
            } # $pInstalledAppxList | ForEach-Object

            if ( $gu_InstalledAppx ) {
                if ( $DebugOut ) { TraceLog -Message "   ... found: $($gu_InstalledAppx.Name)" $TypeNorm }
                $gu_InstalledAppxList = $gu_InstalledAppx.PackageFullName.split('_')
                $gu_MatchedRefFileUWPEntry = @{ 
                    RefFileUWPName = $iUWPEntry.Name.split('.')[1]
                    RefFileUWPVersion = $iUWPEntry.Version
                    InstalledUWPName = $gu_InstalledAppxList[0]
                    InstalledUWPVersion = $gu_InstalledAppxList[1]
                    }
                    if ( $DebugOut ) { TraceLog -Message "   ... Installed package name: $($gu_InstalledAppx.PackageFullName)" $TypeNorm  }
                    if ( $DebugOut ) { TraceLog -Message "   ... Installed UWP name: $($gu_MatchedRefFileUWPEntry.InstalledUWPName)/$($gu_MatchedRefFileUWPEntry.InstalledUWPVersion)" $TypeNorm  }

                If ( [version]$gu_MatchedRefFileUWPEntry.InstalledUWPVersion -lt [version]$gu_MatchedRefFileUWPEntry.RefFileUWPVersion ) {
                    $gu_MatchedRefFileUWPEntry.Status = $Script:Config.Constants.SPQUWPUPDATEAVAILABLE
                } else {
                    $gu_MatchedRefFileUWPEntry.Status = $Script:Config.Constants.SPQUWPUPTODATE
                } # else If ( [version]$gu_MatchedRefFileUWPEntry.InstalledUWPVersion -lt [version]$gu_MatchedRefFileUWPEntry.RefFileUWPVersion )
                if ( $DebugOut ) { TraceLog -Message "   ... reference file/installed appx version: $($gu_MatchedRefFileUWPEntry.RefFileUWPVersion)/$($gu_MatchedRefFileUWPEntry.InstalledUWPVersion)" $TypeNorm  }
                if ( $DebugOut ) { TraceLog -Message "   ... Installed UWP status: $($gu_MatchedRefFileUWPEntry.Status)" $TypeNorm  }

                $gu_MatchedRefFileUWPList += $gu_MatchedRefFileUWPEntry

            } # if ( $gu_InstalledAppx )
        } # if ( $pSoftpaq.ID -like $iUWPEntry.Solutions.UpdateInfo.IdRef ) 
    } # foreach ( $iUWPEntry in $pLists.XMLRefFileUWPApps )

    if ( $DebugOut ) { TraceLog -Message "   < Get-UWPInfoFromRefFile(): $($pSoftpaq.ID) - Found $($gu_MatchedRefFileUWPList.Count) UWP(s)" $true }

    return $gu_MatchedRefFileUWPList
} # Function Get-UWPInfoFromRefFile

<######################################################################################
    Function Find-Driver
        This functions attempts to match a Softpaq against an installed driver
        It parses the Reference File [Devices] HW PnP list against this PnP Hardware IDs to find
        a match, and then checks for the associated driver version info against the CVA version
        It returns a list of driver entries from the Reference File that match the installed driver
    parm: $pSoftpaqID       Softpaq ID to match in the Reference File
          $pLists           list of registry and Reference file entry lists
          $pInstalledDrivers list of installed PnP drivers
    return: $fd_DriverEntry = @{
        MatchedHardwareID=$null
        PnPDriverVersion=$null        
        PnPDriverDate=$null
        DeviceClass=$null
        RefFileDriverVersion=$null
        DetailFileInstalledVersion=$null    
        Status=$Script:Config.Constants.SPQNOTINSTALLED
    } # $fd_DriverEntry = @{}
#>#####################################################################################
Function Find-Driver {
    [CmdletBinding()] param( $pSoftpaqID, $pLists, $pInstalledDrivers )

    if ( $DebugOut ) { TraceLog -Message '  > Find-Driver()' $TypeNorm  }

    $fd_DriverEntry = @{
        MatchedHardwareID=$null
        PnPDriverVersion=$null        
        PnPDriverDate=$null
        DeviceClass=$null
        RefFileDriverVersion=$null
        DetailFileInstalledVersion=$null                                
        Status=$Script:Config.Constants.SPQNOTINSTALLED                 # set Default
    } # $fd_DriverEntry = @{}

    if ( $AnalyzerEnv.OS -eq 'win10') { $AnalyzerEnv.OS = 'WT64' }      # how CVA shows Windows 10/64 bit support
    if ( $AnalyzerEnv.OS -eq 'win11') { $AnalyzerEnv.OS = 'W11' }

    ###########################################################################################
    # Let's start by finding the hardware ID in the Reference file [Devices] section
    # and check if the driver is installed in the system

    $fd_HardwareIDCheck = Get-HardwareMatch $pSoftpaqID $pLists.XMLRefFileDevices $pInstalledDrivers
    <#
        Get-HardwareMatch returns
            $gh_HardwareInfo = @{
                HardwareID=$null
                PnPDiverVersion=$null
                PnpDriverDate=$null
                PnpDriverClass=$null
            } # $gh_HardwareInfo
    #>
    if (  $fd_HardwareIDCheck.HardwareID ) {
        $fd_DriverEntry.MatchedHardwareID = $fd_HardwareIDCheck.HardwareID
        $fd_DriverEntry.DeviceClass = $fd_HardwareIDCheck.PnpDriverClass
        $fd_DriverEntry.PnPDriverVersion = $fd_HardwareIDCheck.PnPDriverVersion
        $fd_DriverEntry.PnPDriverDate = $fd_HardwareIDCheck.PnpDriverDate        

        # obtain information from reference file Devices section about the driver
        $fd_RefFileDeviceDriver = Get-ReferenceFileDeviceDriverInfo $pSoftpaqID $pLists.XMLRefFileDevices $fd_HardwareIDCheck.HardwareID 
        <#
            Get-ReferenceFileDeviceDriverInfo returns @{
                HardwareID=$null
                RefFileDriverVersion=$null
                RefFileDriverDate=$null
            }
        #>        
        $fd_DriverEntry.RefFileDriverVersion = $fd_RefFileDeviceDriver.RefFileDriverVersion
        $fd_DriverEntry.RefFileDriverDate = $fd_RefFileDeviceDriver.RefFileDriverDate

        ###########################################################################################
        # Let's find the DetailFile information in the Reference file [Solutions] section
        #   and check if the driver is installed in the system  

        # first, find the Softpaq entry in the reference file to get the Detail File information
        $fd_Solution =  $pLists.XMLRefFileSolutions.UpdateInfo | Where-Object {$_.id -eq $pSoftpaqid}

        # next, let's check the DetailFile info
        $fd_DetailFileSolutionInfo = Get-SolutionDetailFileDriverInfo $fd_Solution $AnalyzerEnv.OS $AnalyzerEnv.OSVer
        <#
            Get-SolutionDetailFileDriverInfo returns
                $gd_DetailFileHash = @{
                    DetailFileSoftpaqVersion = $null
                    DetailFileInstalledVersion = "0.0.0.0"
                } # $gd_DetailFileHash
        #>
        $fd_DriverEntry.RefFileDriverVersion = $fd_DetailFileSolutionInfo.DetailFileSoftpaqVersion
        $fd_DriverEntry.DetailFileInstalledVersion = $fd_DetailFileSolutionInfo.DetailFileInstalledVersion

        if ( [version]$fd_DriverEntry.PnPDriverVersion -lt [version]$fd_DriverEntry.RefFileDriverVersion -and `
            ( [version]$fd_DriverEntry.PnPDriverVersion -lt [version]$fd_DetailFileSolutionInfo.DetailFileSoftpaqVersion -and `
              [version]$fd_DetailFileSolutionInfo.DetailFileInstalledVersion -lt [version]$fd_DriverEntry.RefFileDriverVersion ) ) {
            $fd_DriverEntry.Status = $Script:Config.Constants.SPQUPDATEAVAILABLE
        } else {
            $fd_DriverEntry.Status = $Script:Config.Constants.SPQUPTODATE          
        } # else if ( [version]$fd_DriverEntry.PnPDriverVersion -lt [version]$fd_DriverEntry.RefFileDriverVersion )
        
    } # if (  $fd_HardwareIDCheck.HardwareID )

    if ( $DebugOut ) {   # Realtek audio driver - for testing
        TraceLog -Message "  < Find-Driver() - returning" $TypeNorm 
        TraceLog -Message "     ... HardwareID: $($fd_DriverEntry.MatchedHardwareID)" $TypeNorm 
        TraceLog -Message "     ... PnP DriverVersion: $($fd_DriverEntry.PnPDriverVersion)" $TypeNorm 
        TraceLog -Message "     ... Installed DriverDate: $($fd_DriverEntry.PnPDriverDate)" $TypeNorm 
        TraceLog -Message "     ... Reference File/Installed Driver Versions: $($fd_DriverEntry.RefFileDriverVersion) / $($fd_DriverEntry.DetailFileInstalledVersion)" $TypeNorm 
        TraceLog -Message "     ... Status: $($fd_DriverEntry.Status)" $TypeNorm 
        TraceLog -Message "     ... DeviceClass: $($fd_DriverEntry.DeviceClass)" $TypeNorm 
    } # if ( $DebugOut )

    return $fd_DriverEntry
    
} # Function Find-Driver

<######################################################################################
    Function Find-Software
    This functions attempts to match a Softpaq against an installed software
    It parses the Reference file [Devices] HW PnP list against this PnP Hardware IDs to find
    a match, and then checks for the associated driver version info against the Reference File version
    Parms: $pSoftpaq:       the Softpaq to check
           $pList:          the list of installed software in the system
    Returns: @{
        SoftpaqVersion=$null
        Version=$null
        Status=$Script:Config.Constants.SPQNOTINSTALLED
    } # $fs_ReturnHashTable = @{}
#>#####################################################################################
Function Find-Software {
    [CmdletBinding()] param( $pSoftpaq, $pList )
 
    if ( $DebugOut ) { TraceLog -Message "   > Find-Software() - Checking Software: $($pSoftpaq.Id)/$($pSoftpaq.name)" $TypeNorm  }   

    $fs_ReturnHashTable = @{}       # empty hash table to return

    #################################################################################
    # handle exceptions in names between installed app and CVA Title name
    if ( $pSoftpaq.name -match 'BIOS Config Utility' ) { $pSoftpaq.name = 'HP BIOS Configuration Utility' }
    if ( $pSoftpaq.name -match 'Cloud Recovery' ) { $pSoftpaq.name = 'HP Cloud Recovery' }    

    # search for the Softpaq in the Referecne File software Solutions list
    $fs_Solution =  $pList.XMLRefFileSolutions.UpdateInfo | Where-Object {$_.id -eq $pSoftpaq.id}
    # let's get the DetailFile info
    $fs_DetailFileInfo = Get-SolutionDetailFileDriverInfo $fs_Solution $AnalyzerEnv.OS $AnalyzerEnv.OSVer
    $fs_ReturnHashTable.SoftpaqVersion = $fs_DetailFileInfo.DetailFileSoftpaqVersion
    $fs_ReturnHashTable.Version = $fs_DetailFileInfo.DetailFileInstalledVersion
    $fs_ReturnHashTable.Status = $Script:Config.Constants.SPQNOTINSTALLED       # set Default

    # search WoW Uninstall entries for matching Software, list obtained with 'Get-ItemProperty'
    foreach ( $iInst in $pList.InstalledWOWApps ) {   
        if ( $iInst.DisplayName -match $pSoftpaq.name ) {        
            $fs_ReturnHashTable.Name = $iInst.DisplayName
            $fs_ReturnHashTable.Version = $iInst.DisplayVersion.split(' ')[0]
            $fs_ReturnHashTable.Date = $iInst.InstallDate
            if ( $DebugOut ) { TraceLog -Message "      - matched WOW App $($pSoftpaq.Id)/$($fs_ReturnHashTable.name)/$($fs_ReturnHashTable.Version)/$($fs_ReturnHashTable.Date) in `$pInstalledWOWApps" $TypeNorm  }
            break
        } # if ( $iInst.DisplayName -match $pSoftpaq.name )
    } # foreach ( $iInst in $pInstalledWOWApps )

    # search Uninstall entries for matching Software, list obtained with 'Get-ItemProperty'

    if ( $fs_ReturnHashTable.Count -eq 0 ) {
        
        foreach ( $iInst in $pList.InstalledApps ) {      
            if ( $iInst.DisplayName -match $pSoftpaq.name ) {
                $fs_ReturnHashTable.Name = $iInst.DisplayName
                $fs_ReturnHashTable.Version = $iInst.DisplayVersion.split(' ')[0]
                $fs_ReturnHashTable.Date = $iInst.InstallDate
                if ( $DebugOut ) { TraceLog -Message "      - matched App $($pSoftpaq.Id)/$($fs_ReturnHashTable.Name)/$($fs_ReturnHashTable.Version)/$($fs_ReturnHashTable.Date) in `$pInstalledSoftware" $TypeNorm  }
                break
            } # if ( $iInst.DisplayName -match $pSoftpaq.name )

        } # foreach ( $iInst in $pInstalledSoftware )      
    } # if ( $null -eq $fs_ReturnHashTable )

    if ( $DebugOut ) { TraceLog -Message "      - matched apps count: $($fs_ReturnHashTable.Count)" $TypeNorm  }

    # check if the installed version is less than the Reference File version
    if ( $fs_ReturnHashTable.Version ) {
        if ( [version]$fs_ReturnHashTable.Version -lt [version]$fs_ReturnHashTable.SoftpaqVersion ) {
            $fs_ReturnHashTable.Status = $Script:Config.Constants.SPQUPDATEAVAILABLE
        } else { 
            $fs_ReturnHashTable.Status = $Script:Config.Constants.SPQUPTODATE
        } # else if ( [version]$fs_ReturnHashTable.Version -lt [version]$fs_ReturnHashTable.SoftpaqVersion )
    }

    #################################################################################
    if ( $DebugOut ) { 
        if ( $fs_ReturnHashTable.Count -gt 0 ) {
            TraceLog -Message "   < Find-Software()" $TypeNorm 
            TraceLog -Message "     ... Name: $($fs_ReturnHashTable.Name)" $TypeNorm 
            TraceLog -Message "     ... Reference File Version: $($fs_ReturnHashTable.SoftpaqVersion)" $TypeNorm 
            TraceLog -Message "     ... Installed Version: $($fs_ReturnHashTable.Version)" $TypeNorm 
            TraceLog -Message "     ... Status: $($fs_ReturnHashTable.Status)" $TypeNorm 
        } else {
            TraceLog -Message "   < Find-Software() - NOT installed as Software app" $TypeNorm 
        } # else if ( $fs_ReturnHashTable )
    } # if ( $DebugOut )

    return $fs_ReturnHashTable

} # Function Find-Software 

<######################################################################################
    Function Resolve-BIOS
        This function checks the installed BIOS version against the Softpaq version
        It returns a hash table with the Softpaq ID, installed version and status
#>#####################################################################################
function Resolve-BIOS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$pSoftpaqEntry,
        [Parameter(Mandatory)]$pSoftpaq
    )
    $rb_InstalledBIOS = (Get-HPBIOSSettingValue 'System BIOS Version').split(' ')
    if ( $DebugOut ) { TraceLog -Message "  ... Resolve-BIOS() Installed BIOS: $($rb_InstalledBIOS)" $TypeNorm }

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

    $pSoftpaqEntry.InstallVersion = $rb_InstalledBIOSVersion
    $pSoftpaqEntry.InstallDate = $rb_InstalledBIOSDate
    $pSoftpaqEntry.Status = $rb_Status 
    if ( $DebugOut ) { TraceLog -Message "  ... Resolve-BIOS() BIOS Check Status: $($rb_Status)" $TypeNorm }

    $pSoftpaqEntry.UWPStatus = $null            # deault to not installed

    return $pSoftpaqEntry
} # function Resolve-BIOS()

<######################################################################################
    Function Resolve-Driver
        This function checks the installed driver version against the Softpaq version
        It returns a hash table with the Softpaq ID, installed version and status
        It also checks if the Softpaq is installed as a Software UWP app
        It returns a hash table with the Softpaq ID, installed version and status
#>#####################################################################################
function Resolve-Driver {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$pSoftpaqEntry,
        [Parameter(Mandatory)]$pSoftpaq,
        [Parameter(Mandatory)]$pLinks,
        [Parameter(Mandatory)]$pDriversList
    )   
    $rd_FindDriver = Find-Driver $pSoftpaq.Id $pLinks $pDriversList

    $pSoftpaqEntry.ReferenceFileVersion = $rd_FindDriver.RefFileDriverVersion
    $pSoftpaqEntry.InstallVersion = $rd_FindDriver.DetailFileInstalledVersion # set default to the [DetailFile] installed version
    #$pSoftpaqEntry.SoftpaqVersion = $rd_FindDriver.DetailFileSoftpaqVersion       # set default to the [DetailFile] installed version
    $pSoftpaqEntry.SoftpaqVersion = $rd_FindDriver.RefFileDriverVersion       # set default to the [DetailFile] installed version
    $pSoftpaqEntry.Status = $rd_FindDriver.Status
    if ( $DebugOut ) { TraceLog -Message "  Resolve-Driver() Softpaq Status: $($pSoftpaqEntry.Status)" $TypeNorm }

    # Add driver Version and Date to the hash table if found in the system
    if ( $rd_FindDriver.MatchedHardwareID ) { 
        $pSoftpaqEntry.CVAHWID = $rd_FindDriver.MatchedHardwareID
        $pSoftpaqEntry.InstallVersion = $rd_FindDriver.PnPDriverVersion      # this is the PNP driver version
        $pSoftpaqEntry.InstallDate = $rd_FindDriver.PnPDriverDate                
        $pSoftpaqEntry.DeviceClass = $rd_FindDriver.DeviceClass
    } else {
        #$pSoftpaqEntry.CVAHWID = 'NA'                                # The PnP HW ID not found in the system
        $pSoftpaqEntry.InstallVersion = $rd_FindDriver.DetailFileInstalledVersion      # this is installed driver file version
        $pSoftpaqEntry.ReferenceFileVersion = $rd_FindDriver.DetailFileInstalledVersion
    } # else if ( $rd_FindDriver.MatchedHardwareID )

    if ( [version]$pSoftpaqEntry.ReferenceFileVersion -lt  [version]$pSoftpaqEntry.SoftpaqVersion ) { 
        $pSoftpaqEntry.ReferenceFileVersion = $pSoftpaqEntry.SoftpaqVersion
    } # if ( [version]$pSoftpaqEntry.ReferenceFileVersion -eq '0.0' )

    if ( $null -eq $pSoftpaqEntry.InstallVersion ) {                        
        $pSoftpaqEntry.InstallVersion = 'MISSING'    # There is a driver available, Hardware exists, but no driver was installed
    } # if ( $null -eq $pSoftpaqEntry.InstallVersion )
    
    $pSoftpaqEntry.UWPStatus = $null    # default to not installed

    # check if the Softpaq is installed as a Software UWP app
    $pSoftpaqEntry.UWP = $pSoftpaq.UWP
    if ( $pSoftpaqEntry.UWP -eq $true ) {
        # check if the Softpaq has a UWP requirement and if it is installed
        # Get-UWPInfoFromRefFile() returns a list of UWP entries from the Reference File that match installed appx's
        $ad_UWPAppxInfo = Get-UWPInfoFromRefFile $pSoftpaq $pLinks

        foreach ( $i_UWP in $ad_UWPAppxInfo ) { # in case the Softpaq has > 1 UWP/Appx applications
            $pSoftpaqEntry.UWPName = $i_UWP.RefFileUWPName
            $pSoftpaqEntry.UWPVersion = $i_UWP.RefFileUWPVersion
            $pSoftpaqEntry.UWPInstallVersion = $i_UWP.InstalledUWPVersion
            $pSoftpaqEntry.UWPStatus = $i_UWP.Status
            if ( $pSoftpaqEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPUPDATEAVAILABLE ) { 
                if ( $DebugOut ) {                                
                    TraceLog -Message "  Analyze(): SOFTPAQ NEEDS UPDATE DUE TO UWP: $($ad_result.UWPName)" $TypeNorm 
                    TraceLog -Message "  ... UWP Available/Installed Version: $($ad_result.UWPVersion)/$($ad_result.UWPInstallVersion)" $TypeNorm 
                    TraceLog -Message "  ... UWP Status: $($ad_result.UWPStatus)" $TypeNorm 
                } # if ( $DebugOut )
                break   
            } # if ( $pSoftpaqEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPNOTINSTALLED )
        } # foreach ( $i_UWP in $a_UWPAppxInfo )

    } else {
        if ( $DebugOut ) { TraceLog -Message "  Analyze() SOFTPAQ DOES NOT INCLUDE A UWP" } $TypeNorm 
    } # else if ( $pSoftpaqEntry.UWP -eq $true )

    return $pSoftpaqEntry
} # function Resolve-Driver()

<######################################################################################
    Function Resolve-Software
        This function checks the installed software version against the Softpaq version
        It returns a hash table with the Softpaq ID, installed version and status
        It also checks if the Softpaq is installed as a Software UWP app
        It returns a hash table with the Softpaq ID, installed version and status   
#>#####################################################################################
function Resolve-Software {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$pSoftpaqEntry,
        [Parameter(Mandatory)]$pSoftpaq,
        [Parameter(Mandatory)]$pLinks
    )
    $as_SoftwareFound = Find-Software $pSoftpaq $pLists

    $pSoftpaqEntry.InstallVersion = $as_SoftwareFound.Version
    $pSoftpaqEntry.SoftpaqVersion = $as_SoftwareFound.SoftpaqVersion
    $pSoftpaqEntry.Status = $as_SoftwareFound.Status

    if ( $pSoftpaq.UWP -eq $true -or ($pSoftpaq.Category -match 'Utility') ) {
        $as_UWPInfoSoftware = Get-UWPInfoFromRefFile $pSoftpaq $pLinks
        if ( $as_UWPInfoSoftware ) {
            if ( $DebugOut ) { TraceLog -Message "  Resolve-Software(): UWP: $($as_UWPInfoSoftware.InstalledUWPName)/$($as_UWPInfoSoftware.RefFileUWPVersion)/$($as_UWPInfoSoftware.InstalledUWPVersion)/$($as_UWPInfoSoftware.Status)" $TypeNorm  }
            $pSoftpaqEntry.UWPName = $as_UWPInfoSoftware.InstalledUWPName
            $pSoftpaqEntry.UWPVersion = $as_UWPInfoSoftware.RefFileUWPVersion
            $pSoftpaqEntry.UWPInstallVersion = $as_UWPInfoSoftware.InstalledUWPVersion
            $pSoftpaqEntry.UWPStatus = $as_UWPInfoSoftware.Status
        } # if ( $as_UWPInfoSoftware.count -gt 0 )
    } # if ( $pSoftpaq.UWP -eq $true )

    if ( (-not $pSoftpaq.UWP) -and $pSoftpaqEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPNOTINSTALLED ) {
        $pSoftpaqEntry.UWPStatus = $null            # default to not installed
    }    

    return $pSoftpaqEntry
} # function Resolve-Software()

<######################################################################################
    Function Resolve-Diagnostics
        This function checks the installed Diagnostic version against the Softpaq version
        It returns a hash table with the Softpaq ID, installed version and status
        It also checks if the Softpaq is installed as a Software UWP app
        It returns a hash table with the Softpaq ID, installed version and status 
#>#####################################################################################
function Resolve-Diagnostics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$pSoftpaqEntry,
        [Parameter(Mandatory)]$pSoftpaq,
        [Parameter(Mandatory)]$pLinks
    )

    $rd_Solution =  $pLinks.XMLRefFileSolutions.UpdateInfo | Where-Object {$_.id -eq $pSoftpaq.id}
    # let's get the DetailFile info
    $rd_DetailFileInfo = Get-SolutionDetailFileDriverInfo $rd_Solution $AnalyzerEnv.OS $AnalyzerEnv.OSVer

    $pSoftpaqEntry.SoftpaqVersion = $rd_DetailFileInfo.DetailFileSoftpaqVersion
    $pSoftpaqEntry.InstallVersion = $rd_DetailFileInfo.DetailFileInstalledVersion

    if ( $rd_DetailFileInfo.DetailFileInstalledVersion ) {
        if ([version]$rd_DetailFileInfo.DetailFileInstalledVersion -lt  [version]$rd_DetailFileInfo.DetailFileSoftpaqVersion) {
            $pSoftpaqEntry.Status = $Script:Config.Constants.SPQUPDATEAVAILABLE
        } else {
            $pSoftpaqEntry.Status = $Script:Config.Constants.SPQUPTODATE
        } # else if ( ... )
    } else {
        $pSoftpaqEntry.Status = $Script:Config.Constants.SPQNOTINSTALLED
    } # else if ( $rd_DetailFileInfo.DetailFileInstalledVersion )

    $pSoftpaqEntry.UWPStatus = $null            # default to not installed

    if ( $DebugOut ) { TraceLog -Message "  < Resolve-Diagnostics(): $($rd_DetailFileInfo.DetailFileSoftpaqVersion)/$($rd_DetailFileInfo.DetailFileInstalledVersion) / $($pSoftpaqEntry.Status)" $TypeNorm  }
            
    return $pSoftpaqEntry
} # function Resolve-Diagnostics()

Function Test-AdminRights {

    # Check if the script is running with administrative privileges
    $ts_Admin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()

    return $ts_Admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

} # Test-AdminRights()

<######################################################################################
    Function Test-CategoryFilter
        This function checks if the Softpaq category matches the specified category
        It returns true if the category matches or if no category is specified
#>#####################################################################################
Function Test-CategoryFilter {
    [CmdletBinding()] param( $pTest, $pCategory )

    if ( -not $pCategory -or ($pCategory -match $pTest) ) {
        return $true
    }
    return $false
} # Function Test-CategoryFilter()

<######################################################################################
    Function Test-StringContainsArrayItems
        This function checks if a string contains any items from an array
        It returns true if any item is found, otherwise false
#>#####################################################################################
function Test-StringContainsArrayItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$pInputString,        
        [Parameter(Mandatory = $true)]
        [array]$pSearchArray
    )
    foreach ( $item in $pSearchArray ) {
        $ts_contains = $pInputString.ToLower().Contains($item.ToLower())
        if ( $ts_contains ) { return $true } # foreach ($item in $SearchArray)
    } # foreach ($item in $SearchArray)

    return $false
} # function Test-StringContainsArrayItems()

<######################################################################################
    Function Initialize-SoftpaqEntry
        This function initializes the analysis result for a Softpaq entry
        It returns a hash table with the initial values
#>#####################################################################################
function Initialize-SoftpaqEntry {
    [CmdletBinding()]
    param( [Parameter(Mandatory)]$pSoftpaq )    
    return [ordered]@{
        SoftpaqID = $pSoftpaq.id
        SoftpaqName = $pSoftpaq.name
        SoftpaqVersion = $pSoftpaq.Version
        SoftpaqDate = $pSoftpaq.ReleaseDate
        ReleaseType = $pSoftpaq.ReleaseType
        ReferenceFileVersion = $pSoftpaq.Version
        URL = $pSoftpaq.url
        Action = 'Scan'                 # default action to 'Scan'. Other actions will override this: 'Install', 'Uninstall', 'Update'
        ActionReturnCode = 0            # default action return code to 0
        SilentInstall = $null
        Status = $Script:Config.Constants.SPQNOTINSTALLED
        Category = $null
        InstallVersion = $null
        InstallDate = $null
        CVAHWID = $null
        UWP = $false
        UWPName = $null
        UWPVersion = $null
        UWPStatus = $Script:Config.Constants.SPQUWPNOTINSTALLED
    }
} # Function Initialize-SoftpaqEntry()

<######################################################################################
    Function Invoke-SoftpaqAnalysis
    This function analyzes a Softpaq object and returns a hash table with the analysis results
    parm: $pSoftpaq:       the Softpaq object to analyze
           $pDriversList:   the list of installed drivers in the system
           $pLists:         the list of Reference file entries
           $pCategory:      the category to analyze (optional)
    return: $is_SoftpaqHashEntry = @{
        SoftpaqID = $pSoftpaq.id
        SoftpaqName = $pSoftpaq.name
        SoftpaqVersion = $pSoftpaq.Version
        SoftpaqDate = $pSoftpaq.ReleaseDate
        ReleaseType = $pSoftpaq.ReleaseType
        ReferenceFileVersion = $pSoftpaq.Version
        URL = $pSoftpaq.url
        SilentInstall = $null   # Info pulled from the Reference File Solutions section
        Status = $Script:Config.Constants.SPQNOTINSTALLED
        Category = $pCategory
        InstallVersion = $null
        InstallDate = $null
        CVAHWID = $null
        UWP = $false
        UWPName = $null
        UWPVersion = $null
        UWPStatus = $Script:Config.Constants.SPQUWPNOTINSTALLED
        Action = 'Scan'                 # default action to 'Scan'... Other actions will override this: 'Install', 'Uninstall', 'Update'
        ActionReturnCode = 0            # default action return code to 0
    } # $is_SoftpaqHashEntry
#>#####################################################################################
Function Invoke-SoftpaqAnalysis {
    [CmdletBinding()] param( $pSoftpaq, $pDriversList, $pLists, $pCategory )

    if ( $DebugOut ) { TraceLog -Message "  > Analyze() $($pSoftpaq.id): $($pSoftpaq.Category)" $TypeNorm }

    $is_SoftpaqHashEntry = Initialize-SoftpaqEntry $pSoftpaq          # set the default values
    # Find the silent install command - entry is in the Reference File Solutions section for the Softpaq
    $is_SoftpaqHashEntry.SilentInstall = ($pLists.XMLRefFileSolutions.UpdateInfo | Where-Object { $_.id -eq $pSoftpaq.id }).SilentInstall

    if ( $DebugOut ) { TraceLog -Message "  ... Softpaq SilentInstall: $($is_SoftpaqHashEntry.SilentInstall)" $TypeNorm }

    switch -regex ( $pSoftpaq.Category) {
        'bios' {
            if ( Test-CategoryFilter 'bios' $pCategory ) {
                $is_SoftpaqHashEntry.Category = 'BIOS'                  # set the category to BIOS
                $is_SoftpaqHashEntry = Resolve-BIOS $is_SoftpaqHashEntry $pSoftpaq
            } # if ( Test-CategoryFilter 'bios' $pCategory )
        } # 'bios'

        '^driver|^dock' {           # assume category 'dock' is a driver Softpaq - if firmware it would have been skipped
            if ( Test-CategoryFilter 'driver' $pCategory ) {
                # if SubCategory is set, check if the Softpaq category matches the SubCategory option from the command line
                if ( $Script:SubCategory ) {
                    $is_SubTest = Test-StringContainsArrayItems -InputString $pSoftpaq.category -SearchArray $Script:SubCategory
                    if ( -not $is_SubTest ) {
                        if ( $DebugOut ) { TraceLog -Message " - Softpaq $($pSoftpaq.Id) Category: $($pSoftpaq.category), doesn't match driver type check, skipping." $TypeNorm  }
                        continue
                    } # if ( -not $is_SubTest )
                } # if ( $Script:SubCategory )
                $is_SoftpaqHashEntry.Category = 'Driver'                     # set the category to Driver
                $is_SoftpaqHashEntry = Resolve-Driver $is_SoftpaqHashEntry $pSoftpaq $pLists $pDriversList
            } # if ( Test-CategoryFilter 'driver' $pCategory )
        } # 'driver|utility'

        'software|utility' {
            if ( -not $pCategory ) {
                $is_SoftpaqHashEntry.Category = 'Software'                  # set the category to Software
                $is_SoftpaqHashEntry = Resolve-Software $is_SoftpaqHashEntry $pSoftpaq $pLists
            } # if ( -not $pCategory )
        } # 'software'

        'diagnostic' {
            if ( -not $pCategory ) {
                $is_SoftpaqHashEntry.Category = 'Diagnostic'                # set the category to Diagnostic
                $is_SoftpaqHashEntry = Resolve-Diagnostics $is_SoftpaqHashEntry $pSoftpaq $pLists
            } # if ( -not $pCategory )
        } # 'diagnostic'
    } # switch -wildcard ( $pSoftpaq.Category)

    return $is_SoftpaqHashEntry
} # Function Invoke-SoftpaqAnalysis

<######################################################################################
    Function initialize-DownloadFolder
    This function initializes the download folder for Softpaq files
    parm: $pDownloadFolder: the folder path to initialize as a download folder
    return: none
    This function checks if the download folder exists, and if not, creates it
#>#####################################################################################
Function initialize-DownloadFolder {
    [CmdletBinding()] param( $pDownloadFolder )

    if ( $DebugOut ) { TraceLog -Message "  > initialize-DownloadFolder() checking download folder: $pDownloadFolder" $TypeNorm  }
    if ( -not (Test-Path $pDownloadFolder) ) {    
        Try {
            New-Item -Path $pDownloadFolder -ItemType directory | Out-Null
            if ( $DebugOut ) { TraceLog -Message "  ... Download path was not found, created: $pDownloadFolder" -Type $TypeNorm  }
        } Catch {
            Throw "  ... problem: $($_)"        # Throw an error to exit if the folder cannot be created
        } # try/catch block for New-Item
    } # if ( -not (Test-Path $pRepoFolder) )

} # Function initialize-DownloadFolder()

<######################################################################################
    Function initialize-HPIArepository
    This function initializes the repository folder for HP Image Assistant
    parm: $pRepoFolder: the folder path to initialize as a repository
    return: none
#>#####################################################################################
Function initialize-HPIArepository {
    [CmdletBinding()]
	param( $pRepoFolder )

    if ( $DebugOut ) { TraceLog -Message "  > initialize-HPIArepository()" -Type $TypeNorm  }
    $ir_CurrentLoc = Get-Location                   # Save the current location to return later

    # Check if the provided repository folder path exists and is valid 
    # Create the repository folder if it does not exist
    if ( -not (Test-Path $pRepoFolder) ) {    
        Try {
            $ih_newDir = New-Item -Path $pRepoFolder -ItemType directory | Out-Null
            if ( -not $CleanOutput ) { TraceLog -Message "  ... repository path was not found, created: $pRepoFolder" -Type $TypeNorm  }
        } Catch {
            if ( -not $CleanOutput ) { TraceLog -Message "  ... problem: $($_)" -Type $TypeError $TypeNorm  }
            return $false
        } # try/catch block for New-Item
    } # if ( -not (Test-Path $pRepoFolder) )

    Set-Location $pRepoFolder   # Change to the repository folder for initialization - required by the repository cmdlets
    Try {
        # Attempt to get repository info to check if it's already initialized
        Get-RepositoryInfo -ErrorAction Stop | Out-Null
        if ( $DebugOut ) { TraceLog -Message "  ... repository already initialized" -Type $TypeNorm  }
    } Catch {
        # Catch block will handle the case where Get-RepositoryInfo fails, indicating it's not initialized               
        (Initialize-Repository) 6>&1
        if ( $DebugOut ) { TraceLog -Message  "  .. repository initialized"  -Type $TypeNorm  }
        Set-RepositoryConfiguration -setting OfflineCacheMode -cachevalue Enable 6>&1 
        Set-RepositoryConfiguration -setting RepositoryReport -Format csv 6>&1
        if ( $DebugOut ) { TraceLog -Message  "  ... repository configuration set to OfflineCacheMode: Enable, RepositoryReport: csv" -Type $TypeNorm  }
        $ih_addFilter = Add-RepositoryFilter -Platform $Script:AnalyzerEnv.PlatformID -OS $Script:AnalyzerEnv.OS -OSVer $Script:AnalyzerEnv.OSVer -Category BIOS 6>&1
        if ( $DebugOut ) { TraceLog -Message  "  ... repository filter added for Category: BIOS - will remove Softpaq once 1st sync completes" -Type $TypeNorm  }
        $ih_repoSync = Invoke-RepositorySync -ErrorAction Stop 6>&1       
        if ( $DebugOut ) { TraceLog -Message  "  ... repository created and synchronized" -Type $TypeNorm  }
    } # Try/Catch block for Get-RepositoryInfo

    # cleanup the repository folder from any previous Softpaq files 
    # This is to ensure the repository is clean before any new Softpaq files are downloaded
    if ( $DebugOut ) { TraceLog -Message "  ... cleaning up repository folder: $pRepoFolder" -Type $TypeNorm  }
    Get-ChildItem -Path $pRepoFolder -Recurse | 
        Where-Object { $_.Name -match '^sp\d{6}\.(exe|cva|html)$'-or ($_.Name -match '^.+\.(mark|csv)$') } |
        ForEach-Object { Remove-Item -Path $_.FullName }

    if ( $DebugOut ) { TraceLog -Message "  < initialize-HPIArepository()" -Type $TypeNorm  }

    Set-Location $ir_CurrentLoc

    return $true
} # Function initialize-HPIArepository()

<######################################################################################
    Function Get-SoftpaqCVAFile
    This function downloads the Softpaq metadata file (CVA) to the specified folder
    parm: $pSoftpaqID:   the Softpaq ID to download the CVA file for
           $pFolderPath:   the folder path to download the CVA file to
    return: $gs_DownloadSuccess: true if the CVA file was downloaded successfully, false otherwise
#>#####################################################################################
Function Get-SoftpaqCVAFile {
    [CmdletBinding()] param( $pSoftpaqID, $pFolderPath )

    if ( $DebugOut ) { TraceLog -Message "    > Get-SoftpaqCVAFile() - Softpaq: $pSoftpaqID" $true }

    $gs_DownloadSuccess = $false

    if ( $DebugOut ) { TraceLog -Message "    ... downloading CVA file for Softpaq: $pSoftpaqID" -Type $TypeNorm  }

    Try {
        $null = Get-SoftpaqMetadataFile $pSoftpaqObj.SoftpaqID -Overwrite 'Yes' -ErrorAction Stop 6>&1
        if ( $DebugOut ) { TraceLog -Message "    ... done" -Type $TypeNorm }
        $gs_DownloadSuccess = $true
    } Catch {
        if ( $DebugOut ) { TraceLog -Message "    ... failed to download: $($Error[2])" -Type $TypeError $true }
    } # Try/Catch block for Get-SoftpaqMetadata

    if ( $DebugOut ) { TraceLog -Message "    < Get-SoftpaqCVAFile()" $TypeNorm  }

    return $gs_DownloadSuccess
} # Function Get-SoftpaqCVAFile()

<######################################################################################
    Function Get-SoftpaqHTMLFile
    This function downloads the Softpaq Release Notes HTML file to the specified folder
    parm: $pSoftpaqID:   the Softpaq ID to download the HTML file for
           $pSoftpaqURL:  the URL to download the HTML file from
           $pFolderPath:  the folder path to download the HTML file to 
    return: $gs_DownloadSuccess: true if the HTML file was downloaded successfully, false otherwise
    This function uses Invoke-WebRequest to download the HTML file from the Softpaq URL
#>#####################################################################################
Function Get-SoftpaqHTMLFile {
    [CmdletBinding()] param( $pSoftpaqID, $pSoftpaqURL, $pFolderPath )

    if ( $DebugOut ) { TraceLog -Message "    > Get-SoftpaqHTMLFile() - Softpaq: $pSoftpaqID" $true }
    $gs_DownloadSuccess = $false

    if ( $DebugOut ) { TraceLog -Message "    ... downloading HTML file for Softpaq: $pSoftpaqID" -Type $TypeNorm  }

    Try {
        $gs_SoftpaqHtml = $pFolderPath+'\'+$pSoftpaqID+'.html' # where to download to
        $null = Invoke-WebRequest -UseBasicParsing -Uri "$($pSoftpaqURL)" -OutFile "$($gs_SoftpaqHtml)"
        if ( $DebugOut ) { TraceLog -Message "    ... done" -Type $TypeNorm  }
        $gs_DownloadSuccess = $true
    } Catch {
        if ( $DebugOut ) { TraceLog -Message "    ... failed to download: $($_)" -Type $TypeError $true }
    } # Try/Catch block for Invoke-WebRequest

    if ( $DebugOut ) { TraceLog -Message "    < Get-SoftpaqHTMLFile()" $TypeNorm  }

    return $gs_DownloadSuccess
} # Function Get-SoftpaqHTMLFile()

Function Invoke-SoftpaqInstall {
    [CmdletBinding()] param( $pSoftpaqObj, $pExtractFolderPath )

    if ( $DebugOut ) { TraceLog -Message "      > Invoke-SoftpaqInstall() - Softpaq: $($pSoftpaqObj.SoftpaqID)"  -Type $TypeErro $true }

    Try {
        $Error.Clear()
        # get the softpaq and extract it to the specified folder
        $null = (Get-Softpaq $pSoftpaqObj.SoftpaqID -Extract -DestinationPath "$($pExtractFolderPath)" -Overwrite skip) 6>&1
        if ( $DebugOut ) { TraceLog -Message "`tExtracted Softpaq $($pSoftpaqObj.SoftpaqID) to $($pExtractFolderPath)" -Type $TypeNorm  }
        # separate the installer executable from the silent install command options (it may not have any)
        $is_installer = $pSoftpaqObj.SilentInstall.split(' ')[0]                            # get the first part of the silent install command
        $is_installerFullPath = $pExtractFolderPath + '\' + $is_installer                   # the path to the installer executable
        $is_InstallerOptions = $pSoftpaqObj.SilentInstall.replace($is_installer,'').Trim()  # remove the first part of the silent install command
        TraceLog -Message  "`tSoftpaq $($pSoftpaqObj.SoftpaqID) installer: $($is_installerFullPath) options: $($is_InstallerOptions)"
        if ( $DebugOut ) { TraceLog -Message "`tSoftpaq $($pSoftpaqObj.SoftpaqID) installer: $($is_installerFullPath) options: $($is_InstallerOptions)" -Type $TypeNorm  }

        # Start the installer process with the silent install command
        # change to the extraction folder to make sure the installer can find the files it needs
        Set-Location $pExtractFolderPath
        if ( $is_InstallerOptions ) {
            #$is_process = Start-Process -FilePath "$($is_installerFullPath)" -ArgumentList "$($is_InstallerOptions)" -Wait -PassThru -NoNewWindow -ErrorAction Stop
        } else {
            #$is_process = Start-Process -FilePath "$($is_installerFullPath)" -Wait -PassThru -NoNewWindow -ErrorAction Stop
        } # else if ( $is_InstallerOptions )

        TraceLog -Message "`tInstall return code $($is_process.ExitCode)" $TypeNorm
        if ( $DebugOut ) { TraceLog -Message "     ... done" -Type $TypeNorm  }
    } Catch {
        if ( $DebugOut ) { TraceLog -Message "     ... failed to download/Install: $($Error[2])" $TypeError $true }
    } # Try/Catch block for Get-Softpaq Install

    if ( $DebugOut ) { TraceLog -Message "      < Invoke-SoftpaqInstall()"  $TypeError $true }

    return $is_process.ExitCode

} # Function Invoke-SoftpaqInstall()

<######################################################################################
    Function Get-SoftpaqFiles
    This function downloads the Softpaq files and metadata to the specified folder
    parm: $pSoftpaqObj:   the Softpaq object to download
           $pFolderPath:   the folder path to download the Softpaq files to
           $pDownloadAction: the action to perform (Download, Extract)
    return: none
    This function downloads the Softpaq executable, CVA file, and Release Notes HTML file
#>#####################################################################################
Function Get-SoftpaqFiles {
    param( $pSoftpaqObj, $pFolderPath, $pDownloadAction )

    if ( $DebugOut ) { TraceLog -Message "    > Get-SoftpaqFiles() - Softpaq: $($pSoftpaqObj.SoftpaqID)" $TypeNorm }

    $gs_StartLocation = Get-Location
    Set-Location $pFolderPath

    $gs_ExtractFolder = $pFolderPath+'\'+$pSoftpaqObj.SoftpaqID
    $gs_SoftpaqExePath = $pFolderPath+'\'+$pSoftpaqObj.SoftpaqID+'.exe'

    switch -regex ( $pDownloadAction ) {

            'Download|CreateRepo' {
                $pSoftpaqObj.Action = 'Download'            # default action is Download
                if ( $pSoftpaqObj.Action -eq 'CreateRepo' ) { $pSoftpaqObj.Action = 'CreateRepo' }
                if ( $DebugOut ) { TraceLog -Message "    ... Softpaq $($pSoftpaqObj.SoftpaqID) - $($pSoftpaqObj.SoftpaqName)" -Type $TypeNorm }
                
                # first the Softpaq executable
                if ( Test-Path $gs_SoftpaqExePath ) {
                    if ( $DebugOut ) { TraceLog -Message "`t$($pSoftpaqObj.SoftpaqID) already downloaded - $($pSoftpaqObj.SoftpaqName)" -Type $TypeWarn }
                } else {                    
                    Try {
                        $Error.Clear()
                        if ( $DebugOut ) { TraceLog -Message "`tdownloading " -Type $TypeNoNewline }
                        $null = (Get-Softpaq $pSoftpaqObj.SoftpaqID -DestinationPath "$($gs_ExtractFolder)") 6>&1
                        if ( $DebugOut ) { TraceLog -Message " ... done" -Type $TypeSuccess }
                        $pSoftpaqObj.ActionReturnCode = 0
                    } Catch {
                        if ( $DebugOut ) { TraceLog -Message " ... failed to download: $($Error[2])" -Type $TypeError }
                        $pSoftpaqObj.ActionReturnCode = -1
                    } # Try/Catch block for Get-Softpaq
                } # else if ( Test-Path $ds_ExePath ) {

                # next, the corresponding CVA file
                $null = Get-SoftpaqCVAFile $pSoftpaqObj.SoftpaqID $pFolderPath

                # finally, download readme HTML file
                $null = Get-SoftpaqHTMLFile $pSoftpaqObj.SoftpaqID $pSoftpaqObj.url.replace('exe','html') $pFolderPath

            } # 'Download|CreateRepo'

            'Install' {                
                $gs_code = Invoke-SoftpaqInstall $pSoftpaqObj $gs_ExtractFolder
                $pSoftpaqObj.Action = 'Install'
                $pSoftpaqObj.ActionReturnCode = $gs_code.ErrorCode
            } # 'Install'

        } # switch ($pDownloadAction)

    if ( $DebugOut ) { TraceLog -Message "    < Get-SoftpaqFiles()" $TypeNorm }

    Set-Location $gs_StartLocation

    return $pSoftpaqObj

} # Function Get-SoftpaqFiles

<######################################################################################
    Function Get-AllSoftpaqs
    This function processes a list of Softpaqs and performs the specified action
    parm: $pEntryList:      the list of Softpaqs to process (hash table entries)
           $pGetAction:     the action to perform (CreateRepo, Download, Install)
    return: $ga_count:      the number of Softpaqs processed
#>#####################################################################################
Function Get-AllSoftpaqs {
    [CmdletBinding()] param( $pEntryList, $pGetAction )

    if ( $DebugOut ) { TraceLog -Message "  > Get-AllSoftpaqs() - processing $($pEntryList.Count) Softpaqs" -Type $TypeNorm }
    $ga_count = 0

    # loop through the Softpaq entries and process each one
    # if the Softpaq has a CVAHWID, it is considered valid for download (assuming it is a Driver)
    foreach ($ga_ientry in $pEntryList) {
        #if ( $ga_ientry.CVAHWID -notlike 'NA' ) {   # N/A is set by the script when a component for the driver is not found in the system
        if ( $ga_ientry.CVAHWID ) {   # N/A is set by the script when a component for the driver is not found in the system
            $ga_count++
            $ga_ientry = Get-SoftpaqFiles -pSoftpaqObj $ga_ientry -pFolderPath $Script:ActionPath -pDownloadAction $pGetAction
        } # if ( $ga_ientry.CVAHWID -notlike 'NA' )
    } # foreach ($ga_ientry in $pEntryList)
    if ( $DebugOut ) { TraceLog -Message "  < Get-AllSoftpaqs() - processed $ga_count Softpaqs" -Type $TypeNorm }

    return $ga_count
} # Function Get-AllSoftpaqs()

<######################################################################################
    Function Get-OutputLine
    This function formats the output line for the Softpaq analysis
    parm: $pEntry           the Softpaq hash entry to format
           $pShowHWID       whether to show the Hardware ID in the output
    return: $go_msg
#>#####################################################################################
Function Get-OutputLine {
    [CmdletBinding()] param( $pEntry, $pShowHWID )

    $VerInstallDate = ($pEntry.InstallDate -split ' ')[0]

    #######################################
    # setup text output string
    #######################################
    
    $go_msg = "$($pEntry.SoftpaqID),$($pEntry.SoftpaqName),$($pEntry.ReferenceFileVersion) $($pEntry.SoftpaqDate)"

    if ( $pEntry.InstallVersion ) {
        if ( $pEntry.InstallVersion -like 'MISSING' ) {
            $go_msg += ','+$pEntry.InstallVersion+' '+($VerInstallDate)
        } else {
            #if ( ($pEntry.category -like 'driver' -and -not $pEntry.CVAHWID) -or ($pEntry.category -notlike 'driver') ) {   # drivers must have a CVAHWID

            #if ( ($pEntry.category -match '^driver|^Dock') -and -not $pEntry.CVAHWID ) {           # PnP ID Not found in systems
            if ( -not $pEntry.CVAHWID ) {           # PnP ID Not found in systems
                $go_msg += ',Device NOT Found'
            } else {
                $go_msg += ',Installed '+$pEntry.InstallVersion+' '+($VerInstallDate)
            }
        } # else if ( $pEntry.InstallVersion -like 'MISSING' )
    } else { 
        if ( $pEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPUPDATEAVAILABLE ) {
            $go_msg += ',UWP Update'
        } else {
            $go_msg += ',Not Installed'  
        }              
    } # else if ( $pEntry.InstallVersion )

    # add Softpaq category to output list
    $go_msg += ",($($pEntry.Category)-$($pEntry.ReleaseType)),$($pEntry.DeviceClass)"

    # add UWP info entries
    switch ( $pEntry.UWPStatus ) {                    
        $Script:Config.Constants.SPQUWPNOTINSTALLED  { 
            if ( $pEntry.UWPVersion ) {
                    $go_msg    += ",UWP:$($pEntry.UWPName):$($pEntry.UWPVersion)"
                } 
        } # $Script:Config.Constants.SPQUWPNOTINSTALLED
         $Script:Config.Constants.SPQUWPUPTODATE  { $go_msg += ",UWP:$($pEntry.UWPName)" } 
         $Script:Config.Constants.SPQUWPUPDATEAVAILABLE  { 
            $go_msg += ",UWP Update:$($pEntry.UWPName):$($pEntry.UWPVersion)/[Installed:$($pEntry.UWPInstallVersion)]" 
        } # $Script:Config.Constants.SPQUWPUPDATEAVAILABLE
    } # switch ( $pEntry.UWPStatus )

    # add HW ID matched to this driver
    if ( $pShowHWID -and $pEntry.CVAHWID ) { $go_msg += ",$($pEntry.CVAHWID.replace('\\','\'))" }        
   
    return $go_msg
} # Function Get-OutputLine()

<######################################################################################
    Function Invoke-ReportToCSV
    This function generates a report of the Softpaq analysis results
    parm: $pEntryList:     the list of Softpaqs to report on
           $pFilePath:      the file path to save the report to
#>#####################################################################################
Function Invoke-ReportToCSV {
    [CmdletBinding()] param( $pEntryList, $pFilePath )

    $ir_columnOrder = @(
        'SoftpaqID', 'SoftpaqName', 'SoftpaqDate', 'SoftpaqVersion', 'InstallVersion', 'Status' , 'Category', 'DeviceClass', 
        'ReleaseType', 'CVAHWID', 'UWPName', 'UWPVersion', 'UWPInstallVersion', 'UWPStatus', 'URL' 
    )
    $pEntryList | 
        Where-Object { $_.ReferenceFileVersion } |             # ensure the entry is in the reference file
        ForEach-Object { [PSCustomObject]$_ } | 
        Select-Object $ir_columnOrder | Sort-Object Category |
        Export-Csv -Path "$($pFilePath)" -NoTypeInformation
    # include notes on status
    Add-Content "$($pFilePath)" -Value " " -Encoding ASCII   # add empty line
    Add-Content "$($pFilePath)" -Value ',,,,,1=Update Available; 0=Up To Date; -1=NOT Installed,,,,,,,,11=Update Available; 10=Up To Date; -11=NOT Installed' -Encoding ASCII   # add empty line

} # Function Invoke-ReportToCSV()

<######################################################################################
    Function New-JsonItem
    This function creates a sorted item from a Softpaq entry to be used for json output
    parm: $pSoftpaqEntry:  the Softpaq hash entry to convert to orderd hash
#>#####################################################################################
Function New-JsonItem {
    [CmdletBinding()] param ( $pSoftpaqEntry )

    $JsonItem = [ordered]@{
        SoftpaqID = $pSoftpaqEntry.SoftpaqID
        SoftpaqName = $pSoftpaqEntry.SoftpaqName
        url = $pSoftpaqEntry.url
        Category = $pSoftpaqEntry.Category
        ReleaseType = $pSoftpaqEntry.ReleaseType
        SoftpaqDate = $pSoftpaqEntry.SoftpaqDate
        SoftpaqVersion = $pSoftpaqEntry.SoftpaqVersion
        InstalledVersion = $pSoftpaqEntry.InstallVersion
        ActionReturnCode = $pSoftpaqEntry.ActionReturnCode
    }
    if ( $pSoftpaqEntry.Category -match 'driver' ) { $JsonItem.DeviceID = $pSoftpaqEntry.CVAHWID }

    return $JsonItem
} # Function New-JsonItem()

# -----------------------------------------------------------------------------------

#####################################################################################
# Start of Script
#####################################################################################

$CurrLocation = Get-location

Resolve-OptionConflicts         # resolve options conflicts

if ( $DebugOut ) { TraceLog -Message "-- Debug mode enabled" -Type $TypeNorm }
if ( $DebugOut ) { $NoDots = $true }

# -----------------------------------------------------------------------------------

# set up the environment for the action, if needed
$Script:AnalyzerEnv = Initialize-Environment $Action $Script:ActionPath

# -----------------------------------------------------------------------------------

$SoftpaqsUpdateList = @()                   # List of Softpaqs that have updates
$SoftpaqsNOUpdateList = @()                 # list of Softpaqs that do NOT require updates
$SoftpaqsNOTInstalledList = @()             # list of Softpaqs that are NOT installed

if ( -not $CleanOutput ) { TraceLog -Message '-- Analyzing Softpaqs - Please wait...' $TypeNorm }
foreach ( $Spq in $AnalyzerEnv.SoftpaqList ) {

    if ( -not $NoDots ) { if ( -not $CleanOutput ) { TraceLog -Message "." -Type $TypeNoNewline } } # if ( -not $NoDots )
    if ( $DebugOut ) { TraceLog -Message "-- Analyzing Softpaq: $($Spq.id) - $($Spq.name)" $TypeNorm }    
    
    ##########################################################################################
    # Let's do the analysis, but only if the Softpaq is not a Firmware (like SSD's) or Manageability (Driver pack) Softpaq
    # Firmware and Manageability Softpaqs, like Docks are not supported by this script, so we skip them    

    ### avoid driver pack softpaqs ###
    if ( $Spq.Category -match '^Manageability' ) {
        if ( $DebugOut ) { TraceLog -Message "  ... skipping Softpaq: $($Spq.id) - $($Spq.name) - Category ''manageability'' not supported by script" $TypeNorm }
        continue
    } # if ( $Spq.Category -match '^Manageability' )
    ### avoid dock firmware softpaqs - OK for drivers ###
    if ( $Spq.Category -match '^Dock' -and ($Spq.Name -notmatch '^All Docks') ) {
        if ( $DebugOut ) { TraceLog -Message "  ... skipping Softpaq: $($Spq.id) - $($Spq.name) - Category 'Dock' firmware not supported by script" $TypeNorm }
        continue
    } # if ( $Spq.Category -match '^Dock' -and ($Spq.Name -notmatch '^All Docks') )
    ### avoid Software Softpaqs that are HP managed - avoid analyzing them ###
    if ( $spq.name -match '^HP Wolf|^HP Sure|^HP Services Scan' ) {
        if ( $DebugOut ) { TraceLog -Message "  ... skipping Softpaq: $($Spq.id) - $($Spq.name) - is managed" $TypeNorm }
        continue
    } # if ( $spq.name -match '^HP Wolf|^HP Sure|^HP Services Scan' )
    ##########################################################################################

    $SoftpaqEntry = Invoke-SoftpaqAnalysis $Spq $Script:AnalyzerEnv.PnpSignedDrivers $AnalyzerEnv.Links $Category

    switch ( $SoftpaqEntry.Status ) {
        $Script:Config.Constants.SPQNOTINSTALLED    { 
            if ( $SoftpaqEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPUPDATEAVAILABLE ) {
                $SoftpaqsUpdateList += $SoftpaqEntry
            } else {
                # if the Softpaq is not installed, we need to check if it is a Software Softpaq that was recommended
                # and if it is, we add it to the SoftpaqsUpdateList
                if (  $RecommendedSoftware -and $SoftpaqEntry.SoftpaqName -in $Script:Config.RecommendedSWList ) {
                    $SoftpaqEntry.SoftpaqVersion = $SoftpaqEntry.ReferenceFileVersion     # use the ReferenceFileVersion for Software Softpaqs            
                    $SoftpaqsUpdateList += $SoftpaqEntry       # adding to the update list
                } else {
                    $SoftpaqsNOTInstalledList += $SoftpaqEntry
                } # if ( $SoftpaqEntry.SoftpaqName -in $Script:Config.RecommendedSWList )         
            } # else
        } # $Script:Config.Constants.SPQNOTINSTALLED 
        $Script:Config.Constants.SPQUPTODATE        { 
            if ( $SoftpaqEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPUPDATEAVAILABLE ) {
                $SoftpaqsUpdateList += $SoftpaqEntry
            } else {
                $SoftpaqsNOUpdateList += $SoftpaqEntry
            } # else if ( $SoftpaqEntry.UWPStatus -eq $Script:Config.Constants.SPQUWPUPDATEAVAILABLE )            
        }
        $Script:Config.Constants.SPQUPDATEAVAILABLE {
            $SoftpaqsUpdateList += $SoftpaqEntry
        }                 
    } # switch ( $SoftpaqEntry.Status )

} # foreach ( $Spq in $AnalyzerEnv.SoftpaqList )

# -----------------------------------------------------------------------------------

####################################################################
# FINALLY: perform the required -Action, if other than 'Scan'
####################################################################

switch ( $Action ) {
    'Scan' {
        if ( -not $CleanOutput ) { TraceLog -Message "`n-- Scanning and Reporting" $TypeNorm  }
    } # 'Scan'
    'CreateRepo' {
        if ( -not $CleanOutput ) { TraceLog -Message "`n-- Downloading Softpaqs to the Repository Folder: $($Script:ActionPath)" $TypeNorm  }
    } # 'CreateRepo'
    'Download' {
        if ( -not $CleanOutput ) { TraceLog -Message "`n-- Downloading Softpaqs to: $($Script:ActionPath)" $TypeNorm }
    } # 'Download'
} # switch ( $Action )

# Show Device information in the JSON output
$JsonOut = [Ordered]@{
    "PlatformName" = $AnalyzerEnv.PlatformName
    "PlatformID" = $AnalyzerEnv.PlatformID
    "Analyzer Script" = $ScriptVersion
    "OS" = $AnalyzerEnv.OS
    "OSVer" = $AnalyzerEnv.OSVer    
    "DateTime" = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    "Action" = $Action
    "Remediations" = @()
} # $JsonHeader

####################################################################
# loop through the Softpaq entries and process each one
# if the Softpaq is a driver and has a CVAHWID, it is considered valid for download
####################################################################
if ( -not $CleanOutput ) { TraceLog -Message '-- Softpaq Updates' $TypeNorm }
$TotalRemediations = 0
if ( -not $NoDots ) {if ( -not $CleanOutput ) { TraceLog -Message ' ' $TypeNorm } }         # output empty line to separate output

foreach ( $iEntry in $SoftpaqsUpdateList ) {

    if ( $iEntry.category -like 'driver' -and (-not $iEntry.CVAHWID) ) { continue } # skip drivers without CVAHWID (e.g. not in the system) 
    
    if ( $null -ne $iEntry.SoftpaqID ) {
        if ( $Action -notlike 'Scan') {
            $iEntry = Get-SoftpaqFiles -pSoftpaqObj $iEntry -pFolderPath $Script:ActionPath -pDownloadAction $pGetAction
        } # if ( $Action -notlike 'Scan')
        $TotalRemediations++
        $OutputLine = Get-OutputLine $iEntry $ShowHWID      # create the output line
        TraceLog -Message $OutputLine $TypeNorm             # output the remediation line
        $JsonOut.Remediations += New-JsonItem $iEntry       # create JSON entry for this remediation
    } # if ( $null -ne $iEntry.SoftpaqID )

} # foreach ($iEntry in $SoftpaqsUpdateList)


####################################################################
# Now report what we found - in CSV and Json formats
####################################################################

# -----------------------------------------------------------------------------------
# Export the Softpaq analysis results to a CSV file, if file can be accessed
try {
    if ( Test-Path $Script:Config.Paths.CsvFile ) { [IO.File]::OpenWrite((Get-ChildItem $Script:Config.Paths.CsvFile).FullName).close() }        
    if ( -not $CleanOutput ) { TraceLog -Message "-- Exporting results to CSV-formatted file: $($Script:Config.Paths.CsvFile)" $TypeNorm  }
    Invoke-ReportToCSV -pEntryList $SoftpaqsUpdateList -pFilePath $Script:Config.Paths.CsvFile
} catch {
    TraceLog -Message "-- CSV File $($Script:Config.Paths.CsvFile) is locked, can not overwrite" $TypeNorm 
} # try/catch block for CSV file

# -----------------------------------------------------------------------------------
# Handle artifact of PS5.1/ConvertTo-Json that does not handle '&' and '\' characters - converts to Unicode characters
if ( -not $CleanOutput ) { TraceLog -Message "-- Exporting results to JSON-formatted file: $($Script:Config.Paths.JsonFile)" $TypeNorm }
$JsonOut = $JsonOut | 
    ConvertTo-Json -Depth 4 | 
    ForEach-Object { $_.Replace('\u0026', '&').Replace('\\', '\') } | 
    Out-File -FilePath $Script:Config.Paths.JsonFile -Encoding UTF8
# -----------------------------------------------------------------------------------

$elapsedTime = New-TimeSpan -Start $startTime -End (get-date)
if ( -not $CleanOutput ) { TraceLog -Message "-- Elapsed: [min:sec] $($elapsedTime.ToString("mm\:ss"))" $TypeNorm }

Set-location $CurrLocation

return  $TotalRemediations
# end of script