# Analyzer

A PowerShell script that analyzes HP business-class PCs to identify available BIOS, Driver, and Software updates (Softpaqs) and provides options to download or create repositories for system maintenance.

## Overview

The HP Softpaq Analyzer script scans supported HP business devices and compares installed components against HP's software repository to identify available updates. It can perform analysis-only scans, download updates, or create HP Image Assistant (HPIA) repositories for deployment.

## Prerequisites

- **HP Client Management Script Library (CMSL)** - Required for device identification and Softpaq management
- **HP Business-class devices** - Must be supported by HPIA and HP CMSL
- **Internet access** - Required for downloading Softpaq information and files
- **PowerShell 5.1 or later**
- **Administrative privileges** (recommended for full functionality)

## Installation

1. Install HP CMSL if not already installed:
   ```powershell
   Install-Module -Name HPCMSL -Force
   ```

2. Download the Analyzer script to your desired location

3. Ensure execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Usage

### Basic Syntax
```powershell
.\Analyzer2.01.02.ps1 [parameters]
```

### Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-Action` | String | Action to perform: 'Scan', 'Download', or 'CreateRepo' | 'Scan' |
| `-ActionPath` | String | Path for downloads or repository creation | `$env:TEMP\HPAnalyzer` |
| `-Category` | String[] | Filter by categories: 'BIOS', 'Driver' | All categories |
| `-CleanOutput` | Switch | Show only remediation items in output | False |
| `-DebugOut` | Switch | Enable detailed debugging information | False |
| `-NoDots` | Switch | Suppress progress dots during analysis | False |
| `-RecommendedSoftware` | Switch | Include HP recommended software | False |
| `-ShowHWID` | Switch | Display matching hardware IDs | False |
| `-Silent` | Switch | Suppress console output (log file only) | False |
| `-SubCategory` | String[] | Filter drivers by subcategory: 'Audio', 'Chipset', 'Graphics', 'Network', 'Video' | All subcategories |
| `-Help` | Switch | Display help information | False |

### Actions

#### Scan (Default)
Analyzes the current device and generates reports without downloading files.
```powershell
.\Analyzer2.01.02.ps1
.\Analyzer2.01.02.ps1 -Action Scan
```

#### Download
Scans the device and downloads available Softpaq updates to the specified path.
```powershell
.\Analyzer2.01.02.ps1 -Action Download -ActionPath "C:\HP_Updates"
```

#### CreateRepo
Creates an HP Image Assistant repository with the identified updates.
```powershell
.\Analyzer2.01.02.ps1 -Action CreateRepo -ActionPath "C:\HPIA_Repo"
```

## Examples

### Basic device scan
```powershell
.\Analyzer2.01.02.ps1
```

### Scan for BIOS updates only
```powershell
.\Analyzer2.01.02.ps1 -Category BIOS
```

### Scan for driver updates showing matching driver hardware IDs
```powershell
.\Analyzer2.01.02.ps1 -Category Driver -ShowHWID
```

### Download graphics and network drivers
```powershell
.\Analyzer2.01.02.ps1 -Action Download -SubCategory Graphics,Network -ActionPath "C:\Drivers"
```

### Include HP recommended software
```powershell
.\Analyzer2.01.02.ps1 -RecommendedSoftware
```

### Silent operation with debug logging
```powershell
.\Analyzer2.01.02.ps1 -Silent -DebugOut
```

### Clean output showing only needed updates
```powershell
.\Analyzer2.01.02.ps1 -CleanOutput
```

## Output Files

The script generates several output files in the current directory:

### Log File
- **Format**: `Analyzer-YYYYMMDD-HHMM.log`
- **Content**: Detailed execution log with timestamps and debug information

### CSV Report
- **Format**: `Analyzer-YYYYMMDD-HHMM.csv`
- **Content**: Structured data of all analyzed Softpaqs with status codes
- **Columns**: SoftpaqID, SoftpaqName, SoftpaqDate, SoftpaqVersion, InstallVersion, Status, Category, DeviceClass, ReleaseType, CVAHWID, UWP information, URL

### JSON Report
- **Format**: `Analyzer-YYYYMMDD-HHMM.json` 
- **Content**: Machine-readable output suitable for automation and integration
- **Structure**: Platform information and remediation details

## Recommended HP Software

When using the `-RecommendedSoftware` parameter, the script will include analysis for:
- HP Notifications
- HP Power Manager  
- HP Smart Health
- HP Programmable Key
- HP Auto Lock and Awake
- System Default Settings

## Troubleshooting

### Common Issues

1. **"Failed to get HP Device Product ID"**
   - Ensure HP CMSL is installed and up to date
   - Verify the device is an HP business-class PC supported by CMSL

2. **"Failed to retrieve Softpaq list"**
   - Check internet connectivity
   - Verify firewall/proxy settings allow HP repository access

3. **CSV file locked error**
   - Close any applications that may have the CSV file open
   - Ensure write permissions to the script directory

### Debug Mode
Use `-DebugOut` parameter for detailed troubleshooting information:
```powershell
.\Analyzer2.01.02.ps1 -DebugOut
```

## Version History

- **2.01.02** (Current) - initial Github release

## Return Values

The script returns the total number of remediations (updates) found:
- `0` = No updates needed
- `>0` = Number of available updates

## platform Support

This script is designed for HP business-class devices and requires HP CMSL. For issues related to:
- **HP CMSL**: Consult HP documentation and support resources
- **Device compatibility**: Verify device is supported by HP Image Assistant
- **Script functionality**: Review debug logs and error messages

## Author

**Dan Felman/HP Inc**

Current version: June 23, 2025
