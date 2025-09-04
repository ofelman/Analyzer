[README-Simple.md](https://github.com/user-attachments/files/22144926/README-Simple.md)
# HP Analyzer

A PowerShell script for analyzing HP business PCs and managing BIOS, driver, and software updates using the HP Client Management Script Library (CMSL).

## Features

- **System Analysis**: Detects HP platform and available updates
- **CVE Security Checking**: Reports on security vulnerabilities fixed by reported Softpaqs
- **Multiple Actions**: Scan, Download, Install, or Create HPIA Repository
- **Filtering Options**: Filter by category (BIOS/Driver) and type of Driver
- **CVE Report Option**: Report on found Softpaqs' CVE fixes
- **Comprehensive Reports**: Generates TXT, CSV, and JSON output files

## Quick Start

### Prerequisites
- Windows 10/11 with PowerShell 5.1+
- HPIA/HP CMSL Supportd HP Business PC
- HP Client Management Script Library (CMSL)

`powershell
Install-Module -Name HPCMSL -Force
`

### Basic Usage

`powershell
# Basic system scan
.\Analyzer2.06.00.ps1

# Scan with CVE checking (NEW in v2.06.00)
.\Analyzer2.06.00.ps1 -CVECheck

# Download all updates to specific path
.\Analyzer2.06.00.ps1 -Action Download -ActionPath \"C:\HPUpdates\"

# Install BIOS updates only
.\Analyzer2.06.00.ps1 -Action Install -Category BIOS
`

## Parameters

| Parameter      | Description                                              | Example |
|----------------|----------------------------------------------------------|---------|
| -Action        | Action to perform: Scan, Download, Install, CreateRepo   | -Action Download |
| -Category      | Filter by BIOS or Driver                                 | -Category BIOS,Driver |
| -CVECheck      | Enable CVE vulnerability checking                        | -CVECheck |
| -SubCategory   | Filter drivers: Audio, Chipset, Graphics, Network, Video | -SubCategory Graphics |
| -ReferenceFile | Use local XML reference file                             | -ReferenceFile "C:\8b92_64_11.0.24H2.xml" |
| -Verbose       | Provide additional information to console, execution log | - Verbose
| -Debug         | write debug information to a debug log file              | - Debug

## What's New in v2.06.00

-  **CVE Checking**: New -CVECheck parameter to identify security fixes from reported Softpaqs. Supported in -Action Scan
-  **Enhanced Reports**: CVE information included in CSV and JSON outputs, also with -Verbose

## Output Files

- **Log**: Analyzer-[timestamp].txt - Detailed execution log
- **CSV**: Analyzer-[timestamp].csv - Structured data with CVE info
- **JSON**: Analyzer-[timestamp].json - Machine-readable format

## Examples

### Analyze device's Network driver status and report on CVE fixes
`powershell
.\Analyzer.ps1 -CVECheck -Category Driver -SubCategory Network
`

### Create HPIA Repository with reported Softpaqs pn specific path
`powershell
.\Analyzer.ps1 -Action CreateRepo -ActionPath "\\Server\HPRepo"
`

### Install with Custom, local Reference File
`powershell
.\Analyzer.ps1 -Action Install -ReferenceFile "C:\8b92_64_11.0.xml"
`

## Requirements

- HP Business PC (supported models)
- Internet connectivity
- Administrative privileges (for Install action)

## Disclaimer

Provided \"as-is\" without warranty. Not officially supported by HP Inc.

## Links

- [HP Client Management Script Library](https://developers.hp.com/hp-client-management)
- [HP Image Assistant](https://ftp.hp.com/pub/caps-softpaq/cmit/HPIA.html)
