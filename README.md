# Analyzer v2.05.05

## Overview

Analyzer is a comprehensive PowerShell script designed to analyze HP business PCs and identify available BIOS, driver, and software updates using only the HP Client Management Script Library (CMSL).

## Features

- **System Analysis**: Automatically detects HP platform and identifies available updates
- **Local Reference File**: Supports a locally provider (massaged) reference file
- **Multiple Actions**: Scan, Download, Install, or Create HPIA Repository with updates
- **Categorized Updates**: Filter by BIOS, Driver categories
- **Subcategory Filtering**: Narrow down driver updates by type (Audio, Chipset, Graphics, Network, Video)
- **Comprehensive Reporting**: Generates detailed logs in text, CSV, and JSON formats
- **Debug Support**: Extensive logging and debugging capabilities in a debug file (-d|debug)

## Prerequisites

### Software Requirements
- **Operating System**: Windows 10/11 as support by HP CMSL for the platform
- **PowerShell**: Windows PowerShell 5.1 or PowerShell 7+
- **HP CMSL**: HP Client Management Script Library module
- **Platform**: Supported HP business PC

### System Requirements
- **Network**: Internet connectivity
- **Privileges**: Administrative rights (required for Install action only)

## Parameter Reference

### -Action [String]
Specifies the operation to perform:
- **Scan** (default): Analyze system and display available updates
- **Download**: Download updates to specified location
- **Install**: Download and install updates (requires elevation)
- **CreateRepo**: Create local repository of updates

### -ActionPath [String]
Target directory for download/repository operations
- **Default**: $env:TEMP\HPAnalyzer
- **Example**: "C:\HPUpdates"

### -Category [String[]]
Limit analysis to specific update categories:
- **BIOS**: System firmware updates
- **Driver**: Hardware driver updates
- **Default**: All categories (BIOS, Driver, Software, Utility)

### -SubCategory [String[]]
Filter driver updates by subcategory:
- **Audio**: Audio device drivers
- **Chipset**: Chipset and system drivers  
- **Graphics**: Display and graphics drivers
- **Network**: Network adapter drivers
- **Video**: Video capture drivers

### -ReferenceFile [String]
Specifies a local XML reference file to use for analysis instead of downloading from HP:
- **Validation**: File must exist, have the proper name and .xml extension
- **Format**: HP Image Assistant information XML file
- **Example**: "C:\TEMP\Reference\8b92_64_11.0.24H2.xml"

## Usage Examples

### Example 1: Basic System Scan
.\Analyzer.ps1
**Output**: Displays all available updates for the current system

### Example 2: BIOS-Only Analysis with additional information
.\Analyzer.ps1 -Category BIOS -Verbose

### Example 3: Download only Graphics Driver Updates
.\Analyzer.ps1 -Action Download -Category Driver -SubCategory Graphics -ActionPath "C:\GraphicsUpdates"

### Example 4: Analyze and create an HPIA Repository with Softpaqs
.\Analyzer.ps1 -Action CreateRepo -ActionPath "\\Server\HPRepository" -Category BIOS,Driver

### Example 5: Automated Installation of 'Network' drivers only -# Run as Administrator REQUIRED
.\Analyzer.ps1 -Action Install -Category Driver -SubCategory Network -Verbose

### Example 6: Report using a Local Reference File (potentially modified or saved as needed)
.\Analyzer.ps1 -Action Scan -ReferenceFile "C:\TEMP\Reference\8b92_64_11.0.24H2.xml"

## Output Files

The script generates several output files with timestamps:

| File Type       | Naming Convention                  | Description                             |
|-----------------|------------------------------------|-----------------------------------------|
| **Log File**    | `Analyzer-YYYYMMDD-HHMM.txt`       | Human-readable execution log            |
| **CSV Report**  | `Analyzer-YYYYMMDD-HHMM.csv`       | Structured data for sprehsheet analysis |
| **JSON Report** | `Analyzer-YYYYMMDD-HHMM.json`      | Machine-readable results                |
| **Debug Log**   | `Analyzer-YYYYMMDD-HHMM-Debug.log` | Detailed debug information (with -Debug)|

*Last Updated: August 29, 2025*
*HP Platform Analyzer v2.05.05*
