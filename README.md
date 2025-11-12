# VPN Scanner

A PowerShell script that scans Windows systems for VPN connections and extracts VPN server IP addresses from multiple sources including active connections, VPN client logs, and Windows Event Logs.

## Features

- **Multi-Source Scanning**: Scans active VPN connections, VPN client logs, and Windows Event Logs
- **Multi-User Support**: Scans all logged-in user profiles for VPN client logs
- **Multiple VPN Client Support**: Detects and scans logs from popular VPN clients including:
  - NordVPN, ExpressVPN, Surfshark, ProtonVPN, CyberGhost
  - Cisco AnyConnect, Pulse Secure, Juniper VPN, FortiClient
  - GlobalProtect, Check Point, SonicWall, Private Internet Access (PIA)
  - Windscribe, TunnelBear, IPVanish, HideMyAss, TorGuard
  - Mullvad, ZenMate, OpenVPN, WireGuard
- **Public IP Filtering**: By default, filters out private IP addresses (can be disabled)
- **CSV Export**: Exports results to a timestamped CSV file
- **Copy-Paste Output**: Provides a comma-separated list of IPs for easy copying
- **Remote Execution**: Can be run directly from GitHub or via ConnectWise ScreenConnect

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Administrator privileges recommended for full functionality
- Access to user profile directories (may require elevated permissions)

## Quick Start

### Run from GitHub (PowerShell)

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1" -OutFile "$env:TEMP\vpn-scan.ps1"
& "$env:TEMP\vpn-scan.ps1"
```

### Run via ScreenConnect

Copy and paste this command into ScreenConnect's Command tab:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -OutFile '$env:TEMP\vpn-scan.ps1'; & '$env:TEMP\vpn-scan.ps1'"
```

## Usage

### Parameters

- `-DaysBack <int>`: Number of days to look back in logs (default: 30)
- `-OutputFile <string>`: Output CSV file path (default: auto-generated with timestamp)
- `-IncludePrivateIPs`: Include private IP addresses in results
- `-Verbose`: Show detailed output for each found IP

### Running from GitHub (PowerShell)

You can run the script directly from GitHub without downloading it first:

```powershell
# Basic execution (one-liner)
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1" -UseBasicParsing).Content

# Download and run (recommended)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1" -OutFile "$env:TEMP\vpn-scan.ps1"
& "$env:TEMP\vpn-scan.ps1" -DaysBack 30

# With parameters
& "$env:TEMP\vpn-scan.ps1" -DaysBack 60 -Verbose
```

### ConnectWise ScreenConnect Command

Use these commands in ScreenConnect's Command tab:

**Basic (default 30 days) - Recommended:**
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -OutFile '$env:TEMP\vpn-scan.ps1'; & '$env:TEMP\vpn-scan.ps1'"
```

**With parameters (60 days back, verbose):**
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -OutFile '$env:TEMP\vpn-scan.ps1'; & '$env:TEMP\vpn-scan.ps1' -DaysBack 60 -Verbose"
```

**Include private IPs:**
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -OutFile '$env:TEMP\vpn-scan.ps1'; & '$env:TEMP\vpn-scan.ps1' -IncludePrivateIPs"
```

**90 days back with custom output:**
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -OutFile '$env:TEMP\vpn-scan.ps1'; & '$env:TEMP\vpn-scan.ps1' -DaysBack 90 -OutputFile 'C:\Reports\vpn_results.csv'"
```

> **Note:** For a complete reference of ScreenConnect commands, see [SCREENCONNECT-COMMANDS.md](SCREENCONNECT-COMMANDS.md)

### Local Usage

If you've cloned or downloaded the repository:

```powershell
# Basic usage
.\vpn-scan.ps1

# Scan last 60 days
.\vpn-scan.ps1 -DaysBack 60

# Include private IPs
.\vpn-scan.ps1 -IncludePrivateIPs

# Custom output file
.\vpn-scan.ps1 -OutputFile "C:\Reports\vpn_ips.csv"

# Verbose output
.\vpn-scan.ps1 -Verbose

# Combine parameters
.\vpn-scan.ps1 -DaysBack 90 -IncludePrivateIPs -Verbose
```

## Output

The script generates a CSV file with the following columns:

- `TimeCreated`: Timestamp when the IP was found/connected
- `IPAddress`: VPN server IP address
- `Source`: Source of the IP (e.g., "Active-nordvpn", "Log-NordVPN", "Windows RasClient")
- `Details`: Additional details about the connection or log entry

### Console Output

The script displays:
- Execution context information (user, admin status, session ID)
- Progress indicators for each scan phase
- Summary of found IPs grouped by source
- A comma-separated list of unique IPs for easy copying

### Output File Location

- **Default**: Current directory with timestamp: `VPN_IPs_YYYYMMDD_HHMMSS.csv`
- **ScreenConnect**: `%TEMP%\VPN_IPs_YYYYMMDD_HHMMSS.csv` (usually `C:\Users\<username>\AppData\Local\Temp\`)

## How It Works

The script performs a three-phase scan:

1. **Active Connections**: Scans running processes for VPN clients and checks their network connections
   - Identifies VPN processes by name and command line patterns
   - Queries active TCP connections for those processes
   - Filters public vs private IPs based on settings

2. **Client Logs**: Searches user profile directories for VPN client log files
   - Scans all logged-in user profiles
   - Searches known VPN client log locations
   - Extracts IP addresses from log entries matching connection patterns
   - Respects the `-DaysBack` parameter for log file filtering

3. **Event Logs**: Queries Windows Event Logs for VPN-related events
   - Checks Application log (RasClient, RasServer)
   - Checks System log (RemoteAccess)
   - Extracts IP addresses from event messages

Results are deduplicated and sorted by IP address and timestamp.

## Supported VPN Clients

The script detects processes and scans logs for:

**Consumer VPNs:**
- NordVPN, ExpressVPN, Surfshark, ProtonVPN, CyberGhost
- Private Internet Access (PIA), Windscribe, TunnelBear
- IPVanish, HideMyAss, TorGuard, Mullvad, ZenMate

**Enterprise VPNs:**
- Cisco AnyConnect, Pulse Secure, Juniper VPN
- FortiClient, GlobalProtect, Check Point, SonicWall

**Open Source:**
- OpenVPN, WireGuard

## Troubleshooting

### No VPN connections found

If the script reports no VPN connections, check:

- **VPN clients running in different sessions**: The script scans all logged-in users, but VPN processes in other user sessions may not be accessible
- **Non-standard log locations**: Some VPN clients may store logs in custom locations
- **Private IP ranges**: Use `-IncludePrivateIPs` to see private IP addresses
- **Insufficient permissions**: Run with administrator privileges for full access

### Access denied errors

- Run PowerShell as Administrator
- Ensure you have access to user profile directories
- Some VPN clients may restrict log file access

### Script execution policy

If you encounter execution policy errors:

```powershell
# For current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Or use the -ExecutionPolicy Bypass flag with powershell.exe
powershell.exe -ExecutionPolicy Bypass -File .\vpn-scan.ps1
```

### Output file not found

- Check the current directory (default location)
- Check `%TEMP%` directory when run via ScreenConnect
- Use `-OutputFile` parameter to specify a custom location

## Security Notes

- This script requires access to user profile directories and may need elevated permissions
- The script only reads log files and network connection information; it does not modify any system settings
- Results may contain sensitive information; handle output files appropriately
- When running from GitHub, ensure you trust the source repository
- Consider reviewing the script contents before execution in sensitive environments

## Use Cases

- **Security Audits**: Identify VPN usage across endpoints
- **Compliance**: Track VPN connections for policy enforcement
- **Incident Response**: Investigate VPN connections during security incidents
- **Network Monitoring**: Monitor VPN server IPs for threat intelligence
- **Remote Support**: Quickly identify VPN clients on remote systems

## License

MIT License - see [LICENSE](LICENSE) file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Repository

**GitHub**: https://github.com/monobrau/vpn-scan
