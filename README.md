# VPN Scanner

A PowerShell script that scans Windows systems for VPN connections and extracts VPN server IP addresses from multiple sources including active connections, VPN client logs, and Windows Event Logs.

## Features

- **Multi-Source Scanning**: Scans active VPN connections, VPN client logs, and Windows Event Logs
- **Multi-User Support**: Scans all logged-in user profiles for VPN client logs
- **Multiple VPN Client Support**: Detects and scans logs from popular VPN clients including:
  - NordVPN
  - ExpressVPN
  - Surfshark
  - ProtonVPN
  - CyberGhost
  - Cisco AnyConnect
  - Windscribe
  - WireGuard
  - And many more...
- **Public IP Filtering**: By default, filters out private IP addresses (can be disabled)
- **CSV Export**: Exports results to a timestamped CSV file
- **Copy-Paste Output**: Provides a comma-separated list of IPs for easy copying

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Administrator privileges recommended for full functionality
- Access to user profile directories (may require elevated permissions)

## Usage

### Basic Usage

```powershell
.\vpn-scan.ps1
```

### Parameters

- `-DaysBack <int>`: Number of days to look back in logs (default: 30)
- `-OutputFile <string>`: Output CSV file path (default: auto-generated with timestamp)
- `-IncludePrivateIPs`: Include private IP addresses in results
- `-Verbose`: Show detailed output for each found IP

### Examples

```powershell
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

The script also displays:
- Execution context information
- Summary of found IPs grouped by source
- A comma-separated list of unique IPs for easy copying

## How It Works

1. **Active Connections**: Scans running processes for VPN clients and checks their network connections
2. **Client Logs**: Searches user profile directories for VPN client log files and extracts IP addresses
3. **Event Logs**: Queries Windows Event Logs for VPN-related events (RasClient, RasServer, RemoteAccess)

## Supported VPN Clients

The script detects processes and scans logs for:

- NordVPN
- ExpressVPN
- Surfshark
- ProtonVPN
- CyberGhost
- Cisco AnyConnect
- Pulse Secure
- Juniper VPN
- FortiClient
- GlobalProtect
- Check Point
- SonicWall
- Private Internet Access (PIA)
- Windscribe
- TunnelBear
- IPVanish
- HideMyAss
- TorGuard
- Mullvad
- ZenMate
- OpenVPN
- WireGuard

## Security Notes

- This script requires access to user profile directories and may need elevated permissions
- The script only reads log files and network connection information; it does not modify any system settings
- Results may contain sensitive information; handle output files appropriately

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

