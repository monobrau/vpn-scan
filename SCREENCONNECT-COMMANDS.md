# ScreenConnect Command Reference

Quick reference for running VPN Scanner via ConnectWise ScreenConnect Command tab.

## Basic Commands

### Default Scan (30 days)
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -OutFile '$env:TEMP\vpn-scan.ps1'; & '$env:TEMP\vpn-scan.ps1'"
```

### 60 Days Back
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -OutFile '$env:TEMP\vpn-scan.ps1'; & '$env:TEMP\vpn-scan.ps1' -DaysBack 60"
```

### 90 Days Back with Verbose Output
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -OutFile '$env:TEMP\vpn-scan.ps1'; & '$env:TEMP\vpn-scan.ps1' -DaysBack 90 -Verbose"
```

### Include Private IPs
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -OutFile '$env:TEMP\vpn-scan.ps1'; & '$env:TEMP\vpn-scan.ps1' -IncludePrivateIPs"
```

### Custom Output Location
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -OutFile '$env:TEMP\vpn-scan.ps1'; & '$env:TEMP\vpn-scan.ps1' -OutputFile 'C:\Reports\vpn_results.csv'"
```

## One-Liner (No Download)

### Basic
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -UseBasicParsing).Content"
```

### With Parameters
```powershell
powershell.exe -ExecutionPolicy Bypass -Command "$script = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/vpn-scan/main/vpn-scan.ps1' -UseBasicParsing).Content; Invoke-Expression $script -DaysBack 60 -Verbose"
```

## Notes

- Output files are saved to `%TEMP%` by default (usually `C:\Users\<username>\AppData\Local\Temp`)
- CSV files are named with timestamp: `VPN_IPs_YYYYMMDD_HHMMSS.csv`
- Results include a copy-paste list of unique IPs at the end
- Administrator privileges recommended for full functionality

