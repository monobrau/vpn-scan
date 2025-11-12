param(
    [int]$DaysBack = 30,
    [string]$OutputFile = "VPN_IPs_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$IncludePrivateIPs,
    [switch]$Verbose
)

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

function Test-PublicIP {
    param([string]$IPAddress)
    if ($IPAddress -eq '127.0.0.1') { return $false }
    if ($IPAddress -match '^127\.') { return $false }
    if ($IPAddress -match '^10\.') { return $false }
    if ($IPAddress -match '^192\.168\.') { return $false }
    if ($IPAddress -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $false }
    if ($IPAddress -match '^169\.254\.') { return $false }
    if ($IPAddress -match '^0\.') { return $false }
    if ($IPAddress -match '^224\.') { return $false }
    if ($IPAddress -eq '0.0.0.0' -or $IPAddress -eq '255.255.255.255') { return $false }
    return $true
}

function Get-ExecutionContext {
    $Context = @{
        User = [Environment]::UserName
        Domain = [Environment]::UserDomainName
        IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        SessionId = (Get-Process -Id $PID).SessionId
        ProcessName = (Get-Process -Id $PID).ProcessName
        UserProfile = $env:USERPROFILE
        LocalAppData = $env:LOCALAPPDATA
    }
    return $Context
}

function Get-LoggedInUsers {
    $LoggedInUsers = @()
    
    try {
        $Sessions = quser 2>$null | ForEach-Object {
            if ($_ -match '^\s*(\w+)\s+(\w+|\s+)\s+(\d+)\s+(\w+)\s+(.+)$') {
                [PSCustomObject]@{
                    Username = $matches[1].Trim()
                    SessionName = $matches[2].Trim()
                    SessionId = $matches[3].Trim()
                    State = $matches[4].Trim()
                    IdleTime = $matches[5].Trim()
                }
            }
        } | Where-Object { $_.State -eq 'Active' }
        
        foreach ($Session in $Sessions) {
            $UserProfile = "C:\Users\$($Session.Username)"
            if (Test-Path $UserProfile) {
                $LoggedInUsers += [PSCustomObject]@{
                    Username = $Session.Username
                    SessionId = $Session.SessionId
                    ProfilePath = $UserProfile
                    LocalAppData = "$UserProfile\AppData\Local"
                }
            }
        }
    }
    catch {
        Write-Log "Could not query user sessions: $_" "Yellow"
    }
    
    if ($LoggedInUsers.Count -eq 0) {
        try {
            $ProfileList = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | 
                          Where-Object {$_.PSChildName -match '^S-1-5-21-[\d\-]+$'} | 
                          Where-Object {$_.ProfileImagePath -and (Test-Path $_.ProfileImagePath)}
            
            foreach ($Profile in $ProfileList) {
                $Username = Split-Path $Profile.ProfileImagePath -Leaf
                $LoggedInUsers += [PSCustomObject]@{
                    Username = $Username
                    SessionId = "Unknown"
                    ProfilePath = $Profile.ProfileImagePath
                    LocalAppData = "$($Profile.ProfileImagePath)\AppData\Local"
                }
            }
        }
        catch {
            Write-Log "Could not enumerate user profiles: $_" "Yellow"
        }
    }
    
    return $LoggedInUsers
}

function Get-InstalledVPNSoftware {
    $InstalledVPNs = @()
    
    $VPNPatterns = @(
        'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'cyberghost',
        'openvpn', 'wireguard', 'cisco', 'anyconnect', 'pulse', 'juniper',
        'forticlient', 'globalprotect', 'checkpoint', 'sonicwall',
        'privateinternetaccess', 'pia', 'windscribe', 'tunnelbear',
        'ipvanish', 'hidemyass', 'torguard', 'mullvad', 'zenmate',
        'vyprvpn', 'strongvpn', 'purevpn', 'hotspot', 'shield', 'betternet',
        'vpn', 'tunnel', 'secure', 'connect', 'client'
    )
    
    # Check Program Files
    $ProgramPaths = @(
        "${env:ProgramFiles}",
        "${env:ProgramFiles(x86)}",
        "${env:ProgramData}"
    )
    
    foreach ($BasePath in $ProgramPaths) {
        if (Test-Path $BasePath) {
            try {
                $Dirs = Get-ChildItem -Path $BasePath -Directory -ErrorAction SilentlyContinue
                foreach ($Dir in $Dirs) {
                    $DirName = $Dir.Name.ToLower()
                    foreach ($Pattern in $VPNPatterns) {
                        if ($DirName -like "*$Pattern*") {
                            $InstalledVPNs += [PSCustomObject]@{
                                Name = $Dir.Name
                                Path = $Dir.FullName
                                Source = "ProgramFiles"
                                Pattern = $Pattern
                            }
                            break
                        }
                    }
                }
            }
            catch {
                # Skip access errors
            }
        }
    }
    
    # Check Registry for installed programs
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($RegPath in $RegPaths) {
        try {
            $AllApps = Get-ItemProperty $RegPath -ErrorAction SilentlyContinue
            foreach ($App in $AllApps) {
                $DisplayName = if ($App.DisplayName) { $App.DisplayName.ToLower() } else { "" }
                $Publisher = if ($App.Publisher) { $App.Publisher.ToLower() } else { "" }
                
                $IsVPN = $false
                foreach ($Pattern in $VPNPatterns) {
                    if ($DisplayName -like "*$Pattern*" -or $Publisher -like "*$Pattern*") {
                        $IsVPN = $true
                        break
                    }
                }
                
                if ($IsVPN) {
                    $InstalledVPNs += [PSCustomObject]@{
                        Name = $App.DisplayName
                        Path = $App.InstallLocation
                        Source = "Registry"
                        Pattern = "Unknown"
                    }
                }
            }
        }
        catch {
            # Skip registry access errors
        }
    }
    
    return $InstalledVPNs | Sort-Object Name -Unique
}

function Get-VPNNetworkAdapters {
    $VPNAdapters = @()
    
    try {
        $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $Name = $_.Name.ToLower()
            $InterfaceDescription = $_.InterfaceDescription.ToLower()
            
            $VPNKeywords = @('vpn', 'tunnel', 'tap', 'tun', 'pptp', 'l2tp', 'ipsec', 
                            'openvpn', 'wireguard', 'nordlynx', 'wintun',
                            'cisco', 'anyconnect', 'pulse', 'fortinet', 'palo', 'checkpoint')
            
            foreach ($Keyword in $VPNKeywords) {
                if ($Name -like "*$Keyword*" -or $InterfaceDescription -like "*$Keyword*") {
                    return $true
                }
            }
            return $false
        }
        
        foreach ($Adapter in $Adapters) {
            $VPNAdapters += [PSCustomObject]@{
                Name = $Adapter.Name
                InterfaceDescription = $Adapter.InterfaceDescription
                Status = $Adapter.Status
                MacAddress = $Adapter.MacAddress
            }
        }
    }
    catch {
        # Skip errors
    }
    
    return $VPNAdapters
}

function Get-VPNServices {
    $VPNServices = @()
    
    $VPNPatterns = @(
        'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'cyberghost',
        'openvpn', 'wireguard', 'cisco', 'anyconnect', 'pulse', 'juniper',
        'forticlient', 'globalprotect', 'checkpoint', 'sonicwall',
        'privateinternetaccess', 'pia', 'windscribe', 'tunnelbear',
        'ipvanish', 'hidemyass', 'torguard', 'mullvad', 'zenmate',
        'vpn', 'tunnel', 'ras', 'remoteaccess'
    )
    
    try {
        $Services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
            $ServiceName = $_.Name.ToLower()
            $DisplayName = $_.DisplayName.ToLower()
            
            foreach ($Pattern in $VPNPatterns) {
                if ($ServiceName -like "*$Pattern*" -or $DisplayName -like "*$Pattern*") {
                    return $true
                }
            }
            return $false
        }
        
        foreach ($Service in $Services) {
            $VPNServices += [PSCustomObject]@{
                Name = $Service.Name
                DisplayName = $Service.DisplayName
                Status = $Service.Status
                StartType = $Service.StartType
            }
        }
    }
    catch {
        # Skip errors
    }
    
    return $VPNServices
}

function Get-AllVPNProcesses {
    $AllVPNProcesses = @()
    
    $VPNPatterns = @(
        'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'cyberghost',
        'openvpn', 'wireguard', 'cisco', 'anyconnect', 'pulse', 'juniper',
        'forticlient', 'globalprotect', 'checkpoint', 'sonicwall',
        'privateinternetaccess', 'pia', 'windscribe', 'tunnelbear',
        'ipvanish', 'hidemyass', 'torguard', 'mullvad', 'zenmate',
        'vyprvpn', 'strongvpn', 'purevpn', 'hotspot', 'shield', 'betternet'
    )
    
    try {
        $AllProcesses = Get-WmiObject -Class Win32_Process | Select-Object ProcessId, Name, CommandLine, SessionId
        
        foreach ($Process in $AllProcesses) {
            $ProcessName = $Process.Name.ToLower()
            $CommandLine = if ($Process.CommandLine) { $Process.CommandLine.ToLower() } else { "" }
            
            $IsVPN = $false
            $VPNType = ""
            
            foreach ($Pattern in $VPNPatterns) {
                if ($ProcessName -like "*$Pattern*" -or $CommandLine -like "*$Pattern*") {
                    $IsVPN = $true
                    $VPNType = $Pattern
                    break
                }
            }
            
            if ($IsVPN) {
                $AllVPNProcesses += [PSCustomObject]@{
                    ProcessId = $Process.ProcessId
                    ProcessName = $Process.Name
                    VPNType = $VPNType
                    SessionId = $Process.SessionId
                    CommandLine = $Process.CommandLine
                }
            }
        }
    }
    catch {
        Write-Log "Error getting VPN processes: $_" "Red"
    }
    
    return $AllVPNProcesses
}

function Get-AllVPNConnections {
    $VPNConnections = @()
    
    try {
        $VPNProcesses = Get-AllVPNProcesses
        
        if ($VPNProcesses.Count -gt 0) {
            Write-Log "Found VPN processes: $($VPNProcesses.ProcessName -join ', ')" "Gray"
            
            $Connections = Get-NetTCPConnection | Where-Object {
                $_.State -eq 'Established' -and 
                $_.OwningProcess -in $VPNProcesses.ProcessId
            }
            
            foreach ($Conn in $Connections) {
                $VPNProcess = $VPNProcesses | Where-Object { $_.ProcessId -eq $Conn.OwningProcess }
                
                if (!$IncludePrivateIPs -and !(Test-PublicIP -IPAddress $Conn.RemoteAddress)) {
                    continue
                }
                
                $VPNConnections += [PSCustomObject]@{
                    RemoteAddress = $Conn.RemoteAddress
                    RemotePort = $Conn.RemotePort
                    LocalAddress = $Conn.LocalAddress
                    LocalPort = $Conn.LocalPort
                    ProcessName = $VPNProcess.ProcessName
                    VPNType = $VPNProcess.VPNType
                    SessionId = $VPNProcess.SessionId
                }
            }
        } else {
            Write-Log "No VPN processes found" "Yellow"
        }
    }
    catch {
        Write-Log "Error getting network connections: $_" "Red"
    }
    
    return $VPNConnections
}

function Get-AllUserVPNLogs {
    param([int]$DaysBack = 30)
    
    $AllLogs = @()
    $CutoffDate = (Get-Date).AddDays(-$DaysBack)
    $Users = Get-LoggedInUsers
    
    Write-Log "Scanning VPN logs for $($Users.Count) user profiles" "Gray"
    
    foreach ($User in $Users) {
        if (!(Test-Path $User.LocalAppData)) {
            Write-Log "Skipping $($User.Username) - AppData not accessible" "DarkGray"
            continue
        }
        
        Write-Log "Scanning logs for user: $($User.Username)" "DarkGray"
        
        $LocalAppData = $User.LocalAppData
        $RoamingAppData = "$($User.ProfilePath)\AppData\Roaming"
        $ProgramData = $env:ProgramData
        
        $LogPaths = @{
            # Local AppData logs
            "NordVPN" = @(
                "$LocalAppData\NordVPN\logs\*.log",
                "$LocalAppData\NordVPN\NordVPN.exe.log",
                "$RoamingAppData\NordVPN\*.log"
            )
            "ExpressVPN" = @(
                "$LocalAppData\expressvpn\*.log",
                "$RoamingAppData\expressvpn\*.log"
            )
            "Surfshark" = @(
                "$LocalAppData\Surfshark\logs\*.log",
                "$LocalAppData\Surfshark\*.log"
            )
            "ProtonVPN" = @(
                "$LocalAppData\ProtonVPN\Logs\*.log",
                "$LocalAppData\ProtonVPN\*.log"
            )
            "CyberGhost" = @(
                "$LocalAppData\CyberGhost 8\*.log",
                "$LocalAppData\CyberGhost\*.log",
                "$ProgramData\CyberGhost\*.log"
            )
            "Cisco_AnyConnect" = @(
                "$LocalAppData\Cisco\Cisco AnyConnect Secure Mobility Client\Logs\*.log",
                "$ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Log\*.log"
            )
            "Windscribe" = @(
                "$LocalAppData\Windscribe\*.log",
                "$RoamingAppData\Windscribe\*.log"
            )
            "WireGuard" = @(
                "$LocalAppData\WireGuard\*.log",
                "$ProgramData\WireGuard\*.log"
            )
            "PrivateInternetAccess" = @(
                "$LocalAppData\pia_manager\*.log",
                "$LocalAppData\PrivateInternetAccess\*.log"
            )
            "TunnelBear" = @(
                "$LocalAppData\TunnelBear\*.log",
                "$RoamingAppData\TunnelBear\*.log"
            )
            "IPVanish" = @(
                "$LocalAppData\IPVanish\*.log",
                "$RoamingAppData\IPVanish\*.log"
            )
            "Mullvad" = @(
                "$LocalAppData\Mullvad VPN\*.log",
                "$ProgramData\Mullvad VPN\*.log"
            )
            "OpenVPN" = @(
                "$ProgramData\OpenVPN\logs\*.log",
                "$ProgramData\OpenVPN\*.log"
            )
            "PulseSecure" = @(
                "$LocalAppData\Pulse Secure\*.log",
                "$ProgramData\Pulse Secure\*.log"
            )
            "FortiClient" = @(
                "$LocalAppData\Fortinet\FortiClient\logs\*.log",
                "$ProgramData\Fortinet\FortiClient\logs\*.log"
            )
            "GlobalProtect" = @(
                "$LocalAppData\Palo Alto Networks\GlobalProtect\logs\*.log",
                "$ProgramData\Palo Alto Networks\GlobalProtect\logs\*.log"
            )
            "CheckPoint" = @(
                "$LocalAppData\CheckPoint\*.log",
                "$ProgramData\CheckPoint\*.log"
            )
            "SonicWall" = @(
                "$LocalAppData\SonicWall\*.log",
                "$ProgramData\SonicWall\*.log"
            )
            "Juniper" = @(
                "$LocalAppData\Juniper Networks\*.log",
                "$ProgramData\Juniper Networks\*.log"
            )
            "VyprVPN" = @(
                "$LocalAppData\VyprVPN\*.log",
                "$RoamingAppData\VyprVPN\*.log"
            )
            "StrongVPN" = @(
                "$LocalAppData\StrongVPN\*.log",
                "$RoamingAppData\StrongVPN\*.log"
            )
            "PureVPN" = @(
                "$LocalAppData\PureVPN\*.log",
                "$RoamingAppData\PureVPN\*.log"
            )
        }
        
        # Also scan for OpenVPN config files and logs
        $ConfigPaths = @(
            "$ProgramData\OpenVPN\config\*.ovpn",
            "$ProgramData\OpenVPN\config\*.conf",
            "$LocalAppData\OpenVPN\*.ovpn",
            "$LocalAppData\OpenVPN\*.conf"
        )
        
        foreach ($ClientName in $LogPaths.Keys) {
            $Paths = $LogPaths[$ClientName]
            if ($Paths -isnot [array]) {
                $Paths = @($Paths)
            }
            
            foreach ($Path in $Paths) {
                try {
                    if (Test-Path $Path) {
                        Write-Log "  Found $ClientName logs" "DarkGray"
                        $LogFiles = Get-ChildItem $Path -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt $CutoffDate}
                        
                        foreach ($LogFile in $LogFiles) {
                            $Content = Get-Content $LogFile.FullName -ErrorAction SilentlyContinue
                            foreach ($Line in $Content) {
                                if ($Line -match 'Connected to|Connecting to|server:|remote:|Gateway:|established|peer|endpoint|host|address') {
                                    $IPMatches = [regex]::Matches($Line, '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
                                    foreach ($Match in $IPMatches) {
                                        if ($Match.Value -eq '0.0.0.0' -or $Match.Value -eq '255.255.255.255') { continue }
                                        
                                        if (!$IncludePrivateIPs -and !(Test-PublicIP -IPAddress $Match.Value)) {
                                            continue
                                        }
                                        
                                        $AllLogs += [PSCustomObject]@{
                                            IPAddress = $Match.Value
                                            Client = $ClientName
                                            Username = $User.Username
                                            LogLine = $Line.Trim()
                                            LastModified = $LogFile.LastWriteTime
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    # Skip access errors silently
                }
            }
        }
        
        # Scan OpenVPN config files for server IPs
        foreach ($ConfigPath in $ConfigPaths) {
            try {
                if (Test-Path $ConfigPath) {
                    $ConfigFiles = Get-ChildItem $ConfigPath -ErrorAction SilentlyContinue
                    foreach ($ConfigFile in $ConfigFiles) {
                        $Content = Get-Content $ConfigFile.FullName -ErrorAction SilentlyContinue
                        foreach ($Line in $Content) {
                            if ($Line -match '^remote\s+|^server\s+|^route\s+') {
                                $IPMatches = [regex]::Matches($Line, '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
                                foreach ($Match in $IPMatches) {
                                    if ($Match.Value -eq '0.0.0.0' -or $Match.Value -eq '255.255.255.255') { continue }
                                    
                                    if (!$IncludePrivateIPs -and !(Test-PublicIP -IPAddress $Match.Value)) {
                                        continue
                                    }
                                    
                                    $AllLogs += [PSCustomObject]@{
                                        IPAddress = $Match.Value
                                        Client = "OpenVPN_Config"
                                        Username = $User.Username
                                        LogLine = $Line.Trim()
                                        LastModified = $ConfigFile.LastWriteTime
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch {
                # Skip access errors silently
            }
        }
    }
    
    return $AllLogs
}

function Get-WindowsVPNEvents {
    param([int]$DaysBack = 30)
    
    $VPNEvents = @()
    $StartTime = (Get-Date).AddDays(-$DaysBack)
    
    $EventSources = @(
        @{LogName='Application'; ProviderName='RasClient'},
        @{LogName='Application'; ProviderName='RasServer'},
        @{LogName='System'; ProviderName='RemoteAccess'},
        @{LogName='System'; ID=20227,20226,20225}
    )
    
    foreach ($Source in $EventSources) {
        try {
            $FilterHash = @{StartTime=$StartTime} + $Source
            $Events = Get-WinEvent -FilterHashtable $FilterHash -ErrorAction SilentlyContinue
            
            foreach ($Event in $Events) {
                $IPMatches = [regex]::Matches($Event.Message, '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
                foreach ($Match in $IPMatches) {
                    if ($Match.Value -eq '0.0.0.0' -or $Match.Value -eq '255.255.255.255') { continue }
                    
                    if (!$IncludePrivateIPs -and !(Test-PublicIP -IPAddress $Match.Value)) {
                        continue
                    }
                    
                    $VPNEvents += [PSCustomObject]@{
                        IPAddress = $Match.Value
                        TimeCreated = $Event.TimeCreated
                        Source = "Windows $($Source.ProviderName)"
                        Message = $Event.Message
                    }
                }
            }
        }
        catch {
            # Skip if log not accessible
        }
    }
    
    return $VPNEvents
}

# Main execution
Write-Log "=== Enhanced VPN Scanner for Remote Sessions ===" "Cyan"

$Context = Get-ExecutionContext
Write-Log "Execution Context:" "Yellow"
Write-Log "  User: $($Context.Domain)\$($Context.User)" "White"
Write-Log "  Admin: $($Context.IsAdmin)" "White"
Write-Log "  Session ID: $($Context.SessionId)" "White"
Write-Log "  Process: $($Context.ProcessName)" "White"

if ($IncludePrivateIPs) {
    Write-Log "Including private IP addresses" "Yellow"
} else {
    Write-Log "Public IP addresses only" "Green"
}

$AllResults = @()

Write-Log "`n[0/4] Detecting installed VPN software..." "Yellow"
$InstalledVPNs = Get-InstalledVPNSoftware
if ($InstalledVPNs.Count -gt 0) {
    Write-Log "Found $($InstalledVPNs.Count) installed VPN client(s):" "Green"
    foreach ($VPN in $InstalledVPNs) {
        Write-Log "  - $($VPN.Name) ($($VPN.Source))" "Gray"
    }
} else {
    Write-Log "No VPN software detected in standard locations" "Yellow"
}

Write-Log "`n[0.5/4] Checking VPN network adapters..." "Yellow"
$VPNAdapters = Get-VPNNetworkAdapters
if ($VPNAdapters.Count -gt 0) {
    Write-Log "Found $($VPNAdapters.Count) VPN network adapter(s):" "Green"
    foreach ($Adapter in $VPNAdapters) {
        Write-Log "  - $($Adapter.Name) ($($Adapter.Status))" "Gray"
    }
} else {
    Write-Log "No VPN network adapters found" "Gray"
}

Write-Log "`n[0.75/4] Checking VPN services..." "Yellow"
$VPNServices = Get-VPNServices
if ($VPNServices.Count -gt 0) {
    Write-Log "Found $($VPNServices.Count) VPN-related service(s):" "Green"
    foreach ($Service in $VPNServices) {
        Write-Log "  - $($Service.DisplayName) ($($Service.Status))" "Gray"
    }
} else {
    Write-Log "No VPN services found" "Gray"
}

Write-Log "`n[1/4] Scanning for active VPN connections..." "Yellow"
$ActiveConnections = Get-AllVPNConnections
Write-Log "Found $($ActiveConnections.Count) active VPN connections" "Green"

foreach ($Conn in $ActiveConnections) {
    $AllResults += [PSCustomObject]@{
        TimeCreated = Get-Date
        IPAddress = $Conn.RemoteAddress
        Source = "Active-$($Conn.VPNType)"
        Details = "$($Conn.ProcessName) -> $($Conn.RemoteAddress):$($Conn.RemotePort)"
    }
    if ($Verbose) {
        Write-Log "  Active: $($Conn.RemoteAddress) via $($Conn.ProcessName)" "Gray"
    }
}

Write-Log "`n[2/4] Scanning VPN client logs..." "Yellow"
$ClientLogs = Get-AllUserVPNLogs -DaysBack $DaysBack
Write-Log "Found $($ClientLogs.Count) VPN log entries" "Green"

foreach ($Log in $ClientLogs) {
    $AllResults += [PSCustomObject]@{
        TimeCreated = $Log.LastModified
        IPAddress = $Log.IPAddress
        Source = "Log-$($Log.Client)"
        Details = "$($Log.Username): $($Log.LogLine)"
    }
    if ($Verbose) {
        Write-Log "  Log: $($Log.IPAddress) from $($Log.Client) ($($Log.Username))" "Gray"
    }
}

Write-Log "`n[3/4] Scanning Windows Event Logs..." "Yellow"
$WindowsEvents = Get-WindowsVPNEvents -DaysBack $DaysBack
Write-Log "Found $($WindowsEvents.Count) Windows VPN events" "Green"

Write-Log "`n[4/4] Compiling results..." "Yellow"

foreach ($Event in $WindowsEvents) {
    $AllResults += [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        IPAddress = $Event.IPAddress
        Source = $Event.Source
        Details = $Event.Message
    }
    if ($Verbose) {
        Write-Log "  Event: $($Event.IPAddress) from $($Event.Source)" "Gray"
    }
}

$UniqueResults = $AllResults | Sort-Object IPAddress, TimeCreated -Unique

if ($UniqueResults.Count -gt 0) {
    $UniqueResults | Export-Csv -Path $OutputFile -NoTypeInformation
    
    Write-Log "`nSUCCESS: Found $($UniqueResults.Count) unique VPN IPs" "Green"
    Write-Log "Results saved to: $OutputFile" "Cyan"
    
    Write-Log "`nVPN Server IPs Found:" "Yellow"
    $UniqueIPs = $UniqueResults.IPAddress | Sort-Object -Unique
    foreach ($IP in $UniqueIPs) {
        $Sources = ($UniqueResults | Where-Object {$_.IPAddress -eq $IP}).Source -join ', '
        Write-Log "  $IP ($Sources)" "White"
    }
    
    Write-Log "`nCopy-paste list:" "Cyan"
    Write-Log ($UniqueIPs -join ', ') "White"
    
} else {
    Write-Log "`nNo VPN connections found" "Red"
    Write-Log "This could mean:" "Yellow"
    Write-Log "  - No VPN clients are currently running" "Gray"
    Write-Log "  - VPN clients are running in different user sessions" "Gray"
    Write-Log "  - VPN logs are in non-standard locations" "Gray"
    Write-Log "  - All connections are to private IP ranges (use -IncludePrivateIPs)" "Gray"
    Write-Log "  - VPN software may be installed but not configured/used" "Gray"
    
    if ($InstalledVPNs.Count -gt 0) {
        Write-Log "`nNote: Found $($InstalledVPNs.Count) installed VPN client(s) but no active connections or logs" "Yellow"
    }
}

Write-Log "`nScan completed" "Green"