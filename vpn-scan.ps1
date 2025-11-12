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

function Get-AllVPNProcesses {
    $AllVPNProcesses = @()
    
    $VPNPatterns = @(
        'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'cyberghost',
        'openvpn', 'wireguard', 'cisco', 'anyconnect', 'pulse', 'juniper',
        'forticlient', 'globalprotect', 'checkpoint', 'sonicwall',
        'privateinternetaccess', 'pia', 'windscribe', 'tunnelbear',
        'ipvanish', 'hidemyass', 'torguard', 'mullvad', 'zenmate'
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
        
        $LogPaths = @{
            "NordVPN" = "$($User.LocalAppData)\NordVPN\logs\*.log"
            "ExpressVPN" = "$($User.LocalAppData)\expressvpn\*.log"
            "Surfshark" = "$($User.LocalAppData)\Surfshark\logs\*.log"
            "ProtonVPN" = "$($User.LocalAppData)\ProtonVPN\Logs\*.log"
            "CyberGhost" = "$($User.LocalAppData)\CyberGhost 8\*.log"
            "Cisco_AnyConnect" = "$($User.LocalAppData)\Cisco\Cisco AnyConnect Secure Mobility Client\Logs\*.log"
            "Windscribe" = "$($User.LocalAppData)\Windscribe\*.log"
            "WireGuard" = "$($User.LocalAppData)\WireGuard\*.log"
        }
        
        foreach ($ClientName in $LogPaths.Keys) {
            $Path = $LogPaths[$ClientName]
            try {
                if (Test-Path $Path) {
                    Write-Log "  Found $ClientName logs" "DarkGray"
                    $LogFiles = Get-ChildItem $Path | Where-Object {$_.LastWriteTime -gt $CutoffDate}
                    
                    foreach ($LogFile in $LogFiles) {
                        $Content = Get-Content $LogFile.FullName -ErrorAction SilentlyContinue
                        foreach ($Line in $Content) {
                            if ($Line -match 'Connected to|Connecting to|server:|remote:|Gateway:|established') {
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

Write-Log "`n[1/3] Scanning for active VPN connections..." "Yellow"
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

Write-Log "`n[2/3] Scanning VPN client logs..." "Yellow"
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

Write-Log "`n[3/3] Scanning Windows Event Logs..." "Yellow"
$WindowsEvents = Get-WindowsVPNEvents -DaysBack $DaysBack
Write-Log "Found $($WindowsEvents.Count) Windows VPN events" "Green"

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
}

Write-Log "`nScan completed" "Green"