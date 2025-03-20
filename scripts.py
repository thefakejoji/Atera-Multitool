script_cleanup = r"""Function Get-UninstallCodes ([string]$DisplayName) {
'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' | ForEach-Object {
Get-ChildItem -Path $_ -ErrorAction SilentlyContinue | ForEach-Object {
If ( $(Get-ItemProperty -Path $_.PSPath -Name 'DisplayName' -ErrorAction SilentlyContinue) -and ($(Get-ItemPropertyValue -Path $_.PSPath -Name 'DisplayName' -ErrorAction SilentlyContinue) -eq $DisplayName) ) {
$str = (Get-ItemPropertyValue -Path $_.PSPath -Name 'UninstallString')
$UninstallCodes.Add($str.Substring(($str.Length - 37),36)) | Out-Null
}
}
}
}

Function Get-ProductKeys ([string]$ProductName) {
Get-ChildItem -Path 'HKCR:Installer\Products' | ForEach-Object {
If ( $(Get-ItemProperty -Path $_.PSPath -Name 'ProductName' -ErrorAction SilentlyContinue) -and ($(Get-ItemPropertyValue -Path $_.PSPath -Name 'ProductName' -ErrorAction SilentlyContinue) -eq $ProductName) ) {
$ProductKeys.Add($_.PSPath.Substring(($_.PSPath.Length - 32))) | Out-Null
}
}
}

Function Get-ServiceStatus ([string]$Name) { (Get-Service -Name $Name -ErrorAction SilentlyContinue).Status }

Function Stop-RunningService ([string]$Name) {
If ( $(Get-ServiceStatus -Name $Name) -eq "Running" ) { Write-Output "Stopping : ${Name} service" ; Stop-Service -Name $Name -Force }
}

Function Remove-StoppedService ([string]$Name) {
$s = (Get-ServiceStatus -Name $Name)
If ( $s ) {
If ( $s -eq "Stopped" ) {
Write-Output "Deleting : ${Name} service"
Start-Process "sc.exe" -ArgumentList "delete ${Name}" -Wait
}
} Else { Write-Output "Not Found: ${Name} service" }
}

Function Stop-RunningProcess ([string]$Name) {
$p = (Get-Process -Name $_ -ErrorAction SilentlyContinue)
If ( $p ) { Write-Output "Stopping : ${Name}.exe" ; $p | Stop-Process -Force }
Else { Write-Output "Not Found: ${Name}.exe is not running"}
}

Function Remove-Path ([string]$Path) {
If ( Test-Path $Path ) {
Write-Output "Deleting : ${Path}"
Remove-Item $Path -Recurse -Force
} Else { Write-Output "Not Found: ${Path}" }
}

Function Get-AllExeFiles ([string]$Path) {
If ( Test-Path $Path ) {
Get-ChildItem -Path $Path -Filter *.exe -Recurse | ForEach-Object { $ExeFiles.Add($_.BaseName) | Out-Null }
}
}

# Mount HKEY_CLASSES_ROOT registry hive
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null

#######
# START: Information gathering
#######

# Get MSI package codes from the uninstall key
$UninstallCodes = New-Object System.Collections.ArrayList
'AteraAgent', 'Splashtop for RMM', 'Splashtop Streamer' | ForEach-Object { Get-UninstallCodes -DisplayName $_ }

# Get product keys from the list of installed products
$ProductKeys = New-Object System.Collections.ArrayList
'AteraAgent', 'Splashtop for RMM', 'Splashtop Streamer' | ForEach-Object { Get-ProductKeys -ProductName $_ }

# Define all the directories we'll need to cleanup at the end of this script
$Directories = @(
"${Env:ProgramFiles}\ATERA Networks",
"${Env:ProgramFiles(x86)}\ATERA Networks",
"${Env:ProgramFiles}\Splashtop\Splashtop Remote\Server",
"${Env:ProgramFiles(x86)}\Splashtop\Splashtop Remote\Server",
"${Env:ProgramFiles}\Splashtop\Splashtop Software Updater",
"${Env:ProgramFiles(x86)}\Splashtop\Splashtop Software Updater",
"${Env:ProgramData}\Splashtop\Splashtop Software Updater"
)

# Get all possible relevant exe files so we can make sure they're closed later on
$ExeFiles = New-Object System.Collections.ArrayList
"${Env:ProgramFiles}\ATERA Networks" | ForEach-Object { Get-AllExeFiles -Path $_ }

# Define a list of services we need to stop and delete (if necessary)
$ServiceList = @(
'AteraAgent',
'SplashtopRemoteService',
'SSUService'
)

# Define a list of registry keys we'll delete
$RegistryKeys = @(
'HKLM:SOFTWARE\ATERA Networks',
'HKLM:SOFTWARE\Splashtop Inc.',
'HKLM:SOFTWARE\WOW6432Node\Splashtop Inc.'
)

#######
# END: Information gathering
#######

# Uninstall each MSI package code in $UninstallCodes
$UninstallCodes | ForEach-Object { Write-Output "Uninstall: ${_}" ; Start-Process "msiexec.exe" -ArgumentList "/X{${_}} /qn" -Wait }

# Stop services if they're still running
$ServiceList | ForEach-Object { Stop-RunningService -Name $_ }

# Terminate all relevant processes that may still be running
$ExeFiles.Add('reg') | Out-Null
$ExeFiles | ForEach-Object { Stop-RunningProcess $_ }

# Delete services if they're still present
$ServiceList | ForEach-Object { Remove-StoppedService -Name $_ }

# Delete products from MSI installer registry
$ProductKeys | ForEach-Object { Remove-Path -Path "HKCR:Installer\Products\${_}" }

# Unmount HKEY_CLASSES_ROOT registry hive
Remove-PSDrive -Name HKCR

# Delete registry keys
$RegistryKeys | ForEach-Object { Remove-Path -Path $_ }

# Delete remaining directories
#Write-Host "Waiting for file locks to be freed" ; Start-Sleep -Seconds 4
$Directories | ForEach-Object { Remove-Path -Path $_ }
"""

script_splashtop = r"""
Start-Process -FilePath "msiexec.exe" -ArgumentList "/x {B7C5EA94-B96A-41F5-BE95-25D78B486678} /qn" -NoNewWindow -Wait
Remove-Item -Path "HKLM:\SOFTWARE\Splashtop Inc." -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Splashtop Inc." -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\Splashtop\Temp" -Recurse -Force -ErrorAction SilentlyContinue
Stop-Service -Name "SSUService" -Force -ErrorAction SilentlyContinue
sc.exe delete "SSUService"
Remove-Item -Path "C:\ProgramData\Splashtop\Splashtop Software Updater" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files (x86)\Splashtop\Splashtop Software Updater" -Recurse -Force -ErrorAction SilentlyContinue
"""

script_ndiscovery = r"""
Start-Process -FilePath "C:\Program Files\Npcap\Uninstall.exe" -ArgumentList "/S" -NoNewWindow -Wait
Start-Process -FilePath "C:\Program Files (x86)\Nmap OEM\Uninstall.exe" -ArgumentList "/S" -NoNewWindow -Wait
Start-Sleep -Seconds 10
Remove-Item -Path "C:\Program Files\Npcap" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files (x86)\Nmap OEM" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\System32\Npcap" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\npcap" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\npcap_wifi" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\System32\drivers\npcap.sys" -Force -ErrorAction SilentlyContinue
schtasks /delete /tn "AteraAgentTasksScheduler" /f
schtasks /delete /tn "npcapwatchdog" /f
Remove-Item -Path "HKLM:\SOFTWARE\ATERA Networks\AlphaAgent\Packages\AgentPackageNetworkDiscovery" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\ATERA Networks\AlphaAgent\TaskSchedulerTasks" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Atera Networks\AteraAgent\Packages\AgentPackageNetworkDiscovery" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Atera Networks\AteraAgent\Packages\AgentPackageTaskScheduler" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Atera Networks\AteraAgent\Packages\AgentPackageNetworkDiscoveryWG" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Atera Networks\AteraAgent\Packages\AgentPackageNetworkDiscoveryDC" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Atera Networks\AteraAgent\Packages\AgentPackageNetworkDiscoveryWG" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Atera Networks\AteraAgent\Packages\AgentPackageNetworkDiscoveryDC" -Recurse -Force -ErrorAction SilentlyContinue
Restart-Service -Name "ateraagent" -Force -ErrorAction SilentlyContinue
"""

script_connection = r"""
# Define the list of target servers and their corresponding ports (TCP and UDP)
$targets = @{
"pubsub.atera.com" = @(443)
"pubsub.pubnub.com" = @(443)
"app.atera.com" = @(443)
"agenthb.atera.com" = @(443)
"packagesstore.blob.core.windows.net" = @(443)
"ps.pndsn.com" = @(443)
"agent-api.atera.com" = @(443)
"cacerts.thawte.com" = @(443)
"agentreportingstore.blob.core.windows.net" = @(443)
"atera-agent-heartbeat.servicebus.windows.net" = @(443)
"ps.atera.com" = @(443)
"atera.pubnubapi.com" = @(443)
"appcdn.atera.com" = @(443)
"atera-agent-heartbeat-cus.servicebus.windows.net" = @(443)
"ticketingitemsstoreeu.blob.core.windows.net" = @(443)
"download.visualstudio.microsoft.com" = @(443)
"a32dl55qcodech-ats.iot.eu-west-1.amazonaws.com" = @(443, 8883)
}

# Function to resolve all IP addresses for a given server
function Get-AllIPAddresses {
param (
[string]$server
)

try {
$ipAddresses = [System.Net.Dns]::GetHostAddresses($server)
$resolvedIPs = $ipAddresses | ForEach-Object { $_.IPAddressToString }
return $resolvedIPs
}
catch {
return $null
}
}

# Function to test TCP connection to a specific port
function Test-TcpConnection {
param (
[string]$server,
[int]$port
)

$resolvedIPs = Get-AllIPAddresses -server $server
if ($resolvedIPs) {
foreach ($resolvedIP in $resolvedIPs) {
try {
$tcpClient = New-Object System.Net.Sockets.TcpClient
$tcpClient.Connect($resolvedIP, $port)
$tcpClient.Close()
Write-Host ("TCP Connection to $server ($resolvedIP) on port $port is successful.") -ForegroundColor Green
}
catch {
Write-Host ("TCP Connection to $server ($resolvedIP) on port $port failed. Error: $($_.Exception.Message)") -ForegroundColor Red
}
}
} else {
Write-Host "Unable to resolve IP addresses for $server." -ForegroundColor Red
}
}

# Loop through the targets and test both TCP and UDP connections
foreach ($target in $targets.GetEnumerator()) {
$server = $target.Key
$ports = $target.Value

Write-Host "Testing connections to $server..."

# Test TCP connections
foreach ($port in $ports) {
Test-TcpConnection -server $server -port $port
}

# Test UDP connections (you can add specific UDP tests if needed)
# foreach ($port in $ports) {
# Test-UdpConnection -server $server -port $port
# }

Write-Host "" # Add an empty line after testing each server
}
"""

script_helpdesk = r"""
# Stop Atera processes and services
Stop-Process -Name "TicketingTray.exe" -Force -ErrorAction SilentlyContinue
Stop-Service -Name "AteraAgent" -Force -ErrorAction SilentlyContinue

# Remove startup entry from HKLM
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AlphaHelpdeskAgent" -Force -ErrorAction SilentlyContinue

# Loop through all user profiles
$UserProfiles = Get-ChildItem "C:\Users" | Select-Object -ExpandProperty Name

foreach ($User in $UserProfiles) {
    $UserHive = "C:\Users\$User\NTUSER.DAT"
    
    # Load user registry hive if it exists
    if (Test-Path $UserHive) {
        reg load HKU\TempHive $UserHive
        Remove-Item -Path "HKU\TempHive\Software\ATERA Networks\*" -Recurse -Force -ErrorAction SilentlyContinue
        reg unload HKU\TempHive
    }

    # Remove temporary files and TicketingAgent package per user
    $UserTemp = "C:\Users\$User\AppData\Local\Temp"
    Remove-Item -Path "$UserTemp\eo.webbrowser.cache.19.0.69.0.1.1" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$UserTemp\TicketingAgentPackage" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$UserTemp\TrayIconCaching" -Recurse -Force -ErrorAction SilentlyContinue
}

# Remove Atera packages from Program Files (affects all users)
Remove-Item -Path "C:\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageTicketing" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5
Start-Service -Name "AteraAgent" -ErrorAction Continue

"""

script_sccm = r"""
# Attempt to run the SCCM uninstaller
function uninstallSCCM() {
if (Test-Path -Path "$Env:SystemDrive\Windows\ccmsetup\ccmsetup.exe") {
# Stop SCCM services
Get-Service -Name CcmExec -ErrorAction SilentlyContinue | Stop-Service -Force -Verbose
Get-Service -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Service -Force -Verbose

# Run the SCCM uninstaller
Start-Process -FilePath "$Env:SystemDrive\Windows\ccmsetup\ccmsetup.exe" -ArgumentList '/uninstall'

# Wait for the uninstaller to finish
do {
Start-Sleep -Milliseconds 1000
$Process = (Get-Process ccmsetup -ErrorAction SilentlyContinue)
} until ($null -eq $Process)

Write-Host "SCCM uninstallation completed"
}
}

# Forcefully remove all traces of SCCM from the computer
function removeSCCM() {
# Stop SCCM services
Get-Service -Name CcmExec -ErrorAction SilentlyContinue | Stop-Service -Force -Verbose
Get-Service -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Service -Force -Verbose

# Take ownership of/delete SCCM's client folder and files
$null = takeown /F "$($Env:WinDir)\CCM" /R /A /D Y 2>&1
Remove-Item -Path "$($Env:WinDir)\CCM" -Force -Recurse -Confirm:$false -Verbose -ErrorAction SilentlyContinue
# Take ownership of/delete SCCM's setup folder and files
$null = takeown /F "$($Env:WinDir)\CCMSetup" /R /A /D Y 2>&1
Remove-Item -Path "$($Env:WinDir)\CCMSetup" -Force -Recurse -Confirm:$false -Verbose -ErrorAction SilentlyContinue
# Take ownership of/delete SCCM cache of downloaded packages and applications
$null = takeown /F "$($Env:WinDir)\CCMCache" /R /A /D Y 2>&1
Remove-Item -Path "$($Env:WinDir)\CCMCache" -Force -Recurse -Confirm:$false -Verbose -ErrorAction SilentlyContinue

# Remove SCCM's smscfg file (contains GUID of previous installation)
Remove-Item -Path "$($Env:WinDir)\smscfg.ini" -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue

# Remove SCCM certificates
Remove-Item -Path 'HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*' -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue

# Remove CCM registry keys
Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Force -Recurse -Verbose -ErrorAction SilentlyContinue
Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\CCM' -Force -Recurse -Confirm:$false -Verbose -ErrorAction SilentlyContinue

# Remove SMS registry keys
Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\SMS' -Force -Recurse -Confirm:$false -Verbose -ErrorAction SilentlyContinue
Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS' -Force -Recurse -Confirm:$false -Verbose -ErrorAction SilentlyContinue

# Remove CCMSetup registry keys
Remove-Item -Path 'HKLM:\Software\Microsoft\CCMSetup' -Force -Recurse -Confirm:$false -Verbose -ErrorAction SilentlyContinue
Remove-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\CCMSetup' -Force -Confirm:$false -Recurse -Verbose -ErrorAction SilentlyContinue

# Remove CcmExec and ccmsetup services
Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CcmExec' -Force -Recurse -Confirm:$false -Verbose -ErrorAction SilentlyContinue
Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ccmsetup' -Force -Recurse -Confirm:$false -Verbose -ErrorAction SilentlyContinue

# Remove SCCM namespaces from WMI repository
Get-CimInstance -Query "Select * From __Namespace Where Name='CCM'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Verbose -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance -Query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Verbose -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance -Query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" -ErrorAction SilentlyContinue | Remove-CimInstance -Verbose -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance -Query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" -ErrorAction SilentlyContinue | Remove-CimInstance -Verbose -Confirm:$false -ErrorAction SilentlyContinue

# Completed
Write-Host "All traces of SCCM have been removed"
}

uninstallSCCM
removeSCCM
"""

script_rebootnotify = r"""
# Ensure HKEY_USERS (HKU) is available
if (-not (Test-Path "HKU:\")) {
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
}

# Function to check and create "Notify me when a restart is required to finish"
function Check-RestartNotificationSetting {
$path = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
$key = "RestartNotificationsAllowed2"

if (-not (Test-Path $path)) {
New-Item -Path $path -Force | Out-Null
}

$value = Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
if ($value -and $value.$key -eq 1) {
Write-Output "'Notify me when a restart is required to finish' is ENABLED."
} else {
Set-ItemProperty -Path $path -Name $key -Type DWord -Value 1
Write-Output "'Notify me when a restart is required to finish' was DISABLED and has been ENABLED."
}
}

# Function to check and create the Atera "REP" registry key
function Check-AteraREP {
$path = "HKLM:\SOFTWARE\ATERA Networks\AlphaAgent\Packages\AgentPackageOsUpdates"
$key = "REP"

if (-not (Test-Path $path)) {
New-Item -Path $path -Force | Out-Null
}

$value = Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
if ($value -and $value.$key -ne $null -and $value.$key -ne "") {
Write-Output "Atera 'REP' key exists and has a value: $($value.$key)"
} else {
Set-ItemProperty -Path $path -Name $key -Type String -Value "DefaultValue"
Write-Output "Atera 'REP' key was MISSING or EMPTY and has been CREATED with a default value."
}
}

# Function to check and enable Notifications for all valid users
function Check-AndFix-SystemNotifications {
$validUserSIDs = Get-ChildItem "Registry::HKEY_USERS" | Where-Object { 
$_.Name -match "^HKEY_USERS\\S-1-5-21" 
} | Select-Object -ExpandProperty Name

if (-not $validUserSIDs) {
Write-Output "No valid user registry hives found under HKEY_USERS."
return
}

foreach ($sidPath in $validUserSIDs) {
$sid = $sidPath -replace "HKEY_USERS\\", "" # Extract just the SID

# Clean SID to ensure no extra spaces or invalid characters
$sid = $sid.Trim()

# Skip invalid SID formats
if ($sid -match "S-1-5-18|S-1-5-19|S-1-5-20") {
continue
}

$userKeyPath = "Registry::$sidPath\Software\Microsoft\Windows\CurrentVersion\PushNotifications"

# Ensure registry path exists
if (-not (Test-Path $userKeyPath)) {
New-Item -Path $userKeyPath -Force | Out-Null
Write-Output "Created registry path for SID: $sid."
}

$value = Get-ItemProperty -Path $userKeyPath -Name "ToastEnabled" -ErrorAction SilentlyContinue
if ($value -and $value.ToastEnabled -eq 1) {
Write-Output "Notifications are ENABLED for SID: $sid."
} else {
Set-ItemProperty -Path $userKeyPath -Name "ToastEnabled" -Type DWord -Value 1
Write-Output "Notifications were DISABLED and have been ENABLED for SID: $sid."
}
}
}

# Run all checks and fixes
Check-RestartNotificationSetting
Check-AteraREP
Check-AndFix-SystemNotifications
"""

script_packages = r"""
# List of URLs to check
$urls = @(
"https://ps.atera.com/agentpackagesnet45/Agent.Package.Availability/0.16/Agent.Package.Availability.zip",
"https://ps.atera.com/agentpackagesnet45/Agent.Package.Watchdog/1.5/Agent.Package.Watchdog.zip",
"https://ps.atera.com/agentpackagesnet45/AgentPackageAgentInformation/37.2/AgentPackageAgentInformation.zip",
"https://ps.atera.com/agentpackagesnet45/AgentPackageInternalPoller/23.8/AgentPackageInternalPoller.zip",
"https://ps.atera.com/agentpackagesnet45/AgentPackageMarketplace/1.4/AgentPackageMarketplace.zip",
"https://ps.atera.com/agentpackagesnet45/AgentPackageMonitoring/36.9/AgentPackageMonitoring.zip"
)

# Loop through each URL and check connection
foreach ($url in $urls) {
# Create a WebRequest object
$request = [System.Net.HttpWebRequest]::Create($url)
$request.Method = "GET"

try {
# Send the request and get the response
$response = $request.GetResponse()

# Check the response status code
if ($response.StatusCode -eq [System.Net.HttpStatusCode]::OK) {
Write-Output "Connection to ${url} succeeded."
} else {
Write-Output "Connection to ${url} failed. Status code: $($response.StatusCode)"
}

# Close the response
$response.Close()
} catch {
# If an exception occurs, output the error message
Write-Output "Error connecting to ${url}: $($_.Exception.Message)"
}
}
"""

disclaimer = r"""Disclaimer

Atera Multitool is an internal troubleshooting utility designed for technical support staff. This tool is provided as is, without any warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement.

By using this tool, you acknowledge and agree that:

You are solely responsible for any actions taken using Atera Multitool.
The developers of this tool are not liable for any data loss, system instability, or unintended consequences resulting from its use.
This tool is intended for authorized personnel only. If you are an end user or do not fully understand its functions, consult with your IT administrator before proceeding.
Some actions performed by this tool cannot be undone. Proceed with caution.

Licenses & Acknowledgments:
Atera Multitool may utilize third-party libraries and components, each licensed under their respective terms. Below is a list of included dependencies and their licenses:

Python – PSF License
Tkinter – Standard Library (Tcl/Tk License)
Pywin32 - PSF License
Pyinstaller - GPL 2.0
For additional details or inquiries, please contact your IT department.

Source code available at https://github.com/thefakejoji/Atera-Multitool
"""
