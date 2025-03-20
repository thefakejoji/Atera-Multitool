import os
import sys
import winreg
import win32api
import win32service
import win32serviceutil
import platform
import ssl
import subprocess
import tempfile
import glob
from scripts import *

def get_resource_path(relative_path):
    """ Get the absolute path to a resource, works for dev and PyInstaller """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)  # For PyInstaller bundle
    return os.path.join(os.path.abspath("."), relative_path)  # For normal script execution

def export_info():
    # Gather information from other functions
    os_info = get_os_info()
    agent_version = get_agent_version()
    agent_service = get_agent_service()
    accountid = get_account_id()
    ssl_version = get_ssl_version()
    tls_version = get_tls_version()
    fips = get_fips()
    net_version = get_net_version()
    core_version = get_core_version()

    # Prepare the content to write to the file
    content = f"""
    OS Information: {os_info}
    Agent Version: {agent_version}
    Agent Service: {agent_service}
    AccountID: {accountid}
    SSL Version: {ssl_version}
    TLS Version: {tls_version}
    FIPS status: {fips}
    .NET Framework Version: {net_version}
    .NET Core Versions: {core_version}
    """

    # Write to the file
    with open("log.txt", "w") as file:
        file.write(content)


def get_agent_version():
    agent_path = r"C:\Program Files\ATERA Networks\AteraAgent\Agent\AteraAgent.exe"
    
    if os.path.exists(agent_path):
        info = win32api.GetFileVersionInfo(agent_path, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        version = f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
        return version
    else:
        return "Agent not found"

def get_agent_service():
    service_name = "AteraAgent"
    
    try:
        # Check if the service exists
        if not win32serviceutil.QueryServiceStatus(service_name):
            return "Service not found"

        # Open the service manager
        hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        hs = win32service.OpenService(hscm, service_name, win32service.SERVICE_QUERY_CONFIG)

        # Get service configuration
        config = win32service.QueryServiceConfig(hs)
        win32service.CloseServiceHandle(hs)
        win32service.CloseServiceHandle(hscm)

        # The service user is stored in config[7]
        return config[7]  # This returns the user the service runs as

    except Exception as e:
        return f"Error retrieving service info: {e}"

def get_account_id():
    try:
        # Open the registry key for the Atera agent settings
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\ATERA Networks\AlphaAgent")
        
        # Try to read the value of AccountId
        value, _ = winreg.QueryValueEx(reg_key, "AccountId")
        
        # Check if the value is None (equivalent to null in other languages)
        if value is not None:
            return value
        else:
            return "AccountId is empty"
    except FileNotFoundError:
        return "Key not found, Agent might not be installed"
    except Exception as e:
        return f"Unable to read due to: {e}"


def get_os_info():
    try:
        # Get OS version and architecture
        os_version = platform.version()  # Example: "10.0.22631"
        arch = platform.architecture()[0]  # Example: "64bit"

        # Get Windows product name (e.g., "Windows 11 Pro", "Windows Server 2019")
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            product_name, _ = winreg.QueryValueEx(key, "ProductName")  # Gets full Windows name
            edition, _ = winreg.QueryValueEx(key, "EditionID")  # Gets "Professional", "Enterprise", etc.

        # If it's a Windows Server, return the full product name
        if "Server" in product_name:
            return f"{product_name} {os_version} {arch}"

        # Otherwise, detect Windows 10/11 based on the build number
        win_version = sys.getwindowsversion()
        major_version = win_version.major  # 10 for Win10, 11 for Win11

        if major_version == 10 and win_version.build >= 22000:
            major_version = 11  # Windows 11 starts from build 22000

        return f"Windows {major_version} {edition} {os_version} {arch}"

    except Exception as e:
        return f"Error: {str(e)}"

def get_ssl_version():
    return ssl.OPENSSL_VERSION

def get_tls_version():
    try:
        supported_versions = []
        
        # Checking each TLS version
        if hasattr(ssl, "TLSVersion"):
            if ssl.TLSVersion.TLSv1_1 in ssl.TLSVersion:
                supported_versions.append("TLS 1.1")
            if ssl.TLSVersion.TLSv1_2 in ssl.TLSVersion:
                supported_versions.append("TLS 1.2")
            if ssl.TLSVersion.TLSv1_3 in ssl.TLSVersion:
                supported_versions.append("TLS 1.3")

        return f"{', '.join(supported_versions)}" if supported_versions else "No TLS versions detected"
    
    except Exception as e:
        return f"Error detecting TLS: {str(e)}"

def get_fips():
    try:
        # Open the registry key for FIPS settings
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Lsa")
        
        # Try to read the value of FIPSAlgorithmPolicy
        value, _ = winreg.QueryValueEx(reg_key, "FIPSAlgorithmPolicy")
        
        # Check the value of FIPSAlgorithmPolicy (1 = enabled, 0 = disabled)
        if value == 1:
            return "Enabled"
        else:
            return "Disabled"
    except FileNotFoundError:
        return "Undefined(not enabled)"
    except Exception as e:
        return f"Error checking FIPS mode: {e}"

def get_net_version():
    try:
        reg_path = r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
            release, _ = winreg.QueryValueEx(key, "Release")

        # Mapping release keys to .NET versions
        net_versions = {378389: "4.5", 378675: "4.5.1", 378758: "4.5.1", 379893: "4.5.2", 393295: "4.6", 
                393297: "4.6", 394254: "4.6.1", 394271: "4.6.1", 394802: "4.6.2", 394806: "4.6.2",
                460798: "4.7", 460805: "4.7", 461308: "4.7.1", 461310: "4.7.1", 461808: "4.7.2",
                461814: "4.7.2", 528040: "4.8", 533320: "4.8.1", 539379: "4.8.1"}

        return net_versions.get(release, f"Unknown version (Release {release})")

    except FileNotFoundError:
        return ".NET Framework not installed"
    except Exception as e:
        return f"Error: {str(e)}"

def get_core_version():
    net_core_path = r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App"
    if os.path.exists(net_core_path):
        return os.listdir(net_core_path)  # List of installed .NET Core versions
    else:
        return "No .NET Core found"

def run_script(script_content):
    try:
        # Create a temporary PowerShell script file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", encoding="utf-8") as temp_script:
            temp_script.write(script_content)
            temp_script_path = temp_script.name  # Store file path

        # Run the script using PowerShell and capture raw output
        process = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", temp_script_path],
            capture_output=True, text=True, shell=True
        )

        # Cleanup: Delete the temp script file
        os.remove(temp_script_path)

        # Return raw output exactly as PowerShell provides it
        return process.stdout + process.stderr

    except Exception as e:
        return f"Exception: {str(e)}"

def find_latest_log(log_folder):
    """Find the latest log file in the given folder."""
    if not os.path.exists(log_folder):
        return None  # Skip if folder does not exist

    rotating_logs = glob.glob(os.path.join(log_folder, "log.*.txt"))
    rotating_logs.sort(reverse=True)  # Sort by date (latest first)

    if rotating_logs:
        return rotating_logs[0]  # Return latest rotating log
    elif os.path.exists(os.path.join(log_folder, "log.txt")):
        return os.path.join(log_folder, "log.txt")  # Fallback to log.txt
    return None  # No logs found

def read_log_file(log_path):
    """Read and filter the log file, removing [INF] and Info: lines."""
    try:
        with open(log_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
        
        error_lines = [line for line in lines if "[INF]" not in line and "Info:" not in line]
        return "".join(error_lines) if error_lines else "No errors or exceptions found."
    except Exception as e:
        return f"Error reading log file: {e}"
