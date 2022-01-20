<# 
Created By Josh Jerdon  
Created on 1/20/2022
Version 1.0
Version 1.01

For Disabling SSL 2.0 / SSL 3.0 and Enabling TLS 1.2 for ADFS and Web Application Proxy Servers. I also created a function to test the server for currently
enabled Protocols that will dump out to a CSV report.

This scripts automates the processes from the following documentation:

https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Switch Explaination:

-EnabledProtocols: This will go through and check each individual protocol on the server to confirm what protocols are responding and what ones are currently disabled.
This is useful to find protocols are currently enabled. It will provide quite a bit of details, the IP Address, Port, Port Status, Certificate name, Thumbprint of the Certificate
Date cert was issued, and date cert is to expire, key length, signature, cipher used during handshake negotiation and Protocol used.

-DisableSSL: Just disables SSL 2.0 and SSL 3.0, it will not do anything outside of that.

-DisableTLS10: Will just disable TLS 1.0 (BE VERY CAREFUL WITH THIS AS THIS CAN CAUSE LEGACY APPLICATIONS TO STOP WORKING!!!)

-DisableTLS11: This will disable TLS 1.1, while not required is an option in case you want to test.

-EnableTLS10: Enables TLS 1.0, usually is already enabled by default but just in case you want to quickly reverse a TLS 1.0 disable change.

-EnableTLS11: Enables TLS 1.1, usually is already enabled by default but just in case you want to quickly reverse a TLS 1.1 disable change.

-EnableTLS12: Just enables TLS 1.2 and will not do anything outside of that.

-SecureMe: Disables SSL 2.0 / SSL 3.0, TLS 1.0 and enables TLS 1.2. It does not touch TLS 1.1. You can disable TLS 1.1 with the above switch if you choose. 
ONLY USE THIS SWITCH IF YOU ARE SURE YOU HAVE NO LEGACY APPLICATIONS THAT REQUIRE TLS 1.0!!!!!!

Version History

2022JAN20

Initial release

2022JAN20

Version 1.01: Added Enable TLS 1.0 switch as it was overlooked upon initial release. Fixed Typos in ReadMe.

#>
[CmdletBinding()]
param (
    [switch]$EnabledProtocols,
    [switch]$DisableSSL,
    [switch]$EnableTLS10,
    [switch]$EnableTLS11,
    [switch]$EnableTLS12,
    [switch]$DisableTLS10,
    [switch]$DisableTLS11,
    [switch]$SecureMe
)

function Get-EnabledProtocols {
    #Checking Powershell Version to Ensure Script Works as Intended.
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        Write-Host "PowerShell meets minimum version requirements, continuing" -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host
    }
    else {
        Write-Host "PowerShell does not meet minimum version requirements To Continue" -ForegroundColor Red
        Write-Error "PowerShell needs to be at least Version 3 or higher." -ErrorAction Stop
        Exit    
    }
    # Global Setting - Have to set PowerShell to trust untrusted or invalid certificates just in case a server returns an invalid certificate.
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    # Specify File Output parameters to output what protocols are currently enabled.
    $OutputFileName = "EnabledProtocolsReport" + "-" + (Get-Date).ToString("MMddyyyyHHmmss") + ".csv"
    $OutputFilePath = "."
    $Output = $OutputFilePath + "\" + $OutputFileName
    # List of Protocols We Are Going to Test from .NET.
    $Protocols = [System.Security.Authentication.SslProtocols] | Get-Member -static -MemberType Property | Where-Object { $_.Name -notin @("Default", "None") } | ForEach-Object { $_.Name }
    # Port Used to Initiate A Secure Connection.
    [int]$Port = 443
    # Get name on certificate to make sure we are testing against the expected cert.
    Write-Host " "
    [string]$HostName = Read-Host -Prompt "Namespace to use in order to check certificate and secure channel details? Example: sts.contoso.com"
    Clear-Host
    # Gets servers primary network interface address to test against. Should work MOST of the time. Likely caveats with servers that have multiple NICS
    # installed and multiple IPS example NIC Binding.
    $Computername = $env:COMPUTERNAME
    $IP = (Test-Connection -ComputerName ($Computername) -Count 1).IPV4Address.IPAddressToString
    # Take above variables and start checking the servers current protocols and see which one connects.
    if ($null -ne $IP) {
        $PortCheck = New-Object System.Net.Sockets.TcpClient($IP, $Port)
        if ($PortCheck.Connected) {
            $Port443Status = "Open"
        }
        else {
            $Port443Status = "Closed"
            Write-Error "Not able to continue port is closed or not responding.." -ErrorAction Stop
            Read-host -Prompt "Hit enter key to exit script"
            Exit
        }
        $PortCheck.Dispose()
        $Protocols | ForEach-Object {
            $ProtocolName = $_
            $SocketClient = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
            $SocketClient.Connect($IP, $Port)
            try {
                $NetStream = New-Object System.Net.Sockets.NetworkStream($SocketClient, $true)
                $SecureChannel = New-Object System.Net.Security.SslStream($NetStream, $true)
                $SecureChannel.AuthenticateAsClient($HostName, $null, $ProtocolName, $false)
                $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SecureChannel.RemoteCertificate
                $ConnectedCipher = [System.Security.Authentication.CipherAlgorithmType]$SecureChannel.CipherAlgorithm
                $ProtocolStatus = "True"
                  
            }

            catch {
                $ProtocolStatus = "False"
                
            }
            $Report = [PSCustomObject]@{
                Server               = $Computername
                IPAddress            = $IP
                PortChecked          = $Port
                PortStatus           = $Port443Status
                Certificate          = $Certificate.Subject
                Thumbprint           = $Certificate.Thumbprint
                CertIssueDate        = $Certificate.NotBefore
                CertExpires          = $Certificate.NotAfter
                KeyLength            = $Certificate.PublicKey.Key.KeySize
                CertificateSignature = $Certificate.SignatureAlgorithm.FriendlyName
                CipherUsed           = $ConnectedCipher
                ProtocolName         = $ProtocolName
                ProtocolEnabled      = $ProtocolStatus
            
            }
            $SocketClient.Dispose()
            $SecureChannel.Dispose()
            $Report | Export-Csv $Output -Append -NoTypeInformation
  
        }
    }
    

    else {
        Write-Error "IP address is Null or unable to connect to server using acquired IP."
        Read-Host -Prompt "Hit Enter to Exit"
        Exit
    }
}


function DisableSSL {
    #Checking Powershell Version to Ensure Script Works as Intended.
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        Write-Host "PowerShell meets minimum version requirements, continuing" -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host
    }
    else {
        Write-Host "PowerShell does not meet minimum version requirements To Continue" -ForegroundColor Red
        Write-Error "PowerShell needs to be at least Version 3 or higher." -ErrorAction Stop
        Exit    
    }
    # Check if script has been executed as an Administrator.
    $Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if ($Admin -eq 'True') {
        Write-Host " "
        Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host   
    }
    # If script is not executed as an Administrator, stop the script.
    else {
        Write-Error 'This Script needs to be executed under Powershell with Administrative Privileges...' -ErrorAction Stop
    }
    $Writable = $true

    Write-Host " "
    Write-Host " "
    Write-Host "Disabling SSL 2.0 and SSL 3.0"
    Start-Sleep -Seconds 3
    Clear-Host
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client”)
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server”)
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client”)
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server”)
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)

    Write-Host " "
    Write-Host " "
    Write-Host "SSL 2.0 and SSL 3.0 have been disabled, you will need to restart the system for the changes to take effect" -ForegroundColor Green
    Read-Host -Prompt "Hit Enter to Exit"
}

function EnableTLS10 {
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        #Checking Powershell Version to Ensure Script Works as Intended.
        Write-Host "PowerShell meets minimum version requirements, continuing" -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host
    }
    else {
        Write-Host "PowerShell does not meet minimum version requirements To Continue" -ForegroundColor Red
        Write-Error "PowerShell needs to be at least Version 3 or higher." -ErrorAction Stop
        Exit    
    }
    # Check if script has been executed as an Administrator.
    $Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if ($Admin -eq 'True') {
        Write-Host " "
        Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host   
    }
    # If script is not executed as an Administrator, stop the script.
    else {
        Write-Error 'This Script needs to be executed under Powershell with Administrative Privileges...' -ErrorAction Stop
    }
   
    $Writable = $true
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")
    $Key.SetValue(“Enabled”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server”)
    $Key.SetValue(“Enabled”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)

    Write-Host " "
    Write-Host " "
    Write-Host "TLS 1.0 has been Enabled, you will need to restart the system for the changes to take effect" -ForegroundColor Green
    Read-Host -Prompt "Hit Enter to Exit"
    
}
function EnableTLS11 {
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        #Checking Powershell Version to Ensure Script Works as Intended.
        Write-Host "PowerShell meets minimum version requirements, continuing" -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host
    }
    else {
        Write-Host "PowerShell does not meet minimum version requirements To Continue" -ForegroundColor Red
        Write-Error "PowerShell needs to be at least Version 3 or higher." -ErrorAction Stop
        Exit    
    }
    # Check if script has been executed as an Administrator.
    $Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if ($Admin -eq 'True') {
        Write-Host " "
        Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host   
    }
    # If script is not executed as an Administrator, stop the script.
    else {
        Write-Error 'This Script needs to be executed under Powershell with Administrative Privileges...' -ErrorAction Stop
    }
   
    $Writable = $true
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")
    $Key.SetValue(“Enabled”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server”)
    $Key.SetValue(“Enabled”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)

    Write-Host " "
    Write-Host " "
    Write-Host "TLS 1.1 has been Enabled, you will need to restart the system for the changes to take effect" -ForegroundColor Green
    Read-Host -Prompt "Hit Enter to Exit"
}
function EnableTLS12 {
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        Write-Host "PowerShell meets minimum version requirements, continuing" -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host
    }
    else {
        Write-Host "PowerShell does not meet minimum version requirements To Continue" -ForegroundColor Red
        Write-Error "PowerShell needs to be at least Version 3 or higher." -ErrorAction Stop
        Exit    
    }
    # Check if script has been executed as an Administrator.
    $Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if ($Admin -eq 'True') {
        Write-Host " "
        Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host   
    }
    # If script is not executed as an Administrator, stop the script.
    else {
        Write-Error 'This Script needs to be executed under Powershell with Administrative Privileges...' -ErrorAction Stop
    }
    $Writable = $true
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client”)
    $Key.SetValue(“Enabled”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server”)
    $Key.SetValue(“Enabled”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    # Have to tell .NET 3.5 and .NET 4.0/4.5 to use TLS 1.2 (I.E. SchUseStrongCrypto)
    $key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("Wow6432Node\Microsoft\.NETFramework\v2.0.50727")
    $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("Microsoft\.NETFramework\v4.0.30319")
    $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)


    Write-Host " "
    Write-Host " "
    Write-Host "TLS 1.2 has been enabled, you will need to restart the system for the changes to take effect" -ForegroundColor Green
    Read-Host -Prompt "Hit Enter to Exit"
}

function DisableTLS10 {
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        #Checking Powershell Version to Ensure Script Works as Intended.
        Write-Host "PowerShell meets minimum version requirements, continuing" -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host
    }
    else {
        Write-Host "PowerShell does not meet minimum version requirements To Continue" -ForegroundColor Red
        Write-Error "PowerShell needs to be at least Version 3 or higher." -ErrorAction Stop
        Exit    
    }
    # Check if script has been executed as an Administrator.
    $Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if ($Admin -eq 'True') {
        Write-Host " "
        Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host   
    }
    # If script is not executed as an Administrator, stop the script.
    else {
        Write-Error 'This Script needs to be executed under Powershell with Administrative Privileges...' -ErrorAction Stop
    }
   
    $Writable = $true
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server”)
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)

    Write-Host " "
    Write-Host " "
    Write-Host "TLS 1.0 has been disabled, you will need to restart the system for the changes to take effect" -ForegroundColor Green
    Read-Host -Prompt "Hit Enter to Exit"
    
}
# Disabling TLS 1.1 generally doesn't need to be done, but I've included it as an option in case someone wants to disable that Protocol.
function DisableTLS11 {
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        #Checking Powershell Version to Ensure Script Works as Intended.
        Write-Host "PowerShell meets minimum version requirements, continuing" -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host
    }
    else {
        Write-Host "PowerShell does not meet minimum version requirements To Continue" -ForegroundColor Red
        Write-Error "PowerShell needs to be at least Version 3 or higher." -ErrorAction Stop
        Exit    
    }
    # Check if script has been executed as an Administrator.
    $Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if ($Admin -eq 'True') {
        Write-Host " "
        Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host   
    }
    # If script is not executed as an Administrator, stop the script.
    else {
        Write-Error 'This Script needs to be executed under Powershell with Administrative Privileges...' -ErrorAction Stop
    }
   
    $Writable = $true
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server”)
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)

    Write-Host " "
    Write-Host " "
    Write-Host "TLS 1.1 has been disabled, you will need to restart the system for the changes to take effect" -ForegroundColor Green
    Read-Host -Prompt "Hit Enter to Exit"
}

function DoItAll {
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        #Checking Powershell Version to Ensure Script Works as Intended.
        Write-Host "PowerShell meets minimum version requirements, continuing" -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host
    }
    else {
        Write-Host "PowerShell does not meet minimum version requirements To Continue" -ForegroundColor Red
        Write-Error "PowerShell needs to be at least Version 3 or higher." -ErrorAction Stop
        Exit    
    }
    # Check if script has been executed as an Administrator.
    $Admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if ($Admin -eq 'True') {
        Write-Host " "
        Write-Host "Script was executed with elevated permissions, continuing..." -ForegroundColor Green
        Start-Sleep -Seconds 3
        Clear-Host   
    }
    # If script is not executed as an Administrator, stop the script.
    else {
        Write-Error 'This Script needs to be executed under Powershell with Administrative Privileges...' -ErrorAction Stop
    }
   
    $Writable = $true

    Write-Host " "
    Write-Host " "
    Write-Host "Disabling SSL 2.0 / SSL 3.0 as well as TLS 1.0, Enabling TLS 1.2"
    Start-Sleep -Seconds 3
    Clear-Host
    #Disable SSL 2.0 and Disable SSL 3.0.
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client”)
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server”)
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client”)
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server”)
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)

    #Disable TLS 1.0 - BE VERY CAREFUL AS THIS CAN BREAK LEGACY APPLICATIONS!!!!!!!
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client”)
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server”)
    $Key.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)

    #Enable TLS 1.2 as well as tell .NET to use Strong Cryptography
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client”)
    $Key.SetValue(“Enabled”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server”)
    $Key.SetValue(“Enabled”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue(“DisabledByDefault”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    # Have to tell .NET 3.5 and .NET 4.0/4.5 to use TLS 1.2 (I.E. SchUseStrongCrypto)
    $key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("Wow6432Node\Microsoft\.NETFramework\v2.0.50727")
    $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("Microsoft\.NETFramework\v4.0.30319")
    $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)

    Write-Host " "
    Write-Host " "
    Write-Host "SSL 2.0 / SSL 3.0 and TLS 1.0 have been disabled successfully. TLS 1.2 has been enabled, please restart the system for changes to take effect." -ForegroundColor Green
    Read-Host -Prompt "Hit Enter to Exit"

}
if ($EnabledProtocols) { Get-EnabledProtocols; Clear-Host; Exit }
if ($DisableSSL) { DisableSSL; Clear-Host; Exit }
if ($EnableTLS10) {EnableTLS10; Clear-Host; Exit }
if ($EnableTLS11) { EnableTLS11; Clear-Host; Exit }
if ($EnableTLS12) { EnableTLS12; Clear-Host; Exit }
if ($DisableTLS10) { DisableTLS10; Clear-Host; Exit }
if ($DisableTLS11) { DisableTLS11; Clear-Host; Exit }
if ($SecureMe) { DoItAll; Clear-Host; Exit }   
   