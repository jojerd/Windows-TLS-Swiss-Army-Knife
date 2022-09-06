# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Created By Josh Jerdon  
# Created on 1/20/2022

<#
.NOTES
	Name: TLS-SwissArmyKnife.ps1
	Requires: PowerShell 3.0, Administrative Privileges. 
    Major Release History:
        01/20/2022 - Initial Release
        09/06/2022 - Complete rewrite of the application to make it more user friendly, also added logging for actions taken.


.DESCRIPTION
For Disabling SSL 2.0 / SSL 3.0 and Enabling TLS 1.2 for ADFS and Web Application Proxy Servers. I also created a function to test the server for currently
enabled Protocols that will dump out to a CSV report.
This utility can be run on any Windows Operating System to disable legacy protocols and enable modern security protocols. Some functions will not work 
if no service is hosted on the system, such as "Test Enabled SCHANNEL Protocols" as that requires a service to be hosted and responding over port 443
to test the systems SCHANNEL protocols.

This scripts automates the processes from the following documentation:

https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Option Explanation:

Retrieve Current SCHANNEL Configuration
This option will go through and pull the registry of SCHANNEL protocols for .NET and standard TLS/SSL keys and provide you
and output of the current configured values or "NOT FOUND" if no key or value was set.

Disable SSL (2.0 and 3.0) 
On modern Windows Operating Systems (2016+) SSL 3.0 is disabled by default, and SSL 2.0 is completely deprecated and unsupported. However for Windows 2012 and 2012 R2 
those keys should be set to be disabled.

Enable TLS 1.0
This is enabled by default, but is included in case you would like to re-enable in the off chance that it was disabled by accident previously.

Enable TLS 1.1
This is enabled by default, but is included in case you would like to re-enable in the off chance that it was disabled by accident previously.

Enable TLS 1.2
On legacy operating systems this needs to ran to enable TLS. On Modern Operating Systems this also needs to be ran, but from a more .NET centric point of view
Out of the box Windows Server 2016+ supports TLS 1.2, however .NET needs to be instructed to use TLS 1.2 because out of the box its default is TLS 1.0

Disable TLS 1.0
This will disable TLS 1.0, I do have it prompt to verify you are sure you want to disable TLS 1.0 as this can break legacy applications who still rely upon TLS 1.0.

Disable TLS 1.1
This will disable TLS 1.1.

Disable all protocols only enable TLS 1.2. 
As the option suggests this will disable SSL 2.0/3.0, TLS 1.0 and TLS 1.1 and will only have TLS 1.2.

Test Enabled SCHANNEL protocols
This will go through and make a loop back connection to itself over port 443 (so its encouraged to be ran from a system hosting a service over port 443) and generate a report
via CSV of the protocols that were able to make a connection. It will detail the computer name, host name of the service, IP address, port, port status (Opened or Closed),
Information regarding the certificate presented (subject, thumbprint, NotBefore, NotAfter, public key), Signature Algorithm, connected cipher, protocol that tested, and protocol
status.

#>

#Requires -Version 3.0
# Will be deprecating version 3.0 when Windows Server 2012 R2 reaches End of Life (October 10th 2023) and will make the minimum requirement 5.1.
#Requires -RunAsAdministrator
$Global:ProgressPreference = 'SilentlyContinue'
#Log filename
$Logname = 'TLS-SwissArmyKnife.log'

# Write Log function, Thanks to EE Matt Byrd for this function.
function Write-Log {
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$String,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$OutHost,

        [switch]$OpenLog

    )

    begin {
        # Get our log file path
        $Path = Get-Location
        $LogFile = Join-Path $Path $Name
        if ($OpenLog) {
            Notepad.exe $LogFile
            exit
        }
    }
    process {

        # Get the current date
        [string]$date = Get-Date -Format G

        # Build output string
        [string]$logstring = ( "[" + $date + "] - " + $string)

        # Write everything to our log file and the screen
        $logstring | Out-File -FilePath $LogFile -Append -Confirm:$false
        if ($OutHost) { Write-Host $logstring }
        else { Write-Verbose  $logstring }
    }
}
# Provides assistance in pulling information from the registry
function Get-RegistryInformation {
    [CmdletBinding()]
    Param
    (
        # Registry Path
        [Parameter(Mandatory = $false,
            Position = 0)]
        [string]
        $RegPath,
    
        # Registry Name
        [Parameter(Mandatory = $false,
            Position = 1)]
        [string]
        $RegName
    )
    $ErrorActionPreference = 0
    $regItem = Get-ItemProperty -Path $RegPath -Name $RegName 
    $output = "" | Select-Object Path, Name, Value
    $output.Path = $RegPath
    $output.Name = $RegName
    
    
    If ($regItem -eq $null) {
        $output.Value = "Not Found"
    }
    Else {
        $output.Value = $regItem.$RegName
    }
    $output
}
# Restart Computer Notification function to be called after a registry change is made to notify as well as ask the user to restart the computer.
function Restart-ComputerNotification {
    begin {
        Write-Log -String "Prompting user to restart computer" -Name $Logname
        Add-Type -AssemblyName PresentationCore, PresentationFramework
        $Button = [System.Windows.MessageBoxButton]::YesNoCancel
        $PopupTitle = "Restart the computer?"
        $PopupIcon = [System.Windows.MessageBoxImage]::Question
        $Popupbody = "Registry changes have been completed, you will need to restart for the changes to take affect do you want to restart the computer now?"

        $PopupResult = [System.Windows.MessageBox]::Show($Popupbody, $PopupTitle, $Button, $PopupIcon)

    }
    process {
        # If yes, log that yes was selected and proceed with restarting the computer.
        if ($PopupResult -eq "Yes") {
            Write-Log -String "User selected Yes to restart the computer now" -Name $Logname
            Restart-Computer
        }
        # If no, log that no was selected and inform the user that computer will not be restarted and return to the menu.
        elseif ($PopupResult -eq "No") {
            Write-Log -String "User selected No to restart the computer, returning to menu" -Name $Logname
            Clear-Host; Write-Host ""
            Write-Host "You selected NO, Computer will NOT be restarted..."
            Read-Host -Prompt "Hit Enter key to continue"
            Start-Menu
        }
        #If cancel, log that cancel was selected and exit the script.
        elseif ($PopupResult -eq "Cancel") {
            Write-Log -String "User selected Cancel, exiting script" -Name $Logname
            Exit
        }
    }
    End {
        #End the restart notification function
        Write-log -String "Ending Restart Notification function" -Name $Logname
    }
}
# Get Enable protocols function.
function Get-EnabledProtocols {
    Write-Log -String "User selected Test current Protocols" -Name $Logname
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
    Write-Log -String "User entered $Hostname for name of service to be checked" -Name $Logname
    Clear-Host
    # Gets servers primary network interface address to test against. Should work MOST of the time. Likely caveats with servers that have multiple NICS
    # installed and multiple IPS example NIC Binding.
    $Computername = ([System.Net.Dns]::GetHostByName(($env:COMPUTERNAME))).Hostname
    $IP = (Test-Connection -ComputerName ($Computername) -Count 1).IPV4Address.IPAddressToString
    Write-Log -String "IP Address retrieved $IP" -Name $Logname
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
            foreach ($object in $Report) {
                foreach ($i in $object.PSObject.Properties) {
                    Write-log -String "$($i.Name), $($i.Value)" -Name $Logname
                }
            }
  
        }

    }
    

    else {
        Write-Log -String "IP address is null or unable to connect to server using acquired IP." -Name $Logname
        Write-Error "IP address is Null or unable to connect to server using acquired IP."
        Read-Host -Prompt "Hit Enter to Exit"
        Start-Menu
    }
    Start-Menu
}
# Pull the current SCHANNEL configuration from the registry using the Get-RegistryInformation function to build the $regsettings array
function Get-Registry {
    Clear-Host
    Write-Log -String "Pulling registry information for SCHANNEL Protocols" -Name $Logname
    $regSettings = @()
    # Retrieve .NET 2.0 TLS configuration
    $regKey = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727'
    $regSettings += Get-RegistryInformation $regKey 'SystemDefaultTlsVersions'
    $regSettings += Get-RegistryInformation $regKey 'SchUseStrongCrypto'
    # Rtrieve .NET 4.0 TLS configuration for 32 bits on 64-bit OS.
    $regKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    $regSettings += Get-RegistryInformation $regKey 'SystemDefaultTlsVersions'
    $regSettings += Get-RegistryInformation $regKey 'SchUseStrongCrypto'
    # Native .NET 4.0 TLS configuration for native 64-bit applications.   
    $regKey = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    $regSettings += Get-RegistryInformation $regKey 'SystemDefaultTlsVersions'
    $regSettings += Get-RegistryInformation $regKey 'SchUseStrongCrypto'
    # TLS 1.2 Server and Client keys    
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
    $regSettings += Get-RegistryInformation $regKey 'Enabled'
    $regSettings += Get-RegistryInformation $regKey 'DisabledByDefault'
        
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $regSettings += Get-RegistryInformation $regKey 'Enabled'
    $regSettings += Get-RegistryInformation $regKey 'DisabledByDefault'
    # TLS 1.1 Server and client keys
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
    $regSettings += Get-RegistryInformation $regKey 'Enabled'
    $regSettings += Get-RegistryInformation $regKey 'DisabledByDefault'
    
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
    $regSettings += Get-RegistryInformation $regKey 'Enabled'
    $regSettings += Get-RegistryInformation $regKey 'DisabledByDefault'
    # TLS 1.0 Server and client keys
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
    $regSettings += Get-RegistryInformation $regKey 'Enabled'
    $regSettings += Get-RegistryInformation $regKey 'DisabledByDefault'
    
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
    $regSettings += Get-RegistryInformation $regKey 'Enabled'
    $regSettings += Get-RegistryInformation $regKey 'DisabledByDefault'
    # SSL 3.0 Server and client keys (These are automatically disabled by default on modern operating systems Windows Server 2016+)
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
    $regSettings += Get-RegistryInformation $regKey 'Enabled'
    $regSettings += Get-RegistryInformation $regKey 'DisabledByDefault'
    
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
    $regSettings += Get-RegistryInformation $regKey 'Enabled'
    $regSettings += Get-RegistryInformation $regKey 'DisabledByDefault'
    # SSL 2.0 Server and client keys (These are completely deprecated on modern operating systems Windows Server 2016+)
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
    $regSettings += Get-RegistryInformation $regKey 'Enabled'
    $regSettings += Get-RegistryInformation $regKey 'DisabledByDefault'
    
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
    $regSettings += Get-RegistryInformation $regKey 'Enabled'
    $regSettings += Get-RegistryInformation $regKey 'DisabledByDefault'
    # Write each object to the log so that we have a record of what was returned from the registry.
    foreach ($object in $regSettings) {
        foreach ($i in $object.PSObject.Properties) {
            Write-log -String "$($i.Name), $($i.Value)" -Name $Logname
        }
    }
    $Regoutput = $regSettings | Format-Table -AutoSize
        
    Write-output $Regoutput
    Read-Host -Prompt "Hit Enter to continue"
    Start-Menu
}

function Disable-SSL {
    Clear-Host
    Write-Log -String "User selected to Disable SSL" -Name $Logname
    $Writable = $true
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Restart-ComputerNotification
}

function Enable-TLS10 {
    Clear-Host
    Write-Log -String "User selected to Enable TLS 1.0" -Name $Logname
    $Writable = $true
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")
    $Key.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server")
    $Key.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Restart-ComputerNotification    
}
function Enable-TLS11 {
    Clear-Host
    Write-Log -String "User selected to enable TLS 1.1" -Name $Logname 
    $Writable = $true
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")
    $Key.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server")
    $Key.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Restart-ComputerNotification
}
# Enable TLS 1.2 function
function Enable-TLS12 {
    Clear-Host
    Write-Log -String "User selected to Enable TLS 1.2" -Name $Logname
    $Writable = $true
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client")
    $Key.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server")
    $Key.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    # Have to tell .NET 4.0/4.5 to use TLS 1.2 (I.E. SchUseStrongCrypto) and set System Default TLS to 1.2
    $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("Microsoft\.NETFramework\v4.0.30319")
    $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    # Enable TLS 1.2 for 32-bit applications installed on a 64-bit OS.
    $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("Wow6432Node\Microsoft\.NETFramework\v2.0.50727")
    $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("WOW6432Node\Microsoft\.NETFramework\v4.0.30319")
    $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Restart-ComputerNotification
}
# Disable TLS 1.0 function
function Disable-TLS10 {
    Clear-Host
    Write-Log -String "User selected to Disable TLS 1.0" -Name $Logname
    # Prompt warning that continuing to disable TLS 1.0 can break legacy applications.
    Add-Type -AssemblyName PresentationCore, PresentationFramework
    $Button = [System.Windows.MessageBoxButton]::YesNoCancel
    $WarningTitle = "Disable TLS 1.0 Warning"
    $WarningIcon = [System.Windows.MessageBoxImage]::Question
    $Warningbody = "Disabling TLS 1.0 involves the risk of interrupting legacy applications that use TLS 1.0, are you sure you want to continue?"

    $WarningResult = [System.Windows.MessageBox]::Show($Warningbody, $WarningTitle, $Button, $WarningIcon)
    # If user selects Yes, they are confirming they are aware that legacy applications could be impacted, but if no legacy applications exists
    # then there should be no end user impact.
    if ($WarningResult -eq "Yes") {
        Write-Log -String "User selected Yes that they understand that disabling TLS 1.0 can interrupt legacy applications, continuing" -Name $Logname
        $Writable = $true
        $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")
        $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
        $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
        $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server")
        $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
        $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
        Write-Log -String "Finished adding registry keys disabling TLS 1.0 prompting user to restart" -Name $Logname
        Restart-ComputerNotification
        
        
    }
    # If user selects no, return to the main menu.
    elseif ($WarningResult -eq "No") {
        Write-Log -String "User selected No to not continue disabling TLS 1.0 " -Name $Logname
        Clear-Host; Write-Host ""
        Write-Host "You selected NO, no changes will be made."
        Read-Host -Prompt "Hit Enter key to continue"
        Start-Menu
    }
    # If user selects cancel, exit the script.
    elseif ($WarningResult -eq "Cancel") {
        Write-Log -String "User selected Cancel, exiting script" -Name $Logname
        Exit
    }

    
     
}
# Disabling TLS 1.1 generally doesn't need to be done, but I've included it as an option in case someone wants to disable that Protocol.
function Disable-TLS11 {
    Clear-Host
    Write-Log -String "User selected to Disable TLS 1.1" -Name $Logname   
    $Writable = $true
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Write-Log -String "Finished adding registry keys to disable TLS 1.1, prompting user to restart" -Name $Logname
    Restart-ComputerNotification
}

function Disable-Multiple {
    Clear-Host
    Write-Log -String "User selected to disable all legacy protocols and only have TLS 1.2 enabled" -Name $Logname
    $Writable = $true
    # Disable SSL 2.0 and Disable SSL 3.0.
    Write-Log -String "Disabling SSL 2.0 and SSL 3.0" -Name $Logname
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Write-Log -String "SSL 2.0 and 3.0 keys have been set to be disabled" -Name $Logname

    # Disable TLS 1.0 - BE VERY CAREFUL AS THIS CAN BREAK LEGACY APPLICATIONS!!!!!!!
    Write-Log -String "Disabling TLS 1.0" -Name $Logname
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Write-Log -String "TLS 1.0 keys have been set to be disabled" -Name $Logname

    # Disable TLS 1.1
    Write-Log -String "Disabling TLS 1.1" -Name $Logname
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server")
    $Key.SetValue("Enabled", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Write-log -String "TLS 1.1 keys have been set to be disabled" -Name $Logname

    # Enable TLS 1.2 as well as tell .NET to use Strong Cryptography
    Write-log -String "Enabling TLS 1.2" -Name $Logname
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client")
    $Key.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server")
    $Key.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Write-Log -String "TLS 1.2 client and server keys updated, continuing to .NET" -Name $Logname
    # Have to tell .NET 4.0/4.5 to use TLS 1.2 (I.E. SchUseStrongCrypto)
    Write-Log -String "Enabling .NET 4.0 to use Strong Crypto" -Name $Logname
    $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("Microsoft\.NETFramework\v4.0.30319")
    $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Write-Log -String ".NET 4.0 registry keys have been updated, continuing to 32-bit application support for TLS 1.2" -Name $Logname
    # Enable TLS 1.2 for 32-bit applications installed on a 64-bit OS.
    Write-Log -String "Enabling TLS 1.2 for 32-bit applications installed on a 64-bit OS" -Name $Logname
    $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("Wow6432Node\Microsoft\.NETFramework\v2.0.50727")
    $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("WOW6432Node\Microsoft\.NETFramework\v4.0.30319")
    $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    $Key.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
    Write-Log -String "TLS 1.2 .NET keys for 32-bit applications installed has been completed, prompting to restart computer" -Name $Logname
    Restart-ComputerNotification

}

Write-Log -String "*********************************************************" -Name $Logname
Write-log -String "*                      START SCRIPT                     *" -Name $Logname
Write-log -String "*********************************************************" -Name $Logname
function Start-Menu {
    # Init PowerShell Gui
    Write-Log -String "Loading menu of choices for user" -Name $Logname
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create a new form
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $TLSForm = New-Object system.Windows.Forms.Form

    # Define the size, title and background color
    $TLSForm.ClientSize = '500,400'
    $TLSForm.text = "TLS Swiss Army Knife"
    $TLSForm.BackColor = "#ffffff"
    $TLSForm.StartPosition = "CenterScreen"
    $TLSForm.TopMost = $false

    $Font = New-Object System.Drawing.Font("Times New Roman", 11)
    $TLSForm.Font = $Font
    # Group box for available options.
    $TLSGroup = New-Object System.Windows.Forms.GroupBox
    $TLSGroup.Location = '40,30'
    $TLSGroup.size = '400,320'
    $TLSGroup.Text = "Select an option on how to proceed"
    # Radio button 1
    $Radiobtn1 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn1.Location = '20,40'
    $Radiobtn1.Size = '350,20'
    $Radiobtn1.Checked = $false
    $Radiobtn1.Text = "Retrieve Current SCHANNEL Configuration"
    # Radio button 2
    $Radiobtn2 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn2.Location = '20,70'
    $Radiobtn2.Size = '350,20'
    $Radiobtn2.Checked = $false
    $Radiobtn2.Text = "Disable SSL (2.0 and 3.0)"
    # Radio button 3
    $Radiobtn3 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn3.Location = '20,100'
    $Radiobtn3.Size = '350,20'
    $Radiobtn3.Checked = $false
    $Radiobtn3.Text = "Enable TLS 1.0"
    # Radio button 4
    $Radiobtn4 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn4.Location = '20,130'
    $Radiobtn4.Size = '350,20'
    $Radiobtn4.Checked = $false
    $Radiobtn4.Text = "Enable TLS 1.1"
    # Radio button 5
    $Radiobtn5 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn5.Location = '20,160'
    $Radiobtn5.Size = '350,20'
    $Radiobtn5.Checked = $false
    $Radiobtn5.Text = "Enable TLS 1.2"
    # Radio button 6
    $Radiobtn6 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn6.Location = '20,190'
    $Radiobtn6.Size = '350,20'
    $Radiobtn6.Checked = $false
    $Radiobtn6.Text = "Disable TLS 1.0"
    # Radio button 7
    $Radiobtn7 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn7.Location = '20,220'
    $Radiobtn7.Size = '350,20'
    $Radiobtn7.Checked = $false
    $Radiobtn7.Text = "Disable TLS 1.1"
    # Radio button 8
    $Radiobtn8 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn8.Location = '20,250'
    $Radiobtn8.Size = '350,20'
    $Radiobtn8.Checked = $false
    $Radiobtn8.Text = "Disable all protocols, only enable TLS 1.2"
    # Radio button 9
    $Radiobtn9 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn9.Location = '20,280'
    $Radiobtn9.Size = '350,20'
    $Radiobtn9.Checked = $false
    $Radiobtn9.Text = "Test Enabled SCHANNEL Protocols"
    # OK button
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = '130,355'
    $OKButton.Size = '100,40'
    $OKButton.Text = 'OK'
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    # Cancel button
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = '250,355'
    $CancelButton.Size = '100,40'
    $CancelButton.Text = 'Cancel'
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    # Build the forms with the group, and radio button objects.
    $TLSGroup.Controls.AddRange(@($Radiobtn1, $Radiobtn2, $Radiobtn3, $Radiobtn4, $Radiobtn5, $Radiobtn6, $Radiobtn7, $Radiobtn8, $Radiobtn9))

    $TLSForm.Controls.AddRange(@($TLSGroup, $OKButton, $CancelButton))

    $TLSForm.AcceptButton = $OKButton
    $TLSForm.CancelButton = $CancelButton

    $TLSForm.Add_Shown({ $TLSForm.Activate() })

    $ButtonResult = $TLSForm.ShowDialog()
    # If "YES" is selected proceed with calling the respective function
    if ($ButtonResult -eq "OK") {
        if ($Radiobtn1.Checked -eq $true) { Get-Registry }
        elseif ($Radiobtn2.Checked -eq $true) { Disable-SSL }
        elseif ($Radiobtn3.Checked -eq $true) { Enable-TLS10 }
        elseif ($Radiobtn4.checked -eq $true) { Enable-TLS11 }
        elseif ($Radiobtn5.Checked -eq $true) { Enable-TLS12 }
        elseif ($Radiobtn6.Checked -eq $true) { Disable-TLS10 }
        elseif ($Radiobtn7.checked -eq $true) { Disable-TLS11 }
        elseif ($Radiobtn8.checked -eq $true) { Disable-Multiple }
        elseif ($Radiobtn9.checked -eq $true) { Get-EnabledProtocols }

    }
    else {
        # If "CANCEL is selected close exit the script"
        if ($ButtonResult -eq "Cancel") { Clear-Host; Write-Log "User selected Cancel ending application" -Name $Logname; Exit }
    }
    [void]$TLSForm.ShowDialog()
}
Clear-Host
# Get current Cipher Suites used by the system
Write-Log -String "Getting list of current supported Ciphers by the system" -Name $Logname
$TLSCiphers = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002 -Name Functions
foreach ($Cipher in $TLSCiphers) {
    Write-Log -String $Cipher -Name $Logname
}
# Load Menu for user to choose how to proceed with script.    
Start-Menu
   