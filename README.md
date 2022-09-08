# Windows-TLS-Swiss-Army-Knife
Windows PowerShell script to Enable TLS 1.2 and Disable legacy protocols. This can be run on any Windows Server Operating System with PowerShell 3.0
or higher. Does require Administrative Privileges to be used during execution. The changes made for TLS are to enable BOTH the Client and Server registry
keys. This is done even on servers as sometimes the server is also the client. Example being communicating with Azure Active Directory, or running a PowerShell
session and connecting to Azure (connect-msolservice). In those instances the server is acting as a client, so its a best practice to enable both the Client and Server
TLS registry keys.

# Requirements

Administrative Permissions during execution of Enable / Disable switches as registry is being changed.
PowerShell 3.0 or higher. I do have the script check for PowerShell version requirements and will error out and stop if at least version 3.0 or higher is not detected.

# Script Execution

Open a PowerShell Window as an Administrator and browse to the location where the script is saved and execute it like the example below:

.\TLS-SwissArmyKnife.ps1, or right click run in PowerShell. If it doesn't open, or closes immediately after execution it likely means that PowerShell was not ran as an Administartor

# Option Explanation

Retrieve Current SCHANNEL Configuration
This option will go through and pull the registry of SCHANNEL protocols for .NET and standard TLS/SSL keys and provide you
an output of the current configured values or "NOT FOUND" if no key or value was set.

Disable SSL (2.0 and 3.0) 
On modern Windows Operating Systems (2016+) SSL 3.0 is disabled by default, and SSL 2.0 is completely deprecated and unsupported. However for Windows 2012 and 2012 R2 
those keys should be set to disabled.

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







