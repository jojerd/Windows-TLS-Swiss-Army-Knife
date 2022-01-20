# Windows-TLS-Swiss-Army-Knife
Windows PowerShell script to Enable TLS 1.2 and Disable legacy protocols. This can be run on any Windows Server Operating System with PowerShell 3.0
or higher. Does require Administrative Privileges to be used during execution if you are going to be making changes as this script make changes to the registry.

# Requirements

Administrative Permissions during execution of Enable / Disable switches as registry is being changed.
PowerShell 3.0 or higher. I do have the script check for PowerShell version requirements and will error out and stop if at least version 3.0 oor higher is not detected.

# Script Execution

Open a PowerShell Window as an Administrator and browse to the location the script is saved and execute it like the example below:

.\TLS-SwissArmyKnife.ps1 -EnableTLS12

# Switch Explaination

-EnabledProtocols: This will go through and check each individual protocol on the server to confirm what protocols are responding and what ones are currently disabled. This is useful to find which protocols are currently enabled. It will provide quite a bit of details, the IP Address, Port, Port Status, Certificate name, Thumbprint of the Certificate, Date certificate was issued, and date certificate is to expire, key length, signature, cipher used during handshake negotiation and Protocol used.

-DisableSSL: Just disables SSL 2.0 and SSL 3.0, it will not do anything outside of that.

-EnableTLS11: Enables TLS 1.1, usually is enabled by default but just in case you want quickly reverse a TLS 1.1 disable.

-EnableTLS12: Just enables TLS 1.2 and will not do anything outside of that.

-DisableTLS10: Will just disable TLS 1.0 (BE VERY CAREFUL WITH THIS AS THIS CAN CAUSE LEGACY APPLICATIONS TO STOP WORKING!!!)

-DisableTLS11: This will disable TLS 1.1, while not required is an option in case you need to roll back a TLS 1.1 disable change quickly.

-SecureMe: Disables SSL 2.0 / SSL 3.0 and enables TLS 1.2. It does not touch TLS 1.1. You can disable TLS 1.1 with the above switch if you choose.






