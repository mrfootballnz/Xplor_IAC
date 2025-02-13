function Write-Log {
    param(
        $message
    )
    $date = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logpath = "$($env:TEMP)\$($date).log"
    Add-Content -Path $logpath -Value "$date`t$message"
    Write-Host "$date`t$message"
}

Write-Log "Initial script started."
#disable windows firewall
set-NetFirewallProfile -All -Enabled False
#Initialize disk 1 and 2. Disk 1 has drive D, application. Disk 2 has drive P, PageFile.
# Dynamic Disk Initialization and Formatting Script
$driveletters = @('D', 'E', 'L', 'T')  # Predefined drive letters
$labels = @('Application', 'Data', 'Logs', 'TempDB')  # Corresponding labels

Write-Log 'Loading the SSH KEY'
$Key_content = Get-Content "C:\ssh_key.key" 
Write-Log 'Loaded SSH KEy'
Write-Log 'key:' + $Key_content
# Function to check if a disk is uninitialized
function Is-DiskUninitialized {
    param([int]$DiskNumber)
    
    $disk = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
    
    if ($disk) {
        return ($disk.PartitionStyle -eq 'RAW')
    }
    
    return $false
}

# Iterate through disks 1-4
Write-Log "Going through the disks..."
for ($i = 1; $i -le 4; $i++) {
    # Check if the disk exists and is uninitialized
    if (Is-DiskUninitialized -DiskNumber $i) {
        try {
            # Initialize the disk
            Initialize-Disk -Number $i -PartitionStyle GPT -ErrorAction Stop
            
            # Create partition using maximum available size
            $partition = New-Partition -DiskNumber $i -UseMaximumSize -ErrorAction Stop
            
            # Assign drive letter (use predefined letters or fallback)
            $driveLetter = if ($i -le $driveletters.Length) { $driveletters[$i-1] } else { (Get-VolumeSuggestedDriveLetter) }
            
            # Add drive letter to the partition
            $partition | Add-PartitionAccessPath -AccessPath "$($driveLetter):" -ErrorAction Stop
            
            # Format the volume
            $label = if ($i -le $labels.Length) { $labels[$i-1] } else { "Data$i" }
            Format-Volume -DriveLetter $driveLetter -FileSystem NTFS -NewFileSystemLabel $label -Confirm:$false -ErrorAction Stop
            
            Write-Log "Disk $i initialized, partitioned, and formatted as drive $driveLetter with label $label"
        }
        catch {
            Write-Log "Error processing Disk ${$i}"
        }
    }
    else {
        Write-Log "Disk $i is either already initialized or not present"
    }
}
Write-Log 'Disk setup completed.'
#Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
#Enable RDP through Windows firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
# Install the OpenSSH Client
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
# Set the ssh-agent service to Automatic (Delayed Start)
Set-Service -Name ssh-agent -StartupType 'Automatic'
# Start the OpenSSH Authentication Agent
Start-Service ssh-agent
# Install the OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
# Start the sshd service
Start-Service sshd
# OPTIONAL but recommended:
Set-Service -Name sshd -StartupType 'Automatic'
#create default shell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
#Create the authorized public key for openssh
New-Item -Path "C:\ProgramData\ssh\" -Name "administrators_authorized_keys" -ItemType "file" -Value $Key_content
#Create the sshd_config file for openssh
Set-Content -Path "C:\ProgramData\ssh\sshd_config" -Value "# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
#HostKey __PROGRAMDATA__/ssh/ssh_host_dsa_key
#HostKey __PROGRAMDATA__/ssh/ssh_host_ecdsa_key
#HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
StrictModes no
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

# For this to work you will also need host keys in %programData%/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication no
#PermitEmptyPasswords no

# GSSAPI options
#GSSAPIAuthentication no

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#PermitUserEnvironment no
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem	sftp	sftp-server.exe

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server

Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"
#Restart ssh server service after setting the key
Restart-Service -Force -Name sshd
#disable need to run Internet Explorer's first launch configuration
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

Write-Log "Initial script completed."
