What is power cli ? 

```
VMware PowerCLI is a command-line and scripting tool built on PowerShell, and provides more than 7000 cmdlets for managing and automating VMware vSphere, VMware Cloud Director, vRealize Operations Manager, vSAN, VMware NSX-T, VMware Cloud Services, VMware Cloud on AWS, VMware HCX, VMware Site Recovery Manager, and VMware Horizon environments.
```


#PowerShell

Get-ExecutionPolicy

Get-ExecutionPolicy -List

Get-ExecutionPolicy -Scope CurrentUser

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

Set-ExecutionPolicy RemoteSigned #alternatively

------------------------------------------------------------------------------------------------------------------------------------

#login

>Get-PowerCLIConfiguration

#connect to vCenter with Invalid certificate (self-signed certificate or invalid cert) but shows with certificate warning.

>Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction warn

# Connects to a vSphere server by using the User and Password parameters

>Connect-VIServer -Server 10.23.112.235 -Protocol https -User admin -Password pass #login via CLI

>Connect-VIServer -Server 10.35.1.200 -credential $(Get-Credential) #login via windows pop-up menu

>Connect-VIServer -Menu #login via windows pop-up menu without server parameters

>Disconnect-VIServer #end session

--------------------------------------------------------------------------------------------------------------------------------------------

Get-VM | Get-Snapshot|Select VM,Name

get-vm -name VMNAME | get-snapshot

Get-Snapshot -VM VMNAME -Name 'Before ServicePack 2' #Retrieves the snapshot named "Before ServicePack2" of the VM virtual machine.

create a new snapshot

New-Snapshot -VM Test-1 -Name 'This is a test snapshot' -Description 'Testing this out' -Quiesce -Memory

New-Snapshot -VM VM -Name BeforePatch

New-Snapshot -VM VM2 -Name PoweredOnVM -Memory $true

revert a VM to a snapshot

Set-VM -VM Test-1 -Snapshot (Get-Snapshot -VM Test-1 -Name 'This is a test snapshot'

Remove a snapshot

> Get-Snapshot -VM Test-1 | Remove-Snapshot -RemoveChildren

filter your request by using the Where-Object cmdlet and use the Guest property,

Get-VM | Where-Object {$_.Guest -like "*Centos*"}

Get-VM | Where-Object {$_.Guest -like "*Windows Server 2012*"}

Get-VM | Where-Object {$_.Guest -like "*Windows Server 2016*"}

--------------------------------------------------------------------------------------------------------------------------------------------

Get-View -Viewtype VirtualMachine -Property name, guest.ipaddress

Get-VMHost #ESXi Hosts

Get-VMHost | format-list -Property Name,Version

Get-VMHost | fl #Detailed Information on ESXi Hosts

Get-VMHost -Name esxiserver | Get-VM

Start-VM "Tiny Linux template" #Power On a VM

Stop-VM "Tiny Linux template" #Power Off a VM

Restart-VM "Tiny Linux template"

Shutdown-VMGuest ‑VM <vm>

Restart-VMGuest ‑VM <vm>

#(dis)Mounts the VMware Tools CD installer

Mount-Tools ‑VM <vm>

Dismount-Tools ‑VM <vm>

# SSH and Esxi Shell Status TSM – – Denotes Esxi Shell

> Get-VMHost| Get-VMHostService | Where-Object {$_.Key -like "TSM*"}

> Get-VMHost -Name esxiserver | Get-VMHostService | Where-Object {$_.Key -like "TSM*"}

Enabling SSH And Shell

Get-VMHost -Name esxiserver | Get-VMHostService | Where-Object {$_.Key -like "TSM*"}| Set-VMHostService -policy "on"

Get-VMHost | Get-VMHostService | Where-Object {$_.Key -like "TSM*"}| Set-VMHostService -policy "on"

Restart SSH And Shell

Get-VMHost -Name esxiserver | Get-VMHostService | Where-Object {$_.Key -like "TSM*"}| Restart-VMHostService

Get-VMHost | Get-VMHostService | Where-Object {$_.Key -like "TSM*"}| Restart-VMHostService

#list machines loaded with ISOs Unnecessarily

Get-VM | Get-CDDrive | where-object{$_.isopath -notlike $null} | FT Parent,Isopath –AutoSize

> Get-VM | where-object {$_.PowerState -eq "PoweredOff"} #VMs that are in the PoweredOff state

> Get-VM | where-object {$_.PowerState –eq “PoweredOff”} | Start-VM

Get-VM | where-object {$_.NumCpu –gt 1 } # VMs more than 1 CPU assigned

> Get-vm | where-object {$_.MemoryGB -eq 4 } | select -ExpandProperty Name | out-file c:\tmp\VMs.txt #VMs w 4GB memory

Get-VirtualSwitch #the virtual switches configured

Get-VirtualSwitch -Name vSwitch8

Get-VirtualSwitch -Name vSwitch8 | fl

Get-VirtualSwitch | fl

Get-VirtualPortGroup #virtual port groups

Get-VM | Where-Object { ($PSItem | Get-NetworkAdapter | where {$_.networkname -match "DPortgroup"})} #VMs inside port group DPortGroup

#Getting OS Version Information on VMs

Get-VM | Sort-Object -Property Name | Get-View -Property @("Name", "Config.GuestFullName", "Guest.GuestFullName") | Select-Object -Property Name, @{N="Configured OS";E={$_.Config.GuestFullName}}, @{N="Running OS";E={$_.Guest.GuestFullName}}

# txt output

Get-VM | Sort-Object -Property Name | Get-View -Property @("Name", "Config.GuestFullName", "Guest.GuestFullName") |Select-Object -Property Name, @{N="Configured OS";E={$_.Config.GuestFullName}}, @{N="Running OS";E={$_.Guest.GuestFullName}} | out-file c:\tmp\VMswOS.txt

#csv output

Get-VM | Sort-Object -Property Name | Get-View -Property @("Name", "Config.GuestFullName", "Guest.GuestFullName") |Select -Property Name, @{N="Configured OS";E={$_.Config.GuestFullName}}, @{N="Running OS";E={$_.Guest.GuestFullName}} | Export-CSV C:\tmp\report.csv -NoTypeInformation

Invoke-VMScript -VM WindowsVM -ScriptText "dir C:\" -GuestUser administrator -GuestPassword pass2

Get-View -ViewType VirtualMachine -Filter @{"Name" = "WindowsVM"}

> $VM = Get-View -ViewType VirtualMachine -Filter @{"Name" = "WindowsVM"}

> $VM.Guest

> $VM.Guest.GuestFullName

Get-Log -Bundle -DestinationPath C:\vSphere_logs #Generate Diagnostic Log Bundle on ESXi Host or vCenter