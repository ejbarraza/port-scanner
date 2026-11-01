# CIS-25 Lab Work

Screenshots and definitions from CIS-25 coursework, captured October 15, 2026
on the CIS25VM3 Windows 11 VirtualBox VM. Topics: Windows 11 settings
navigation, printers, power/battery, Bluetooth/devices, Device Manager,
network configuration and connectivity, disk management, and mobile device
concepts.

## Files

| File | Shows |
| --- | --- |
| `WiFi_Settings.pdf` | Network & internet settings — Ethernet adapter page (IP assignment, DNS, adapter details) |
| `Printer_Types.pdf` | Definitions: Bluetooth, hotspot, tethering, MDM, laser / inkjet / thermal / impact printers |
| `Printer_Troubleshooter.pdf` | System → Troubleshoot → Other troubleshooters |
| `Printer_Properties.pdf` | Microsoft Print to PDF properties dialog (General, Sharing, Ports, Advanced, Color Management, Security) |
| `Print_Queue.pdf` | Print queue window (no print jobs) |
| `Power___Battery_Settings.pdf` | System → Power (power mode, screen timeout, energy saver, power & sleep button controls) |
| `Bluetooth_Settings.pdf` | Bluetooth & devices page |
| `Device_Manager_Mobile-Related_Devices.pdf` | Device Manager device tree (network adapters expanded) |
| `Installed_Printers-1.pdf` | Bluetooth & devices → Printers & scanners (Microsoft Print to PDF, print preferences) |
| `Mobile_Device_Management_Concepts.pdf` | Definitions: Bluetooth, hotspot, tethering, MDM, laser printer |
| `Detailed_Network_Configuration.pdf` | PowerShell `ipconfig /all` output (adapter, MAC, IPv4/IPv6, DNS, DHCP) |
| `Device_Manager.pdf` | Device Manager with VBOX HARDDISK properties (device working properly) |
| `Disable_Enable_Network_Adapter.pdf` | Network Connections, Ethernet adapter Disabled |
| `Disk_Initialized.pdf` | Disk Management, Disk 1 (1.98 GB) Unallocated |
| `Disk_Management.pdf` | Disk Management, Disk 0 + CD-ROM (D:) |
| `DiskPart_Results.pdf` | `diskpart` list disk (Disk 0 80 GB GPT, Disk 1 2048 MB GPT) |
| `Explore_Virtualization_Settings-2.pdf` | VirtualBox CIS25VM3 settings, System/Motherboard (8 GB RAM, TPM 2.0, UEFI) |
| `Identify_Network_Adapter.pdf` | Device Manager, Network adapters (Intel PRO/1000 MT) |
| `Input_Devices.pdf` | Device Manager, Keyboards + Mice expanded |
| `Installed_Printers.pdf` | Settings → Microsoft Print to PDF page (queue, test page, properties, preferences) |
| `IP_Configuration.pdf` | PowerShell `ipconfig` output (IPv4, IPv6, gateway) |
| `Keyboard_Settings.pdf` | Time & language → Typing settings |
| `Mouse_Settings.pdf` | Bluetooth & devices → Mouse settings |
| `New_Volume_Created.pdf` | Disk Management, LabDrive (E:) 1.98 GB NTFS created |
| `Output_Devices.pdf` | Device Manager, audio inputs/outputs + sound controllers |
| `Test_Connectivity.pdf` | `ipconfig /all` + `ping google.com` (0% loss) |
| `Test_local_Network.pdf` | `ping google.com` + `ping 10.0.2.2` gateway (0% loss) |
| `Troubleshooting.pdf` | Get Help / recommended troubleshooter options |
| `VHD_Created.pdf` | Microsoft Virtual Disk properties, Disk 1 Unknown / Not Initialized |
| `View_Active_Network_Connection-2.pdf` | Command Prompt `netstat` active connections |
| `View_Wi-Fi_Networks.pdf` | `netsh wlan show networks` (Wireless AutoConfig not running) |

## October 27, 2026 — Windows troubleshooting tools

Same CIS25VM3 Windows 11 VM. Screenshot-documented walkthroughs of the
built-in troubleshooting tools (10 files, bringing this folder to 41 PDFs).
No grades or personal information in these screenshots.

| File | Shows |
| --- | --- |
| `Disk_Cleanup.pdf` | Disk Cleanup for (C:) — 626 MB reclaimable, 14.4 MB selected (Temporary Internet Files, Delivery Optimization Files, Temporary files) |
| `Disk_Management-2.pdf` | Disk Management — Disk 0 (79.98 GB), (C:) 78.89 GB NTFS (BitLocker Encrypted), 43.05 GB free |
| `Event_Viewer.pdf` | Event Viewer, System log (2,262 events, 10/27/2026) — Virtual Disk Service, Event 4 |
| `Performance_Tab.pdf` | Task Manager → Performance, CPU Intel Core i7-10700 @ 2.90 GHz (4%), Memory 3.0/8.0 GB (38%), uptime 0:00:19:31 |
| `Resource_Monitor.pdf` | Resource Monitor Overview — CPU, Memory, Disk, and Network sections (10/27/2026) |
| `Services_Console.pdf` | Services (Local) console — service name, description, status, startup type |
| `Startup_Applications.pdf` | Task Manager → Startup apps — Copilot/OneDrive/ShareX enabled, Teams/Terminal/Xbox disabled |
| `System_Configuration.pdf` | System Configuration (msconfig) → Boot — Windows 11 (C:\WINDOWS) current OS, default OS, 30-second timeout |
| `Task_Manager_Processes.pdf` | Task Manager → Processes — Apps (2), Background processes (45) |
| `Windows_Troubleshooting_Tools_Summary.pdf` | Doc.txt definitions — Task Manager, Event Viewer, Resource Monitor, Disk Cleanup, msconfig |
