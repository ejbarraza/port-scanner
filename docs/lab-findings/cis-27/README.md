# CIS-27 Lab Work

CIS-27 (Fall), cybersecurity course using TestOut LabSim. Raw lab reports
are not published here (they contain lab credentials and session links);
this file summarizes what was covered. No personal information is included.

Chapter 1 is an intro to the lab simulator (no labs).

## Midterm — topics covered

Security challenges (sophisticated attacks, attack scale and velocity),
policy-driven access control, AAA, password security, anti-spoofing firewall
rules, Active Directory structure, data exfiltration, fail-open vs.
fail-closed, password cracking, certificates and the CA trust model, control
categories vs. control types, corrective vs. compensating controls, SBOM
and SCA, network architecture trade-offs, authentication prerequisites,
dual-homed gateways, screened subnets and ACLs, MFA and biometrics, package
monitoring and vulnerability scanning, federation, social engineering
phases, router ACLs, CRLs, security groups, authentication factors, hashing
and message digests, obfuscation.

## Chapter 2 Labs

| Lab | Covered |
| --- | --- |
| 2.3.6 | Windows Security exclusions, protection updates, quick scan |

## Chapter 3 Labs

| Lab | Covered |
| --- | --- |
| 3.1.11 | Steganography: hide and extract data with password |
| 3.3.5 | File integrity via MD5 hash comparison |
| 3.4.3 | EFS folder encryption + authorized user |
| 3.4.8 | TPM enable/activate + BitLocker full-drive encryption |
| 3.5.6 | Certificate Authority: issue, deny, revoke, unrevoke |

## Chapter 4 Labs

| Lab | Covered |
| --- | --- |
| 4.4.5 | Active Directory OUs: create, accidental-deletion protection |
| 4.4.6 | Active Directory OUs: delete |
| 4.4.10 | GPO: create, link, import security template |
| 4.4.11 | AD user accounts + logon hours / expiry |
| 4.4.12 | AD account management: unlock, disable, enable, rename, restrictions |
| 4.4.13 | Security group + members |
| 4.4.14 | Global security groups + members |
| 4.5.5 | Password + account lockout policy |
| 4.5.7 | GPO: built-in Administrators group membership |
| 4.5.8 | Local users/groups: rename admin, disable guest, cleanup |
| 4.5.9 | UAC settings via GPO |
| 4.5.12 | GPO enforced + smart card logon |
| 4.6.4 | Linux: create user account + password |
| 4.6.5 | Linux: rename account, move home directory |
| 4.6.6 | Linux: delete account + home directory |
| 4.6.7 | Linux: change account password |
| 4.6.8 | Linux: set another user's password |
| 4.6.9 | Linux: lock/unlock accounts, verify via /etc/shadow |
| 4.7.3 | Linux: rename/create groups, change membership |
| 4.7.4 | Linux: add users to a group |
| 4.7.5 | Linux: remove a user from a group |

## Chapter 5 Labs

| Lab | Covered |
| --- | --- |
| 5.2.7 | pfSense: DNS servers, WAN settings, gateway |
| 5.2.8 | pfSense: admin password, new user, session timeout, anti-lockout |
| 5.3.3 | pfSense: SCREENED/DMZ interface, firewall rule, DHCP server |
| 5.4.5 | pfSense: firewall rules (HTTP/HTTPS WAN→DMZ, LAN→DMZ) |
| 5.5.4 | pfSense: OpenVPN server, CA + server certificate, VPN users |
| 5.5.5 | IPSec VPN client configuration and connection |
| 5.7 | Cisco switch: new user account, default account, save config |
