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

**------------------------------------------------------------------------------------------------------------------------------------------**

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
