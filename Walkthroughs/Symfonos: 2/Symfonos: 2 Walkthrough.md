# **Vulnerable System** : Symphonos2

**Operating System** : Debian 9

**Kernel** : 4.9.0

----------------------------------------------------------------------------------------------------------------------------------------

1st low privilege

**Vulnerability Exploited** : Poorly configured SMB shares/weak password

**Vulnerability Explained** :  Poorly configured SMB shares allowed to obtain a file containing configurations for various services. A username found of the file had a weak password which was then bruteforced.

**Vulnerability fix** : Implement strong permissions on SMB shares implement strong password policy.

**Severity** : **Medium**

----------------------------------------------------------------------------------------------------------------------------------------

2nd low privilege

**Vulnerability Exploited** : LibreNMS addhost Command Injection

**Exploit Used** : Metasploit&#39;s exploit/linux/http/librenms\_addhost\_cmd\_inject

**Proof of Concept Code** : [https://www.exploit-db.com/exploits/46970](https://www.exploit-db.com/exploits/46970)

**Vulnerability Explained** :  This vulnerability allows attacker to execute commands as a user who owns the instance of LibreNMS running. The vulnerability resulted in obtaining a low privilege shell.

**Vulnerability fix** : No fixes were found.

**Severity** : **Medium**

----------------------------------------------------------------------------------------------------------------------------------------

**Privilege Escalation Vulnerability** : SQL database running with administrative privileges and is accessible to non privileged user.

**Privilege Escalation Vulnerability Explained:** Due to SQL running as root, a low privileged user was able to connect to MYSQL database and escape into root interface.

**Vulnerability fix** : Make a separate user for MySQL with as least privileges as needed.

**Severity** : **High**

## Methodology

    * Port Scanning (nmap)
    * Web Port Enumeration (nikto, gobuster, firefox)
    * SMB Enumeration (smbclient)
    * File enumeration (cat)
    * FTP Enumeration (ftp)
    * FTP Password Bruteforce (hydra)
    * Obtained Low Privilege Shell for User aeolus (ssh)
    * Privilege Escalation Enumeration (uname, cat /etc/*-release, ss -ant)
    * Setup SSH Local Port Forwarding (ssh)
    * Setup Firefox Proxy (firefox)
    * Discovered Appropriate Exploit: LibreNMS - Command Execution (searchsploit/exploit-db)
    * Setup Proxy Connection for msfconsole (proxychains & ssh)
    * Updated Metasploit with a New Exploit.
    * Ran the Exploit and Gained Low Privilege Shell for User cronus
    * Privilege Escalation Enumeration (sudo -l)
    * Privilege Escalation (MySQL ran with Administrative Privileges)

## Reconnaissance 

### Host Discovery (arp-scan)
arp-scan -l:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/arp-scan.png?raw=true)

### Port Scanning(Nmap)

All ports scan:

nmap -p- 192.168.20.142

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/nmap%20all%20ports.png?raw=true)

nmap -sV -sC -A (Version &amp; Default Scripts &amp; Aggressive) scan of selected ports. 

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/nmap_sv_sc.png?raw=true)

### Port 80 Enumeration

#### Nikto

Nikto enumeration of port 80:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/nikto.png?raw=true)

#### Gobuster

Gobuster enumeration of port 80:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/gobuster.png?raw=true)

#### Browser

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/browser.png?raw=true)

## SMB Enumeartion (smbclient) 

SMB enumeration for accessible shares found anonymous share:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/smb1.png?raw=true)

Connecting to anonymous share and discovering log.txt file:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/smb2.png?raw=true)

The file consisted of a couple of configuration files: smb.conf and proftpd.conf

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/file.png?raw=true)

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/file1.png?raw=true)

## FTP

Proftpd.conf file provided us with 2 usersnames: anonymous(ftp) and Aeolus.

As can be seen from the screenshot below anonymous login failed.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/ftp.png?raw=true)

## Low Privilige Exploitation

### hydra

Hydra was used to bruteforce the password for user Aeolus.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/hydra.png?raw=true)

Nothing different was found when enumerating FTP.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/ftp2.png?raw=true)

### SSH 

SSH credentials were the same as discovered ftp credentials, which allowed to obtain low privilege shell.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/ssh.png?raw=true)

## Privilege Escalation Enumeration:

Doing basic enumeration:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/uname.png?raw=true)

Netstat wasn&#39;t available on the system but SS was:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/Ss.png?raw=true)

It seems that there's an internal webserver running.

### SSH Local Port Forwarding

SSH local port forwarding can be used to enumerate this webpage further:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/ssh_port_forward.png?raw=true)

With Firefox configured to use manual proxy as follows:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/proxyconfig.png?raw=true)

Internal port 8080 is now available in the browser and LibreNMS software discovered:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/librenms.png?raw=true)

Successful login with Aeolus' credentials:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/librenms_dash.png?raw=true)

### Exploitation

Searching exploit-db for suitable exploit, as can be seen there are 2 version of it a manual exploit and Metasploit:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/searchsploit.png?raw=true)

#### Manual Exploit

First attempt will be made with a manual exploit.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/searchsploit1.png?raw=true)

A manual exploit was found at: [https://www.exploit-db.com/exploits/47044](https://www.exploit-db.com/exploits/47044)

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/exploitdb.png?raw=true)

The exploit requires a cookie, which can be obtained by pressing F12 in your browser after logging in with aoelus' credentials:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/cookies.png?raw=true)

Instead of using apache webserver and /var/www/html folder, python's Simple HTTP Server can be used to serve the exploit from working directory:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/pythonHTTP.png?raw=true)

Downloading exploit to the victim's machine:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/wget_expliot.png?raw=true)

Although the exploit ran successfully no reverse shell was obtained:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/exploit_success.png)

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/nc-nvlp.png)

#### Metasploit Exploit

Next Metasploit framework can be checked.

In order to access internal website with Metasploit, local port forwarding and proxychains can be used with SSH tunnel we created earlier.

Proxychains allows to proxy traffic through the SSH proxy, allowing Metasploit access to the internal applications of victim's machine.

In order for Metasploit to launch successfully through proxychains the following line has to be added to /etc/proxychains.conf for postgresql not to error out when launching msfconsole.

localnet 127.0.0.1 000 255.255.255.255

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/localnet.png?raw=true)

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msfconsole.png?raw=true)

When trying to use the exploit for some reason it was not present in Metasploit:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msf_not_found.png?raw=true)

In this case it can be manually imported from exploit-db as follows:

Create appropriate folder for the exploit in /root/.mfs4/modules/exploits:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msf4.png?raw=true)

Once created copy the exploit into the appropriate folder:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msf_exploitdb.png?raw=true)

Once done run the updatedb command.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/updatedb.png?raw=true)

Let's try this again:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/search_librenms.png?raw=true)

One selected we can use info command to learn more about the exploit:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/info.png?raw=true)

As can be seen the required options are: password, rhost, rport, targeturi and username. For the reverse shell lhost has to be specified as well.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msf_settings.png?raw=true)

Once all the options are set, it's ready to be exploited:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msf_run_exploit.png?raw=true)

## Second Low Privilege Shell Enumeration

This time around the low privilege shell was obtained for user cronus and python -c "import pty;pty.spawn('/bin/bash')" command was used to escape the default shell.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/cronus.png?raw=true)

Sudo -l can be used to check if this user has any sudo privileges:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/sudo_l.png?raw=true)

## Root

As can be seen on the screenshot above, user cronus can execute /usr/bin/mysql with administrative privileges.

Mysql also can be escaped into a shell with ```\! /bin/bash``` command.

Using mysql command execution and escape capability, high privileged shell can be obtained as following:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/sudo_sql.png?raw=true)

Proof file:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/proof_txt.png?raw=true)
