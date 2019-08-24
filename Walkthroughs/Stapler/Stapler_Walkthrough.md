# **Vulnerable System** : 192.168.20.141 (Stapler)

**Operating System** : Ubuntu 16.04

**Kernel** : 4.4.0

**Vulnerability Exploited** : WordPress Plugin Advanced Video 1.0 - Local File Inclusion

**Proof of Concept Code** : [https://www.exploit-db.com/exploits/39646](https://www.exploit-db.com/exploits/39646)

**Vulnerability Explained** :  WordPress Plugin local file inclusion can be used by the attacker to gain access to confidential files, in this case /etc/passwd and WordPress configuration file.

**Vulnerability fix** : There is no current patches or fixes for this vulnerability.

**Severity** : **Medium**

**Privilege Escalation Vulnerability** : Administrative user&#39;s password is stored

**Privilege Escalation Vulnerability Explained:** Administrative user&#39;s password was found in a .bash\_history file of a low privilege user that could be read by anyone on the system.

**Vulnerability fix** : Implement strong permissions on user owned private files (such as chmod 400). Users should not share passwords with each other.

**Severity** : **High**

## Arp-scan

Discovering the vulnerable system with arp-scan -l:

![arp_scan)](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/Lin%20Enum.png?raw=true)

## nmap

Nmap all ports scan:

![nmap_allports](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/nmap_all_scan.png)

Nmap -sV -sC -A:

![nmap_sv_sc](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/nmap_sv_sc1.png)

-p specifies the ports to scan

-sV flag attempts to determine service and version information for given ports

-sC flag utilizes a default set of nmap scripts

## nikto

Nikto enumeration of port 80:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/nikto_80.png)

Nikto enumeration of port 12380:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/nikto_12380.png)

*Note: Nikto scans a web application for vulnerabilities.

## FTP

ftp enumeration:
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/ftp.png)

## SMB

SMB enumeration with smbclient:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/smb_L.png)

*Note: -L option lists SMB shares

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/smb_kathy.png)
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/smb_tmp.png)

## 666

Port 666 Enumeration with netcat (nc):

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/port_666.png)
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/port_666_zip.png)


## Port 12380

As a &quot;red.initech&quot; entry has been added to /etc/hosts on the kali machine.

Port 12380 enumeration with browser:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/browser_12380.png)

Robots.txt content:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/browser_12380_robots.png)

## WordPress

/blogblog/ directory presents us with WordPress style website:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wordpress.png)

Wp-scan is ran to find low hanging fruit, however it does not find anything interesting:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wpscan1.png)
-------------------------------------------------Snippet---------------------------------------------------
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wordpress2.png)

*Note: -e vt,vp options check for vulnerable themes and vulnerable plugins

Manual enumeration of WordPress plugins and themes, presents an interesting plugin called Advanced Video Embed – Embed Videos or Playlists:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wordpress_plugins.png)
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wordpress_plugins2.png)
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wordpress_plugins3.png)
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wordpress_plugins4.png)

As per readme.txt, the plugin&#39;s version is 1.0.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wordpress_advanced_video.png)

## Searchsploit

Searching exploit-db for suitable exploit

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/searchsploit_advanced.png)
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/searchsploit_advanced_p.png)
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/advanced_cp.png)

Reviewing the exploit and subbing the URL parameter, the default settings is to download wp-config.php:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/advanced_modify_url.png)

## Exploitation

As the exploit is ran, errors regarding SSL appear.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/advanced_exploit.png)


To work around the error, quick google search suggests importing SSL library and editing SSL context as shown below:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/advanced_exploit_error_fix.png)

After running the exploit again, change the file to /etc/passwd and run it again:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/advanced_modify_url.png)

When visiting the blog once more, notice that new entries were created (the exploit does not mention that or how it obtains the file):

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/jpeg_blog_entries.png)


These .jpeg files can be found in the wp-content upload folder (as can be seen per the multiple images being uploaded it took a little bit to figure out that this how the exploit worked):

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wp_uploads.png)


They can be then manually saved (Oh no he didn&#39;t just use GUI to download files):

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wp_uploads_save.png)
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wp_uploads_save2.png)



Change the file extensions to text:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/file%20extensions.png)


File.txt is wp-config.php:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/wp-config.png)


File2.txt is /etc/passwd:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/etc_passwd.png)


Clean up /etc/passwd (removing false and nologin):

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/etc_passwd_clean.png)


Create user list:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/userlist.png)

##Hydra
Use hydra to bruteforce SSH:

-e nsr option:
![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/hydra_nsr.png)


Password obtained from WordPress:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/hydra_wordpress.png)


Logging in in with Zoe&#39;s credentials:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/zoe_ssh.png)


## Privilege Escalation

### Enumerating (Manual way):

Determining users with administrative privileges:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/admin_priv_user.png)


Determining readable files in home directory:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/readalbe_home1.png)

---------------------------Snippet--------------------------

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/readalbe_home2.png)


Enumerating JKanode&#39;s bash\_history file:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/jkanode_bash_history.png)

Alternatively:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/jkanode_bash_history2.png)


### Enumerating (Automated Way):

LinEnum.sh, scripted by rebootuser, can be used to automate enumeration process. The script can be obtained from rebootuser&#39;s [GitHub](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh).

Although automated scripts might seem as an easier way, sometimes one can get lost in abundance of information it provides. Personally, enumerating manually have helped me just as many times as automatic scripts. Automatic scripts are more for the low hanging fruit in my opinion.

First the script has to be downloaded to the victim machine.

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/Lin%20Enum.png)

Once downloading and running it:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/Lin%20Enum2.png)

-------------------------------------------------------------Snippet-----------------------------------------------------------

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/Lin%20Enum3.png)

-------------------------------------------------------------Snippet-----------------------------------------------------------

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/Lin%20Enum4.png)


As per script&#39;s result it can be seen that &quot;peter&quot; is an admin user and that the possible password is JZQuyIN5.

Logging into Peter&#39;s account and changing root&#39;s password:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/peter.png)


Flag file:

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/flag.png)

