# Task 1: Introduction to OWASP Top 10 

## Overview
This task introduces the OWASP Top 10 vulnerabilities, providing a structured breakdown of each vulnerability, including their definitions, how they occur, and methods for exploitation. The room aims to bridge theory with practical application through interactive challenges.
This box can be found [here](https://tryhackme.com/r/room/owasptop10) 
### OWASP Top 10 Vulnerabilities Covered:
1. Injection
2. Broken Authentication
3. Sensitive Data Exposure
4. XML External Entity (XXE)
5. Broken Access Control
6. Security Misconfiguration
7. Cross-site Scripting (XSS)
8. Insecure Deserialization
9. Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring

## Learning Objectives
- Understand the fundamental vulnerabilities outlined in the OWASP Top 10.
- Learn how each vulnerability manifests and why they are critical.
- Gain hands-on experience through practical challenges designed for beginners.

This room is tailored for individuals new to cybersecurity, assuming no prior knowledge, and aims to equip participants with foundational skills in identifying, understanding, and mitigating common web application security risks.


# Task 2:
Connect to the machine: I use OpenVPN


# Task 3: Injection 

## Overview

Injection flaws are prevalent vulnerabilities in web applications, stemming from user-controlled input being interpreted as commands or parameters by the application. This can lead to severe security risks depending on the technology stack and how inputs are handled.

### Common Types of Injection Attacks

1. **SQL Injection**: Occurs when user input is injected into SQL queries, allowing attackers to manipulate database operations.
   
2. **Command Injection**: Involves injecting user input into system commands, enabling attackers to execute arbitrary commands on application servers.

### Potential Risks of Successful Injection Attacks

- **Database Access**: Attackers can access, modify, or delete sensitive information stored in databases.
- **System Command Execution**: Allows execution of unauthorized system commands, compromising server integrity and enabling further attacks.

### Mitigation Strategies

To mitigate injection vulnerabilities, developers should implement robust defenses:

- **Use of Allow Lists**: Compare input against a list of safe characters or patterns. Only process input marked as safe.
  
- **Input Sanitization**: Remove or neutralize dangerous characters from input before processing.
  
- **Library Usage**: Utilize libraries designed to handle input validation and sanitization automatically, reducing manual error.

Injection attacks underscore the importance of secure coding practices and thorough input validation to protect against unauthorized data access and system compromise.


# Task 4: OS Command Injection

## Overview

Command Injection is a critical web vulnerability where server-side code, such as PHP, makes system calls on the hosting machine. This flaw allows attackers to manipulate these calls to execute arbitrary operating system commands on the server. While some commands might be benign (e.g., `whoami` or file reading), command injection can escalate to more malicious actions, such as spawning a reverse shell, granting full control over the server.

### Potential Risks of Command Injection

- **Execution of Arbitrary Commands**: Attackers can execute commands as the user running the web server, potentially compromising system integrity.
  
- **Reverse Shell**: By exploiting command injection, attackers can establish a reverse shell, gaining interactive command-line access to the server.
  
- **System Enumeration and Pivoting**: Once access is gained, attackers can enumerate the system, pivot to other machines, and escalate privileges within the network.

### Testing for Command Injection

To test for command injection vulnerabilities:

1. **Input Validation**: Input fields susceptible to user input should be thoroughly validated and sanitized.
   
2. **Payload Testing**: Inject common command injection payloads such as `;ls`, `;id`, or variations that might execute commands or spawn shells.
   
3. **Error Messages**: Observe if error messages or unexpected behaviors indicate command execution or system calls.

### Mitigation Strategies

- **Input Sanitization**: Filter and validate all user-supplied input to prevent unauthorized commands.
  
- **Least Privilege**: Ensure web server processes run with minimal privileges to limit the impact of successful command injections.
  
- **Use of Safe APIs**: Avoid making system calls directly from user input; utilize safe APIs that do not interpret input as executable commands.

Command Injection underscores the importance of secure coding practices and rigorous testing to safeguard web applications from unauthorized command execution and server compromise.











# Task 5: Command Injection Practical
## Introduction
Command Injection vulnerabilities allow attackers to execute arbitrary system commands on a server by manipulating input data. In this practical exercise, we explore Active Command Injection, where the server's response to system commands can be directly observed in the HTML output, making it easier for attackers to exploit.

Understanding Active Command Injection
Active Command Injection differs from Blind Command Injection in that it allows the attacker to see the output of the system command directly in the HTML response. This can be achieved through various HTML elements that display the output returned by injected commands.

### Scenario
EvilCorp inadvertently exposed a web-based shell to the internet, containing a Command Injection vulnerability. Despite being in early development, this shell allows attackers to execute arbitrary commands on the server and view the results in real-time.

EvilShell (evilshell.php) Code Example
php
Copy code
<?php
if (isset($_GET['commandString'])) {
    $command_string = $_GET['commandString'];
    
    try {
        passthru($command_string);
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
?>
Checks if the parameter "commandString" is set.
Retrieves the value passed into the input field.
Uses passthru($command_string) to execute the command and directly output the result to the browser.
Catches any exceptions thrown during execution.
Ways to Detect Active Command Injection
Detection of Active Command Injection revolves around observing the server's response to injected commands within the HTML output. The use of functions like passthru() directly exposes the command's output, aiding in detection and exploitation.

### Commands to Try
Linux
whoami
id
ifconfig or ip addr
uname -a
ps -ef
Windows
whoami
ver
ipconfig
tasklist
netstat -an
Practical Exercise
To complete the questions below, navigate to http://MACHINE_IP/evilshell.php and execute the provided commands.

### Questions and Answers
What strange text file is in the website root directory?

Answer: drpepper.txt


### How many non-root/non-service/non-daemon users are there?

#### Answer: 0

### What user is this app running as?

#### Answer: www-data

### What is the user's shell set as?

#### Answer: /usr/sbin/nologin

### What version of Ubuntu is running?

#### Answer: 18.04.4

### Print out the MOTD. What favorite beverage is shown?

#### Answer: Dr Pepper








# Task 6: Broken Authentication
## Introduction
Authentication and session management are critical aspects of web applications, ensuring that users are who they claim to be and maintaining their logged-in state securely. However, flaws in these mechanisms can lead to serious security vulnerabilities, allowing attackers to gain unauthorized access to user accounts and sensitive data.

Understanding Broken Authentication
Broken Authentication refers to vulnerabilities in authentication and session management processes that can be exploited by attackers. Common vulnerabilities include weak passwords, predictable session cookies, and insufficient brute force protection.

### Common Flaws in Authentication Mechanisms
Brute Force Attacks:

Attackers attempt multiple username and password combinations to gain unauthorized access.
Use of Weak Credentials:

Applications allowing weak passwords like "password1" make it easier for attackers to guess credentials without brute force.
Weak Session Cookies:

Predictable or easily guessable session cookies can be manipulated by attackers to impersonate legitimate users.
Mitigation Strategies
Various strategies can mitigate Broken Authentication vulnerabilities:

Strong Password Policy:
Enforce complex password requirements to resist brute force attacks.
Account Lockout:
Automatically lock user accounts after a certain number of failed login attempts to prevent brute force attacks.
Multi-Factor Authentication (MFA):
Require users to authenticate using multiple factors (e.g., password and a one-time code sent to their mobile device), enhancing security.
Practical Measures
Understanding and implementing these strategies can significantly improve the security posture of web applications, protecting user accounts and sensitive data from unauthorized access.






# Task 7: Logic Flaw in Authentication
Introduction
In this example, we'll explore a logic flaw within an authentication mechanism that allows for re-registration of an existing user, potentially granting unauthorized access to sensitive information.

Understanding the Vulnerability
Developers often overlook input sanitization in user registration processes, leading to vulnerabilities like re-registration of existing usernames with slight modifications. This oversight can allow attackers to gain access to privileged accounts by exploiting logic flaws.

Exploiting the Vulnerability
Scenario:
Suppose there is an existing user "admin" with privileged access.
Exploitation:
Attempt to register a new user with the username " admin" (note the leading space).
Submit other required information (email, password) and complete the registration.
Despite the space, the system registers a new user with similar privileges as the original "admin".
Practical Demonstration
To observe this vulnerability in action:

Navigate to http://MACHINE_IP:8888.
Attempt to register a username "darren". You'll be notified that the user already exists.
Register a new user with the username " darren" (space before "darren").
Log in with this new account to access the content associated with "darren", including the flag.
Results
Flag Found in Darren's Account: fe86079416a21a3c99937fea8874b667
Attempt to Access Arthur's Account: No answer needed, but the flag found is d9ac0f7db4fda460ac3edeb75d75e16e.
This demonstrates how a simple logic flaw in authentication can lead to significant security vulnerabilities, emphasizing the importance of thorough input validation and security testing in application development.








# Task 8: Sensitive Data Exposure (Introduction)
Introduction
Sensitive Data Exposure occurs when a web application inadvertently reveals sensitive information. This can include customer data like names, dates of birth, financial information, as well as technical data such as usernames and passwords. Vulnerabilities in web applications can lead to this exposure, ranging from simple misconfigurations to more complex attacks like Man-in-the-Middle (MitM), where attackers intercept unencrypted or weakly encrypted data.

Task Description
Deploy the provided machine and read through the supporting material as it boots up.

Instructions
Deploy the Machine: Start the virtual machine provided for this task.

Review Supporting Material: As the machine boots up, review any provided materials or instructions related to Sensitive Data Exposure.

Questions
Read the introduction to Sensitive Data Exposure and deploy the machine.

No answer needed.

If you need further modifications or additional tasks, please let me know













# Task 9: Sensitive Data Exposure (Supporting Material 1)
SQLite Databases and Sensitive Data Exposure
Introduction
Sensitive Data Exposure can occur when databases, including flat-file databases like SQLite, are stored in locations accessible to users via a web application. This scenario poses a significant security risk as attackers can potentially download and query these databases, gaining access to sensitive information stored within them.

Key Points
Database Storage: Flat-file databases, such as SQLite, are stored as single files on the computer's disk. If these files are stored within the root directory of a web application, they can be accessed and downloaded by users.

SQLite Basics: SQLite databases are interacted with using tools like sqlite3, which allows querying directly from the command line. This tool is commonly available in environments like Kali Linux.

Querying SQLite Databases: Once a SQLite database is downloaded, it can be accessed and queried using commands like .tables to list tables and SELECT * FROM <table_name> to retrieve data from specific tables.

Practical Example
Suppose we have downloaded a SQLite database named example.db:

bash
Copy code
sqlite3 example.db
.tables
PRAGMA table_info(customers);
SELECT * FROM customers;
This sequence of commands lists tables, displays table information, and dumps data from the customers table, revealing columns such as custID, custName, creditCard, and hashed passwords.

Conclusion
Understanding how SQLite databases are managed and accessed is crucial in identifying and mitigating vulnerabilities related to Sensitive Data Exposure in web applications.

Questions
Read and understand the supporting material on SQLite Databases.

No answer needed.











# Task 10: Cracking Password Hashes
Cracking Weak Password Hashes with Crackstation
Introduction
Cracking password hashes is a critical step in assessing the security of a system, especially when dealing with weak hash algorithms like MD5. In this task, we'll use Crackstation, an online tool capable of efficiently cracking weak password hashes using a large wordlist.

Key Points
Hash Cracking Tools: Kali Linux includes various tools for hash cracking, but for simplicity, we'll use Crackstation, an online platform that specializes in cracking weak hashes.

Hash Type: The password hashes we'll crack are weak MD5 hashes. Crackstation excels in cracking such hashes efficiently.

Using Crackstation: Navigate to the Crackstation website and paste the MD5 hash you want to crack into the interface. Solve the Captcha and click "Crack Hashes". If successful, Crackstation will reveal the plaintext password associated with the hash.

Practical Example
Suppose we have a MD5 hash 5f4dcc3b5aa765d61d8327deb882cf99 from the previous task. We paste this hash into Crackstation, solve the Captcha, and click "Crack Hashes". The result shows that the password corresponding to this hash is "password".

Considerations
Wordlist Dependency: Crackstation uses a massive wordlist for hash cracking. If a password is not in the wordlist, Crackstation may not be able to crack the hash.

Hash Security: If Crackstation fails to crack a hash, it may indicate that the hash is designed to resist cracking attempts, possibly using a more secure hashing algorithm or a stronger salted hash.

Questions
Read the supporting material about cracking hashes.

No answer needed.











# Task 11: Practical Application - Accessing Sensitive Data and Admin Account
Step 1: Explore the Webapp
Directory with Sensitive Data
Directory Mentioned: /assets
File Containing Sensitive Data
File: webapp.db
Step 2: Accessing Sensitive Data
Password Hash of Admin User
Password Hash: 6eea9b7ef19179a06954edd0f6c05ceb
Step 3: Cracking the Hash
Admin's Plaintext Password
Plaintext Password: qwertyuiop
Step 4: Login as Admin

Flag: THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}








# Task 12: XML External Entity (XXE) Attack
Introduction
An XML External Entity (XXE) attack is a vulnerability that exploits XML parsers to interact with backend systems and potentially retrieve sensitive information or perform malicious actions like Server-Side Request Forgery (SSRF) or remote code execution.

Task Description
Objective: Deploy and understand an XXE vulnerability in a web application.

Steps Taken
Understanding XXE: XXE vulnerabilities arise when an application processes XML input from untrusted sources without proper validation. Attackers can exploit this to read files, perform SSRF attacks, or execute commands.

Types of XXE Attacks:

In-Band XXE: Provides an immediate response to the attacker’s payload.
Out-of-Band (OOB) XXE: Requires the attacker to reflect the output of their payload to another location for retrieval.
Deployment and Exploration:

Deployed the vulnerable machine associated with the task.
Explored the application to identify the XXE vulnerability.
Demonstrated how an XXE payload can be crafted to retrieve sensitive files or execute commands on the server.
Conclusion
XXE vulnerabilities highlight the importance of secure XML parsing and input validation. Properly sanitizing XML inputs and disabling external entity references unless absolutely necessary are critical to mitigating XXE attacks.








# Task 13: Understanding XML and XXE
XML Basics
XML (eXtensible Markup Language):

XML is a markup language used for encoding documents in a format that is both human-readable and machine-readable.
It allows for platform-independent and programming language-independent data storage and transportation.
XML documents can be validated using Document Type Definitions (DTD) or XML Schema to ensure syntactic correctness.
It facilitates data sharing between different systems without requiring conversion.
XML Syntax:

XML Prolog: Optional header specifying XML version and encoding (<?xml version="1.0" encoding="UTF-8"?>).
Root Element: Every XML document must have a root element encapsulating all other elements.
Case Sensitivity: XML tags and attributes are case sensitive (<to> must be closed with </to>).
Attributes in XML:

Attributes provide additional metadata within XML tags (<text category="message">...</text>).
XML Prolog and Validation
XML Prolog: Specifies XML version and encoding, not compulsory but considered good practice. (Answer: no)
Validation: XML documents can be validated against a schema (DTD or XML Schema) to ensure structure and data integrity. (Answer: yes)







# Task 14: Understanding DTD in XML
Document Type Definition (DTD)
DTD (Document Type Definition):

DTD defines the structure and legal elements/attributes of an XML document.
It ensures XML documents conform to specified rules for validation.
Example Usage
Given a DTD file note.dtd:

xml
Copy code
<!DOCTYPE note [
    <!ELEMENT note (to, from, heading, body)>
    <!ELEMENT to (#PCDATA)>
    <!ELEMENT from (#PCDATA)>
    <!ELEMENT heading (#PCDATA)>
    <!ELEMENT body (#PCDATA)>
]>
Using the DTD to validate an XML document:

xml
Copy code
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
    <to>falcon</to>
    <from>feast</from>
    <heading>hacking</heading>
    <body>XXE attack</body>
</note>
Understanding DTD Terms
!DOCTYPE note: Defines the root element of the XML document as note. (Answer: !DOCTYPE)
!ELEMENT note: Specifies that the note element must contain to, from, heading, and body elements. (Answer: !ELEMENT)
!ELEMENT to: Defines the to element as containing parseable character data (#PCDATA). (Answer: !ELEMENT)
!ELEMENT from: Defines the from element similarly. (Answer: !ELEMENT)
!ELEMENT heading: Defines the heading element similarly. (Answer: !ELEMENT)
!ELEMENT body: Defines the body element similarly. (Answer: !ELEMENT)
Key Terms in DTD:

!ELEMENT: Defines a new element in the XML structure.
!DOCTYPE: Specifies the root element of the XML document.
!ENTITY: Defines a new entity within the XML document.







# Task 15: Understanding and Crafting XXE Payloads
Introduction to XXE Payloads
An XML External Entity (XXE) attack allows an attacker to interfere with an application’s processing of XML data. By exploiting features of XML parsers, attackers can execute various harmful actions, including reading local files.

Example XXE Payloads
Simple XXE Payload:
This payload demonstrates how to define an ENTITY and use it within the XML document.

xml
Copy code
<!DOCTYPE replace [
    <!ENTITY name "feast">
]>
<userInfo>
    <firstName>falcon</firstName>
    <lastName>&name;</lastName>
</userInfo>
Explanation:
!DOCTYPE replace: Declares a document type definition.
<!ENTITY name "feast">: Defines an entity named name with the value "feast".
<lastName>&name;</lastName>: Uses the name entity in the XML data.
This payload simply replaces the entity reference &name; with the value "feast".

File Reading XXE Payload:
This payload shows how to use the SYSTEM keyword to read a file from the server.

xml
Copy code
<?xml version="1.0"?>
<!DOCTYPE root [
    <!ENTITY read SYSTEM 'file:///etc/passwd'>
]>
<root>&read;</root>
Explanation:
!DOCTYPE root: Declares a document type definition for the root element.
<!ENTITY read SYSTEM 'file:///etc/passwd'>: Defines an entity named read with a SYSTEM identifier that points to the /etc/passwd file.
<root>&read;</root>: Uses the read entity to include the contents of the /etc/passwd file within the XML document.
If the application is vulnerable to XXE, it would process the XML and display the contents of /etc/passwd.

Practical Usage
Try the payloads on a vulnerable website:

Simple Payload:
Inject the simple payload to see if the ENTITY replacement works correctly.
File Reading Payload:
Inject the file reading payload to check if the application reveals the contents of the specified file.
Note: If the application does not display the file contents, it might be due to:

The file does not exist.
The application has protections in place against XXE.
The XML parser used by the application does not support external entities.
Conclusion
Understanding and crafting XXE payloads is crucial for identifying and exploiting XXE vulnerabilities. By defining and using ENTITY references, attackers can manipulate XML data to extract sensitive information from the server.








# Task 16: XML External Entity - Exploiting
Introduction to Exploiting XXE Vulnerabilities
In this task, we explore how to exploit XXE vulnerabilities using practical examples and payloads. This involves understanding how ENTITY references can be manipulated to read files or perform other malicious activities.

Example XXE Payloads
Simple ENTITY Replacement:
This payload demonstrates how to define an ENTITY and use it within the XML document to replace a value.

xml
Copy code
<!DOCTYPE replace [
    <!ENTITY name "feast">
]>
<userInfo>
    <firstName>falcon</firstName>
    <lastName>&name;</lastName>
</userInfo>
Explanation:
!DOCTYPE replace: Declares a document type definition.
<!ENTITY name "feast">: Defines an entity named name with the value "feast".
<lastName>&name;</lastName>: Uses the name entity in the XML data, which gets replaced by "feast".
Reading Local Files:
This payload shows how to use the SYSTEM keyword to read a file from the server.

xml
Copy code
<?xml version="1.0"?>
<!DOCTYPE root [
    <!ENTITY read SYSTEM 'file:///etc/passwd'>
]>
<root>&read;</root>
Explanation:
!DOCTYPE root: Declares a document type definition for the root element.
<!ENTITY read SYSTEM 'file:///etc/passwd'>: Defines an entity named read with a SYSTEM identifier that points to the /etc/passwd file.
<root>&read;</root>: Uses the read entity to include the contents of the /etc/passwd file within the XML document.
If the application is vulnerable to XXE, it would process the XML and display the contents of /etc/passwd.

Hands-On Example
Try the payloads on a vulnerable website:

Simple ENTITY Replacement:
Inject the simple payload to see if the ENTITY replacement works correctly.
Reading Local Files:
Inject the file reading payload to check if the application reveals the contents of the specified file.
Note: If the application does not display the file contents, it might be due to:

The file does not exist.
The application has protections in place against XXE.
The XML parser used by the application does not support external entities.
Additional Exercises
Displaying a Name Using XXE:

Payload:

xml
Copy code
<!DOCTYPE replace [
    <!ENTITY name "feast">
]>
<userInfo>
    <firstName>falcon</firstName>
    <lastName>&name;</lastName>
</userInfo>
Result:

The website successfully displays the name as "falcon feast".
Reading /etc/passwd Using XXE:

Payload:

xml
Copy code
<?xml version="1.0"?>
<!DOCTYPE root [
    <!ENTITY read SYSTEM 'file:///etc/passwd'>
]>
<root>&read;</root>
Result:

The website successfully reads and displays the contents of /etc/passwd.
Additional Questions and Answers
Try to display your own name using any payload:
No answer needed
See if you can read the /etc/passwd:
No answer needed
What is the name of the user in /etc/passwd?
Answer: falcon
Where is falcon's SSH key located?
Answer: /home/falcon/.ssh/id_rsa
What are the first 18 characters for falcon's private key?
Answer: MIIEogIBAAKCAQEA7
Conclusion
Exploiting XXE vulnerabilities involves manipulating ENTITY references in XML documents. By understanding and crafting specific payloads, attackers can extract sensitive information from the server, showcasing the importance of proper XML handling and security measures.







# Task 17: Broken Access Control
Introduction to Broken Access Control
Broken access control occurs when a website's access controls are improperly implemented, allowing unauthorized users to access protected pages and functionalities. This can result in severe consequences, such as unauthorized access to sensitive information or the ability to perform actions reserved for privileged users.

Impact of Broken Access Control
When a regular visitor can access protected pages, it can lead to:

Viewing sensitive information
Accessing unauthorized functionalities
OWASP Attack Scenarios
OWASP provides several examples of broken access control vulnerabilities:

Scenario #1: SQL Injection via Unverified Data

Example code:
java
Copy code
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery();
Description:
An attacker modifies the acct parameter in the browser to access any account number they desire.
URL: http://example.com/app/accountInfo?acct=notmyacct
Scenario #2: Force Browsing to Restricted URLs

Description:
An attacker force browses to target URLs that require admin rights for access. If an unauthenticated user or a non-admin user can access these pages, it indicates broken access control.
URLs:
http://example.com/app/getappInfo
http://example.com/app/admin_getappInfo
Understanding the Risks
Broken access control allows attackers to bypass authorization mechanisms, enabling them to:

View sensitive data
Perform actions as privileged users
Summary
Ensuring proper implementation of access controls is crucial for maintaining the security of web applications. Regularly testing for broken access control vulnerabilities and enforcing strict authorization checks can help mitigate these risks.

Questions and Answers
Read and understand how broken access control works:
Answer: No answer needed





# Task 18: Broken Access Control (IDOR Challenge)
Introduction to IDOR (Insecure Direct Object Reference)
Insecure Direct Object Reference (IDOR) is a type of access control vulnerability that occurs when an application provides direct access to objects based on user-supplied input without proper authorization checks. This can lead to unauthorized access to sensitive information or functionalities.

Understanding IDOR with an Example
Consider the following scenario:

A user logs into their bank account and is redirected to a URL such as https://example.com/bank?account_number=1234.
This page displays the user's bank details based on the account_number parameter.
Potential Issue:

An attacker could change the account_number parameter to another value, such as 1235, and if the application does not properly verify access, the attacker could access another user's bank details.
IDOR Challenge Steps
Read and Understand How IDOR Works:

Answer: No answer needed
Deploy the Machine:

Go to http://MACHINE_IP
Login with the username noot and the password test1234.
Look at Other Users' Notes:

Question: What is the flag?
Answer: flag{fivefourthree}










# Task 19: Security Misconfiguration
Introduction to Security Misconfiguration
Security misconfigurations occur when security settings are not correctly implemented, leaving systems vulnerable to attacks. These can include:

Poorly configured permissions on cloud services, like S3 buckets.
Unnecessary features enabled, such as services, pages, accounts, or privileges.
Default accounts with unchanged passwords.
Overly detailed error messages that reveal system information.
Lack of HTTP security headers or excessive detail in the Server: HTTP header.
These vulnerabilities can lead to more serious issues, such as access to sensitive data or the execution of commands on admin pages.

Importance of Changing Default Passwords
One common example of security misconfiguration is the use of default passwords. These are often found in embedded and Internet of Things (IoT) devices and can lead to significant security breaches if not changed.

Example Incident:
In October 2016, Dyn, a DNS provider, was taken offline by a DDoS attack primarily executed using IoT devices infected with the Mirai malware. The malware exploited devices with default credentials, logging into exposed telnet services with a list of 63 username/password pairs. This attack caused major websites and services like Amazon, Twitter, and Netflix to go offline.

Practical Example
This task involves exploiting a security misconfiguration in a VM showcasing an OWASP Top 10 vulnerability. Specifically, the focus is on default passwords.

Challenge Steps
Deploy the VM:

Answer: No answer needed
Hack into the Webapp and Find the Flag:

Question: What is the flag?
Answer: thm{4b9513968fd564a87b28aa1f9d672e17}






# Task 20: Cross-site Scripting (XSS)
Introduction to XSS
Cross-site scripting (XSS) is a security vulnerability typically found in web applications. It allows an attacker to execute malicious scripts on a victim's machine. A web application is vulnerable to XSS if it uses unsanitized user input. XSS can occur in JavaScript, VBScript, Flash, and CSS. There are three main types of cross-site scripting:

Stored XSS: The most dangerous type of XSS, where a malicious string originates from the website’s database. This happens when user input is not sanitized before being stored in the database.
Reflected XSS: The malicious payload is part of the victim's request to the website, and the website includes this payload in its response.
DOM-Based XSS: This occurs when the DOM (Document Object Model) of a web page is manipulated, and the payload is executed on the client side without sending the payload to the server.
For more XSS explanations and exercises, check out the XSS room on TryHackMe.

Common XSS Payloads
Some common XSS payloads include:

Popups: <script>alert("Hello World")</script> creates a popup message.
Writing HTML: document.write can override the website's HTML to add your own content.
XSS Keylogger: Capture keystrokes to log sensitive information.
Port scanning: Perform local port scanning using JavaScript.
XSS-Payloads.com is a resource for XSS-related payloads, tools, documentation, and more.

XSS Challenge
The VM attached to this task showcases DOM-Based, Reflected, and Stored XSS. Deploy the machine and exploit each type.

Challenge Steps
Deploy the VM:

Answer: No answer needed
Navigate to the Reflected XSS page and craft a payload for a popup saying "Hello":

Question: What is the payload?
Answer: ThereIsMoreToXSSThanYouThink
Craft a reflected XSS payload for a popup with your machine's IP address:

Question: What is the payload?
Answer: ReflectiveXss4TheWin
Navigate to the Stored XSS page, create an account, and insert HTML in a comment:

Question: What is the payload?
Answer: HTML_T4gs
Create an alert popup box with your document cookies on the Stored XSS page:

Question: What is the payload?
Answer: W3LL_D0N3_LVL2
Change "XSS Playground" to "I am a hacker" by adding a comment using JavaScript:

Question: What is the payload?
Answer: websites_can_be_easily_defaced_with_xss








# Task 21: Insecure Deserialization
Introduction to Insecure Deserialization
Insecure Deserialization is a vulnerability that occurs when untrusted data is used to abuse the logic of an application. This can lead to anything from Denial of Service (DoS) to Remote Code Execution (RCE), which an attacker can use to gain a foothold in a pentesting scenario.

This vulnerability leverages the legitimate serialization and deserialization process used by web applications. Serialization is the process of converting an object into a format that can be easily stored or transmitted, and deserialization is the reverse process. When deserialization processes untrusted data, it can execute malicious code.

OWASP Ranking
OWASP ranks this vulnerability as 8 out of 10 due to the following reasons:

Low exploitability: This vulnerability is often case-by-case, requiring attackers to have a good understanding of the inner workings of the Target of Evaluation (ToE).
Exploit danger: The impact of the exploit depends on the attacker's skill and the value of the data exposed. For example, causing a DoS will vary in impact depending on the organization's infrastructure.
Vulnerable Applications
Any application that stores or fetches data without validations or integrity checks can be vulnerable. Examples include:

E-Commerce Sites
Forums
APIs
Application Runtimes (Tomcat, Jenkins, JBoss, etc.)
Challenge Steps
Deploy the VM:

Answer: No answer needed
Identify the developer of the Tomcat application:

Question: Who developed the Tomcat application?
Answer: The Apache Software Foundation
Identify the type of attack that crashes services using insecure deserialization:

Question: What type of attack that crashes services can be performed with insecure deserialization?
Answer: Denial of Service





# Task 22: Insecure Deserialization - Objects
Understanding Objects in Object-Oriented Programming (OOP)
In object-oriented programming, objects are a key element, composed of:

State: Represents the data or attributes of the object.
Behaviour: Represents the functions or methods that the object can perform.
Objects allow for more efficient and reusable code, reducing the need to write repetitive lines. For example, a lamp can be an object with:

State: Different types of bulbs.
Behaviour: Being either on or off.
Instead of writing code for every possible bulb type and on/off state, methods can be used to change the state and behaviour of the lamp.

Challenge Steps
Identify the correct term for the given statement:
Question: If a dog was sleeping, would this be:
A) A State
B) A Behaviour
Answer: B) A Behaviour






# Task 23: Insecure Deserialization - De(Serialization)
Understanding Serialization and Deserialization
Serialization is the process of converting complex objects used in programming into simpler formats that are compatible for transmitting between systems or networks for further processing or storage.

Deserialization is the reverse process, where the serialized information is converted back into its complex form, which the application can understand.

Example:
Imagine a tourist who doesn't speak your language asks for directions to a landmark. You draw a map because pictures can cross language barriers. The tourist then uses the map to find the landmark. In this analogy:

Drawing the map is serialization.
Using the map to find the landmark is deserialization.
Practical Application:
When a program has a password "password123" that needs to be stored in a database on another system:

The password is serialized into a simpler format (e.g., binary) to travel across the network.
Upon reaching the database, the serialized data is deserialized back into "password123" for storage.
Serialization allows data to be easily transmitted and stored, while deserialization allows the data to be used in its original form.

Vulnerability:
Insecure deserialization occurs when data from an untrusted source is executed without proper filtering or input validation. The system assumes the data is trustworthy and executes it, which can lead to security vulnerabilities.

Answer the question:
Question: What is the name of the base-2 formatting that data is sent across a network as?

Answer: Binary








# Task 24: Insecure Deserialization - Cookies
Understanding Cookies
Cookies are small pieces of data created by websites and stored on a user's computer. They serve various purposes, such as storing user-specific behaviors (like items in a shopping cart) or session IDs for authentication.

Cookie Attributes
Cookies have several attributes that define their behavior:

Cookie Name: The name of the cookie.
Cookie Value: The data stored in the cookie, which can be plaintext or encoded.
Secure Only: If set, the cookie will only be sent over HTTPS connections.
Expiry: Specifies when the cookie will expire and be removed from the browser.
Path: Specifies the URL path for which the cookie is valid.
Creating Cookies in Flask
In Python's Flask framework, cookies can be set easily using code like this:

python
Copy code
from flask import Flask, make_response, request
import datetime

app = Flask(__name__)

@app.route('/setcookie', methods=['GET', 'POST'])
def setcookie():
    if request.method == 'POST':
        timestamp = datetime.datetime.now()
        resp = make_response('Cookie set!')
        resp.set_cookie('registrationTimestamp', str(timestamp))
        return resp
    return 'Method Not Allowed'

if __name__ == '__main__':
    app.run(debug=True)
This code snippet sets a cookie named registrationTimestamp with the current timestamp when a user visits /setcookie.

Answering the Questions
Question: If a cookie had the path of webapp.com/login, what would the URL that the user has to visit be?
Answer: webapp.com/login
Question: What is the acronym for the web technology that Secure cookies work over?
Answer: HTTPS







# Task 25 Write-Up: Insecure Deserialization - Cookies Practical
Objective
The objective of this task is to explore and manipulate cookies within a web application to gain access to hidden features, specifically changing user permissions from "user" to "admin" using insecure deserialization.

Steps Taken
Accessing the Instance:

Connected to the provided VPN and navigated to http://MACHINE_IP in the web browser.
Creating an Account:

Created a new account within the web application.
Viewing Profile Details:

After account creation, accessed the profile page to view personal details.
Inspecting Cookies:

Right-clicked on the page, opened the browser's developer tools (specifically the "Inspect Element" option), and navigated to the "Storage" tab to inspect cookies.
Finding the First Flag:

Identified a cookie containing the first flag (THM{good_old_base64_huh}), either in plaintext or base64 encoded format.
Modifying userType Cookie:

Located the userType cookie, which controls user permissions (e.g., "user" or "admin").
Edited the value of userType from "user" to "admin" by double-clicking on its value and entering "admin".
Accessing Admin Dashboard:

Navigated to http://MACHINE_IP/admin after modifying the userType cookie.
Accessed the admin dashboard, which revealed the second flag (THM{heres_the_admin_flag}).
Conclusion
This task demonstrated how cookies can store important session information such as user permissions (userType). By manipulating this cookie, specifically changing it from "user" to "admin", access to otherwise restricted areas like the admin dashboard was achieved. This exercise highlights the risks associated with insecure deserialization in web applications, where trusting user-controlled data without proper validation can lead to privilege escalation.
















# Task 26: Insecure Deserialization - Code Execution
Setup
Modify Cookie Value:

Change the value of the userType cookie from "admin" to "user" and navigate to http://MACHINE_IP/myprofile.
Accessing Vulnerable URLs:

Click on the URL in "Exchange your vim" and "Provide your feedback!" as instructed.
Vulnerability Description
The vulnerability arises from insecure deserialization in a Flask application. When a user visits the feedback form after modifying the cookie, the application decodes and deserializes the cookie using pickle.loads, assuming the data is trustworthy. This assumption can be exploited by malicious users to execute arbitrary Python code.

Exploit Steps
Setting Up Netcat Listener:

Prepare a netcat listener on your Kali machine to receive a reverse shell connection.
Creating Exploit Script:

Create a Python script (e.g., rce.py) to craft a payload that will be deserialized by the application.
Modify the script provided (e.g., pickleme.py) to include your TryHackMe VPN IP address where indicated.
Generating Payload:

Execute rce.py to generate a base64-encoded payload containing the command to spawn a reverse shell.
Injecting Payload:

Copy the generated payload (enclosed in single quotes) and paste it as the value of the encodedPayload cookie in your browser's developer tools.
Activating Payload:

Refresh the vulnerable page. The application will decode and deserialize the payload, executing the injected command.
Gaining Access:

If successful, your netcat listener will receive a connection from the vulnerable machine, providing you with a remote shell.
Verification
Check the output on your netcat listener to confirm successful execution of the payload.
Look for flag.txt or other relevant files to retrieve required information (e.g., 4a69a7ff9fd68).
Conclusion
This exercise demonstrates the severity of insecure deserialization vulnerabilities, where improper handling of serialized data can lead to remote code execution. Mitigations involve careful validation of serialized inputs and avoiding deserialization of untrusted data.













# Task 27: Components With Known Vulnerabilities - Intro
Introduction
During penetration testing engagements, it's not uncommon to discover that organizations are using software with well-documented vulnerabilities. These vulnerabilities can range from outdated versions of applications to specific weaknesses that have been publicly disclosed and exploited.

Example Scenario
Consider a company that has neglected to update their WordPress installation, leaving it at version 4.6. Using tools like wpscan, a penetration tester quickly identifies that WordPress 4.6 is susceptible to an unauthenticated remote code execution (RCE) exploit. A simple search reveals that there exists an exploit for this vulnerability on exploit-db, a common repository for such exploits.

Implications
The presence of a known vulnerability in widely used software like WordPress underscores the potential risks organizations face. Attackers can leverage these vulnerabilities with minimal effort, often using pre-existing exploits readily available online. This ease of exploitation significantly increases the likelihood of successful attacks targeting systems that have not been kept up to date.

OWASP Rating
OWASP rates the prevalence of vulnerabilities stemming from outdated software versions and known exploits as high (severity 3). This rating reflects the ease with which organizations can inadvertently expose themselves to security risks by failing to apply updates promptly.

Conclusion
Maintaining up-to-date software and promptly applying security patches are critical steps in mitigating the risks associated with components featuring known vulnerabilities. By doing so, organizations can reduce their attack surface and enhance overall cybersecurity resilience.








# Task 28: Components With Known Vulnerabilities - Exploit
Introduction
When conducting penetration testing, discovering and exploiting known vulnerabilities can often be straightforward due to existing exploit scripts and resources like exploit-db. This task explores exploiting a vulnerability in the Nostromo web server as an example.

Nostromo 1.9.6
Identifying the Software:

The target server is running Nostromo version 1.9.6, identified from its default page. This version information is crucial for searching for corresponding exploits.
Using exploit-db:

Exploit-db is a valuable resource where exploits for various software vulnerabilities are cataloged. Searching for "Nostromo 1.9.6" on exploit-db yields an exploit script designed for this specific version.
Downloading and Testing the Exploit:

Download the exploit script and attempt to execute it. It's important to note that sometimes initial attempts may fail due to minor issues like coding errors or missing configurations.
Understanding the Script:

A basic understanding of the programming language used in the exploit script (e.g., Python, Bash) is beneficial. This knowledge helps in troubleshooting and making necessary modifications to ensure the exploit runs correctly.
Achieving Remote Code Execution (RCE):

After addressing any issues (e.g., uncommented lines), re-run the exploit script. Upon successful execution, you gain RCE capabilities on the target system.
Conclusion:

Utilizing known vulnerabilities reduces the effort required during penetration testing. Exploit scripts typically provide clear instructions on usage parameters, simplifying the exploitation process.
Key Takeaways
Ease of Exploitation: Exploiting known vulnerabilities often involves leveraging pre-existing exploit scripts, which provide clear instructions on usage.
Resource Utilization: Platforms like exploit-db streamline the process by providing a repository of exploits for a wide range of software vulnerabilities.
Ongoing Learning: While exploiting vulnerabilities may seem straightforward with the right tools, understanding the underlying mechanisms enhances effectiveness and adaptability.






# Task 29 [Components With Known Vulnerabilities-Lab]
The first thing to do to exploit a web application is to perform some sort of reconnaissance about it, eg. what kind of platform is used to build this web application and the technologies it uses. I found out that it's using PHP and MYSQL. Also, seems to be developed with projectworlds.


secondly based on the hint: “You know it's a bookstore application, you should check for recent unauthenticated bookstore app rce’s.” I made a search query


We find the payload we are looking for: https://www.exploit-db.com/exploits/47887

Download the payload with the command wget https://www.exploit-db.com/download/47887 and run it against your target.

Then run wc -C /etc/passwd to obtain the number of characters in the file.


Ans: 1611








# Task 30 [Severity 10] Insufficient Logging and Monitoring]
What IP address is the attacker using?

Observing logs shows the attacker’s IP is 49.99.13.16

What kind of attack is being carried out?

Seems like a brute force attack to try out a combination of usernames and passwords based on the requests.















