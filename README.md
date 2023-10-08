# Investigating with Splunk

## Desciption
Splunk is one of the leading SIEM solutions in the market that provides the ability to collect, analyze and correlate the network and machine logs in real-time. In this lab, I will run through a scenario and use Splunk to investigate a cyber attack.

## Table of Contents

   * [Languages and Utilities Used](#Languages-and-Utilities-Used)
   * [Environments Used](#Environments-Used)
   * [Walk-Through](#Walk-Through)

## Languages and Utilities Used

* **Splunk** 

## Environments Used

* **Ubuntu 18.04.6 LTS**

## Walk-Through

### Scenario

SOC Analyst Johny has observed some anomalous behaviours in the logs of a few windows machines. It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies.

### Q1) How many events were collected and Ingested in the index main?

To find the number of events logged in the index main I used the following search query: `index=main`

The results showed that 12,256 events have been logged.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/27826692-1a40-448d-ac44-0040e9d46433" height="50%" width="50%"/>
</br>
</br>

**A1) 12,256 events**

### Q2) On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?

I used the following search query: `index=main EventID="4720"`
* The 4720 EventID indicates a new user account was created.

One event was returned in the results, and it showed the user **A1berto** was created on the **Micheal.Beaven** host.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/c2f1e999-37cf-4db5-94b6-14fbafffecb9" height="60%" width="60%"/>
</br>
</br>

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/2e0067fa-8859-45b8-a5e8-195d804c1c8f" height="30%" width="30%"/>
</br>
</br>

**A2) A1berto**
 	
### Q3) On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?

I filtered to show only events from the Micheal.Beaven host containing the keyword A1berto using the following search query: `index=main Hostname="Micheal.Beaven" "A1berto"`

I checked the **Category** field and saw 5 values. I selected the **Registry object added or deleted (rule: RegistryEvent)** value to add it to the search query and found 2 events in the results.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/8a7bb98b-8ffe-407c-ac77-f9bb273b2557" height="70%" width="70%"/>
</br>
</br>

Next to **Target Object** on the first event, I saw the path of the registry key that was modified.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/0dfd8b46-e90e-417f-a249-edae9782f3ad" height="60%" width="60%"/>
</br>
</br>

**A3) HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto**

### Q4) Examine the logs and identify the user that the adversary was trying to impersonate.

I went back to the first search query: `index=main`

I looked at the **Users** field and saw a user named **Alberto** that the adversary was trying to impersonate with the A1berto user they created.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/c9caf99e-26a0-4c5d-bb5d-5bd98409f998" height="70%" width="70%"/>
</br>
</br>

**A4) Alberto**

### Q5) What is the command used to add a backdoor user from a remote computer?

First, I fitered for events containing the A1berto keyword using the following search query: `index=main "A1berto"`

Next, I added **CommandLine** to the selected fields.

There were 19 values in the CommandLine field. One of the values showed the command used to create the A1berto user.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/55b45463-2ae1-4897-87d4-5ea5804baea4" height="70%" width="70%"/>
</br>
</br>

**A5) C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1**

### Q6) How many times was the login attempt from the backdoor user observed during the investigation?

I checked the **Category** field to see if there was anything indicating a login. None of the values indicated a login for the A1berto user.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/af752c7c-edc1-4b3a-8eb5-7a9cec0111b4" height="70%" width="70%"/>
</br>
</br>

I also checked the **EventID** field. None of the EventIDs indicated a login for A1berto.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/f30fd23b-e3ca-4fc8-85b3-9103942660db" height="70%" width="70%"/>
</br>
</br>

**A6) 0**

### Q7) What is the name of the infected host on which suspicious Powershell commands were executed?

I filtered for events containing the powershell keyword using the following search query: `index=main powershell`

Next, I checked the **Hostname** field and saw **James.Browne** was the only hostname listed.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/75db1573-2157-4704-ab6e-d5a1f0ac1725" height="70%" width="70%"/>
</br>
</br>

**A7) James.Browne**

### Q8) PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?

I used the following search query: `index=main PowerShell EventID=”4103”`
* The 4103 EventID indicates PowerShell logging enabled.

79 events were returned in the results.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/10c40b00-7009-4003-96b1-8f6ff8398080" height="50%" width="50%"/>
</br>
</br>

**A8) 79**

### Q9) An encoded Powershell script from the infected host initiated a web request. What is the full URL?

I examined the full PowerShell command and saw a long string of Base64 code.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/f37cd481-4d8c-4667-9626-05fedb88d546" height="70%" width="70%"/>
</br>
</br>

I decoded the string in **Terminal** and examined the decoded information.

I found what looked like the end of a URL and a strig of Base64 code in front of it.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/cc7ff19c-b68f-4d13-af46-d8b3f90cd7da" height="70%" width="70%"/>
</br>
</br>

I decoded the Base64 string to get the rest of the URL.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/1721e76f-79ed-4280-8094-01d3a84dc8f2" height="70%" width="70%"/>
</br>
</br>

The full URL is **http://10.10.10.5/new.php**.

**A9) hxxp[://]10[.]10[.]10[.]5/news[.]php**
