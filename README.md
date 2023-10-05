# Investigating with Splunk

## Desciption
Splunk is one of the leading SIEM solutions in the market that provides the ability to collect, analyze and correlate the network and machine logs in real-time. In this lab, I will use Splunk to investigate and answer questions about an attack.

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

Use the following search query: `index=main`

The results show that 12,256 events have been logged.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/27826692-1a40-448d-ac44-0040e9d46433" height="50%" width="50%"/>
</br>
</br>

**A1) 12,256 events**

### Q2) On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?

Use the following search query: `index=main EventID="4720"`
* The 4720 EventID indicates a new user account was created.

One event is returned in the results, and it shows the user **A1berto** was created on the **Micheal.Beaven** host.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/c2f1e999-37cf-4db5-94b6-14fbafffecb9" height="60%" width="60%"/>
</br>
</br>

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/2e0067fa-8859-45b8-a5e8-195d804c1c8f" height="30%" width="30%"/>
</br>
</br>

**A2) A1berto**
 	
### Q3) On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?

Use the following search query: `index=main Hostname="Micheal.Beaven" "A1berto"`

Check the **Category** field and you will see 5 valuess. Select **Registry object added or deleted (rule: RegistryEvent)** to add to query, and you will see 2 events in the results.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/8a7bb98b-8ffe-407c-ac77-f9bb273b2557" height="70%" width="70%"/>
</br>
</br>

Next to **Target Object** on the first event, you will see the path of the registry key that was modified.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/0dfd8b46-e90e-417f-a249-edae9782f3ad" height="60%" width="60%"/>
</br>
</br>

**A3) HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto**

### Q4) Examine the logs and identify the user that the adversary was trying to impersonate.

Go back to the first search query: `index=main`

Look at the **Users** field, and you will see a user named **Alberto**.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/c9caf99e-26a0-4c5d-bb5d-5bd98409f998" height="70%" width="70%"/>
</br>
</br>

**A4) Alberto**

### Q5) What is the command used to add a backdoor user from a remote computer?

Add **CommandLine** to selected fields.

There are 19 values in the CommandLine field. One of the values shows a command used to create the A1berto user.

<img src="" height="50%" width="50%"/>
</br>
</br>

**A5) C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1**

### Q6) How many times was the login attempt from the backdoor user observed during the investigation?

Use the following search query: `index=main “A1berto”`

Check the **Category** field to see if there is anything indicating a login. None of the values indicate an attempted login.

<img src="" height="50%" width="50%"/>
</br>
</br>

You can also check the EventID field. None of the EventIDs indicate a login for A1berto.

<img src="" height="50%" width="50%"/>
</br>
</br>

**A6) 0**

### Q7) What is the name of the infected host on which suspicious Powershell commands were executed?

Use the following search query: `index=main powershell`

Check the **Hostname** field, and you wil see **James.Browne** is the only hostname listed.

<img src="" height="50%" width="50%"/>
</br>
</br>

**A7) James.Browne**

### Q8) PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?

Use the following search query: `index=main PowerShell EventID=”4103”`
* The 4103 EventID indicates PowerShell logging enabled.

79 events are returned in the results.

<img src="" height="50%" width="50%"/>
</br>
</br>

**A8) 79**

### Q9) An encoded Powershell script from the infected host initiated a web request. What is the full URL?

Look at the full PowerShell command and you will see a long string of Base64 code.

<img src="" height="50%" width="50%"/>
</br>
</br>

Decode the string in **Terminal**, and examine the decoded information.

You will find what looks like the end of a URL and a strig of base64 code in front of it.

<img src="" height="50%" width="50%"/>
</br>
</br>

Decode the string to get the rest of the URL path.

<img src="" height="50%" width="50%"/>
</br>
</br>

**A9) hxxp[://]10[.]10[.]10[.]5/news[.]php**
