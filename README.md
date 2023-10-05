# Investigating with Splunk

## Desciption
Snort is an open-source, rule-based Network Intrusion Detection and Prevention System (NIDS/NIPS) developed and maintained by Martin Roesch and the Cisco Talos team. In this lab, I will run through two scenariors using Snort to identify and block malicious network traffic.

## Table of Contents

   * [Languages and Utilities Used](#Languages-and-Utilities-Used)
   * [Environments Used](#Environments-Used)
   * [Scenario 1](Scenario-1)
   * [Scenario 2](Scenario-2)

## Languages and Utilities Used

* **Splunk** 

## Environments Used

* **Ubuntu 18.04.6 LTS**

## Walk-Through

**Q1) How many events were collected and Ingested in the index main?**

Use the following search query: `index=main`

The results show that 12,256 events have been logged.

**A1) 12,256 events**

**Q2) On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?**

Use the following search query: `index=main EventID="4720"`
* The 4720 EventID indicates a new user account was created.

One event is returned in the results, and it shows the user **A1berto** was created on the **Micheal.Beaven** host.

**A2) A1berto**
 	
**Q3) On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?**

Use the following search query: `index=main Hostname="Micheal.Beaven" "A1berto"`

Add **Category** to selected fields.

There are 5 values in the Category field. Select **Registry object added or deleted (rule: RegistryEvent)** to add to query, and you will see 2 events in the results.

Next to **Target Object** on the first event, you will see the path of the registry key that was modified.

**A3) HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto**

**Q4) Examine the logs and identify the user that the adversary was trying to impersonate.**

Go back to the first search query: `index=main`

Look at the Users field, and you will see a user named Alberto.

**A4) Alberto**

**Q5) What is the command used to add a backdoor user from a remote computer?**

Add **CommandLine** to selected fields.

There are 19 values in the CommandLine field. One of the values shows a command used to create the A1berto user.

**A5) C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1**

**Q6) How many times was the login attempt from the backdoor user observed during the investigation?**

Use the following search query: `index=main “A1berto”`

Check the Category field to see if there is anything indicating a login. None of the values indicate an attempted login.

You can also check the EventID field. None of the EventIDs indicate a login for A1berto.

**A6) 0**

**Q7) What is the name of the infected host on which suspicious Powershell commands were executed?**

Use the following search query: index=main powershell

Check the Hostname field, and you wil see James.Browne is the only hostname listed.

**A7) James.Browne**

**Q8) PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?**

Use the following search query: index=main PowerShell EventID=”4103”
* The 4103 EventID indicates PowerShell logging enabled.

79 events are returned in the results.

**A8) 79**

**Q9) An encoded Powershell script from the infected host initiated a web request. What is the full URL?**

Look at the full PowerShell command and you will see a long string of Base64 code.

Decode the string in **Terminal**, and examine the decoded information.

You will find what looks like the end of a URL and a strig of base64 code in front of it.

Decode the string to get the rest of the URL path.

**A9) hxxp[://]10[.]10[.]10[.]5/news[.]php**
