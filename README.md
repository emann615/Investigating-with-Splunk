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
* The 4720 event ID indicates a new user account was created.

One event is returned in the results, and it shows the user **A1berto** was created on the **Micheal.Beaven** host.

**A2) A1berto**
 	
Q3)
Query: index=main Hostname="Micheal.Beaven" "A1berto"
-	Add Category to selected fields.
o	5 values
o	Select Registry object added or deleted (rule: RegistryEvent) to add to query.
	2 events
	Next to Target Object you will see the path of the registry key that was added.
	HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto
A3) HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto

Q4)
Query: index=main
-	Add CommandLine to selected fields.
o	19 values
o	One value show to command used to create the A1berto user.
A4) C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1

Q5)
Query: index=main “A1berto”
-	Check the Category field to see if there is anything indicating a login.
o	There is not.
-	You can also check the EventID field.
o	There is no EventID indicating a login for A1berto.
A5) 0

Q6)
Query: index=main powershell
-	Check the Hotname field.
o	James.Browne is the only hostname.
A6) James.Browne

Q7)
Query: index=main PowerShell EventID=”4103”
-	4103 is the EventID for PowerShell logging enabled.
-	79 events are returned in the results.
A7) 79

Q8)
-	Look at the full PowerShell command.
-	There is a long string of Base64 code.
-	Decode the string in Terminal.
-	Examine the decoded information.
-	You will find what looks like the end of a URL and a strig of base64 code in front of it.
-	Decode the sting to get the rest of the URL path.
