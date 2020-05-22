# Threat Mitigation Strategies: Observations and Recommendations

**James Tubberville | January 25, 2018 | Tweet This Post: [:fa-twitter:](https://twitter.com/intent/tweet?url=http://threatexpress.com/blogs/2018/threat-mitigation-strategies-observations-recommendations/&text=Threat Mitigation Strategies - Part 1)**

_Full disclosure: This post is heavy on text. Much of the content is very broad and uses simplified examples. There are literally thousands of extremely cool and interesting ways to limit threat activity; however, I've decided to simplify and focus on those that could have the most significant impact with relatively easy implementation. Enjoy!_

![][1]

## Topic

While much of the world talks of protecting against an Advanced Persistent Threat (APT), in reality nearly all organizations and networks have an extremely hard time protecting against basic (or dare I say novice?) threats. I've been wanting to write a full white paper on the topic, but can't seem to find the time. Rather, I've decided to summarize my experience into a short series. The first in this series provides an introduction divided into three categories: general problem sets, observations, and recommendations. Follow-on post in the series will provide the technical detail (or "how to") for each of the recommendations.

## Background

Over the years my team has performed numerous evaluations against a variety of networks. These evaluations attempted to extend beyond the simple enumeration of potential vulnerabilities (i.e. patches, updates and compliance measures) by reviewing the actions of real-world cyber based threats and attacks. Each assisted in determining the true risk associated with actions performed by a knowledgeable and determined threat. Each evaluation focused on these realistic risk profiles rather than focusing on ephemeral vulnerabilities.

## Threat Synopsis

For those unfamiliar with threat operations, I think it is important to annotate the simplified set of threat actions commonly performed in a network prior to identification of problem sets, observations and recommendations.

> So, what does an example attack path look like?

A threat typically gains access to an externally facing system or service (commonly in a DMZ) that is, in most instances, managed by the internal domain (not a true DMZ). The second method of access involves targeting internal client workstations by phishing, web drive-by, or some other form of social engineering.

Once a threat has gained initial access, they leverage various lateral movement techniques to traverse the network away from the initial foothold. At this stage, a threat commonly establishes a method for command and control (C2) and persistence. C2 is simply the influence a threat has over a system to which access has been achieved. Persistence is simply a method for re-establishing or regaining access to C2. The established C2 and continued lateral movement enables the discovery of additional systems, interesting files, and potential paths to a target. The target is the information, system, person or process for which the threat is attempting to access. The threat re-evaluates each pivot through the network looking for these items and for methods of privilege escalation.

In real-world scenarios, this stage is when the threat finds elevated account credentials stored in a file or pulls tokens and credentials from memory; however, there are also numerous methods for leveraging applications and services to gain elevated access. Threats repeat this process until privileges have been escalated to that of a Domain Administrator (DA) or higher.

Once escalation is achieved, the threat most often targets a server, commonly the Domain Controller (DC). The DC communicates with and controls virtually everything within a windows based network. At this stage, the threat often has access to the target and can perform information collection and impacts as desired. In short, it's usually game over for the target.

Although this simplification identifies a Windows based network. It is also important to understand that access to a server, DC, or directory services may not be a requirement for access or impact to the target; however, it is more often than not a major enabler.

This synopsis simply demonstrates that most threat attack paths follow the same principles of __getting in__, __staying in__ and __acting__ regardless of the tools, techniques, and procedures (TTPs), or motivators.

## Problem Sets

As IT and security professionals, we must understand that "security" isn't what we should strive towards. Our purpose is to enable the objectives, functions, sustainment and success of the businesses and systems we support. Rather than forcing the concepts of "security", we should be identifying and communicating how our efforts support those basic business requirements and provide solutions to existing (and potential) problems to business success. In this article, I'm focusing on those security problems in which most IT and security staff directly influence. Although every organization has it's own unique set of problems, there is a clear commonality that all lead to four root causes.

!!! Tip "Consider This"
    Anyone has the ability to influence any aspect of the organization regardless of their position!

### Compliance does not equate to security

Given the general construct of how a threat's actions might leverage a network's architecture, simply meeting compliance requirements does little to enable the prevention or detection of threat actions. Across the board, compliance has been set as the bar of achievement when, in reality, compliance is the absolute minimum set of controls, policies and procedures that should be enforced. Don't misunderstand the concept. Compliance is absolutely a requirement and does much for the general security posture of a system or network. However, I've tested hundreds of systems and networks that (at least on paper) were fully compliant with their required standard, but failed to adequately protect the business and associated functions/information.

### Partial implementation of security controls enable a threat

Of the compliance measures employed, many are only partially implemented. One example observed in every effort to date are remote management capabilities. Most Windows Firewall requirements state unsolicited inbound connections must be blocked; however, in each evaluation all hosts tested were able to send and receive connections to/from other devices on the network. Although a firewall was installed and active, it allowed connections via multiple ports, protocols and services (PPS). While this is a single example, it emphasizes the methods in which compliance measures are only partially implemented.

### Tools are only Enablers

Another commonality across the board is an over reliance on tools to perform prevention and detection activities. Our industry dedicates large amounts of valuable resources to the development or purchase of systems and software (tools) that provide little value in the overall security of a network. Many of these tools have been in use or development for multiple years and have undergone numerous reviews; however, few have been successful in thwarting real-world threats. In fact, many of the tools deployed to date have been easily bypassed, detected or leveraged by knowledgeable threats. Tools are enablers. They provide a cognizant human with the information required to make an intelligent decision.

### Policies and Procedural Nightmares

Cumbersome policies and procedures elongate the process for implementing timely and effective defensive mitigations. All interviewed system, network and defensive staff identified longstanding issues with receiving approval to implement change **and** the timeliness of any approvals received. This concern has been relayed throughout the industry for years. If policy and procedures are primary inhibitors to the successful defense of our networks, policy and procedures must be modified to accommodate the need.

If detailed, the number of existing problem sets, vulnerabilities, and operational requirements far exceed any realistic ability to read, digest and act in a timely manner. The four problem sets listed above are of high importance as they are the foundation to all other sets. Each organization must begin addressing methods for limiting a threat's actions without increasing complexity, impacting the way in which systems and networks operate by design (user work-flow), or chasing ephemeral vulnerabilities. I'm left asking myself, why would we (the IT and security community) continue down the same ineffective paths, but continuously expect different results?

While meeting compliance requirements does have an extremely valuable effect on security, the next section provides recommendations that would benefit any organization far more.

Each of the observations and recommendations are the result of many, many efforts. The recommendations can be applied to any and all networks. Some networks will have exceptions; however, these are exceptions (not the status quo) and should be handled as such.

## Client-to-client communication

Clients rarely need to communicate amongst themselves. Over a roughly eighteen-year period and hundreds of various networks, less than a handful of architectures have had requirements for client-to-client communication (most due to application design failures/features).

### Observations

Of the systems and networks evaluated in recent years, none have required client-to-client communications. In fact, most have already implemented some type of host-based firewall. Yet in every network evaluated to date, all have been configured to allow client-to-client communication. Often the systems, network and defensive teams were unaware that such communications were allowed. In other instances administrative functions were identified as reasons for allowing communication.

__Example:__ During review, each network staff identifies that host-based firewalls have been implemented; however, initiating a connection to other clients using multiple ports and protocols has always been successful. Most often the staff cite requirements for system and network administration using Server Message Block (SMB), Remote Desktop Protocol (RDP) or another Remote Administration Tool (RAT). In several instances, security tools were also identified as reasoning for allowing client-to-client communications.

!!! Note
    There are multiple methods of allowing communications for administrative purposes only when required and should never be allowed perpetually.

### Recommendation: Prevent client-to-client communication

Simply implement and configure host and network based firewalls, IPTables, Access Control Lists (ACLs), etc. Leverage any and all capabilities of the network and organization. Preventing these communications limits a threat's ability to move freely throughout the network, reduces the likelihood of privileged account discovery, forces an increase in time and effort (more activities and artifacts), and therefore can increase the defender's ability to detect.

!!! Note
    Effective configuration of host based firewalls requires a thorough understanding of what network traffic should occur (what does normal look like?).

* * *

## Server-to-client communication

Most client-server designs require a client to request information from a server. Experience has provided few instances where a server should initiate communications to a client.

### Observations

Of the networks evaluated, none have required server-to-client communications. Yet in every network evaluated to date, all have been configured to allow server-to-client communication. A common threat action is to leverage a server's ability to communicate with clients or segments to move through a network. This often allows the threat to access targets or bridge network segments even when segmentation has been properly implemented.

### Recommendation: Prevent server-to-client communication

Assuming the network has prevented client-to-client communications, the only option a threat has is to attempt access to a server. Given this scenario, it is more than feasible to limit a server's ability to initiate communications with a client. This recommendation limits the threat's ability to move from workstation, to a server and back to another workstation. When connections to clients are attempted, those should stand out as indicators of malicious activity.

The most common IT staff concern with this implementation is malfunctioning or broken clients. This is a perfect example of where security implementations assist with the overall health of the network. If a client cannot initiate communications with the server, the client has other issues. This should be cause for investigation and correction rather than simply forcing connections from the server.

Another common concern is the ability to "push" software, updates, etc. from the server. This is another instance where best practices are not being followed. A client should always request from a server. If deploying software or updates, the client should be notified when communicating with the server (via policy, configurations, etc.) and pull the respective requirements.

!!! Note
    In this context, a server is a functional role rather than a type of device.

* * *

## Outbound Server Communications

With very few exceptions, servers should never call outside the network.

### Observations

Of the networks evaluated, all have had servers that allow communication with external (non-organizational) systems. This communication allows a threat to exfiltrate data directly from a server in which it has gained access. It also allows data restricted to certain network segments to be moved through a server and out of the network, often without detection.

### Recommendation: Block outbound server communications

There are few instances where a server needs to communicate with a system external to the network. These are exceptions and should be managed to allow only connections to the required external asset or IP and allow only the use of required ports and protocols. All other outbound communications from servers should be blocked. This implementation combined with the limits between clients and server-to-client exponentially increases the difficulty of lateral movement and command and control.

??? Question "Should your internal Domain Controller manage the server in the DMZ?"
    Of course not, but how many organization effectively control communication paths?

* * *

## Cached administrative credentials

Cached credential discovery is a common and primary method in which threats escalate privileges. Cached credentials are simply credentials temporarily stored for use by the system in which they reside. When administrative access for the current activity or session ends, the cached credential is no longer required.

### Observations

Of the networks evaluated, all have had cached administrative credentials present. These credentials are stored in memory when system and network administrators perform maintenance functions, when helpdesk personnel perform user support and when a tool is used to perform an automated task. This is a common problem on virtually all networks and the reason why a threat will leverage this functionality.

### Recommendation: Clear cached administrative credentials

Clearing credentials is relatively easy to do, yet is not often done. A few simple registry changes and requiring administrators to reboot (mainly workstations/clients) after using elevated accounts is a great step forward in limiting cached credentials. Also, forcing the use of Remote Desktop Credential Guard and Restricted Admin (see client-to-client above) has proven to be helpful in limitations; however, depending upon function, there may still be cached credentials present. It is recommended to always reboot after administrative functions.

!!! Note
    There are also several methods for injecting invalid credentials into memory for use as indicators. These HoneyTokens can be used as indicators of malicious activity.

* * *

## KRBTGT (Domain Kerberos Account)

By now most have heard of Golden Tickets (GT) and Silver Tickets (ST) created via the domain KRBTGT (Domain Kerberos) account's NTLM hash. These tickets can be valid for extremely long periods of time and allow access to domain resources even after administrative credentials have been changed.

### Observations

Although many security professionals understand the GT/ST concept, most standard IT staff either don't know or are unclear on how they work. Many of the organizations evaluated have never reset the KRBTGT account. Of the few that have, many only reset once. This first reset does change the credential; however, the initial reset also creates a "backup". Due to this functionality, the KRBTGT account must be reset twice to flush old credentials completely. Only after the second reset are existing Golden and Silver Tickets rendered useless.

### Recommendation: Reset the KRBTGT Account

Reset the KRBTGT account twice within a limited time-frame (36-48 hours apart is recommended) followed by the changing of all administrative credentials. These resets limit a threat's ability to maintain access after credential changes. The administrative credential change is highly recommended and should be required. If the threat has a valid GT they have obtained valid credentials. A new Golden Ticket can be created after the KRBTGT reset if credentials have not been changed (defeating the purpose of the KRBTGT reset). This process should be completed periodically (no less frequently than quarterly).

!!! Note
    Anyone using assets not on the network during the resets (traveling, out of office, etc.) will likely need help authenticating when reconnecting.

* * *

## Sensitive Items

Sensitive items include credentials, configuration files, Privacy of Information Act (PIA) data, Intellectual Property, anything close-hold or critical to business operations, etc.

### Observations

In every network evaluated, multiple instances of sensitive items were discovered. Items were found in many different locations to include organizational file shares, personal file shares, workstation directories, server directories, organizational websites and often on external (non-organizational) websites. More often than not, they are available to anyone with access to the network. These items provide the threat either the information for the target or the information required to obtain access to the target.

### Recommendation: Perform a sensitive items review

Perform frequent search and discovery activities for critical items stored across the network and network systems.  With the exception of credential storage, there are legitimate reasons for storing information such as configurations, diagrams, business information, etc. on the network. These need special focus to determine where they are stored, who has access and if they have any authenticators or credentials.

Challenge: Perform a string search for "pass", "assw", "pwd", "key", and "Type 7" on the network. You may be amazed at what is discovered.

* * *

## Ports, Protocols, and Services

Ports, protocols and services (PPS) are simply the technical means by which networks communicate.

### Observations

In every network evaluated, PPS were not limited to only those required. This applies to internal as much as external communications. Many organizations rely on firewalls to limit specific ports and protocols from external sources; however, they have limited controls on what PPS traverse the internal network. Even when internal firewalls are in place, traffic is often not restricted appropriately.

### Recommendation: Block and Disable non-required ports, protocols, and services (PPS)

Both internal and external systems and network devices should block PPS that aren't required for the network. Limit PPS to only what is required for each specific system. Think of this as "PPS white-listing". Does the network have a need for port 5900 to traverse the entire network? Or is there a need for port 5900 to a specific system? Does the network really need IPX/SPX, WPAD, LLMNR, and NetBIOS enabled? Controlling PPS limits a threat's range of capabilities and increases chances of detection.

!!! Note
    Firewalls (network or host based) are listed above as an easy example. Network based firewalls are simply traffic control devices that allow ingress and egress traffic based upon configuration. Host based firewalls do the same for individual hosts.

* * *

## Accounts and privileges

Accounts, group memberships, and privileges are primary enablers for most threat actions. Effective management and control greatly limits a threat's ability to execute within a network.

### Observations

Many organizations have user accounts with some level of elevated access, administrative accounts that administer multiple resource types, and groups with specific permissions nested within other groups with higher level permissions. Each of these enable a threat to freely escalate privileges to a level required to meet their objective.

!!! Tip "Consider this Concept"
    A threat has the ability to elevate a standard user to one of privileged access, elevate a privileged access account to local administrator, and/or elevate local administrator to domain administrator. If a threat has the ability to escalate a standard user account to that of DA, so does every other user on the network.

### Recommendation 1: Implement separation of accounts and privileges

Ensure separation of user, privileged access, and administrator accounts. Also ensure administrative accounts can only administer within its area of responsibility. System administrators should only administer systems and not have access to servers. Server administrators should only be able to administer servers and not have access to workstations. Domain administrators should not have access to administer servers or workstations.

Users should be limited to only what is required to perform daily tasks. Standard users often do not require elevated privileges on a daily basis. In rare scenarios where a user needs elevation often, require the use of a secondary account with only the access required and no external communications ability. Likewise, administrators shouldn't be using elevated accounts for daily tasks. _As a general rule all elevated accounts should be restricted from external communications (including internet and email)._

Also, consider having separate dedicated administrative systems with no email client, Internet browser, timecard access, document editing, any external communication, etc.

### Recommendation 2: Ensure group permissions are appropriately identified and mapped.

This recommendation has multiple applications; however, the main focus is nested groups and permissions. Nesting is a common problem in nearly every windows based-network in existence. Is it easier to troubleshoot permissions or give a user membership to a group to solve the problem? We've all been there.

!!! Tip "Consider this Concept"
    Group 3 has domain access. Group 2 has server access. Group 1 has workstation access. Group 0 are domain users in a specific division. If a member of Group 0 is assigned to Group 1 due to an elevation requirement, the chances of that user being able to escalate to domain administrator (Group 3) are high. This occurs simply because at least one member of Group 1 is likely a member of Group 2, and at least one member of Group 2 is likely a member of Group 3. It may require a bit of work, but these are the paths and nested permissions a threat will leverage to gain elevated access.

### Recommendation 3: Implement Microsoft Local Administrator Password Solution (LAPS)

LAPS provides automated local administrator account management for every computer in Active Directory. A client-side component generates a random password, updates the LAPS password on the Active Directory computer account, and sets the password locally. LAPS configuration is managed through Group Policy which provides the values for password complexity, password length, local account name for password change, password change frequency, etc.

### Recommendation 4: Rudimentary *nix Two Factor Authentication (2FA)

Many organizations have issues with credential reuse and implementation of Two Factor Authentication (2FA) in *nix based systems especially in off-line or closed networks. A very rudimentary but simple implementation of 2FA is the use of ssh key-files. The user generates a key-file that requires a password for use. The system administrator configures the system to require a key and password. The user now must use the password protected key-file to connect and the system password to complete authentication.

* * *

## Account and Event Activity

Account and event activity should be major factors in identifying potential issues or threats within a network. Unfortunately, these are often logged but rarely monitored effectively.

### Observations

Account and event activity collection is commonly identified as a compliance item and treated as a box to be checked. Multiple organizations have successfully configured logging and event forwarding and have alerts to match each event. Yet a common issue discovered in every organization to date is the unreasonable number of notifications or alerts received. Defensive staff are unable to follow every thread to a root cause due to time constraints and the vast number of alerts received. If a dedicated defensive team is unable to run every alert to ground, the alerts, logging, and collection has not been appropriately configured and tuned.

### Recommendation 1: Monitor login failures and successes

Short and simple. Multiple fails followed by a success indicates bad things. Many organizations focus on the failures and only respond when a target number of failures occur (i.e. three failed attempts per account or 300 failed attempts total).

!!! Tip "Consider this Concept"
    A threat has a password discovered via open source intelligence. The account is unknown; however, the password file has a recent date. The threat performs one validation per account for all accounts on the network (or Outlook Web Access or external SharePoint Portal). After twenty attempts one account has the same password and successfully authenticates. This action met neither of the conditions for alerting. Would this action be identified?

### Recommendation 2: Consider implementing a second instance or dashboard (or properly tuning the primary)

Given that most organizations have a compliance requirement to log all events, it is unreasonable to discard all incoming data. It is feasible to tune the primary or a second instance, dashboard, etc. to look specifically for the indicators as described above.

__Example:__ The network has been configured to prevent client-to-client communications. If client-to-client communications are attempted, an alert provides notification.

!!! Note:
    The example action should occur for the eight or ten actions common to most threats. Eight or ten possible scenarios are much easier to monitor and maintain _and_ provide a realistic view of potential threats (outsider or insider) within the network.

* * *

### Application Whitelisting

Application Whitelisting is the process of identifying approved software, allowing only those applications to run on a system, and blocking all others.

### Observations

Application Whitelisting is extremely useful in securing a network; however, for any organization with a larger footprint, dispersed locations and a diverse set of business requirements; it can be cumbersome to configure and maintain. In addition, many Application Whitelisting tools and techniques have been bypassed or leveraged to execute malicious code and security researchers continue to discover new ways of doing so. Application Whitelisting provides some value to the overall security of a network, but isn't the silver bullet everyone expects. Combined with other recommendations Application Whitelisting provides an exponential increase in time and difficulty to a threat.

### Recommendation: Application Whitelisting

Implement Application Whitelisting only after all of the prior recommendations have been implemented. An interim strategy (until Application Whitelisting can be fully implemented) may be to prevent standard user execution of specific applications such as: arp, at, certutil, cscript, cmd, dsquery, hostname, ipconfig, msbuild, nbtstat, net, netsh, netstat, nslookup, ntdsutil, pcalua, ping, powershell, psexec, reg, regasm, regedit, regedt32, regsvr32, regsvcs, rundll32, set, sc, schtasks, systeminfo, tasklist, tracert, whoami, wmic, wscript, wsmprovhost, etc.

??? Question "Do standard users normally run any of the preceding commands? Should they?"
    Most users do not use these commands. If they do, why?

* * *

Most organizations have historically focused on prevention (which is why we consistently see networks with a harder exterior and soft chewy center). While prevention is a huge concern, complete protection will never be possible. Although preventative in nature, the major benefit of the listed recommendations is relative ease of detection. Each activity performed outside the baseline should stand out as indicators of malicious activity.

My closing recommendation is for all organizations and security professionals to adopt the concept of _"Assumed Breach"_. An Assumed Breach mentality accepts that a network is currently, or will eventually be, compromised. Prepare your networks and business functions as if there's a known or impending threat to the network. I'll expand more on this in future posts.

??? Question "If a standard user was given administrative credentials while sitting at their workstation, what could they do?"
    What did you come up with?
    Should a user be able to perform those actions?

* * *

Refer to [Part 2](http://threatexpress.com/blogs/2018/threat-mitigation-strategies-technical-recommendations-and-info-part-2/) for detailed technical implementation.


[1]: /img/20180125_132744_attack.png

  
