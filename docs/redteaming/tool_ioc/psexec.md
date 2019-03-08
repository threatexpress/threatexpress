# PsExec.exe IOCs and Detection

PsExec.exe is a tool commonly used by system administrators, penetration testers, and threat actors. It is important to understand what indicators a tool may leave behind before using on a Red Team engagement.

This document highlights key IOCs generated when the SysInternals version of PsExec [SysInternals PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)is used. This is just only procedure of a larger set of techiques. Most variations of this technique share similar IOCs.

## MITRE TTP

[MITRE Technique T1035](https://attack.mitre.org/wiki/Technique/T1035)

| MITRE TTP     |              |
|---------------|--------------|
| __Tatic__     | Execution    |
| __Technique__ | Service Execution |
| __Procedure__ | Use PsExec.exe to execute commands on a remote Windows system |

## Category

Command Execution

## Description

Executes a command on a remote host.

## Example of Presumed Tool Use During an Attack

The tool is used to execute a remote command on hosts and servers in a domain.

## Tool Operation Overview 

| Item                   | Description |
|------------------------|------------------------------------------------------------------------------------------|
| OS                     | Windows                                                                                  |
| Belongs to Domain      | Not required                                                                             |  
| Rights                 | Standard User / Administrator                                                            |  
| Communication Protocol | - 88/tcp (when executing in a domain environment) - 135/tcp - 445/tcp - Random High Port |  

## Information Acquired from Log

__Standard Settings__

| | |
|-|-|
| Source host | - A registry value created when the PsExec License Agreement has been agreed to (registry). - Execution history (Prefetch)
| Destination Host | - The fact that the PSEXESVC service has been installed, started, and ended is recorded (system log). - Execution history (Prefetch) |

__Additional Settings__

| | |
|-|-|
| Source host | - The fact that the PsExec process was executed and that connection was made to the destination via the network, as well as the command name and argument for a remotely executed command are recorded (audit policy, Sysmon). | - A registry value created when the PsExec License Agreement has been agreed to (Sysmon). |
| Destination Host | - The fact that PSEXESVC.exe was created and accessed, and that connection was made from the source via the network, as well as the command name and argument for a remotely executed command are recorded (audit policy, Sysmon). |
| Packet Capture | - Transmission of PSEXESVC and its output file (-stdin, -stdout, -stderr) with SMB2. |

## Evidence That Can Be Confirmed When Execution is Successful

| | |
|-|-|
| Source Host      | The Event ID 4689 (A process has exited) indicating that psexec.exe was executed and has exited, was recorded in the event log "Security" with the execution result (return value) of "0x0". |
| Destination host | In the Event ID: 7045 of the event log "System", the fact that the PSEXESVC service was installed is recorded. |

## Main Information Recorded at Execution

### Source Host

__Event Log__

| Log                                  | Event ID | Task Category                                      | Event Details                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|--------------------------------------|----------|----------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Microsoft-Windows-Sysmon/Operational | 1        | Process Create (rule: ProcessCreate)               | **Process Create.** CommandLine:__ Command line of the execution command ([Path to Executable File] [Execution Command]) UtcTime:__ Process execution date and time (UTC) __ProcessGuid/ProcessId:__ Process ID __Image:__ Path to the executable file (path to the executable file) __User:__ Execute as user                                                                                                                                        |
| Microsoft-Windows-Sysmon/Operationa  | 3        | Network connection detected (rule: NetworkConnect) | **Network Connection Detected:** __Protocol:__ Protocol (tcp) __Image:__ Path to the executable file (System) __ProcessGuid/ProcessId:__ Process ID (4) __User:__ Execute as user (NT_AUTHORITY\SYSTEM) __SourceIp/SourceHostname/SourcePort:__ Source IP address/Host name/Port number (source host) __DestinationIp/DestinationHostname/DestinationPort:__ Destination IP address/Host name/Port number (destination ports: 135 and 445, high port) |
| Microsoft-Windows-Sysmon/Operationa  | 13       | Registry value set (rule: RegistryEvent)           | **Registry value set.** __Image:__ Path to the executable file (path to the tool) __ProcessGuid/ProcessId:__ Process ID __Details:__ Setting value written to the registry (DWORD: 0x00000001) __TargetObject:__ Registry value at the write destination (\REGISTRY\USER\[User SID]\SOFTWARE\Sysinternals\PsExec\EulaAccepted)                                                                                                                        |
| Security                             | 4689     | Process Termination                                | **A process has exited.** __Log Date and Time:__ Process terminated date and time (local time)Process Information > Exit Status:__ Process return value (0x0) __Subject > Security ID/Account Name/Account Domain:__ SID/Account name/Domain of the user who executed the tool __Process Information > Process Name:__ Path to the executable file (path to the tool)                                                                                 |

__Prefetch__

C:\Windows\Prefetch\[Executable File Name of Tool]-[RANDOM].pf

__Registry__

Registry entry

Key: HKEY_USERS\[User SID]\SOFTWARE\Sysinternals\PsExec\EulaAccepted
Value: 0x00000001

### Destination Host

| Log                                  | Event ID | Task Category                                      | Event Details                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|--------------------------------------|------|----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Security                             | 5145 | Detailed File Share                    | A network share object was checked to see whether the client can be granted the desired access. __Shared Information > Share Name:__ Share name (\\*\ADMIN$) __Subject > Security ID/Account Name/Account Domain:__ SID/Account name/Domain of the user who executed the tool __Shared Information > Share Path:__ Share path (\\??\C:\Windows) __Shared Information > Relative Target Name:__ Relative target name from the share path (PSEXESVC.exe) __Access Request Information > Access:__ Requested privileges (including WriteData or AddFile, and AppendData)     |
| Microsoft-Windows-Sysmon/Operational | 1    | Process Create (rule: ProcessCreate)   | Process Create. __ParentImage:__ Executable file of the parent process (C:\Windows\system32\services.exe) __CommandLine:__ Command line of the execution command __ParentCommandLine:__ Command line of the parent process (C:\Windows\system32\services.exe) __UtcTime:__ Process execution date and time (UTC) __ProcessGuid/ProcessId:__ Process IDUser: Execute as user (NT AUTHORITY\SYSTEM) __Image:__ Path to the executable file (C:\Windows\PSEXESVC.exe)                                                                                                             |
| System                               | 7045 | A service was installed in the system. | A service was installed. __Service start type:__ Operation of trigger that starts the service (demand start) __Service account:__ Executing account (LocalSystem) __Service type:__ Type of the service to be executed (user mode service) __Service Name:__ Name displayed in the service list (PSEXESVC) __Service File Name:__ Service executable file (%SystemRoot%\PSEXESVC.exe)                                                                                                                                                                                     |
| Security                             | 5145 | Detailed File Share                    | A network share object was checked to see whether the client can be granted the desired access. __Shared Information > Share Name:__ Share name (\\*\IPC$) __Subject > Security ID/Account Name/Account Domain:__ SID/Account name/Domain of the user who executed the tool __Shared Information > Relative Target Name:__ Relative target name from the share path (PSEXESVC-[Source Host Name]-[Source Process ID]-[stdin, stdout, stderr])                                                                                                                   |
| Microsoft-Windows-Sysmon/Operational | 1    | Process Create (rule: ProcessCreate)   | Process Create. __ParentProcessGuid/ParentProcessId:__ Process ID of the parent process __ParentImage:__ Executable file of the parent process (C:\Windows\PSEXESVC.exe) __Image:__ Path to the executable file (Path to the executable file that was executed by PsExec) __ParentCommandLine:__ Command line of the parent process (C:\Windows\PSEXESVC.exe)__UtcTime:__ Process execution date and time (UTC) __ProcessGuid/ProcessId:__ Process ID                                                                                                                         |
| System                               | 7036 | Service Control Manager                | The [Service Name] service entered the [Status] state. __Status:__ State after the transition (Stopped) __Service Name:__ Target service name (PSEXESVC)                                                                                                                                                                                                                                                                                                                                                                                                   |
| Security                             | 4689 | Process Termination                    | A process has exited. __Log Date and Time:__ Process terminated date and time (local time) __Process Information > Exit Status:__ Process return value (0x0) __Process Information > Process Name:__ Path to the executable file (C:\Windows\PSEXESVC.exe)                                                                                                                                                                                                                                                                                                      |
| Security                             | 4674 | Sensitive Privilege Use                | An operation was attempted on a privileged object. __Subject > Security ID/Account Name/Account Domain:__ SID/Account name/Domain of the user who executed the tool __Object > Object Name:__ Name of the object to be processed (PSEXESVC) __Object > Object Server:__ Service that executed the process (SC Manager) __Requested operation > Privileges:__ Requested privilege (DELETE) __Process Information > Process Name:__ Path to the executable file (C:\Windows\System32\services.exe) __Object > Object Type:__ Type of the object to be processed (SERVICE OBJECT) |
| Microsoft-Windows-Sysmon/Operational | 11   | File created (rule: FileCreate)        | File created. __Image:__ Path to the executable file (C:\Windows\System32\svchost.exe) __ProcessGuid/ProcessId:__ Process IDTarget __Filename:__ Created file (C:\Windows\Prefetch\PSEXECSVC.EXE-[Random Number].pf)Creation __UtcTime:__ File creation date and time (UTC)                                                                                                                                                                                                                                                                                          |

### USN Journal

|File Name	                | Process     |
|---------------------------|-------------|
| PSEXESVC.exe	            | FILE_CREATE |
| PSEXESVC.exe 	            | DATA_EXTEND+FILE_CREATE |
| PSEXESVC.exe	            | CLOSE+DATA_EXTEND+FILE_CREATE |
| PSEXESVC.EXE-[RANDOM].pf	| FILE_CREATE |
| PSEXESVC.EXE-[RANDOM].pf	| DATA_EXTEND+FILE_CREATE |
| PSEXESVC.EXE-[RANDOM].pf	| CLOSE+DATA_EXTEND+FILE_CREATE |
| PSEXESVC.exe	            | CLOSE+FILE_DELETE |

## Prefetch

`C:\Windows\Prefetch\PSEXESVC.EXE-[RANDOM].pf`

## Interesting Events

![](/images/psexec.png)

## References

JPCERT - Research Report Released: Detecting Lateral Movement through Tracking Event Logs [https://blog.jpcert.or.jp/2017/06/1-ae0d.html](https://blog.jpcert.or.jp/2017/06/1-ae0d.html)

MITRE ATT&CK - Technique T1035 [https://attack.mitre.org/wiki/Technique/T1035](https://attack.mitre.org/wiki/Technique/T1035)

JPCERT Tool Analysis Results [https://jpcertcc.github.io/ToolAnalysisResultSheet/](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

JPCERT Tool Analysis Results - PsExec [https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PsExec.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PsExec.htm)

