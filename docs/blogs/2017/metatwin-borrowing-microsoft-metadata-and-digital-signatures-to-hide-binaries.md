
# Borrowing Microsoft MetaData and Signatures to Hide Binary Payloads

**Joe Vest | October 9, 2017 | Tweet This Post: [:fa-twitter:](https://twitter.com/intent/tweet?url=http://threatexpress.com/blogs/2017/10/metatwin-borrowing-microsoft-metadata-and-digital-signatures-to-hide-binaries/&text=Borrowing Microsoft MetaData and Signatures to Hide Binary Payloads)**

![][1]

## Overview

A [twitter post][2] by Casey Smith [(@subtee)][3] inspired me to update a tool written by Andrew Chiles [(@andrewchiles)][4] and I a few years ago.

During a Red Team engagement, it can be helpful to blend in with the environment as best as possible when forced to operate from disk. Operating in memory is great, but in many situations or scenarios, you must resort to binaries on disk.  A technique I've used with great success is to modify a binary's resource information (metadata). This includes fields such as file icons, version, description, product name, copyright, etc.  When defeating security defenses or managing IOCs ([See my SANS Breaking Red webcast series for more on IOC management][5]), a threat will often attempt to trick or deceive an analyst. Making files blend into the environment can cause an analyst to treat malicious behavior as trusted.  If a binary says is it from Microsoft, it must be…

This is where [MetaTwin][6] comes into play.  This is rewritten to not only modify a binary's metadata, but also add a digital signature as recently described by @subtee and @mattifestation.

## How MetaTwin Works

1. MetaTwin starts with a legitimate signed source binary, such as explorer.exe
2. Extracts the resources ([via ResourceHacker][7]) and digital signature information ([via SigThief][8])
3. Writes the captured data to a target binary

## Demo

In this example, I'm simply using a default meterpreter reverse_tcp binary.  Nothing special here, use any binary (.exe or .dll). Personally, we're huge fans of Cobalt Strike during real engagements.

![][9]

Before MetaTwin |  After MetaTwin
----------------|------
 ![][10]        |  ![][11] 

As you can see, the file looks and feels like it could belong there.  Storing this in a location such as c:ProgramData... with a modified time stamp, **could** buy a Red Team operator a bit of time and support long(er) term persistence.

## Interesting Observations

### AntiVirus

Often simple modifications can cause defensive tools to react in different ways.  Of course AV is often not a show stopping defensive tool, but we were curious as to how AV handled a default Metasploit meterpreter binary when modified with MetaTwin.  No obfuscation other than the addition of metadata and digital signatures.  The results were interesting…

#### Default Reverse TCP Meterpreter Binary

![][12]

As expected, VirusTotal reported several hits

#### Metadata added to Reverse TCP Meterpreter Binary

![][13]

Interestingly, adding metadata alone reduced the AV detection rate.

#### Metadata and Digital Signature added to Reverse TCP Meterpreter Binary

![][14]

After adding a digital signature and the metadata, exposure dropped from 76% to 58%. This is important because we're not even trying to evade AV!

### SysInternals AutoRuns

In additions to Antivirus, you can see how default tool behavior responds to these modifications using SysInternals AutoRuns.

Using the modified binary, we created simple persistence mechanism using a scheduled task.  AutoRuns can be used to display this type of Windows persistence.  But… the modified binary is hidden by default.  Take a look…

## **AutoRuns Default Settings Hide the "Microsoft" scheduled task**

## ![][15]

**AutoRuns Default Options**

## ![][16]

**_Changing the Default Reveals the "Microsoft" scheduled task_**

## ![][17]

## **Takeaway**

Based on these observations, it's clear that some AV and EDR tools make poor assumptions based on file metadata and digital signatures that can make them less effective or confuse an inexperienced Blue Team member. Red Team operators can use this to their advantage  if forced to operate from disk in future engagements.

## Try MetaTwin Yourself

Get a copy here 

## Want to learn more about Red Teaming?

![Red Team Operation and Threat Emulation][18]

Check out the new SANS Red Team course written by MINIS' own Joe Vest and James Tubberville

SEC 564 Red Team Operation and Threat Emulation 

[1]: /img/metatwin.png
[2]: https://twitter.com/subTee/status/912769644473098240
[3]: https://twitter.com/subTee
[4]: https://twitter.com/AndrewChiles
[5]: https://www.youtube.com/watch?v=_JiGsFPYDMQ&t=969s
[6]: https://github.com/threatexpress/metatwin
[7]: http://angusj.com/resourcehacker/
[8]: https://github.com/secretsquirrel/SigThief
[9]: /img/metatwin.gif
[10]: /img/20171007_202524_revmet-722x1024.png
[11]: /img/after-1024x743.png
[12]: /img/plain_binary.png
[13]: /img/metadata_only.png
[14]: /img/metadata_signed.png
[15]: /img/autoruns_default.png
[16]: /img/autoruns_options.png
[17]: /img/autoruns_display.png
[18]: /img/sanslogo.png

  