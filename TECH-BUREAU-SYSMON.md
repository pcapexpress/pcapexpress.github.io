---
layout: default
title: SYSMON
---
# TECH-BUREAU-SUPLIMENT
## THE SAGA OF SYSMON
### WHATS SHOWCASED:
<section>
  <ul class="hover-card"> 
    <li>
      <span class="text-data"><strong>DEFFENSE:</strong></span> The essential steps to kickstart the Sysmon logs
    </li>
  </ul>
</section>

### The Goal

This particular assignment was a challenge indeed, had had multiple issues with the alert sensitivity and the Sysmon config file, tried also rules from SOC Fortress but failed to configure the agent correctly and got a meriad of errors that became a nightmare to untangle… So I started from scratch and settled for a basic setup of using SwiftOnSecurity as the config file and just the inbuilt Wazuh Sysmon rules. The goal was to simply have the logs recording and funneling to the Wazuh manager and we even got some neat alerts out of it. So lets have a closer look.

## THE SETUP

![Agent-active.png](assets/images/tech-bureau/sysmon/Agent-active.png)

<small>“Agent-active.png”<small>

We have a TECH-BUREAU Windows Box booted up and connected to our Wazuh manager.<br>

## Sysmon-running.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Sysmon-running.png)

<small>“Sysmon-running.png”<small>

Sysmon is installed and running, the <span class="badge-data">fltmc</span> command confirms that the file monitoring is active.
However the next 2 steps are what make it all work.

## Wazuh-ossec.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Wazuh-ossec.png)

<small>“Wazuh-ossec.png”<small>

We need to configure teh <span class="badge-data">ossec.conf</span> file on the AGENT in our case thats the Windows VM.<br>
We can simply use the notepad to add the following bit of xml code.

<pre data-label="ossec.conf" style="--delay: 0s;"><code>
&lt;localfile&gt;
  &lt;location&gt;Microsoft-Windows-Sysmon<span class="orange"><strong>/Operational</strong></span>&lt;/location&gt;
  &lt;log_format&gt;<span class="orange"><strong>eventchannel</strong></span>&lt;/log_format&gt;
&lt;/localfile&gt;  
</code></pre>

The /Operational directory is where we want to pull our Sysmon generated logs.<br>
The eventchannel is what will be taking the logs in to Wazuh and interpreting them in <span class="badge-data">JSON</span> format<br>
Very digestible and doesnt requier a bespoke decoder to work.<br>

And finaly we want to give Sysmon a configuration file to focus on what to log and what to ignore,<br>
SwiftOnSecurity is the one that comes higlhy recomended so we shall use that one.<br>
After downloading the file we rename it to sysmonconfig.xml and run a simple command.<br>

<pre data-label="SwiftOnSecurityf" style="--delay: 0.7s;"><code>
<span class="orange"><strong>./sysmon64.exe -i sysmonconfig.xml</strong></span>

Copyright (C) 2014-2021 Mark Russinovich and Thomas Garnier
Sysinternals - www.sysinternals.com

Configuration file <span class="orange"><strong>validated.</strong></span>
Configuration <span class="orange"><strong>updated.</strong></span>
</code></pre>

That is it realy. Now we have in depth Windows process monitoring capabilities.<br>
We shall run a series of simple powershell commands to check our setup.<br>
Also i was very happy to finaly see the Rule IDs 92000 – 93000 fire.<br>


## Alert-01.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-01.png)

<small>“Alert-01.png”<small>

Command: <span class="badge-data">PS C:\Windows> powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA</span><br>
Here is an encoding of Whoami being caught.

PS C:\Windows> powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA

powershell.exe -EncodedCommand...92057 Base64 Encoded Command (Level 12): Detects the -e or -EncodedCommand flag, which attackers use to hide scripts from basic command-line logging.

## Alert-03.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-03.png)

<small>“Alert-03.png”<small>

<span class="badge-data">4433</span>

PS C:\Windows> reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "Malware" /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
The operation completed successfully.

reg add ...\Run /v "Malware" 92302 & 92041 Registry Persistence (Level 6 & 10): Detects modification of the "Run" key and notes that the value looks suspicious (Base64-like pattern).

## Alert-04.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-04.png)

<small>“Alert-04.png”<small>

This is a simple one, a new user is being created

PS C:\Windows> net user Lab_Attacker P@ssw0rd123 /add
The command completed successfully.

net user Lab_Attacker /add 92039 Account Discovery/Creation (Level 3): Identifies the use of net.exe to manage accounts, which is a key step in creating "Backdoor" users.

## Alert-05.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-05.png)

<small>“Alert-05.png”<small>

<span class="badge-data">4433</span>

PS C:\Windows> copy C:\Windows\System32\whoami.exe C:\Windows\Temp\test.exe; C:\Windows\Temp\test.exe
tech-bureau-02\lead_engineer

copy whoami.exe C:\Windows\Temp\test.exe 92213 & 92066 Suspicious Binary Location (Level 15): An executable was "dropped" in a Temp folder and then executed. Level 15 is the highest alert level because this is very typical of malware behavior.

## Alert-08.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-08.png)

<small>“Alert-08.png”<small>

<span class="badge-data">4433</span>

PS C:\Windows> net view \\127.0.0.1 /all
Shared resources at \\127.0.0.1

Share name  Type  Used as  Comment

ADMIN$      Disk           Remote Admin
C$          Disk           Default share
IPC$        IPC            Remote IPC
The command completed successfully.

net view \\127.0.0.1 /all 92033 Network Discovery (Level 3): Flags the enumeration of network shares, which is how attackers find sensitive data on other servers.

## LESSONS LEARNED

* Deeper understanding of the Wazuh structure<br>
* Sysmon config files can be notoriously noise or restrictive<br>
* Sometimes a prudent man deletes all the progress and starts from step one<br>
<br>
This concludes the <span class="badge-data">TECH-BUREAU</span> series, up next<br>
lets take a look at some cheeky malware shall we?<br>
[MALWARE-BOILER Series: main hub ](./MALWARE-BOILER-main.md) <br>
*Making a few Trojans and acting rather impish!*

<div class="divider-wire">
  <span class="line"></span>
  <span class="symbol">⦿</span>
  <span class="line"></span>
</div>
<p class="text-center">[3.4]</p>
