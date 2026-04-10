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
      <span class="text-data"><strong>DEFENSE:</strong></span> The essential steps to connect and kickstart Sysmon
    </li>
  </ul>
</section>

### The Goal

This particular assignment was a challenge indeed, had had multiple issues with the alert sensitivity and the **Sysmon** config file, tried also rules from **SOC Fortress** but failed to configure the agent correctly and got a myriad of errors that became a nightmare to untangle… So I started from scratch and settled for a basic setup of using <span class="badge-data">SwiftOnSecurity</span> as the config file and just the inbuilt **Wazuh Sysmon** rules. The goal was to simply have the logs recording and funneling to the **Wazuh** manager and we even got some neat alerts out of it. So lets have a closer look.

## THE SETUP

![Agent-active.png](assets/images/tech-bureau/sysmon/Agent-active.png)

<small>“Agent-active.png”<small>

We have a **TECH-BUREAU** Windows Box booted up and connected to our Wazuh manager.<br>

## Sysmon & FLTMC

![Agent-active.png](assets/images/tech-bureau/sysmon/Sysmon-running.png)

<small>“Sysmon-running.png”<small>

**Sysmon** is installed and running, the <span class="badge-data">fltmc</span> command confirms that the file monitoring is active.
*However the next 2 steps are what make it all work.*

## Wazuh & ossec.cong

![Agent-active.png](assets/images/tech-bureau/sysmon/Wazuh-ossec.png)

<small>“Wazuh-ossec.png”<small>

We need to configure the <span class="badge-data">ossec.conf</span> file on the AGENT in our case that's the Windows VM.<br>
We can simply use the notepad to add the following bit of **xml** code.

<pre data-label="ossec.conf" style="--delay: 0s;"><code>
&lt;localfile&gt;
  &lt;location&gt;Microsoft-Windows-Sysmon<span class="orange"><strong>/Operational</strong></span>&lt;/location&gt;
  &lt;log_format&gt;<span class="orange"><strong>eventchannel</strong></span>&lt;/log_format&gt;
&lt;/localfile&gt;  
</code></pre>

The <span class="text-orange">/Operational</span> directory is where we want to pull our **Sysmon** generated logs from.<br>
The <span class="text-orange">eventchannel</span> is what will be taking the logs in to Wazuh and interpreting them in <span class="badge-data">JSON</span> format<br>
Very digestible and doesn't require a bespoke decoder to work.<br>

And finally we want to give **Sysmon** a configuration file to focus on what to log and what to ignore,<br>
<span class="text-orange">SwiftOnSecurity</span> is the one that comes highly recommended so we shall use that one.<br>
After downloading the file we rename it to <span class="badge-data">sysmonconfig.xml</span> and run a simple command.<br>

<pre data-label="SwiftOnSecurityf" style="--delay: 0.7s;"><code>
<span class="orange"><strong>./sysmon64.exe -i sysmonconfig.xml</strong></span>

Copyright (C) 2014-2021 Mark Russinovich and Thomas Garnier
Sysinternals - www.sysinternals.com

Configuration file <span class="orange"><strong>validated.</strong></span>
Configuration <span class="orange"><strong>updated.</strong></span>
</code></pre>

That is it realy. Now we have in depth Windows process monitoring capabilities.<br>
We shall run a series of simple Powershell commands to check our setup.<br>
Also i was very happy to finally see the Rule IDs 92000 – 93000 fire.<br>

## 92057

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-01.png)

<small>“Alert-01.png”<small>

Command: <span class="badge-data">PS C:\Windows> powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA</span><br>
Here is an example of a **Powershell** encoded command being detected. The rule reacts to the *-EncodedCommand* flag.
This is a way to obfuscate malicious code. In our case the encoding is a humble **Whoami.**

## 92033

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-08.png)

<small>“Alert-08.png”<small>

Command: <span class="badge-data">PS C:\Windows> net view \\127.0.0.1 /all</span><br>
In this instance we observe a discovery activity of network shares using the **net view** with the **-all** flag.<br>
For lateral movement potentialy.<br>

## 92302

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-03.png)

<small>“Alert-03.png”<small>

Command: <span class="badge-data">PS C:\Windows> reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"</span><br>
<span class="badge-data"> /v "Malware" /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f</span><br>
Here we have a registry entry modified to execute a **"Malware"** on log on, which would be a persistance mechanism.<br>
The rule has detected a change to the **"Run"** key.<br>

## 92039

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-04.png)

<small>“Alert-04.png”<small>

Command: <span class="badge-data">PS C:\Windows> net user Lab_Attacker P@ssw0rd123 /add</span><br>
This is a simple one, a new user is being created using the **net.exe**<br>
A persistance or **"backdoor"** mechanism.

## 92066

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-05.png)

<small>“Alert-05.png”<small>

<span class="badge-data">4433</span>

Command: <span class="badge-data">PS C:\Windows> copy C:\Windows\System32\whoami.exe C:\Windows\Temp\test.exe;</span><br>
<span class="badge-data">C:\Windows\Temp\test.exe</span><br>
This one is a high level priority alert. It showcases malware like behaviour, a file being copied and than executed from the Temp folder.
But Sysmon sees all. *"Suspicious binary launched by powershell."*

## LESSONS LEARNED

* Deeper understanding of the Wazuh structure<br>
* Sysmon config files can be notoriously noisy or restrictive<br>
* Sometimes a prudent man deletes all the progress and starts from scratch<br>
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
