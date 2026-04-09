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

We have a TECH-BUREAU Windows Box botted up and connected to our Wazuh manager.<br>

## Sysmon-running.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Sysmon-running.png)

<small>“Sysmon-running.png”<small>

Sysmon is installed and running, the fltmc command confirms that the file monitoring is active.
However the next 2 steps are what make it all work.

## Wazuh-ossec.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Wazuh-ossec.png)

<small>“Wazuh-ossec.png”<small>

We need to configure teh ossec file on the AGENT in our case thats the Windows VM.<br>
We can simply use the notepad to add the following bit of xml code.

<pre data-label="ossec.conf" style="--delay: 0s;"><code>
&lt;localfile&gt;
  &lt;location&gt;<span class="orange"><strong>Microsoft-Windows-Sysmon/Operational</strong></span>&lt;/location&gt;
  &lt;log_format&gt;<span class="orange"><strong>eventchannel</strong></span>&lt;/log_format&gt;
&lt;/localfile&gt;  
</code></pre>

The /Operational directory is where we want to pull our Sysmon generated logs.<br>
The eventchannel is what will be taking the logs in to Wazuh and interpreting them in JSON format<br>
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


## Alert-01.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-01.png)

<small>“Alert-01.png”<small>

<span class="badge-data">4433</span>

## Alert-02.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-02.png)

<small>“Alert-02.png”<small>

<span class="badge-data">4433</span>

## Alert-03.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-03.png)

<small>“Alert-03.png”<small>

<span class="badge-data">4433</span>

## Alert-04.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-04.png)

<small>“Alert-04.png”<small>

<span class="badge-data">4433</span>

## Alert-05.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-05.png)

<small>“Alert-05.png”<small>

<span class="badge-data">4433</span>

## Alert-06.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-06.png)

<small>“Alert-06.png”<small>

<span class="badge-data">4433</span>

## Alert-07.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-07.png)

<small>“Alert-07.png”<small>

<span class="badge-data">4433</span>

## Alert-08.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-08.png)

<small>“Alert-08.png”<small>

<span class="badge-data">4433</span>

We see loads of traffic going to port <span class="badge-data">4433</span>, we want to see the stream immediately.<br>

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
