---
layout: default
title: SYSMON
---
# TECH-BUREAU-SUPLIMENT: THE SAGA OF SYSMON.
## THE SYSMON WAZUH CONNECTION
### WHATS SHOWCASED:
<section>
  <ul class="hover-card"> 
    <li>
      <span class="text-data"><strong>DEFFENSE:</strong></span> The essential steps to kickstart the Sysmon logs
    </li>
  </ul>
 

### The initial Setup
In this scenario our **lead_engineer** has downloaded a tool from a compromised website.<br>
The tool is a python script that acts as a Trojan. Contains a legitimate math calculation function<br>
and in the background unbeknownst to the host it establishes a shell with the adversarial box.<br>

<pre data-label="..." style="--delay: 0.5s;"><code>
<span class="orange"><strong>...</strong></span>
</code></pre>

# ALERT CHECK

## Agent-active.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Agent-active.png)

<small>“Agent-active.png”<small>

## Wazuh-ossec.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Wazuh-ossec.png)

<small>“Wazuh-ossec.png”<small>

## Eventchannel.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Eventchannel.png)

<small>“Eventchannel.png”<small>

## Sysmon-running.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Sysmon-running.png)

<small>“Sysmon-running.png”<small>

## Alert-01.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-01.png)

<small>“Alert-01.png”<small>

## Alert-02.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-02.png)

<small>“Alert-02.png”<small>

## Alert-03.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-03.png)

<small>“Alert-03.png”<small>

## Alert-04.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-04.png)

<small>“Alert-04.png”<small>

## Alert-05.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-05.png)

<small>“Alert-05.png”<small>

## Alert-06.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-06.png)

<small>“Alert-06.png”<small>

## Alert-07.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-07.png)

<small>“Alert-07.png”<small>

## Alert-08.png

![Agent-active.png](assets/images/tech-bureau/sysmon/Alert-08.png)

<small>“Alert-08.png”<small>

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
