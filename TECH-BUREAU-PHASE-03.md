---
layout: default
title: BUREAU:03
---
# TECH-BUREAU SERIES: PHASE 03
## CVE exploitation, privilege escalation and protocol tunneling.
### WHATS SHOWCASED
<section>
  <ul class="hover-card"> 
    <li>
      <span class="text-data"><strong>OFFENSE:</strong></span> Leveraging a system misscofiguration, priviledge escalating using an administrative oversight, Stealthy Data exfiltration 
    </li>
  </ul>
  <ul class="hover-card"> 
    <li>
      <span class="text-data"><strong>DEFENSE:</strong></span> Being more cautious and restrictive with the server. 
    </li> 
  </ul>
</section>

### The initial Setup
...

# AT4K-3XPR3S rolling out.
...

<pre data-label="auditctl" style="--delay: 0s;">
  <code>
<span class="orange"><strong>root@TECH-BUREAU-UBUNTU-24:</strong></span>/home/lead_engineer# auditctl -l
-w /home/lead_engineer/PROJECT.5527/Frame_specs.txt -p rwa -k file_agitated
  </code></pre>

## 01.WAZUH ALERTS

![01.wazuh-alerts.png](assets/images/tech-bureau/phase.03/01.wazuh-alerts.png)

<small>“01.wazuh-alerts.png”<small>

## 02.WAZUH OUTBOUND TRAFFIC

![02.wazuh-4433-out.png](assets/images/tech-bureau/phase.03/02.wazuh-4433-out.png)

<small>“02.wazuh-4433-out.png”<small>

## 03.WAZUH OUTBOUND TRAFFIC 4433

![03.wazuh-cat.png](assets/images/tech-bureau/phase.03/03.wazuh-cat.png)

<small>“03.wazuh-cat.png”<small>

## 04.WAZUH PACKAGE INSTALLED

![04.wazuh-package-installed.png](assets/images/tech-bureau/phase.03/04.wazuh-package-installed.png)

<small>“04.wazuh-package-installed.png”<small>

## 05.WAZUH PACKAGE INSTALLED

![05.wazuh-steghide-used.png](assets/images/tech-bureau/phase.03/05.wazuh-steghide-used.png)

<small>“05.wazuh-steghide-used.png”<small>

## 06.WAZUH OUTBOUND TRAFFIC 4040

![06.wazuh-4040-out.png](assets/images/tech-bureau/phase.03/06.wazuh-4040-out.png)

<small>“06.wazuh-4040-out.png”<small>

## 07.WAZUH CURL

![07.wazuh-CURL.png](assets/images/tech-bureau/phase.03/07.wazuh-CURL.png)

<small>“07.wazuh-CURL.png”<small>

## 08.WAZUH FILE DELETED

![08.wazuh-delete.png](assets/images/tech-bureau/phase.03/08.wazuh-delete.png)

<small>“08.wazuh-delete.png”<small>

## 09.WIRESHARK SHELL TRAFFIC

![09.wireshark-shell-traffic.png](assets/images/tech-bureau/phase.03/09.wireshark-shell-traffic.png)

<small>“09.wireshark-shell-traffic.png”<small>

## 10.WIRESHARK SHELL STREAM

![10.wireshark-shell-stream.png](assets/images/tech-bureau/phase.03/10.wireshark-shell-stream.png)

<small>“10.wireshark-shell-stream.png”<small>

## 11.WIRESHARK POST TRAFFIC

![11.wireshark-post-traffic.png](assets/images/tech-bureau/phase.03/11.wireshark-post-traffic.png)

<small>“11.wireshark-post-traffic.png”<small>

## 12.WIRESHARK POST STREAM

![12.wireshark-post-stream.png](assets/images/tech-bureau/phase.03/12.wireshark-post-stream.png)

<small>“12.wireshark-post-stream.png”<small>

## 13.RULE OUTBOUD TRAFFIC

![13.rule-outbound-traffic.png](assets/images/tech-bureau/phase.03/13.rule-outbound-traffic.png)

<small>“13.rule-outbound-traffic.png”<small>

## 14.RULE FILE OPENED

![14.rule-file-opened.png](assets/images/tech-bureau/phase.03/14.rule-file-opened.png)

<small>“14.rule-file-opened.png”<small>

## 15.RULE STEGHIDE USED

![15.rule-steghide-used.png](assets/images/tech-bureau/phase.03/15.rule-steghide-used.png)

<small>“15.rule-steghide-used.png”<small>

## 16.RULE CURL USED

![16.rule-curl-used.png](assets/images/tech-bureau/phase.03/16.rule-curl-used.png)

<small>“16.rule-curl-used.png”<small>

## 17.GHEX CARVING

![17.ghex-carving.png](assets/images/tech-bureau/phase.03/17.ghex-carving.png)

<small>“17.ghex-carving.png”<small>

## 18.RECONSTRUCTED IMAGE
![T1:Casing.jpg](assets/images/tech-bureau/phase.03/T1:Casing.jpg)

<small>“T1:Casing.jpg”<small>

## 19.REVERSE STEGONOGRAPHY?
![18.pcap-image-steghide.png](assets/images/tech-bureau/phase.03/18.pcap-image-steghide.png)

<small>“18.pcap-image-steghide.png”<small>










## LESSONS LEARNED
As the attacker:<br>
* <br>
* <br>
* <br>
As the defender:<br>
* <br>
* <br>
* .<br>
<br>
Continue?
<br>
[**TECH-BUREAU-SERIES: PHASE 03.** ](./TECH-BUREAU-PHASE-03.md) <br>
*Phish, infect, persist, escalate, obfuscate and extract. The system has been hardened to the fullest.<br>
A phishing campaign  is now in the cards, but how can we extract the data this time to dupe the TECH-BUREAU?<br>
**STAY TUNED TO FIND OUT!***

<div class="divider-wire">
  <span class="line"></span>
  <span class="symbol">⦿</span>
  <span class="line"></span>
</div>
<p class="text-center">[3.2]</p>
