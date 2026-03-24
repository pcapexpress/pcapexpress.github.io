---
layout: default
title: PCAP:03
---

# PCAPEXPRESS Wireshark Series
## Exercise 03: Big Fish In a Little Pond
### Briefing:
**Platform:** <span class="badge-data">malware-traffic-analysis[.]net</span><br>
**Pcap File:** <span class="badge-data">2024-09-04-traffic-analysis-exercise.pcap</span><br>

Indicators suggest a host within the network environment has been infected with malware. This analysis covers the investigation of the provided packet capture and associated alert logs.

### TASK:
<pre data-label="TASK" style="--delay: 0s;"><code>
01.Discover host details - <span class="orange">[x]</span> 02.Investigate breach - <span class="orange">[x]</span> 03.Write consise report - <span class="orange">[x]</span>
</code></pre>
### Tools:
<pre data-label="TASK" style="--delay: 0.7s;"><code>
<span class="orange"><strong>* Wireshark</strong></span> – pcap inspection         <span class="orange"><strong>* VirusTotal</strong></span> – malicious IPs and File inspection
<span class="orange"><strong>* CyberChef</strong></span> – decoding packet data    <span class="orange"><strong>* md5sum</strong></span> – calculating file hashes
</code></pre>

## 00: Prologue
This is the third exercise in the series. The initial investigation began with a review of the alert logs.<br>
Again it is very helpful and time saving to be able to direct ones attention to the source, and have a time line<br>
of events happening on the wire. Let us dive in!

![00.Alerts.png](assets/images/pcap-express/project.03/00.Alerts.png)

<small>'00.Alerts.png'</small>

<div class="divider"></div>

## 01: Host Discovery

I'm beginning with the affected hosts detail gathering.<br>
First is checking for the **DHCP** Request.<br>

![01a.DHCP Request.png](assets/images/pcap-express/project.03/01a.DHCP_Request(c).png)

<small>‘01a.DHCP Request.png’</small>

We have that traffic. We look in to the packet details.

![01b.DHCP Request Details.png](assets/images/pcap-express/project.03/01b.DHCP_Request_Details(c).png)

<small>‘01b.DHCP Request Details.png’</small>

Moving on to <span class="badge-data">Kerberos</span> to check for a **user name**.

![01c.Kerberos Cname.png](assets/images/pcap-express/project.03/01c.Kerberos_CName(c).png)

<small>‘01c.Kerberos Cname.png’</small>

We can further check the **LDAP** for **CN=Users** to get a full user name.<br>

![01d.LDAP CN=Users.png](assets/images/pcap-express/project.03/01d.LDAP_CN=Users(c).png)

<small>‘01d.LDAP CN=Users.png’</small>

The gathered results are below. With the Host Discovery out of the way<br>
Next we turn to the network traffic keeping the provided alert list in mind.<br>

**IP Address:** <span class="badge-data">172.17.0.99</span><br>
**MAC address:** <span class="badge-data">Intel_b6:8d:c4 (18:3d:a2:b6:8d:c4)</span><br>
**Host Name:** <span class="badge-data">DESKTOP-RNV09AT</span><br>
**Client name:** <span class="badge-data">andrewfletcher</span><br>
**User Name:** <span class="badge-data">Andrew Fletcher</span><br>

<div class="divider"></div>

## 02: Examining Traffic

**Alert:** <span class="badge-data">ET INFO GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser</span>

This one is straight forward, we see a POST request that is directed to an IP address rather than a host.<br>

![10a.Suspicious POST.png](assets/images/pcap-express/project.03/10a.Suspicious_POST(c).png)

<small>‘10a.Suspicious POST.png’</small>

**Alert:** <span class="badge-data">ETPRO TROJAN Win32/Koi Stealer CnC Checkin (POST) M2</span>

We can see the numerous **POST** requests being sent out 1 minute apart.<br>
This is an indicator of **C2** beacon traffic.<br>
However all of the <span class="badge-data">/foots.php</span> are sent out with 0 bytes<br>
witch would mean no data has been sent out, **command** or **exfiltration** wise.<br>

![11a.CnC Trafic.png](assets/images/pcap-express/project.03/11a.CnC_Trafic(c).png)

<small>‘11a.CnC Trafic.png’</small>

<div class="divider"></div>

## 03: Examining Objects/Domains

One object of interest has been discovered along with a couple of suspicious domains,<br>
lets check VirusTOtal for some details.<br>

<pre data-label="OBJECTS"><code>
01.File Name: <span class="red">sd4.ps1</span>
MD5 Hash: 3e86c8009a224924049a5279b9d21786
VirusTotal Result: <span class="red">Malicious</span>
Poplar threat label: trojan.koistealer/psinj
BitDefender: Trojan.Generic.37535674
</code></pre>

**02.IP:** <span class="badge-data">79[.]124[.]78[.]197</span><br>
**Domain:** <span class="badge-data">n/a</span><br>
**VirusTotal Result:** 2 detected files communicating with this IP address<br>
**Comment:** I have checked the suspicious files associated with this particular address<br>
and the first one mentioned is a power shell file called **“sd4.ps1”**, checking the details of the<br>
file we see it is indeed a malicious file that is labeled as **"koistealer trojan"**.<br>
<br>
**03.I.P:** <span class="badge-data">46[.]254[.]34[.]201</span><br>
**Domain:** <span class="badge-data">www[.]bellantonicioccolato[.]it</span><br>
**VirusTotal Result:** At least 10 detected files communicating with this domain<br>
**Comment:** This domain is a accessed close to our malicious POST traffic. The ViruTotal comment<br>
section has a mention of a KOI distribution domain. I have also checked the TCP stream,<br>
it is encrypted but we know that a total of 228kb of data has been exchanged<br>
with 221kb coming from the malicious domain.<br>
<br>

<div class="divider"></div>

## 04. Short Report and Conclusion

In this particular exercise the pcap file did not feature the initial infection process.<br>
we have observed the post infection but not the full payload deployment/developement.<br>
We have detected traffic indicating our compromised host<br>
**(DESKTOP-RNV09AT)** communicating with a suspicious domain **(www[.]bellantonicioccolato[.]it)**.<br>
After a short moment we have observed the host sending **POST** requests to a malicious IP address<br>
indicating system compromise and the malware sending a beacon<br>
to the adversarial command and control server 79[.]124[.]78[.]197.
The virus activity has been picket up by the IDS and triggered an alert - “**Win32/Koi Stealer CnC Checkin (POST)**”<br>
Upon investigating the malicious domains with VirusTottal we have found evidence that they are in fact associated with the KOIstealer Trojan.<br>
Based on the length of the supplied pcap file we did not see any evidence of data exfiltration.<br>
The affected machine is to be reimaged/reinstalled and the malicious IPs and file hash to be added to the company's IDS system.

### TIME TO SWITCH GEARS

This concludes the **PCAP** series, however we are not done with **Wireshark**,<br>
I shall be using in througght the entire portfolio.<br>
I now invite you to check out the Purple Team exercises!<br>
[TECH BUREAU SERIES: main hub ](./TECH-BUREAU-main.md)<br>
*Spinning up a Wazuh agent and guarding a server, hope no one tries to steal the corporate secretes.*

<div class="divider-wire">
  <span class="line"></span>
  <span class="symbol">⦿</span>
  <span class="line"></span>
</div>
<p class="text-center">[2.3]</p>
