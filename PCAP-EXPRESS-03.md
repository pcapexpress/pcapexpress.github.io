---
layout: default
title: PCAP:03
---

# PCAPEXPRESS Wireshark Series
## Exercise 03: Big Fish In a Little Pond
### Briefing:
**Platform:** <span class="badge-data">malware-traffic-analysis[.]net</span><br>

Indicators suggest a host within the network environment has been infected with malware. This analysis covers the investigation of the provided packet capture and associated alert logs.


---

## 00: Prologue
This is the third exercise in the series. The initial triage began with a review of the alert logs. Observations included SMB alerts similar to previous tasks, providing a baseline for comparison. 

A significant portion of the triage involved distinguishing between false positives and legitimate malicious indicators. I utilized **Gemini** to assist with contextualizing specific alert signatures and **CyberChef** for deobfuscating traffic strings. 

![00.Alerts.png](assets/images/pcap-express/project.03/00.Alerts.png)

<small>'00.Alerts.png'</small>

---

## 01: Host Discovery

I'm beginning with the affected hosts detail gathering.

First is checking for the DHCP Request.

![01a.DHCP Request.png](assets/images/pcap-express/project.03/01a.DHCP_Request(c).png)

<small>‘01a.DHCP Request.png’</small>

We have that traffic. We look in to the packet details.

![01b.DHCP Request Details.png](assets/images/pcap-express/project.03/01b.DHCP_Request_Details(c).png)

<small>‘01b.DHCP Request Details.png’</small>

We have discovered:

> MAC address: Intel_b6:8d:c4 (18:3d:a2:b6:8d:c4)
> IP address: 172.17.0.99
> Host Name: DESKTOP-RNV09AT

Next we look in to Kerberos to check for a user name.

![01c.Kerberos Cname.png](assets/images/pcap-express/project.03/01c.Kerberos_CName(c).png)

<small>‘01c.Kerberos Cname.png’</small>

We get CnameString data:

> User Name: afletcher

We can further check the LDAP for CN=Users to see if we can expand on the user name a bit. And we are successful.

![01d.LDAP CN=Users.png](assets/images/pcap-express/project.03/01d.LDAP_CN=Users(c).png)

<small>‘01d.LDAP CN=Users.png’</small>

The info column gives us the first name.

User Name: Andrew Fletcher

With the Host Discovery out of the way I would like to go through the alert list now and try to find evidence(or lack there off) of each one.

---

## 02: Examining Alerts



ET INFO GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser

This one is straight forward, we see a POST request that is directed to an IP address rather than a host.

![10a.Suspicious POST.png](assets/images/pcap-express/project.03/10a.Suspicious_POST(c).png)

<small>‘10a.Suspicious POST.png’</small>

If we look at the HTTP stream of the packet we find the User-Agent to be Mozilla/4.0 which translates to an old version of Internet Explorer.

“A legacy identifier used by early versions of Internet Explorer (up to IE 8) to indicate compatibility with the Mozilla rendering engine”

Alert confirmed.

![10b.Suspicious POST Details.png](assets/images/pcap-express/project.03/10b.Suspicious_POST_Details(c).png)

<small>‘10b.Suspicious POST Details.png’</small>

ETPRO TROJAN Win32/Koi Stealer CnC Checkin (POST) M2

We can see that the POST requests are quite numerous and they are sent out 1 minute apart. This is an indicator of C2 traffic, sending out beacons. However all of the /foots.php are sent out with 0 bytes witch would mean no exfiltration has yet occurred.

Alert Confirmed

![11a.CnC Trafic.png](assets/images/pcap-express/project.03/11a.CnC_Trafic(c).png)

<small>‘11a.CnC Trafic.png’</small>

---

## 03: Examining Objects/Domains

Nothing of interest in the object department however we have some interesting findings regarding the domains.

**01.IP:** 79[.]124[.]78[.]197
**Domain:** n/a
**VirusTotal Result:** 2 detected files communicating with this IP address
**Comment:** I have checked the suspicious files associated with this particular address and the first one mentioned is a power shell file called “sd4.ps1”, checking the details of the file we see it is indeed a malicious file that is labeled as koistealer trojan.

**File Name:** sd4.ps1
**MD5 hash:** 3e86c8009a224924049a5279b9d21786
**Popular threat label:** trojan.koistealer/psinj
**BitDefender:** Trojan.Generic.37535674

**02.I.P:** 46[.]254[.]34[.]201
**Domain:** www[.]bellantonicioccolato[.]it
**VirusTotal Result:** At least 10 detected files communicating with this domain
**Comment:** This domain is a accessed close to our malicious POST traffic. The ViruTotal comment section has a mention of a KOI distribution domain. I have also checked the TCP stream, it is encrypted but we know that a total of 228kb of data has been exchanged with 221kb coming from the malicious domain.

---

## 04. Malware Inspection

Nothing of interest found.

---

## 05. Short Report and Conclusion

Reflections:
For this exercise I decided to delve in to the alert section and spent a large chunk of time investigating weather or not we got false or true positives. We also received a pcap file that did not alow to see the full picture of the infection, we have observed the post infection but not the full payload deployment/developement.

We have observed traffic indicating our compromised host DESKTOP-RNV09AT communicating with a suspicious domain www[.]bellantonicioccolato[.]it.

After a short moment we have observed the host sending POST requests to a malicious IP address indicating system compromise and a malware sending a beacon to the adversarial command and control server 79[.]124[.]78[.]197.

The virus activity has been picket up by the IDS and triggered an alert - “Win32/Koi Stealer CnC Checkin (POST)”

Upon investigating the malicious domains with VirusTottal we have found evidence that they are in fact associated with the KOIstealer Trojan.

Acording to the length of the supplied pcap file we did not see any evidence of data exfiltration.

The affected machine is to be reimaged/reinstalled and the malicious IPs and file hash to be added to the company's IDS system.


## Our Findings

#### Compromised Host

IP Address: 172.17.0.99
MAC address: Intel_b6:8d:c4 (18:3d:a2:b6:8d:c4)
Host Name: DESKTOP-RNV09AT
Client name: andrewfletcher
User Name: Andrew Fletcher

#### Attackers

Fake domain 01: www[.]bellantonicioccolato[.]it

C2 Server 01: 79[.]124[.]78[.]197

#### Malware MD5 Hashes

sd4.ps1 - 3e86c8009a224924049a5279b9d21786
 

This concludes the packet inspection with wireshark for the moment. I am now focusing on the next project witch is establishing a simplified functional SOC lab.

<div class="divider-wire">
  <span class="line"></span>
  <span class="symbol">⦿</span>
  <span class="line"></span>
</div>
<p class="text-center">[2.3]</p>
