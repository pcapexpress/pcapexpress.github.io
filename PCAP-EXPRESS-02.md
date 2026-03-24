---
layout: default
title: PCAP:02
---

# PCAPEXPRESS Wireshark Series
## Exercise 02: Nemotodes
### Briefing:
**Platform:** <span class="badge-data">malware-traffic-analysis[.]net</span><br>
**Pcap File:** <span class="badge-data">2024-11-26-traffic-analysis-exercise.pcap</span><br>
We are a SOC analyst for a medical research facility.<br>
Alerts on traffic th network indicate someone has been infected.<br>
Two alert log files have been provided to help correlate the events.<br>
Analyze and report.<br>

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

This exercise is giving us some useful pointers regarding the infection.<br>
As 2 log files are given we can quicker get to the infection source.

<div class="divider"></div>

## 01: Host Discovery

Starting of with our standard discovery techniques.<br>
First I check the **DHCP** with the <span class="badge-data">”dhcp.option.type == 12”</span> filter.<br>
There's no **DHCP** traffic.<br>
Moving on to **NETBIOS**. Filtering for <span class="badge-data">“nbns.flags.opcode == 5”</span>.

![02a.Netbios.png](assets/images/pcap-express/project.02/02.Netbios(c).png)

<small>‘02a.Netbios.png’</small>

We get some **Registration Data**. We can examine the packet details to get some **Host** details.

![02b.Packet Details.png](assets/images/pcap-express/project.02/03.Packet_Details(c).png)

<small>‘02b.Packet Details.png’</small>

Than we check <span class="badge-data">Kerberos</span><br>

![03.Kerberos.png](assets/images/pcap-express/project.02/04.Kerberos(c).png)

<small>‘03.Kerberos.png’</small>

Here are the results of our host enumiration:

**IP Address:** <span class="badge-data">10.11.26.183</span><br>
**MAC address:** <span class="badge-data">Intel_ce:fc:8b (d0:57:7b:ce:fc:8b)</span><br>
**Host Name:** <span class="badge-data">DESKTOP-B8TQK49</span><br>
**User Name:** <span class="badge-data">oboomwald</span><br>

<div class="divider"></div>

## 02: Examining Traffic

Now we’ll focus on the actual **HTTP** traffic to see if we can spot any unusual requests.<br>
And quite quickly we discover just that.<br>

![13.POST traffic.png](assets/images/pcap-express/project.02/13.POST_traffic(c).png)

<small>‘13.POST traffic.png’</small>

POST request to a nameless host with <span class="badge-data">fakeurl.htm</span> in its **URL**.<br>
The 2 **GET** requests just above the POST don’t instill confidence.<br>
The first host in the image is <span class="badge-data">modandcrackedapk[.]com</span> witch is highly suspicious on its own. Before checking the IPs lets scroll up and find if the “**modandcrackedapk**” host has appeared before.<br>

![14.Tracing back.png](assets/images/pcap-express/project.02/14.Tracing_back(c).png)

<small>‘14.Tracing back.png’</small>

Here is the first mention of **“modandcrackedapk”** and right before<br>
we have 2 potentially suspicious candidates that we will look in to as well.<br>
We shall start checking the IPs with VirusTotal in order of their apearence.<br>

**01.IP**: 	<span class="badge-data">213[.]246[.]109[.]5</span><br>
**Domain**: <span class="badge-data">classicgrand[.]com</span><br>
**VirusTotal Result**: 1 detected file communicating with this domain<br>
**Comment**: Suspicious, might be the first malicious website in the infection chain.<br>

02.IP: <span class="badge-data">52[.]8[.]34[.]0</span><br>
Domain: <span class="badge-data">confirmsubscription[.]com</span><br>
VirusTotal Result: 1/93 security vendor flagged this domain as malicious<br>
Comment: This website is visited right before “modandcrackedapk.<br>

03.IP: <span class="badge-data">193[.]42[.]38[.]139</span><br>
Domain: <span class="badge-data">modandcrackedapk[.]com</span><br>
VirusTotal Result: 13/95 security vendors flagged this domain as malicious<br>
Comment: This domain has been flagged in an a DNS lookup alert. This is a true positive,<br>
the domain is malicious associated with Phishing and Malware. As seen in the image below,<br>
the conversations statistics. The most amount of data is exchanged between our infected host<br>
and the malicious domain. The data is going over port 443 and is encrypted.<br>

![15.Conversations.png](assets/images/pcap-express/project.02/15.Conversations.png)

<small>‘15.Conversations.png’</small>

We also have a true positive alert for this domain.

![16.DNS lookup.png](assets/images/pcap-express/project.02/16.DNS_lookup(c).png)

<small>‘16.DNS lookup.png’</small>

04.IP: <span class="badge-data">104[.]117[.]247[.]99</span><br>		
Domain: <span class="badge-data">r10.o.lencr.org</span><br>
VirusTotal Result: At least 9 detected files communicating with this domain<br>
Object:MFMwUTBPME(cut for bravity)69GH4A%3D%3D HTTP/1.1 
Comment: This is the first suspicious GET request. I checked the file object. Took the MD5 hash.<br>
It returned benign on VirusTotal. However I would asume it is some type of script or command that I don’t know how to decrypt. 

05.IP: <span class="badge-data">104[.]26[.]1[.]231</span><br>		
Domain: <span class="badge-data">geo[.]netsupportsoftware[.]com</span><br>
VirusTotal Result: 8/95 security vendors flagged this domain as malicious<br>
Object:loca.asp<br>
Comment: Second suspicious GET. I ran the strings command on the loca.asp<br>
and we got coordinates: 33.7488,-84.3877. Evidence of recognizance.<br>
“The geographic coordinates 33.7488° N, 84.3877° W<br>
correspond to a location in Downtown Atlanta, Georgia”<br>

We got an true alert for this one.

![17.Geo lookup.png](assets/images/pcap-express/project.02/17.Geo_lookup(c).png)

<small>‘17.Geo lookup.png’</small>

06.IP: <span class="badge-data">194[.]180[.]191[.]64</span><br>		
Domain: <span class="badge-data">194[.]180[.]191[.]64</span><br>
VirusTotal Result: 5/95 security vendors flagged this IP address as malicious<br>

Object:http://194.180.191.64/fakeurl.htm HTTP/1.1<br>

Comment: Malicious. Since this address is getting POST request every second I am assuming it is the Command and Control server. Curiously the data is sent over HTTP on port 443. We can follow the HTTP stream and gather that there are several commands being requested and or executed.

First is CMD=POLL; INFO=1; ACK=1.
Followed by CMD=ENCD; ES=1; DATA=.g+$.{.. \....W..D.6..=M..w}..o.......…
So the post commands are being encrypted.

This confirms several alerts.

![18.RAT activity.png](assets/images/pcap-express/project.02/18.RAT_activity(c).png)

<small>‘18.RAT activity.png’</small>

<div class="divider"></div>

## 03. Short Report and Conclusion

We have confirmed that a user **(DESKTOP-B8TQK49)** has interacted with a malicious domain witch<br>
has started an infection sequence that has been cross referenced with the alerts provided.<br>
Investigating the traffic revealed a successful malware execution<br>
most likely via interaction with the malicious domain **(confirmsubscription[.]com)**.<br>
This has led to an infection by a **Remote Access Trojan** or (RAT) on the victims system,<br>
the virus has began communicating with the Command and Control server of the adversary<br>
using encrypted **HTTP POST** requests over port **443** (not 80).<br>
The immediate steps would be to have the affected hosts machine re imaged/reinstalled.<br>
The malicious URLs are to be added to the IDS/Firewall block list.<br>

### HOP ON FOR THE NEXT ONE!

We got to explore and focus on domains in an infection chain rather than malicious objects.<br>
Lets move on to number 3 shall we?<br>
[PCAP-EXPRESS:03 "Big Fish In a Little Pond" ](./PCAP-EXPRESS-03.md)<br>
*Virus with a beacon.*

<div class="divider-wire">
  <span class="line"></span>
  <span class="symbol">⦿</span>
  <span class="line"></span>
</div>
<p class="text-center">[2.2]</p>
