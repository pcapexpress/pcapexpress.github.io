---
layout: default
title: PCAP:03
---

# PCAPEXPRESS Wireshark Series
## Exercise 03: Big Fish In a Little Pond
#### **Setting:**
Indicators suggest a host within the network environment has been infected with malware. This analysis covers the investigation of the provided packet capture and associated alert logs.

### LAN Segment Details
| Parameter | Value |
| :--- | :--- |
| **LAN Segment Range** | `172.17.0.0/24` |
| **Domain** | `bepositive.com` |
| **Domain Controller** | `172.17.0.17` (WIN-CTL9XBQ9Y19) |
| **AD Environment** | `BEPOSITIVE` |
| **Gateway** | `172.17.0.1` |
| **Broadcast Address** | `172.17.0.255` |

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

ET POLICY Reserved Internal IP Traffic

Was not sure what to think of this one at first. We see what appears to be a standard LDAP query that goes out to the Domain Controller. The response looks legitimate as well. Used Gemini. An interesting suggestion was to check the request/response machines MAC addresses to make sure they are 2 separate entities and not in fact a Docker or Virtual Machine. That would be one explanation for the IDS to be confused.

![02a.Internal IP.png](assets/images/pcap-express/project.03/02a.Internal_IP(c).png)

<small>’02a.Internal IP.png’</small>

The image below indicates that we have to separate machines and makers. The alert is designed to check for any lateral movement on the network but in this case it is a case of standard communication between a Windows client and a Domain Controller. 

False Positive

![02b.MAC comparison.png](assets/images/pcap-express/project.03/02b.MAC_comparison(c).png)

<small>‘02b.MAC comparison.png’</small>

![03a.DNS No Name.png](assets/images/pcap-express/project.03/03a.DNS_No_Name(c).png)

<small>‘03a.DNS No Name.png’</small>

ET INFO Terse Request for .txt and ET INFO Microsoft Connection Test

This is a familiar alert at this point. We have to check that the domain is legitimate (using VirusTotal) which it is. And we can also check the user agent and its Microsoft NCSI.
This is legitimate traffic.

False Positive.

![04a.Connecttest.png](assets/images/pcap-express/project.03/04a.Connecttest(c).png)

<small>‘04a.Connecttest.png’</small>

ET INFO Potentially unsafe SMBv1 protocol in use

Here we need to look in to the packet details of the SMB protocol request and response.

![05a.SMB Negotiate Protocol.png](assets/images/pcap-express/project.03/05a.SMB_Negotiate_Protocol(c).png)

<small>‘05a.SMB Negotiate Protocol.png’</small>

We are looking for a legacy SMB version witch is lower than v3. SMBv1 will be written as NT LM 0.12 and that's what we get in the Request Dialect section.


And in the Selected Index Response. This indicates protocol downgrading.

Alert Confirmed

![05b.Negotiate Request.png](assets/images/pcap-express/project.03/05b.Negotiate_Request(c).png)

<small>‘05b.Negotiate Request.png’</small>

![05c.Negotiate Response.png](assets/images/pcap-express/project.03/05c.Negotiate_Response(c).png)

<small>‘05c.Negotiate Response.png’</small>


GPL NETBIOS SMB Session Setup NTMLSSP unicode asn1 overflow

Again consulted Gemini on this one. We are looking for a session setup request, and looking for the security blob information, the overflow would be indicated if we see abnormally large strings in the fields for Domain or User. So lets check.

Here is our request.

![06a.Check for ASN1.png](assets/images/pcap-express/project.03/06a.Check_for_ASN1(c).png)

<small>‘06a.Check for ASN1.png’</small>

And here are the details. The Nulls indicate that the Domain and User name haven't been allocated just yet but we see a legitimate Host name.

False Positive

![06b.Packet Details.png](assets/images/pcap-express/project.03/06b.Packet_Details(c).png)

<small>‘06b.Packet Details.png’</small>

GPL NETBIOS SMB IPC$ unicode share access

We detect the evidence of the IPC$ share being requested in the Tree Connect AndX Request path. We get several of these throughout the pcap file. According to the quote below IPC$ can be used for system and network enumeration.

“The IPC$ share enables remote operations like listing shared resources, enumerating users, accessing the registry, managing services, and running commands on a remote system via protocols such as Remote Procedure Call (RPC), DCOM, and SMB.”

![07a.SMB IPC access.png](assets/images/pcap-express/project.03/07a.SMB_IPC_access(c).png)

<small>‘07a.SMB IPC access.png’/<small>

To prove the share was accessed we look at the packet that follows the Tree Connect AndX Response and check the details. The alert checks out tough this could be yet another False Positive and its just standard request from our Windows Client.

Alert Confirmed

![07b.IPC Success.png](assets/images/pcap-express/project.03/07b.IPC_Success(c).png)

<small>‘07b.IPC Success.png’</small>


GPL NETBIOS SMB SMB_COM_TRANSACTION Max Data Count of 0 DOS Attempt

Could not find the evidence Used Gemini here. Checking the packet details of the packet that trigered the alert we see the Max Data Count is definitely not 0.

![08a.Data Count.png](assets/images/pcap-express/project.03/08a.Data_Count(c).png)

<small>‘08a.Data Count.png’</small>

Quote from Gemini:

“*The Pipe: \PIPE\LANMAN (Lan Manager) is used for Remote Administration Protocol (RAP).
*The Purpose: It is how a computer asks a server for a list of shared resources (like folders or printers) or a list of users.
*The "4374" Value: This number isn't random. 4374 is a classic buffer size used by Windows clients when they ask a server to "List all the shared folders you have."
This confirms legitimate use of the protocol and no DoS attack in action. In case of a Denial of Service we would should see a large count of such requests. The IDS might be misinterpreting some of the data.
Gemini Quote:
“The IDS might be looking at the wrong 2 bytes of the packet, seeing 00 00, and sounding the alarm, while Wireshark (which has a much more sophisticated parser) correctly identifies the 4374 at the proper offset.”
False Positive

![08b.Transaction Name.png](assets/images/pcap-express/project.03/08b.Transaction_Name(c).png)

<small>‘08b.Transaction Name.png’</small>

GPL RPC kerberos principal name overflow TCP

I couldn’t figure this one out for a while. The alert indicates that we should find a very long string in either the CNameString or SnameString. I found no such thing in the request.

![09a.name overflow.png](assets/images/pcap-express/project.03/09a.name_overflow(c).png)

<small>‘09a.name overflow.png’</small>

![09b.Name and bytes.png](assets/images/pcap-express/project.03/09b.Name_and_bytes(c).png)

<small>‘09b.Name and bytes.png’</small>

Checked with Gemini. After some back and forth was requested to submit the first 8 bytes of the Packet Bytes. Here is the verdict.

Gemini quote:

“Since the destination is Port 88 (the standard Kerberos port) and you are seeing the first 8 bytes 00 23 ae 50 ba fd 18 3d, we can confirm this is a False Positive triggered by an IDS/IPS misinterpretation.
Here is the technical breakdown of why this data is not a Kerberos attack:
1. The Header Does Not Match Kerberos-over-TCP
When Kerberos runs over TCP (instead of UDP), it must use a Record Marking header as defined in RFC 4120. This header is exactly 4 bytes long and specifies the length of the following Kerberos message.
    • Your First 4 Bytes: 00 23 ae 50
    • Interpretation: In Kerberos-over-TCP, this would mean the message length is 2,338,384 bytes ($0x23AE50$ in hex).
    • The Conflict: If the packet you are looking at is a standard size (e.g., ~1500 bytes or less), then the header is lying. A real Kerberos request that large would be split across thousands of packets. Because your packet is small but the "length" header is huge, the IDS thinks an attacker is trying to "overflow" the parser by declaring a massive size.”
This was a fascinating one, also I never really paid much attention to the Packet Bytes before. Based on what we gathered this alert can be ignored.

False Positive

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
