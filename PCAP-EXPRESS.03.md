# PCAPEXPRESS Wireshark Series
## Exercise 03: Big Fish In a Little Pond

---

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

![00 Alerts](https://github.com/user-attachments/assets/19625c7f-269b-41aa-8f71-16db0cce76ba)

<small>'00.Alerts.png'</small>

---

## 01: Host Discovery

I'm beginning with the affected hosts detail gathering.

First is checking for the DHCP Request.

<img width="1277" height="104" alt="01a DHCP Request" src="https://github.com/user-attachments/assets/c55720a2-cca7-40b4-b7a9-7e6e8c8b6f0b" />

<small>‘01a.DHCP Request.png’</small>

We have that traffic. We look in to the packet details.

<img width="598" height="259" alt="01b DHCP Request Details" src="https://github.com/user-attachments/assets/77c82c25-09a4-4492-9828-a5ebb2434ff8" />

<small>‘01b.DHCP Request Details.png’</small>

We have discovered:

> MAC address: Intel_b6:8d:c4 (18:3d:a2:b6:8d:c4)
> IP address: 172.17.0.99
> Host Name: DESKTOP-RNV09AT

Next we look in to Kerberos to check for a user name.

<img width="1281" height="112" alt="01c Kerberos CName" src="https://github.com/user-attachments/assets/4db2047a-c97e-4a21-9cd0-24ed8f3e7330" />

<small>‘01c.Kerberos Cname.png’</small>

We get CnameString data:

> User Name: afletcher

We can further check the LDAP for CN=Users to see if we can expand on the user name a bit. And we are successful.

<img width="1152" height="117" alt="01d LDAP CN=Users" src="https://github.com/user-attachments/assets/4a58ea81-2b67-4ce1-93a7-184beb7d16f4" />

<small>‘01d.LDAP CN=Users.png’</small>

The info column gives us the first name.

User Name: Andrew Fletcher

With the Host Discovery out of the way I would like to go through the alert list now and try to find evidence(or lack there off) of each one.

---

## 02: Examining Alerts

ET POLICY Reserved Internal IP Traffic

Was not sure what to think of this one at first. We see what appears to be a standard LDAP query that goes out to the Domain Controller. The response looks legitimate as well. Used Gemini. An interesting suggestion was to check the request/response machines MAC addresses to make sure they are 2 separate entities and not in fact a Docker or Virtual Machine. That would be one explanation for the IDS to be confused.

<img width="1289" height="107" alt="02a Internal IP" src="https://github.com/user-attachments/assets/a2562661-dfc5-4c7b-ba0c-ddf9d6c5c098" />

<small>’02a.Internal IP.png’</small>

The image below indicates that we have to separate machines and makers. The alert is designed to check for any lateral movement on the network but in this case it is a case of standard communication between a Windows client and a Domain Controller. 

False Positive

<img width="693" height="147" alt="02b MAC comparison" src="https://github.com/user-attachments/assets/a93b9514-1ad0-434d-b75b-db7fea9e6cb8" />

<small>‘02b.MAC comparison.png’</small>

<img width="1130" height="200" alt="03a DNS No Name" src="https://github.com/user-attachments/assets/facda62b-ec50-4755-8b19-bf0cfb0d9cdc" />

<small>‘03a.DNS No Name.png’</small>

ET INFO Terse Request for .txt and ET INFO Microsoft Connection Test

This is a familiar alert at this point. We have to check that the domain is legitimate (using VirusTotal) which it is. And we can also check the user agent and its Microsoft NCSI.
This is legitimate traffic.

False Positive.

<img width="1200" height="149" alt="04a Connecttest" src="https://github.com/user-attachments/assets/8d9fcc28-bbc4-4e17-8d92-1541d6fd6d31" />

<small>‘04a.Connecttest.png’</small>

ET INFO Potentially unsafe SMBv1 protocol in use

Here we need to look in to the packet details of the SMB protocol request and response.

<img width="1202" height="169" alt="05a SMB Negotiate Protocol" src="https://github.com/user-attachments/assets/edff4025-a3b0-4c7f-aa1b-013a023af62b" />

<small>‘05a.SMB Negotiate Protocol.png’</small>

We are looking for a legacy SMB version witch is lower than v3. SMBv1 will be written as NT LM 0.12 and that's what we get in the Request Dialect section.


And in the Selected Index Response. This indicates protocol downgrading.

Alert Confirmed

<img width="580" height="271" alt="05b Negotiate Request" src="https://github.com/user-attachments/assets/0e97f58f-5da0-4fe6-8e33-2659e9cfe641" />

<small>‘05b.Negotiate Request.png’</small>

<img width="580" height="271" alt="05c Negotiate Response" src="https://github.com/user-attachments/assets/665ab038-07ab-4df0-9a9b-8e7f791e9546" />

<small>‘05c.Negotiate Response.png’</small>


GPL NETBIOS SMB Session Setup NTMLSSP unicode asn1 overflow

Again consulted Gemini on this one. We are looking for a session setup request, and looking for the security blob information, the overflow would be indicated if we see abnormally large strings in the fields for Domain or User. So lets check.

Here is our request.

<img width="1259" height="131" alt="06a Check for ASN1" src="https://github.com/user-attachments/assets/d0722227-34be-457d-b139-e4191715b5e9" />

<small>‘06a.Check for ASN1.png’</small>

And here are the details. The Nulls indicate that the Domain and User name haven't been allocated just yet but we see a legitimate Host name.

False Positive

<img width="444" height="195" alt="06b Packet Details" src="https://github.com/user-attachments/assets/ccb1c973-48ee-44a4-a61a-0b9c7c821f47" />

<small>‘06b.Packet Details.png’</small>

GPL NETBIOS SMB IPC$ unicode share access

We detect the evidence of the IPC$ share being requested in the Tree Connect AndX Request path. We get several of these throughout the pcap file. According to the quote below IPC$ can be used for system and network enumeration.

“The IPC$ share enables remote operations like listing shared resources, enumerating users, accessing the registry, managing services, and running commands on a remote system via protocols such as Remote Procedure Call (RPC), DCOM, and SMB.”

<img width="1199" height="113" alt="07a SMB IPC access" src="https://github.com/user-attachments/assets/6c67c07d-1421-48eb-89fe-bef3ef623231" />

<small>‘07a.SMB IPC access.png’/<small>

To prove the share was accessed we look at the packet that follows the Tree Connect AndX Response and check the details. The alert checks out tough this could be yet another False Positive and its just standard request from our Windows Client.

Alert Confirmed

<img width="594" height="159" alt="07b IPC Success" src="https://github.com/user-attachments/assets/10be6ffb-cdb0-425d-ae19-a35c277d3c83" />

<small>‘07b.IPC Success.png’</small>


GPL NETBIOS SMB SMB_COM_TRANSACTION Max Data Count of 0 DOS Attempt

Could not find the evidence Used Gemini here. Checking the packet details of the packet that trigered the alert we see the Max Data Count is definitely not 0.

<img width="523" height="141" alt="08a Data Count" src="https://github.com/user-attachments/assets/a6dff1aa-fbfd-42fc-98b6-1d92a8e7bd9f" />

<small>‘08a.Data Count.png’</small>

Quote from Gemini:

“*The Pipe: \PIPE\LANMAN (Lan Manager) is used for Remote Administration Protocol (RAP).
*The Purpose: It is how a computer asks a server for a list of shared resources (like folders or printers) or a list of users.
*The "4374" Value: This number isn't random. 4374 is a classic buffer size used by Windows clients when they ask a server to "List all the shared folders you have."
This confirms legitimate use of the protocol and no DoS attack in action. In case of a Denial of Service we would should see a large count of such requests. The IDS might be misinterpreting some of the data.
Gemini Quote:
“The IDS might be looking at the wrong 2 bytes of the packet, seeing 00 00, and sounding the alarm, while Wireshark (which has a much more sophisticated parser) correctly identifies the 4374 at the proper offset.”
False Positive

<img width="523" height="141" alt="08b Transaction Name" src="https://github.com/user-attachments/assets/c4ee3b09-3fab-4055-959b-7b920eceb7e2" />

<small>‘08b.Transaction Name.png’</small>

GPL RPC kerberos principal name overflow TCP

I couldn’t figure this one out for a while. The alert indicates that we should find a very long string in either the CNameString or SnameString. I found no such thing in the request.

<img width="1069" height="95" alt="09a name overflow" src="https://github.com/user-attachments/assets/9f075273-7685-41c2-aaf7-ccca0930c58b" />

<small>‘09a.name overflow.png’</small>

<img width="852" height="230" alt="09b Name and bytes" src="https://github.com/user-attachments/assets/994e927c-b926-473e-8da3-4e2824a3a649" />

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

<img width="1191" height="126" alt="10a Suspicious POST" src="https://github.com/user-attachments/assets/16480b26-bae7-4b02-b9e9-89a7adc26632" />

<small>‘10a.Suspicious POST.png’</small>

If we look at the HTTP stream of the packet we find the User-Agent to be Mozilla/4.0 which translates to an old version of Internet Explorer.

“A legacy identifier used by early versions of Internet Explorer (up to IE 8) to indicate compatibility with the Mozilla rendering engine”

Alert confirmed.

<img width="583" height="267" alt="10b Suspicious POST Details" src="https://github.com/user-attachments/assets/51b793c0-7a66-4ad3-8603-f129a9e70280" />

<small>‘10b.Suspicious POST Details.png’</small>

ETPRO TROJAN Win32/Koi Stealer CnC Checkin (POST) M2

We can see that the POST requests are quite numerous and they are sent out 1 minute apart. This is an indicator of C2 traffic, sending out beacons. However all of the /foots.php are sent out with 0 bytes witch would mean no exfiltration has yet occurred.

Alert Confirmed

<img width="993" height="314" alt="11a CnC Trafic" src="https://github.com/user-attachments/assets/d8884bd4-1765-43c7-a37c-b4bd9ca86beb" />

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

---
