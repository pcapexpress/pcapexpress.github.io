# PCAPEXPRESS Wireshark Series
## Exercise 02: Nemotodes

#### Briefing:
We are a SOC analyst for a medical research facility. Alerts on traffic in your network indicate someone has been infected.
Two alert log files have been provided to help correlate the events. Analyze and report.

LAN SEGMENT DETAILS FROM THE PCAP
    • LAN segment range:  10.11.26[.]0/24 (10.11.26[.]0 through 10.11.26[.]255)
    • Domain:  nemotodes[.]health
    • Active Directory (AD) domain controller:  10.11.26[.]3 - NEMOTODES-DC
    • AD environment name:  NEMOTODES
    • LAN segment gateway:  10.11.26[.]1
    • LAN segment broadcast address:  10.11.26[.]255

TASK:
    • Write an incident report based on malicious network activity from the pcap and from the alerts.
    • The incident report should contains 3 sections:
    • Executive Summary: State in simple, direct terms what happened (when, who, what).
    • Victim Details: Details of the victim (hostname, IP address, MAC address, Windows user account name).
    • Indicators of Compromise (IOCs): IP addresses, domains and URLs associated with the activity.  SHA256 hashes if any malware binaries can be extracted from the pcap.

Tools:

Wireshark – pcap inspection
VirusTotal – checking for malicious IPs and Files
CyberChef – decoding malicious traffic
md5sum – calculating file hashes
sha256sum – calculating file hashes


## 00: Prologue

This exercise is giving us some useful pointers regarding the infection. As 2 log files are given I shall be referencing them below to compare the findings.

## 01: Host Discovery

Lets start checking the endpoints statistics.

<img width="288" height="125" alt="01 Endpoints" src="https://github.com/user-attachments/assets/02a27137-1a83-45aa-9109-278174cae351" />

<small>‘01.Endpoints.png’</small>

We see our victim machine at the top and the second IP address is featured in our supplied alerts, we will keep an eye out for that one. Moving on to our standard discovery techniques.

First I check the DHCP with the ”dhcp.option.type == 12” filter. There's no DHCP traffic. Moving on to NETBIOS. Filtering for “nbns.flags.opcode == 5”.

<img width="972" height="113" alt="02 Netbios" src="https://github.com/user-attachments/assets/86903c75-0495-4dbd-b7de-43fe70b808b1" />

<small>‘02a.Netbios.png’</small>

We get some Registration Data. We can examine the packet details to get some Host details.

<img width="645" height="274" alt="03 Packet Details" src="https://github.com/user-attachments/assets/06ebd80b-6e0a-4fcc-9afa-fcc35eb75ebc" />

<small>‘02b.Packet Details.png’</small>

IP Address: 10.11.26.183
MAC Address: Intel_ce:fc:8b (d0:57:7b:ce:fc:8b)
Host Name: DESKTOP-B8TQK49

Than we check Kerberos

<img width="842" height="115" alt="04 Kerberos" src="https://github.com/user-attachments/assets/32ccf12d-74ce-45fb-bdf5-d3dd740c602a" />

<small>‘03.Kerberos.png’</small>

User name: oboomwald

We continue and check the LDAP filtering for - “ldap contains "CN=Users"”

<img width="776" height="100" alt="05 LDAP" src="https://github.com/user-attachments/assets/cfc696e6-b0a0-4454-9641-36c4a1e24362" />

<small>‘05.LDAP.png’</small>

This gives us a user name detail.

User name: Oliver Q. Boomwald

Finally checking for HTTP header information to get the OS, why not. For that we use our “standard” HTTP requests filter, and checking for a GET requests HTTP stream. Needed to check around a bit but found an acceptable GET request, here is the HTTP stream example.

<img width="843" height="134" alt="06 HTTP stream" src="https://github.com/user-attachments/assets/5fb97f35-feb7-4f5b-b57f-b4252913b28b" />

<small>‘06.HTTP stream.png’</small>

Points of interest.

The browser is an older version of Internet Explorer

“The HTTP header User-Agent: Mozilla/4.0 is commonly used to identify a client application, often mimicking older versions of Internet Explorer or other browsers for compatibility purposes.”

The Operating System is Windows 8

“The NT 6.2  identifier is used in the User-Agent header to indicate that the operating system is Windows 8”

Tablet Compatible, found that interesting.

“The "Tablet PC 2.0" token in an HTTP User-Agent header typically indicates that the system is running a version of Windows that supports tablet functionality”

This would conclude our host enumeration phase moving to piecing together the attack.

---

02: Examining Traffic

Now we shall go over the alert files and try to correlate the pcap data with the key points.

<img width="1007" height="76" alt="07 Connection Test" src="https://github.com/user-attachments/assets/1d908405-4d95-4435-8602-130100c58d21" />

<small>‘07.Connection Test.png’</small>

These 2 alerts are in the very beginning of our pcap file, as I understand this is the starting point of the upcoming exploit. Below is a short explanation what the requests could mean.

“Likely Hostile" indicates that a request for a .txt file is being flagged as potentially indicative of a threat, such as a reconnaissance attempt to identify vulnerable servers or services. These requests are considered "terse" because they are short and lack additional context, which may suggest automated scanning or probing behavior rather than legitimate user activity.”

The Connection Test itself is not malicious though. Moving on to the next alert.

<img width="965" height="29" alt="08 DNS name error" src="https://github.com/user-attachments/assets/83a76bdc-5289-435a-a7e9-8ccee9d96cfb" />

<small>‘08.DNS name error.png’</small>

10.11.26.3 is our AD controller, is returning error to the victim machine. Lets check for that. After some examination we see that there's quite a few errors in fact. 

<img width="724" height="190" alt="09 DNS no name" src="https://github.com/user-attachments/assets/7a8c391d-0d14-4190-a266-b83f16c29b25" />

<small>‘09.DNS no name.png’</small>

Far too many “no such name” responses to be a simple user error. I am not certain of the mechanism behind this but it very much could indicate some enumeration script running.

“These patterns can also reveal reconnaissance activities by advanced persistent threats exploring the network for vulnerabilities.”

This confirms that the attack attempt on the host has indeed started.

The next one is the TLSv1.0 Used in Session.

<img width="556" height="30" alt="10 TLS alert" src="https://github.com/user-attachments/assets/25d6ade4-4aab-4340-bb82-2955a55c5c71" />

<small>‘10.TLS alert.png’</small>

This is an outdated version of the protocol, that is vulnerable to decrypting. This would be a downgrading attack, allowing the adversary access to the data, that otherwise would be impossible to decrypt.

TLS 1.0 has been deprecated due to vulnerabilities, susceptible to certain cryptographic attacks. As a result, TLS 1.0 was officially deprecated in 2021, along with TLS 1.1, and is no longer considered secure for modern applications.

I must say that I have not been able to verify the downgrade in the capture file. I see the TLS1.0 only in the context of compatibility during the handshake. Here is the IP and port used during the alert. We need to see what the server has to say regarding the TLS version.

<img width="994" height="94" alt="10a TLS server hello" src="https://github.com/user-attachments/assets/2da5e392-5a1f-4319-897b-1b460571b0dc" />

<small>‘10a.TLS server hello.png’</small>

<img width="650" height="231" alt="10b TLS packet details" src="https://github.com/user-attachments/assets/d852dade-a5a4-431f-bfe6-f2599aa28617" />

<small>‘10b.TLS packet details.png’</small>

Perhaps in a professional sense not a satisfying result, but was worth digging in to non the less.

Moving on. There's a whole sequence of SMB protocol alerts. Lets have a look at that.

<img width="695" height="110" alt="10c SMB alerts" src="https://github.com/user-attachments/assets/82e25b56-5a78-4fb6-bd02-a5720faf7d9d" />

<small>'10c.SMB alerts.png'</small>

First up unsafe SMBv1 protocol in use. Once again Downgrading in action.

“The Server Message Block version 1 (SMBv1) protocol is considered obsolete and insecure, posing a significant security risk to systems and networks. Microsoft has deprecated SMBv1 since 2014 and no longer installs it by default. The protocol is particularly vulnerable to exploitation”
I was successful at confirming the alert by checking the SMB protocol negotiation.

<img width="1027" height="43" alt="10d SMB protocol negotiation" src="https://github.com/user-attachments/assets/4a75cb75-f976-4471-94fc-1b4918ae7ec4" />

<small>‘10d.SMB protocol negotiation.png’</small>

We need to observe the packet details, we are looking for the request to offer the SMBv1 protocol witch will be referred to as “NT LM 0.12”.
Heres the Request:

<img width="424" height="278" alt="10e Request Detail" src="https://github.com/user-attachments/assets/12fb0c32-2e93-45c1-8a9e-a17670637f0f" />

<small>‘10e.Request Detail.png’</small>

Heres the Response:

<img width="567" height="278" alt="10f Response Detail" src="https://github.com/user-attachments/assets/26e3f956-2824-4988-868d-5bbfd7fcbc37" />

<small>‘10f.Response Detail.png.’</small>

This confirms the alert as a true positive.

Next alert is GPL NETBIOS SMB Session Setup NTMLSSP unicode asn1 overflow attempt.
“Detecting potential exploitation attempts targeting a vulnerability in Microsoft's ASN.1 library. This vulnerability arises from unchecked buffers in the ASN.1 library, which can be exploited by sending a malformed NETBIOS message to TCP ports 139 or 445, commonly used by SMB (Server Message Block) services. The attack can lead to a Denial of Service (DoS) or, in some cases, allow arbitrary code execution, potentially resulting in system compromise.”
It is recommended to check for “Expert Info” function and look for Malformed Errors regarding the NETBIOS, however I did not find such errors. Regarding the alert description I have found I’m inclined to think that we are looking at arbitrary code execution and not a DoS attack.

The SMB IPC$ unicode share access.
“The SMB IPC$ share is a special, hidden share used to facilitate inter-process communication (IPC) between systems on a network. It does not provide access to files or directories like standard shares but instead exposes named pipes that allow communication with processes running on a remote system.” 
We see attempts being made to try and access the share in the Tree Connect andX Request Path. Alert justified.

<img width="1123" height="34" alt="10g IPC$ share request" src="https://github.com/user-attachments/assets/074d9047-99d4-4da9-844a-7f7d8bc2ad21" />

<small>‘10g.IPC$ share request.png’</small>

Now we’ll focus on the actual HTTP traffic to see if we can spot any unusual HTTP requests. And quite quickly we discover just that. 

<img width="811" height="157" alt="13 POST traffic" src="https://github.com/user-attachments/assets/652b7b4f-bd97-4941-a401-102d74db545f" />

<small>‘13.POST traffic.png’</small>

POST request to a nameless host with “fakeurl.htm” in its URL. The 2 GET requests just above the POST don’t instill confidence. The first host in the image is modandcrackedapk[.]com witch is highly suspicious on its own. Before checking the IPs lets scroll up and find if the “modandcrackedapk” host has appeared before. 

<img width="811" height="157" alt="14 Tracing back" src="https://github.com/user-attachments/assets/76494cbf-2970-499b-b9f3-7d379c35c240" />

<small>‘14.Tracing back.png’</small>

Here is the first mention of “modandcrackedapk” and right before we have 2 potentially suspicious candidates that we will look in to as well.

We shall start checking the IPs with VirusTotal in order of their apearence.

01.IP: 	213[.]246[.]109[.]5
Domain: classicgrand[.]com
VirusTotal Result: 1 detected file communicating with this domain
Comment: Suspicious, might be the first malicious website in the infection chain.

02.IP: 52[.]8[.]34[.]0	
Domain: confirmsubscription[.]com
VirusTotal Result: 1/93 security vendor flagged this domain as malicious
Comment: This website is visited right before “modandcrackedapk.

03.IP: 193[.]42[.]38[.]139
Domain: modandcrackedapk[.]com
VirusTotal Result: 13/95 security vendors flagged this domain as malicious
Comment: This domain has been flagged in an a DNS lookup alert. This is a true positive, the domain is malicious associated with Phishing and Malware. As seen in the image below, the conversations statistics. The most amount of data is exchanged between our infected host and the malicious domain. The data is going over port 443 and is encrypted. 

<img width="396" height="52" alt="15 Conversations" src="https://github.com/user-attachments/assets/d6862055-3f02-4a05-9f3b-78ba61a69d9d" />

<small>‘15.Conversations.png’</small>

We also have a true positive alert for this domain.

<img width="636" height="72" alt="16 DNS lookup" src="https://github.com/user-attachments/assets/5ab63846-03c8-4b49-81bc-5016d73608e8" />

<small>‘16.DNS lookup.png’</small>

04.IP: 104[.]117[.]247[.]99		
Domain: r10.o.lencr.org
VirusTotal Result: At least 9 detected files communicating with this domain
Object:MFMwUTBPME0wSzAJBgUrDgMCGgUABBRpD%2BQVZ%2B1vf7U0RGQGBm8JZwdxcgQUdKR2KRcYVIUxN75n5gZYwLzFBXICEgRSsdGCXQJklJZNbHi669GH4A%3D%3D HTTP/1.1 

Comment: This is the first suspicious GET request. I checked the file object. Took the MD5 hash. It returned benign on VirusTotal. However I would asume it is some type of script or command that I don’t know how to decrypt. 

From URL decode we get this:

MFMwUTBPME0wSzAJBgUrDgMCGgUABBRpD+QVZ+1vf7U0RGQGBm8JZwdxcgQUdKR2KRcYVIUxN75n5gZYwLzFBXICEgRSsdGCXQJklJZNbHi669GH4A==

Its base64 that decrypts in to gibberish.

05.IP: 104[.]26[.]1[.]231		
Domain: geo[.]netsupportsoftware[.]com
VirusTotal Result: 8/95 security vendors flagged this domain as malicious

Object:loca.asp

Comment: Second suspicious GET. I ran the strings command on the loca.asp and we got coordinates: 33.7488,-84.3877. Evidence of recognizance.

“The geographic coordinates 33.7488° N, 84.3877° W correspond to a location in Downtown Atlanta, Georgia”

We got an true alert for this one.

<img width="433" height="51" alt="17 Geo lookup" src="https://github.com/user-attachments/assets/fae840b6-3651-43bc-87f2-019d255ec661" />

<small>‘17.Geo lookup.png’</small>

06.IP: 194[.]180[.]191[.]64		
Domain: 194[.]180[.]191[.]64
VirusTotal Result: 5/95 security vendors flagged this IP address as malicious

Object:http://194.180.191.64/fakeurl.htm HTTP/1.1

Comment: Malicious. Since this address is getting POST request every second I am assuming it is the Command and Control server. Curiously the data is sent over HTTP on port 443. We can follow the HTTP stream and gather that there are several commands being requested and or executed.

First is CMD=POLL; INFO=1; ACK=1.
Followed by CMD=ENCD; ES=1; DATA=.g+$.{.. \....W..D.6..=M..w}..o.......…
So the post commands are being encrypted.

This confirms several alerts.

<img width="475" height="160" alt="18 RAT activity" src="https://github.com/user-attachments/assets/ba676aa1-671f-4c70-8db5-dc79d860d5e9" />

<small>‘18.RAT activity.png’</small>

## 03. Short Report and Conclusion


This is the second exercise for the pcapexpress series. I have been struggling to interpret some of the alert data, had to do some research and attempt to correlate as much and as best as I could. But after spending enough time with every pcap navigation and understanding becomes more natural.

We have determined that a user has interacted with a malicious domain witch has started an infection chain. The infection sequence has been noted by the security department and alerts have been triggered. Investigating the traffic revealed attempts at system enumeration and protocol downgrading SMB and TLS followed by a successful malware execution most likely via interaction with malicious domain (confirmsubscription[.]com).

This has led to an infection by a Remote Access Trojan or (RAT) on the victims system, the virus has began communicating with the Command and Control server of the adversary using encrypted HTTP POST requests over an unusual port 443.

The immediate steps would be to have the affected hosts machine re imaged/reinstalled. The malicious URLs are to be added to the IDS/Firewall block list.

Below is a summary of data for future use and investigations.

#### Compromised Host

IP Address: 10.11.26.183
MAC address: Intel (d0:57:7b:ce:fc:8b)
Host Name: DESKTOP-B8TQK49
Client name: DESKTOP-B8TQK49.nemotodes.health
OS: Windows 8
User Name: oboomwald (Oliver Q. Boomwald)

#### Attackers

Malicious domain 01: confirmsubscription[.]com
Malicious domain 02:modandcrackedapk[.]com
Malicious domain 03: r10.o.lencr.org
Malicious domain 04: geo[.]netsupportsoftware[.]com 

C2 Server 01: 194[.]180[.]191[.]64

#### Malicious MD5 Hashes

*Not Discovered*

This will conclude the second exercise in the series. Follow me to number three!
