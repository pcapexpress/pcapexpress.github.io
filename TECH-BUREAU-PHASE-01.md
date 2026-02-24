---
layout: default
---

# TECH-BUREAU Series

## Phase 01: RECON/BRUTEFORCE/EXFILTRATION

<span class="h4-style">**Platform:**</span> https://www.malware-traffic-analysis.net/<br>
<span class="h4-style">**Pcap File:**</span> 2025-01-22-traffic-analysis-exercise.pcap

## Briefing:

... 

##Machine Recognisence Using nmap
<pre data-label="Network Environment"><code>
* <span class="red"><strong>AT4CK-3XPR3S$:</strong></span>  nmap -nP -p 22, 443 TECH-BUREAU
* <span class="orange"><strong>open:</strong></span>  SSH
* <span class="orange"><strong>Active Directory (AD) domain controller:</strong></span>  10.1.17[.]2 - WIN-GSH54QLW48D
* <span class="orange"><strong>AD environment name:</strong></span>  BLUEMOONTUESDAY
* <span class="orange"><strong>LAN segment gateway:</strong></span>  10.1.17[.]1
* <span class="orange"><strong>LAN segment broadcast address:</strong></span>  10.1.17[.]255
</code></pre>

PHASE.01 – Noisy 
The initial Setup
The Ubuntu server is configured via auditctl to watch a specific file in derectory – PROJECT.5527, any interaction with the containing schematic file will raise an alert.
<<AUTDITCTL + LOCAL RULE>>
The server firewall iptables is also watching for any suspicious incoming trafic to the main ports to try and raise the alert in case of an outside port scan.
<<IPTABLES + LOCAL RULE>>
The First Attack
We check that the server is up by sending a ping. Servers Up.
<<PING>>
Next is to see the port status, we are going for 4 ports in this scenario.
<<NMAP>>
We confirm port 22 up, ssh brute force is attempted next, we use the username intern for this scenario and a custom top 10 RockYou passwords file. Hydra is used.
<<HYDRA>>
The bruteforce is successful, we have secured the credentials needed to ssh in to the server.
<<SSH>>
We are in, using the find command we search for the file Frame_specs.txt
<<FIND>>
File located, we take a look at the content using the cat command.
<<CAT>>
The exfiltration will be done using a simple http server and port 8000.
<<HTTP SERVER>>
The file is received, the ssh connection is closed. The attack is compleete.
<<EXFILTRATION + EXIT>>
The Defense
Here we see the series of custom Wazuh alerts that fiered during the attack.
<<WAZUH ALERTS>>
We can confirm the nmap scan on exactly 4 ports. I will point out the detail that to a [SYN] request ports 80 and 443 are giving out an immediate [RST, ACK] to a scan attempt proving that the ports are closed. Ports 22 and 3306 however give a sequence of  [SYN] → [SYN,ACK] → [ACK] → [RST,ACK] signifying a handshake and than a immediate drop from the portscanner.
Port Scan Confirmed
<<WIRESHARK NMAP>>
With the hydra bruteforce we can simply observe the time signature and notice that a burst of 10 SSH protocol requests to the Ubuntu Server happening at the same time, followed by a series of key exchanges.
Brute Force Confirmed
<<WIRESHARK HYDRA>> 
request details
<<WAZUH SSH AS INTERN>>

<<WAZUH CAT AS INTERN>>
<<WIRESHARK HTTP.SERVER>>
In the HTTP stream we can observe a connection handshake followed by a GET request for the Frame_specs file, followed by a [PHS,ACK] push, that's the moment our data is getting exfiltrated. We than see an http code 200 and a connection closing sequence of  [FIN,ACK] → [ACK] 2ice (graceful close).
