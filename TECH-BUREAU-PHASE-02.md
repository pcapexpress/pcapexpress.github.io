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

### CONFIGURING THE GTFO BIN AS LEAD_ENGINEER
root@TECH-BUREAU-UBUNTU-24:/home/lead_engineer# cp /usr/bin/find /tmp/engineer_find
root@TECH-BUREAU-UBUNTU-24:/home/lead_engineer# chown lead_engineer:lead_engineer /tmp/engineer_find
root@TECH-BUREAU-UBUNTU-24:/home/lead_engineer# chmod 4755 /tmp/engineer_find

### CONFIGURING MARIADB CREDENTIALS AND REMOTE ACCESS
-- Login locally first
sudo mysql

-- Change root to use a password and allow remote access
ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('password123');
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'password123' WITH GRANT OPTION;
FLUSH PRIVILEGES;


-- 1. Create the user 'admin' allowed to connect from any host ('%')
CREATE USER 'admin'@'%' IDENTIFIED BY 'password';

-- 2. Grant 'admin' full privileges over every database and table
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' WITH GRANT OPTION;

-- 3. Reload the privileges to make the changes active
FLUSH PRIVILEGES;
## 01.Recognisence

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
