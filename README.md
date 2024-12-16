# Top-10-OWASP-CHEATSHEET
Important site recap [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
  ## *Top 1*./ Broken acces control
  - IDOR (insecure direct object reference) just modify :
  ```bash
  #change parameters post, change id, try and see the response of server 200,404,302 
  http://example.com/user/"35" or http://example.com/user/file.php?image="4",...
  ```
  ## *Top 2*./ Cryptographic failures
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
  ## *Top 3*./ Injection breach
Before starting to try some payload you need to understand how web application work.   
You need to enumerate:
  - All users input
  - Url parameters
  - Variable like *GET*, *POST*, *COOKIES*
  - configuration files
  - Query parameters in URL script or application
  - View source code to know the version of OS, server SQL, server web.

Analyse every error message, its a good practise for what can you do and what can't you do 
  ### Command injection
Try this basic caracters and add command like `dir` or `cat /etc/passwd`.
```text
;
|
&
&&
||
$(...)
`...`
'''
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
  ##### Top 4 non-secure application
  ##### Top 5 bad configuration
  ##### Top 6 composant vulnerability
  ##### Top 7 authentification failure
  ##### Top 8 failure integrity data
  ##### Top 9 journalisation defect
  ## *Top 10*./ SSRF (Server-Side Request Forgery)
Permet sur une application web (API) de faire une requete avec le server. (like preview button)
Une fois la faille SSRF découverte on peut tester de faire des requetes interne comme :
```bash
http://127.0.0.1:<port>/
http://localhost/API/endpoint
http://localhost/admin
http://<common_cloud_IP_addr>/
```
Utiliser Burpsuite ou FFUF pour analyser les réponses server.
```bash
ffuf --request req.txt -w /path/wordlist -u http://example.com/
```
